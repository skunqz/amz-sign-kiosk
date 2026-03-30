require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Resend } = require("resend");
const { PDFDocument } = require("pdf-lib");

const app = express();
const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

const AUTH_COOKIE_NAME = "admin_auth";
const AUTH_COOKIE_SECRET = process.env.AUTH_COOKIE_SECRET || "change-this-secret";

const uploadsDir = path.join(__dirname, "uploads");
const signedDir = path.join(__dirname, "signed");
const dataDir = path.join(__dirname, "data");
const sessionFile = path.join(dataDir, "current-session.json");
const statusFile = path.join(dataDir, "status.json");
const publicDir = path.join(__dirname, "..", "public");

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(signedDir)) fs.mkdirSync(signedDir, { recursive: true });
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

app.use(express.json({ limit: "80mb" }));
app.use(express.urlencoded({ extended: true }));

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  });

  return cookies;
}

function createAuthToken(username) {
  const payload = `${username}|${Date.now()}`;
  const signature = crypto
    .createHmac("sha256", AUTH_COOKIE_SECRET)
    .update(payload)
    .digest("hex");

  return Buffer.from(`${payload}|${signature}`).toString("base64url");
}

function verifyAuthToken(token) {
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf8");
    const parts = decoded.split("|");
    if (parts.length !== 3) return false;

    const [username, timestamp, signature] = parts;
    const payload = `${username}|${timestamp}`;
    const expected = crypto
      .createHmac("sha256", AUTH_COOKIE_SECRET)
      .update(payload)
      .digest("hex");

    if (signature !== expected) return false;

    const ageMs = Date.now() - Number(timestamp);
    const maxAgeMs = 1000 * 60 * 60 * 12; // 12h

    return ageMs >= 0 && ageMs <= maxAgeMs;
  } catch {
    return false;
  }
}

function isAdminAuthenticated(req) {
  const cookies = parseCookies(req);
  const token = cookies[AUTH_COOKIE_NAME];
  if (!token) return false;
  return verifyAuthToken(token);
}

function setAuthCookie(res, username) {
  const token = createAuthToken(username);
  const isSecure = process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `${AUTH_COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax${isSecure ? "; Secure" : ""}; Max-Age=43200`
  );
}

function clearAuthCookie(res) {
  const isSecure = process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `${AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax${isSecure ? "; Secure" : ""}; Max-Age=0`
  );
}

function requireAdminAuth(req, res, next) {
  if (!isAdminAuthenticated(req)) {
    return res.status(401).json({
      success: false,
      error: "Nicht eingeloggt"
    });
  }

  next();
}

function getAllPdfFiles() {
  return fs.readdirSync(uploadsDir).filter(f => f.toLowerCase().endsWith(".pdf")).sort();
}

function getCurrentPdfFile() {
  const files = getAllPdfFiles();
  return files.length > 0 ? files[0] : null;
}

function readSession() {
  if (!fs.existsSync(sessionFile)) return null;

  try {
    return JSON.parse(fs.readFileSync(sessionFile, "utf8"));
  } catch {
    return null;
  }
}

function saveSession(data) {
  fs.writeFileSync(sessionFile, JSON.stringify(data, null, 2), "utf8");
}

function clearSession() {
  if (fs.existsSync(sessionFile)) {
    fs.unlinkSync(sessionFile);
  }
}

function readStatus() {
  if (!fs.existsSync(statusFile)) {
    return {
      active: false,
      mode: null,
      name: null,
      filename: null,
      lastSignedAt: null,
      lastSignedName: null,
      lastSignedFile: null
    };
  }

  try {
    return JSON.parse(fs.readFileSync(statusFile, "utf8"));
  } catch {
    return {
      active: false,
      mode: null,
      name: null,
      filename: null,
      lastSignedAt: null,
      lastSignedName: null,
      lastSignedFile: null
    };
  }
}

function saveStatus(data) {
  fs.writeFileSync(statusFile, JSON.stringify(data, null, 2), "utf8");
}

function updateLiveStatus(patch = {}) {
  const currentPdf = getCurrentPdfFile();
  const session = readSession();
  const currentStatus = readStatus();

  const nextStatus = {
    ...currentStatus,
    active: !!currentPdf,
    mode: session?.mode || null,
    name: session?.name || null,
    filename: currentPdf || null,
    ...patch
  };

  saveStatus(nextStatus);
}

function validateSessionPayload(payload) {
  const mode = String(payload.mode || "").trim();

  if (!["mode1", "mode2", "mode3"].includes(mode)) {
    return "Ungültiger Modus.";
  }

  if (mode === "mode1") {
    if (!payload.name || !payload.email || !payload.phone) {
      return "Bitte Name, E-Mail und Telefonnummer ausfüllen.";
    }
  }

  if (mode === "mode3") {
    if (!payload.name || !payload.reason) {
      return "Bitte Name und Grund ausfüllen.";
    }
  }

  return null;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, safeName);
  },
});

const upload = multer({ storage });

async function createSignedPdf(originalPdfPath, overlays, outputPdfPath) {
  const pdfBytes = fs.readFileSync(originalPdfPath);
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const pages = pdfDoc.getPages();

  for (const overlay of overlays) {
    const pageIndex = Number(overlay.pageIndex);

    if (Number.isNaN(pageIndex) || pageIndex < 0 || pageIndex >= pages.length) {
      continue;
    }

    const imageBase64 = String(overlay.image || "").replace(/^data:image\/png;base64,/, "");
    if (!imageBase64) continue;

    const pngBytes = Buffer.from(imageBase64, "base64");
    const pngImage = await pdfDoc.embedPng(pngBytes);

    const page = pages[pageIndex];
    const { width, height } = page.getSize();

    page.drawImage(pngImage, {
      x: 0,
      y: 0,
      width,
      height
    });
  }

  const signedPdfBytes = await pdfDoc.save();
  fs.writeFileSync(outputPdfPath, signedPdfBytes);
}

function buildMailContent(session, currentPdf) {
  if (session.mode === "mode1") {
    return {
      subject: `Bestätigung von ${session.name}`,
      html: `
        <h2>Neue Bestätigung eingegangen</h2>
        <p><strong>Modus:</strong> Dokument unterzeichnen mit Kontaktdaten</p>
        <p><strong>Name:</strong> ${session.name}</p>
        <p><strong>E-Mail:</strong> ${session.email}</p>
        <p><strong>Telefonnummer:</strong> ${session.phone}</p>
        <p><strong>Zeit:</strong> ${new Date().toLocaleString("de-DE")}</p>
        <p><strong>Datei:</strong> ${currentPdf}</p>
      `
    };
  }

  if (session.mode === "mode3") {
    return {
      subject: `Bestätigung von ${session.name}`,
      html: `
        <h2>Neue Bestätigung eingegangen</h2>
        <p><strong>Modus:</strong> Dokument unterzeichnen mit Name und Grund</p>
        <p><strong>Name:</strong> ${session.name}</p>
        <p><strong>Grund:</strong> ${session.reason}</p>
        <p><strong>Zeit:</strong> ${new Date().toLocaleString("de-DE")}</p>
        <p><strong>Datei:</strong> ${currentPdf}</p>
      `
    };
  }

  return {
    subject: "PDF angezeigt",
    html: `
      <h2>PDF wurde angezeigt</h2>
      <p><strong>Zeit:</strong> ${new Date().toLocaleString("de-DE")}</p>
      <p><strong>Datei:</strong> ${currentPdf}</p>
    `
  };
}

// Admin-Routen vor static setzen
app.get("/admin", (req, res) => {
  if (isAdminAuthenticated(req)) {
    return res.sendFile(path.join(publicDir, "admin.html"));
  }

  return res.sendFile(path.join(publicDir, "admin-login.html"));
});

app.get("/admin.html", (req, res) => {
  return res.redirect("/admin");
});

app.get("/admin-login.html", (req, res) => {
  return res.redirect("/admin");
});

app.post("/admin/login", (req, res) => {
  const adminUser = process.env.ADMIN_USER;
  const adminPass = process.env.ADMIN_PASS;

  if (!adminUser || !adminPass) {
    return res.status(500).json({
      success: false,
      error: "Admin-Zugang ist nicht konfiguriert."
    });
  }

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  if (username !== adminUser || password !== adminPass) {
    return res.status(401).json({
      success: false,
      error: "Benutzername oder Passwort ist falsch."
    });
  }

  setAuthCookie(res, username);

  return res.json({
    success: true
  });
});

app.post("/admin/logout", (req, res) => {
  clearAuthCookie(res);
  return res.json({ success: true });
});

app.get("/api/admin/me", (req, res) => {
  return res.json({
    authenticated: isAdminAuthenticated(req)
  });
});

// blockiert direkten Zugriff auf admin.html über static
app.use((req, res, next) => {
  if (req.path === "/admin.html" || req.path === "/admin-login.html") {
    return res.redirect("/admin");
  }
  next();
});

app.use(express.static(publicDir));
app.use("/files", express.static(uploadsDir));

app.get("/api/status", requireAdminAuth, (req, res) => {
  const currentPdf = getCurrentPdfFile();
  const session = readSession();
  const currentStatus = readStatus();

  return res.json({
    active: !!currentPdf,
    mode: session?.mode || null,
    name: session?.name || null,
    filename: currentPdf || null,
    lastSignedAt: currentStatus.lastSignedAt || null,
    lastSignedName: currentStatus.lastSignedName || null,
    lastSignedFile: currentStatus.lastSignedFile || null
  });
});

app.get("/api/document", (req, res) => {
  const currentPdf = getCurrentPdfFile();
  const session = readSession();

  if (!currentPdf || !session) {
    return res.json({
      status: "empty",
      version: Date.now()
    });
  }

  const filePath = path.join(uploadsDir, currentPdf);

  return res.json({
    status: "ok",
    file: `/files/${currentPdf}`,
    filename: currentPdf,
    version: fs.statSync(filePath).mtimeMs,
    mode: session.mode,
    session
  });
});

app.get("/api/session", requireAdminAuth, (req, res) => {
  const session = readSession();
  return res.json({ success: true, session });
});

app.post("/api/session", requireAdminAuth, (req, res) => {
  const payload = {
    mode: String(req.body.mode || "").trim(),
    name: String(req.body.name || "").trim(),
    email: String(req.body.email || "").trim(),
    phone: String(req.body.phone || "").trim(),
    reason: String(req.body.reason || "").trim(),
    createdAt: new Date().toISOString()
  };

  const error = validateSessionPayload(payload);
  if (error) {
    return res.status(400).json({
      success: false,
      error
    });
  }

  saveSession(payload);
  updateLiveStatus();

  return res.json({
    success: true,
    session: payload
  });
});

app.post("/api/upload", requireAdminAuth, upload.single("pdf"), (req, res) => {
  const session = readSession();

  if (!session) {
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    return res.status(400).json({
      success: false,
      error: "Bitte zuerst eine Option auswählen und die erforderlichen Daten eingeben."
    });
  }

  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: "Keine PDF hochgeladen"
    });
  }

  const allFiles = getAllPdfFiles();
  for (const file of allFiles) {
    if (file !== req.file.filename) {
      const filePath = path.join(uploadsDir, file);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
  }

  updateLiveStatus();

  return res.json({
    success: true,
    filename: req.file.filename,
    session
  });
});

app.post("/api/sign", async (req, res) => {
  try {
    const overlays = Array.isArray(req.body.overlays) ? req.body.overlays : [];
    const session = readSession();
    const currentPdf = getCurrentPdfFile();

    if (!session) {
      return res.status(400).json({
        success: false,
        error: "Keine aktive Sitzung vorhanden"
      });
    }

    if (session.mode === "mode2") {
      return res.status(400).json({
        success: false,
        error: "Dieses Dokument ist nur zum Anzeigen gedacht."
      });
    }

    if (!currentPdf) {
      return res.status(400).json({
        success: false,
        error: "Kein PDF vorhanden"
      });
    }

    if (!overlays.length) {
      return res.status(400).json({
        success: false,
        error: "Keine Signatur erhalten"
      });
    }

    if (!process.env.RESEND_API_KEY || !process.env.MAIL_FROM || !process.env.MAIL_TO) {
      return res.status(500).json({
        success: false,
        error: "Mail-Konfiguration unvollständig"
      });
    }

    const timestamp = Date.now();
    const originalPdfPath = path.join(uploadsDir, currentPdf);
    const signedPdfName = `signed-${timestamp}-${currentPdf}`;
    const signedPdfPath = path.join(signedDir, signedPdfName);

    await createSignedPdf(originalPdfPath, overlays, signedPdfPath);

    const mailContent = buildMailContent(session, currentPdf);

    const result = await resend.emails.send({
      from: process.env.MAIL_FROM,
      to: [process.env.MAIL_TO],
      subject: mailContent.subject,
      html: mailContent.html,
      attachments: [
        {
          filename: signedPdfName,
          content: fs.readFileSync(signedPdfPath).toString("base64")
        }
      ]
    });

    if (result.error) {
      return res.status(500).json({
        success: false,
        error: result.error.message || JSON.stringify(result.error)
      });
    }

    if (fs.existsSync(originalPdfPath)) {
      fs.unlinkSync(originalPdfPath);
    }

    saveStatus({
      active: false,
      mode: null,
      name: null,
      filename: null,
      lastSignedAt: new Date().toISOString(),
      lastSignedName: session?.name || "Unbekannt",
      lastSignedFile: currentPdf
    });

    clearSession();

    return res.json({
      success: true,
      emailId: result.data?.id || null
    });
  } catch (error) {
    console.error("FEHLER /api/sign:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Unbekannter Fehler"
    });
  }
});

app.post("/api/close", (req, res) => {
  try {
    const currentPdf = getCurrentPdfFile();
    const session = readSession();

    if (session?.mode !== "mode2" && !isAdminAuthenticated(req)) {
      return res.status(403).json({
        success: false,
        error: "Nicht erlaubt"
      });
    }

    if (currentPdf) {
      const originalPdfPath = path.join(uploadsDir, currentPdf);
      if (fs.existsSync(originalPdfPath)) {
        fs.unlinkSync(originalPdfPath);
      }
    }

    clearSession();
    updateLiveStatus({
      active: false,
      mode: null,
      name: null,
      filename: null
    });

    return res.json({
      success: true
    });
  } catch (error) {
    console.error("FEHLER /api/close:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Unbekannter Fehler"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
