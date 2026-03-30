require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const { Resend } = require("resend");
const { PDFDocument } = require("pdf-lib");

const app = express();
const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

const AUTH_COOKIE_NAME = "admin_auth";
const AUTH_COOKIE_SECRET = process.env.AUTH_COOKIE_SECRET || "change-this-secret";

const publicDir = path.join(__dirname, "..", "public");
const dataDir = path.join(__dirname, "data");
const uploadsRootDir = path.join(__dirname, "uploads");
const signedRootDir = path.join(__dirname, "signed");

const ALLOWED_SCREENS = ["1", "2"];

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(uploadsRootDir)) fs.mkdirSync(uploadsRootDir, { recursive: true });
if (!fs.existsSync(signedRootDir)) fs.mkdirSync(signedRootDir, { recursive: true });

for (const screen of ALLOWED_SCREENS) {
  const uploadDir = path.join(uploadsRootDir, `screen${screen}`);
  const signedDir = path.join(signedRootDir, `screen${screen}`);

  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
  if (!fs.existsSync(signedDir)) fs.mkdirSync(signedDir, { recursive: true });
}

app.use(express.json({ limit: "80mb" }));
app.use(express.urlencoded({ extended: true }));

function normalizeScreen(value) {
  const screen = String(value || "").trim();
  return ALLOWED_SCREENS.includes(screen) ? screen : "1";
}

function getUploadsDir(screen) {
  return path.join(uploadsRootDir, `screen${screen}`);
}

function getSignedDir(screen) {
  return path.join(signedRootDir, `screen${screen}`);
}

function getSessionFile(screen) {
  return path.join(dataDir, `session_screen${screen}.json`);
}

function getStatusFile(screen) {
  return path.join(dataDir, `status_screen${screen}.json`);
}

function getScreenLabel(screen) {
  return screen === "2" ? "Screen 2" : "Screen 1";
}

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
    const maxAgeMs = 1000 * 60 * 60 * 12;

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
    return res.status(401).json({ success: false, error: "Nicht eingeloggt" });
  }
  next();
}

function getAllPdfFiles(screen) {
  return fs
    .readdirSync(getUploadsDir(screen))
    .filter((f) => f.toLowerCase().endsWith(".pdf"))
    .sort();
}

function getCurrentPdfFile(screen) {
  const files = getAllPdfFiles(screen);
  return files.length > 0 ? files[0] : null;
}

function readSession(screen) {
  const sessionFile = getSessionFile(screen);
  if (!fs.existsSync(sessionFile)) return null;

  try {
    return JSON.parse(fs.readFileSync(sessionFile, "utf8"));
  } catch {
    return null;
  }
}

function saveSession(screen, data) {
  fs.writeFileSync(getSessionFile(screen), JSON.stringify(data, null, 2), "utf8");
}

function clearSession(screen) {
  const sessionFile = getSessionFile(screen);
  if (fs.existsSync(sessionFile)) fs.unlinkSync(sessionFile);
}

function readStatus(screen) {
  const statusFile = getStatusFile(screen);

  if (!fs.existsSync(statusFile)) {
    return {
      active: false,
      mode: null,
      name: null,
      filename: null,
      lastSignedAt: null,
      lastSignedName: null,
      lastSignedFile: null,
      lastDropboxPath: null,
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
      lastSignedFile: null,
      lastDropboxPath: null,
    };
  }
}

function saveStatus(screen, data) {
  fs.writeFileSync(getStatusFile(screen), JSON.stringify(data, null, 2), "utf8");
}

function updateLiveStatus(screen, patch = {}) {
  const currentPdf = getCurrentPdfFile(screen);
  const session = readSession(screen);
  const currentStatus = readStatus(screen);

  const nextStatus = {
    ...currentStatus,
    active: !!currentPdf,
    mode: session?.mode || null,
    name: session?.name || null,
    filename: currentPdf || null,
    ...patch,
  };

  saveStatus(screen, nextStatus);
}

function validateSessionPayload(payload) {
  const mode = String(payload.mode || "").trim();

  if (!["mode1", "mode2", "mode3"].includes(mode)) {
    return "Ungültiger Modus.";
  }

  if (mode === "mode1") {
    if (!payload.name || !payload.email || !payload.phone || !payload.plate) {
      return "Bitte Name, E-Mail, Telefonnummer und KFZ-Kennzeichen ausfüllen.";
    }
  }

  if (mode === "mode3") {
    if (!payload.name || !payload.plate || !payload.reason) {
      return "Bitte Name, KFZ-Kennzeichen und Grund ausfüllen.";
    }
  }

  return null;
}

function getUploader(screen) {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, getUploadsDir(screen)),
    filename: (req, file, cb) => {
      const safeName = `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`;
      cb(null, safeName);
    },
  });

  return multer({ storage });
}

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
      height,
    });
  }

  const signedPdfBytes = await pdfDoc.save();
  fs.writeFileSync(outputPdfPath, signedPdfBytes);
}

function buildMailContent(session, currentPdf, screen, dropboxPath = null) {
  const screenLabel = getScreenLabel(screen);
  const now = new Date().toLocaleString("de-DE");

  if (session.mode === "mode1") {
    return {
      subject: `Bestätigung von ${session.name} (${screenLabel})`,
      html: `
        <h2>Neue Bestätigung eingegangen</h2>
        <p><strong>Screen:</strong> ${screenLabel}</p>
        <p><strong>Modus:</strong> Dokument unterzeichnen mit Kontaktdaten</p>
        <p><strong>Name:</strong> ${session.name}</p>
        <p><strong>E-Mail:</strong> ${session.email}</p>
        <p><strong>Telefonnummer:</strong> ${session.phone}</p>
        <p><strong>KFZ-Kennzeichen:</strong> ${session.plate}</p>
        <p><strong>Zeit:</strong> ${now}</p>
        <p><strong>Datei:</strong> ${currentPdf}</p>
        ${dropboxPath ? `<p><strong>Dropbox:</strong> ${dropboxPath}</p>` : ""}
      `,
    };
  }

  if (session.mode === "mode3") {
    return {
      subject: `Bestätigung von ${session.name} (${screenLabel})`,
      html: `
        <h2>Neue Bestätigung eingegangen</h2>
        <p><strong>Screen:</strong> ${screenLabel}</p>
        <p><strong>Modus:</strong> Dokument unterzeichnen mit Name und Grund</p>
        <p><strong>Name:</strong> ${session.name}</p>
        <p><strong>KFZ-Kennzeichen:</strong> ${session.plate}</p>
        <p><strong>Grund:</strong> ${session.reason}</p>
        <p><strong>Zeit:</strong> ${now}</p>
        <p><strong>Datei:</strong> ${currentPdf}</p>
        ${dropboxPath ? `<p><strong>Dropbox:</strong> ${dropboxPath}</p>` : ""}
      `,
    };
  }

  return {
    subject: `PDF angezeigt (${screenLabel})`,
    html: `
      <h2>PDF wurde angezeigt</h2>
      <p><strong>Screen:</strong> ${screenLabel}</p>
      <p><strong>Zeit:</strong> ${now}</p>
      <p><strong>Datei:</strong> ${currentPdf}</p>
      ${dropboxPath ? `<p><strong>Dropbox:</strong> ${dropboxPath}</p>` : ""}
    `,
  };
}

function sanitizeFilePart(value, fallback = "unbekannt") {
  const cleaned = String(value || "")
    .trim()
    .replace(/[^\p{L}\p{N}\-_ ]/gu, "")
    .replace(/\s+/g, "_");

  return cleaned || fallback;
}

function buildDropboxFilename(session) {
  const now = new Date();
  const ts = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, "0"),
    String(now.getDate()).padStart(2, "0"),
    "-",
    String(now.getHours()).padStart(2, "0"),
    String(now.getMinutes()).padStart(2, "0"),
    String(now.getSeconds()).padStart(2, "0"),
  ].join("");

  const safeName = sanitizeFilePart(session?.name, "unbekannt");
  const safePlate = sanitizeFilePart(session?.plate, "ohne_Kennzeichen");

  return `${safeName}__${safePlate}__${ts}.pdf`;
}

function uploadFileToDropbox(localFilePath, dropboxFileName) {
  return new Promise((resolve, reject) => {
    const accessToken = process.env.DROPBOX_ACCESS_TOKEN;
    if (!accessToken) {
      return resolve(null);
    }

    const folder = String(process.env.DROPBOX_FOLDER || "/Kiosk-Signaturen").trim();
    const normalizedFolder = folder.startsWith("/") ? folder : `/${folder}`;
    const dropboxPath = `${normalizedFolder}/${dropboxFileName}`.replace(/\/+/g, "/");

    const fileBuffer = fs.readFileSync(localFilePath);

    const apiArg = JSON.stringify({
      path: dropboxPath,
      mode: "overwrite",
      autorename: false,
      mute: false,
      strict_conflict: false,
    });

    const req = https.request(
      {
        hostname: "content.dropboxapi.com",
        path: "/2/files/upload",
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Dropbox-API-Arg": apiArg,
          "Content-Type": "application/octet-stream",
          "Content-Length": fileBuffer.length,
        },
      },
      (res) => {
        let body = "";

        res.on("data", (chunk) => {
          body += chunk.toString("utf8");
        });

        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = body ? JSON.parse(body) : {};
              resolve({
                path: parsed.path_display || dropboxPath,
                id: parsed.id || null,
                rev: parsed.rev || null,
              });
            } catch {
              resolve({ path: dropboxPath });
            }
          } else {
            reject(
              new Error(
                `Dropbox-Upload fehlgeschlagen (${res.statusCode || "?"}): ${body || "keine Details"}`
              )
            );
          }
        });
      }
    );

    req.on("error", (err) => reject(err));
    req.write(fileBuffer);
    req.end();
  });
}

// Admin/Login
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
      error: "Admin-Zugang ist nicht konfiguriert.",
    });
  }

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  if (username !== adminUser || password !== adminPass) {
    return res.status(401).json({
      success: false,
      error: "Benutzername oder Passwort ist falsch.",
    });
  }

  setAuthCookie(res, username);
  return res.json({ success: true });
});

app.post("/admin/logout", (req, res) => {
  clearAuthCookie(res);
  return res.json({ success: true });
});

app.get("/api/admin/me", (req, res) => {
  return res.json({
    authenticated: isAdminAuthenticated(req),
    screens: ALLOWED_SCREENS,
  });
});

// Pages
app.get("/", (req, res) => {
  return res.sendFile(path.join(publicDir, "screen-select.html"));
});

app.get("/kiosk", (req, res) => {
  return res.sendFile(path.join(publicDir, "screen-select.html"));
});

app.get("/kiosk.html", (req, res) => {
  return res.sendFile(path.join(publicDir, "kiosk.html"));
});

// block direct admin access
app.use((req, res, next) => {
  if (req.path === "/admin.html" || req.path === "/admin-login.html") {
    return res.redirect("/admin");
  }
  next();
});

app.use(express.static(publicDir));
app.use("/files", express.static(uploadsRootDir));

// Admin APIs
app.get("/api/status", requireAdminAuth, (req, res) => {
  const screen = normalizeScreen(req.query.screen);
  const currentPdf = getCurrentPdfFile(screen);
  const session = readSession(screen);
  const currentStatus = readStatus(screen);

  return res.json({
    active: !!currentPdf,
    mode: session?.mode || null,
    name: session?.name || null,
    filename: currentPdf || null,
    lastSignedAt: currentStatus.lastSignedAt || null,
    lastSignedName: currentStatus.lastSignedName || null,
    lastSignedFile: currentStatus.lastSignedFile || null,
    lastDropboxPath: currentStatus.lastDropboxPath || null,
    screen,
  });
});

app.get("/api/session", requireAdminAuth, (req, res) => {
  const screen = normalizeScreen(req.query.screen);
  const session = readSession(screen);
  return res.json({ success: true, session, screen });
});

app.post("/api/session", requireAdminAuth, (req, res) => {
  const screen = normalizeScreen(req.query.screen);

  const payload = {
    mode: String(req.body.mode || "").trim(),
    name: String(req.body.name || "").trim(),
    email: String(req.body.email || "").trim(),
    phone: String(req.body.phone || "").trim(),
    plate: String(req.body.plate || "").trim(),
    reason: String(req.body.reason || "").trim(),
    createdAt: new Date().toISOString(),
  };

  const error = validateSessionPayload(payload);
  if (error) {
    return res.status(400).json({ success: false, error });
  }

  saveSession(screen, payload);
  updateLiveStatus(screen);

  return res.json({ success: true, session: payload, screen });
});

app.post("/api/upload", requireAdminAuth, (req, res) => {
  const screen = normalizeScreen(req.query.screen);
  const upload = getUploader(screen).single("pdf");

  upload(req, res, (err) => {
    if (err) {
      return res.status(500).json({ success: false, error: "Fehler beim Hochladen" });
    }

    const session = readSession(screen);

    if (!session) {
      if (req.file?.path && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      return res.status(400).json({
        success: false,
        error: "Bitte zuerst eine Option auswählen und die erforderlichen Daten eingeben.",
      });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: "Keine PDF hochgeladen" });
    }

    const allFiles = getAllPdfFiles(screen);
    for (const file of allFiles) {
      if (file !== req.file.filename) {
        const filePath = path.join(getUploadsDir(screen), file);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
    }

    updateLiveStatus(screen);

    return res.json({
      success: true,
      filename: req.file.filename,
      screen,
    });
  });
});

// Kiosk APIs
app.get("/api/document", (req, res) => {
  const screen = normalizeScreen(req.query.screen);
  const currentPdf = getCurrentPdfFile(screen);
  const session = readSession(screen);

  if (!currentPdf || !session) {
    return res.json({
      status: "empty",
      version: Date.now(),
      screen,
    });
  }

  const filePath = path.join(getUploadsDir(screen), currentPdf);

  return res.json({
    status: "ok",
    file: `/files/screen${screen}/${currentPdf}`,
    filename: currentPdf,
    version: fs.statSync(filePath).mtimeMs,
    mode: session.mode,
    session,
    screen,
  });
});

app.post("/api/sign", async (req, res) => {
  try {
    const screen = normalizeScreen(req.query.screen);
    const overlays = Array.isArray(req.body.overlays) ? req.body.overlays : [];
    const session = readSession(screen);
    const currentPdf = getCurrentPdfFile(screen);

    if (!session) {
      return res.status(400).json({ success: false, error: "Keine aktive Sitzung vorhanden" });
    }

    if (session.mode === "mode2") {
      return res.status(400).json({
        success: false,
        error: "Dieses Dokument ist nur zum Anzeigen gedacht.",
      });
    }

    if (!currentPdf) {
      return res.status(400).json({ success: false, error: "Kein PDF vorhanden" });
    }

    if (!overlays.length) {
      return res.status(400).json({ success: false, error: "Keine Signatur erhalten" });
    }

    if (!process.env.RESEND_API_KEY || !process.env.MAIL_FROM || !process.env.MAIL_TO) {
      return res.status(500).json({
        success: false,
        error: "Mail-Konfiguration unvollständig",
      });
    }

    const timestamp = Date.now();
    const originalPdfPath = path.join(getUploadsDir(screen), currentPdf);
    const signedPdfName = `signed-${timestamp}-${currentPdf}`;
    const signedPdfPath = path.join(getSignedDir(screen), signedPdfName);

    await createSignedPdf(originalPdfPath, overlays, signedPdfPath);

let dropboxResult = null;

if (process.env.DROPBOX_ACCESS_TOKEN) {
  try {
    const dropboxFileName = buildDropboxFilename(session);

    console.log("Starte Dropbox Upload...");
    dropboxResult = await uploadFileToDropbox(signedPdfPath, dropboxFileName);

    console.log("Dropbox Upload erfolgreich:", dropboxResult?.path);
    console.log("Dropbox Token vorhanden:", !!process.env.DROPBOX_ACCESS_TOKEN);
    console.log("Dropbox Ordner:", process.env.DROPBOX_FOLDER);

  } catch (err) {
    console.error("❌ Dropbox Fehler:", err.message || err);

    // ❗ GANZ WICHTIG:
    // Fehler ignorieren, damit Email trotzdem rausgeht
    dropboxResult = null;
  }
}

    const mailContent = buildMailContent(
      session,
      currentPdf,
      screen,
      dropboxResult?.path || null
    );

    const result = await resend.emails.send({
      from: process.env.MAIL_FROM,
      to: [process.env.MAIL_TO],
      subject: mailContent.subject,
      html: mailContent.html,
      attachments: [
        {
          filename: signedPdfName,
          content: fs.readFileSync(signedPdfPath).toString("base64"),
        },
      ],
    });

    if (result.error) {
      return res.status(500).json({
        success: false,
        error: result.error.message || JSON.stringify(result.error),
      });
    }

    if (fs.existsSync(originalPdfPath)) {
      fs.unlinkSync(originalPdfPath);
    }

    saveStatus(screen, {
      active: false,
      mode: null,
      name: null,
      filename: null,
      lastSignedAt: new Date().toISOString(),
      lastSignedName: session?.name || "Unbekannt",
      lastSignedFile: currentPdf,
      lastDropboxPath: dropboxResult?.path || null,
    });

    clearSession(screen);

    return res.json({
      success: true,
      emailId: result.data?.id || null,
      dropboxPath: dropboxResult?.path || null,
      screen,
    });
  } catch (error) {
    console.error("FEHLER /api/sign:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Unbekannter Fehler",
    });
  }
});

app.post("/api/close", (req, res) => {
  try {
    const screen = normalizeScreen(req.query.screen);
    const currentPdf = getCurrentPdfFile(screen);
    const session = readSession(screen);

    if (session?.mode !== "mode2" && !isAdminAuthenticated(req)) {
      return res.status(403).json({ success: false, error: "Nicht erlaubt" });
    }

    if (currentPdf) {
      const originalPdfPath = path.join(getUploadsDir(screen), currentPdf);
      if (fs.existsSync(originalPdfPath)) {
        fs.unlinkSync(originalPdfPath);
      }
    }

    clearSession(screen);
    updateLiveStatus(screen, {
      active: false,
      mode: null,
      name: null,
      filename: null,
    });

    return res.json({ success: true, screen });
  } catch (error) {
    console.error("FEHLER /api/close:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Unbekannter Fehler",
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
