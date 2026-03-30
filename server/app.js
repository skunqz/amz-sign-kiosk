require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "../public")));

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

function getScreen(req) {
  return req.query.screen === "2" ? "2" : "1";
}

function getUploadDir(screen) {
  const dir = path.join(__dirname, `uploads_screen${screen}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}

function getSessionFile(screen) {
  return path.join(dataDir, `session_${screen}.json`);
}

function getPdf(screen) {
  const dir = getUploadDir(screen);
  const files = fs.readdirSync(dir);
  return files[0] || null;
}

// Upload
app.post("/api/upload", (req, res) => {
  const screen = getScreen(req);

  const upload = multer({
    storage: multer.diskStorage({
      destination: getUploadDir(screen),
      filename: (req, file, cb) => cb(null, "doc.pdf")
    })
  }).single("pdf");

  upload(req, res, err => {
    if (err) return res.json({ success: false });

    res.json({ success: true });
  });
});

// Session speichern
app.post("/api/session", (req, res) => {
  const screen = getScreen(req);
  fs.writeFileSync(getSessionFile(screen), JSON.stringify(req.body));
  res.json({ success: true });
});

// Dokument abrufen
app.get("/api/document", (req, res) => {
  const screen = getScreen(req);
  const pdf = getPdf(screen);

  if (!pdf) return res.json({ status: "empty" });

  res.json({
    status: "ok",
    file: `/uploads_screen${screen}/${pdf}`
  });
});

// Close
app.post("/api/close", (req, res) => {
  const screen = getScreen(req);
  const dir = getUploadDir(screen);

  fs.readdirSync(dir).forEach(f => fs.unlinkSync(path.join(dir, f)));

  res.json({ success: true });
});

app.listen(PORT, () => console.log("Server läuft"));