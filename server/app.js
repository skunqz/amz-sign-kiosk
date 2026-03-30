require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const publicDir = path.join(__dirname, "..", "public");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicDir));

const AUTH_COOKIE = "admin_token";

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function isLoggedIn(req) {
  const cookie = req.headers.cookie || "";
  return cookie.includes(AUTH_COOKIE);
}

// -------- LOGIN ROUTES --------

app.get("/admin", (req, res) => {
  if (!isLoggedIn(req)) {
    return res.sendFile(path.join(publicDir, "admin-login.html"));
  }
  res.sendFile(path.join(publicDir, "admin.html"));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USER &&
    password === process.env.ADMIN_PASS
  ) {
    const token = createToken();

    res.setHeader(
      "Set-Cookie",
      `${AUTH_COOKIE}=${token}; Path=/; HttpOnly`
    );

    return res.json({ success: true });
  }

  res.status(401).json({ error: "Falsche Login Daten" });
});

app.post("/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    `${AUTH_COOKIE}=; Path=/; Max-Age=0`
  );
  res.json({ success: true });
});

// -------- SERVER --------

app.listen(PORT, () => {
  console.log("Server läuft auf Port", PORT);
});
