require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;
const dbUrl = process.env.DATABASE_URL;
const adminUsername = process.env.ADMIN_USERNAME;
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

const express = require("express");
const sqlite3 = require("better-sqlite3");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 5000;
const DB_FILE = process.env.DB_FILE || "licenses.db";
const SECRET_KEY = process.env.SECRET_KEY;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize database
const db = new sqlite3(DB_FILE);

try {
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_hash TEXT,
            expires_at TEXT
        )
    `;
    db.prepare(createTableStmt).run();
    console.log("✅ Database initialized.");
} catch (err) {
    console.error("Error initializing database:", err.message);
}

function verifyAdmin(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== "admin") {
            return res.status(403).json({ message: "Access denied. Not an admin." });
        }
        next();
    } catch (error) {
        res.status(400).json({ message: "Invalid token." });
    }
}

app.post("/admin-login", async (req, res) => {
    const { username, password } = req.body;

    if (username !== adminUsername) {
        return res.status(401).json({ message: "Invalid username" });
    }

    try {
        const isPasswordCorrect = await bcrypt.compare(password, adminPasswordHash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ role: "admin" }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// 🔐 Validate license with device_hash
app.post("/validate-license", (req, res) => {
    const { license_key, device_hash } = req.body;

    if (!license_key || !device_hash) {
        return res.status(400).json({ valid: false, message: "Missing license_key or device_hash" });
    }

    const license = db.prepare("SELECT * FROM licenses WHERE license_key = ?").get(license_key);

    if (!license) {
        return res.status(404).json({ valid: false, message: "License not found" });
    }

    if (license.device_hash && license.device_hash !== device_hash) {
        return res.status(403).json({ valid: false, message: "License used on another device" });
    }

    return res.json({ valid: true });
});

// ✅ Activate license with hashed fingerprint binding
app.post("/activate", (req, res) => {
    const { license_key, device_hash } = req.body;

    if (!license_key || !device_hash) {
        return res.status(400).json({ success: false, message: "Missing license_key or device_hash" });
    }

    const license = db.prepare("SELECT * FROM licenses WHERE license_key = ?").get(license_key);

    if (!license) {
        return res.status(400).json({ success: false, message: "License not found" });
    }

    if (license.device_hash && license.device_hash !== device_hash) {
        return res.status(403).json({ success: false, message: "License already used on another device" });
    }

    db.prepare("UPDATE licenses SET device_hash = ? WHERE license_key = ?").run(device_hash, license_key);

    return res.json({ success: true, message: "License activated successfully" });
});

app.listen(PORT, () => {
    console.log(`🚀 License server running on http://localhost:${PORT}`);
});
