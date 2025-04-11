
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
            device_id TEXT,
            fingerprint TEXT,
            expires_at TEXT
        )
    `;
    db.prepare(createTableStmt).run();
    console.log("✅ License table is ready.");
} catch (error) {
    console.error("❌ Failed to initialize database:", error);
}

// Admin login
app.post("/admin-login", (req, res) => {
    const { username, password } = req.body;

    if (username === adminUsername && bcrypt.compareSync(password, adminPasswordHash)) {
        const token = jwt.sign({ username }, jwtSecret, { expiresIn: "2h" });
        res.json({ token });
    } else {
        res.status(401).json({ error: "Invalid credentials" });
    }
});

// Add license (admin only)
app.post("/add-license", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing token" });
    }

    const token = authHeader.split(" ")[1];
    try {
        jwt.verify(token, jwtSecret);
    } catch (err) {
        return res.status(403).json({ error: "Invalid token" });
    }

    const { license, expiresAt } = req.body;

    if (!license) return res.status(400).json({ error: "License is required" });

    try {
        const existing = db.prepare("SELECT * FROM licenses WHERE license_key = ?").get(license);
        if (existing) {
            return res.status(400).json({ error: "License already exists" });
        }

        const insert = db.prepare("INSERT INTO licenses (license_key, expires_at) VALUES (?, ?)");
        insert.run(license, expiresAt || null);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Failed to add license" });
    }
});

// ✅ Activate license (bind to fingerprint + deviceId)
app.post("/activate", (req, res) => {
    const { license, fingerprint, deviceId } = req.body;

    if (!license || !fingerprint || !deviceId) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        const existing = db.prepare("SELECT * FROM licenses WHERE license_key = ?").get(license);
        if (!existing) {
            return res.status(404).json({ error: "License not found" });
        }

        if (existing.device_id || existing.fingerprint) {
            return res.status(400).json({ error: "License already activated" });
        }

        const update = db.prepare("UPDATE licenses SET device_id = ?, fingerprint = ? WHERE license_key = ?");
        update.run(deviceId, fingerprint, license);

        console.log(`✅ Activated license ${license} for device ${deviceId} / fp ${fingerprint}`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Activation failed" });
    }
});

// 🔐 Validate license with fingerprint + memory-only deviceId
app.get("/validate-license", (req, res) => {
    const { license, fingerprint, deviceId } = req.query;

    if (!license || !fingerprint || !deviceId) {
        return res.status(400).json({ valid: false, error: "Missing fields" });
    }

    try {
        const record = db.prepare("SELECT * FROM licenses WHERE license_key = ?").get(license);
        if (!record) {
            return res.status(404).json({ valid: false, error: "License not found" });
        }

        if (record.fingerprint !== fingerprint || record.device_id !== deviceId) {
            return res.status(403).json({ valid: false, error: "Fingerprint or DeviceID mismatch" });
        }

        res.json({ valid: true });
    } catch (err) {
        res.status(500).json({ valid: false, error: "Validation error" });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 License server running on http://localhost:${PORT}`);
});
