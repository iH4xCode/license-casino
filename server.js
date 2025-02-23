require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;
const dbUrl = process.env.DATABASE_URL;
const adminUsername = process.env.ADMIN_USERNAME;
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const DB_FILE = process.env.DB_FILE || "licenses.db";
const SECRET_KEY = process.env.SECRET_KEY; // Ensure this is set in your .env file

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize database
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        db.run(
            `CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL,
                device_id TEXT,
                expires_at TEXT
            )`,
            (err) => {
                if (err) console.error("Error creating table:", err.message);
                else console.log("✅ Database initialized.");
            }
        );
    }
});

// Middleware to verify admin token
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

// Admin login to get a token
app.post("/admin-login", async (req, res) => {
    const { username, password } = req.body;

    if (username !== adminUsername) {
        return res.status(401).json({ message: "Invalid username" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, adminPasswordHash);
    if (!isPasswordCorrect) {
        return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ role: "admin" }, SECRET_KEY, { expiresIn: "1h" });
    return res.json({ token });
});

// ✅ Add license (Admin only) with hashing and expiration
app.post("/add-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10); // Hash the license key
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30); // Set expiration to 30 days

        db.run(
            "INSERT INTO licenses (license_key, device_id, expires_at) VALUES (?, NULL, ?)",
            [hashedKey, expiresAt.toISOString()],
            (err) => {
                if (err) return res.status(500).json({ message: "Database error" });

                return res.json({ message: "License key added successfully", expires_at: expiresAt });
            }
        );
    } catch (error) {
        return res.status(500).json({ message: "Error hashing license key" });
    }
});

// ✅ Validate License
app.post("/validate-license", (req, res) => {
    const { license_key, device_id } = req.body;
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing data" });
    }

    db.get("SELECT * FROM licenses WHERE device_id IS NULL", [], async (err, row) => {
        if (err) return res.status(500).json({ valid: false, message: "Database error" });

        if (!row) return res.status(404).json({ valid: false, message: "License not found" });

        // Check if license is expired
        if (new Date(row.expires_at) < new Date()) {
            return res.status(403).json({ valid: false, message: "License expired" });
        }

        // Compare hashed key
        const isMatch = await bcrypt.compare(license_key, row.license_key);
        if (!isMatch) {
            return res.status(403).json({ valid: false, message: "Invalid license key" });
        }

        // 🔹 Bind the first valid license to a device
        if (!row.device_id) {
            db.run("UPDATE licenses SET device_id = ? WHERE license_key = ?", [device_id, row.license_key]);
        }

        return res.json({ valid: true, message: "License is valid" });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});