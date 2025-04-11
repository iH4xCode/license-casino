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
    // Updated schema to include fingerprint tracking
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            hardware_fingerprint TEXT,
            activation_count INTEGER DEFAULT 0,
            last_validation TEXT,
            first_activation TEXT,
            script_version TEXT,
            expires_at TEXT
        )
    `;
    db.prepare(createTableStmt).run();
    console.log("✅ Database initialized.");
} catch (err) {
    console.error("Error initializing database:", err.message);
}

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

    try {
        const isPasswordCorrect = await bcrypt.compare(password, adminPasswordHash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ role: "admin" }, SECRET_KEY, { expiresIn: "1h" });
        return res.json({ token });
    } catch (error) {
        console.error("Error during admin login:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Add license (Admin only)
app.post("/add-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, hardware_fingerprint, activation_count, expires_at) VALUES (?, NULL, NULL, 0, ?)");
        stmt.run(hashedKey, expiresAt.toISOString());

        console.log("License key added successfully.");
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// ✅ Validate License (Enhanced with fingerprint detection)
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id, hardware_fingerprint, security_data, script_version, verification_type } = req.body;
    
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing data" });
    }

    // Check if all required security data exists
    if (!hardware_fingerprint) {
        console.log("⛔ Missing hardware fingerprint");
        return res.status(400).json({ valid: false, message: "Invalid client configuration" });
    }

    try {
        // Fetch the license directly from the database
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();

        let validLicense = null;

        for (const license of licenses) {
            const isMatch = await bcrypt.compare(license_key, license.license_key);
            if (isMatch) {
                validLicense = license;
                break;
            }
        }

        if (!validLicense) {
            return res.status(404).json({ valid: false, message: "License is invalid" });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            return res.status(403).json({ valid: false, message: "License expired" });
        }

        // Process for initial activation
        if (!validLicense.device_id) {
            // First time activation
            const currentTime = new Date().toISOString();
            const updateStmt = db.prepare(
                "UPDATE licenses SET device_id = ?, hardware_fingerprint = ?, activation_count = 1, last_validation = ?, first_activation = ?, script_version = ? WHERE id = ?"
            );
            updateStmt.run(
                device_id,
                hardware_fingerprint,
                currentTime,
                currentTime,
                script_version || "unknown",
                validLicense.id
            );
            console.log(`✅ License key bound to device: ${device_id} with fingerprint: ${hardware_fingerprint}`);
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at 
            });
        }

        // Check if this is the same device
        if (validLicense.device_id !== device_id) {
            console.log(`⛔ License key already used on another device: ${validLicense.device_id} vs ${device_id}`);
            return res.status(403).json({ 
                valid: false, 
                message: "License already in use by another device" 
            });
        }

        // Verify hardware fingerprint hasn't changed (detect import/export)
        if (validLicense.hardware_fingerprint && validLicense.hardware_fingerprint !== hardware_fingerprint) {
            console.log(`⛔ Hardware fingerprint mismatch: ${validLicense.hardware_fingerprint} vs ${hardware_fingerprint}`);
            return res.status(403).json({ 
                valid: false, 
                message: "Device fingerprint mismatch. License tampering detected." 
            });
        }

        // Update activation data 
        const updateStmt = db.prepare(
            "UPDATE licenses SET activation_count = activation_count + 1, last_validation = ?, script_version = ? WHERE id = ?"
        );
        updateStmt.run(
            new Date().toISOString(),
            script_version || validLicense.script_version || "unknown",
            validLicense.id
        );

        // All checks passed
        return res.json({ 
            valid: true, 
            message: verification_type === "watchdog" ? "License verified" : "License validated", 
            expires_at: validLicense.expires_at 
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// Admin endpoint to get license details
app.get("/license-details", verifyAdmin, (req, res) => {
    try {
        const stmt = db.prepare("SELECT id, device_id, hardware_fingerprint, activation_count, last_validation, first_activation, script_version, expires_at FROM licenses");
        const licenses = stmt.all();
        return res.json({ licenses });
    } catch (error) {
        console.error("Error fetching license details:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Admin endpoint to revoke a license
app.post("/revoke-license", verifyAdmin, (req, res) => {
    const { license_id } = req.body;
    if (!license_id) {
        return res.status(400).json({ message: "License ID required" });
    }

    try {
        const stmt = db.prepare("UPDATE licenses SET device_id = NULL, hardware_fingerprint = NULL, activation_count = 0 WHERE id = ?");
        const result = stmt.run(license_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ message: "License not found" });
        }
        
        return res.json({ message: "License successfully revoked" });
    } catch (error) {
        console.error("Error revoking license:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});