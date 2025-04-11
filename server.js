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

// Initialize database with updated schema to include hardware fingerprint
const db = new sqlite3(DB_FILE);

try {
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            hardware_fingerprint TEXT,
            security_data TEXT,
            script_version TEXT,
            activation_date TEXT,
            last_validation_date TEXT,
            expires_at TEXT
        )
    `;
    db.prepare(createTableStmt).run();
    console.log("✅ Database initialized with hardware fingerprint support.");
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

// Add license (Admin only)
app.post("/add-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, hardware_fingerprint, expires_at) VALUES (?, NULL, NULL, ?)");
        stmt.run(hashedKey, expiresAt.toISOString());

        console.log("License key added successfully.");
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// Enhanced validate license endpoint with hardware fingerprint check
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id, hardware_fingerprint, security_data, script_version, verification_type } = req.body;
    
    if (!license_key || !device_id || !hardware_fingerprint) {
        return res.status(400).json({ valid: false, message: "Missing required data" });
    }

    try {
        // Log validation attempt for debugging
        console.log(`🔍 License validation attempt - Device: ${device_id.substring(0, 10)}... | HW: ${hardware_fingerprint.substring(0, 10)}...`);
        
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

        // Store current date for logging
        const currentDate = new Date().toISOString();

        // CASE 1: First-time activation (license not yet bound to any device)
        if (!validLicense.device_id && !validLicense.hardware_fingerprint) {
            console.log(`✅ First activation of license - binding to device: ${device_id.substring(0, 10)}... and HW: ${hardware_fingerprint.substring(0, 10)}...`);
            
            const updateStmt = db.prepare(`
                UPDATE licenses 
                SET device_id = ?, 
                    hardware_fingerprint = ?, 
                    security_data = ?,
                    script_version = ?,
                    activation_date = ?,
                    last_validation_date = ?
                WHERE id = ?
            `);
            
            updateStmt.run(
                device_id, 
                hardware_fingerprint, 
                security_data,
                script_version,
                currentDate,
                currentDate,
                validLicense.id
            );
            
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at 
            });
        }
        
        // CASE 2: Device ID and fingerprint match (valid use on registered device)
        if (validLicense.device_id === device_id && validLicense.hardware_fingerprint === hardware_fingerprint) {
            // Update last validation date
            const updateStmt = db.prepare("UPDATE licenses SET last_validation_date = ? WHERE id = ?");
            updateStmt.run(currentDate, validLicense.id);
            
            console.log(`✅ Valid license check from registered device: ${device_id.substring(0, 10)}...`);
            return res.json({ 
                valid: true, 
                message: "License validated", 
                expires_at: validLicense.expires_at 
            });
        }
        
        // CASE 3: License is being used on a different device
        console.log(`⛔ License key used on unauthorized device - Registered: ${validLicense.device_id.substring(0, 10)}... | HW: ${validLicense.hardware_fingerprint.substring(0, 10)}...`);
        console.log(`⛔ Attempt from: ${device_id.substring(0, 10)}... | HW: ${hardware_fingerprint.substring(0, 10)}...`);
        
        return res.status(403).json({ 
            valid: false, 
            message: "License is already activated on another device and cannot be transferred" 
        });
        
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// Get license information (Admin only)
app.get("/admin/licenses", verifyAdmin, (req, res) => {
    try {
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();
        return res.json({ licenses });
    } catch (error) {
        console.error("Error fetching licenses:", error);
        return res.status(500).json({ message: "Error fetching licenses" });
    }
});

// Revoke license (Admin only)
app.post("/admin/revoke-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();

        let licenseId = null;
        
        for (const license of licenses) {
            const isMatch = await bcrypt.compare(license_key, license.license_key);
            if (isMatch) {
                licenseId = license.id;
                break;
            }
        }

        if (!licenseId) {
            return res.status(404).json({ message: "License not found" });
        }

        const updateStmt = db.prepare("UPDATE licenses SET device_id = NULL, hardware_fingerprint = NULL WHERE id = ?");
        updateStmt.run(licenseId);

        return res.json({ message: "License revoked successfully" });
    } catch (error) {
        console.error("Error revoking license:", error);
        return res.status(500).json({ message: "Error revoking license" });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    return res.json({ status: "ok", message: "License server is running" });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});
