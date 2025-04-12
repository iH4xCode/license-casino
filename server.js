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
    // Main licenses table
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            revoked_at TEXT DEFAULT NULL,
            last_active TEXT DEFAULT NULL,
            active_status INTEGER DEFAULT 0,
            device_count INTEGER DEFAULT 0
        )
    `;
    db.prepare(createTableStmt).run();
    
    // Create admin key reference table
    const createKeyRefTableStmt = `
        CREATE TABLE IF NOT EXISTS admin_license_keys (
            license_id INTEGER PRIMARY KEY,
            plain_key TEXT NOT NULL,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )
    `;
    db.prepare(createKeyRefTableStmt).run();
    
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

        // Insert into licenses table
        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, expires_at, revoked) VALUES (?, NULL, ?, 0)");
        const result = stmt.run(hashedKey, expiresAt.toISOString());
        
        // Store plain key for admin reference
        const keyRefStmt = db.prepare("INSERT INTO admin_license_keys (license_id, plain_key) VALUES (?, ?)");
        keyRefStmt.run(result.lastInsertRowid, license_key);

        console.log("License key added successfully.");
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// ✅ Revoke license (Admin only)
app.post("/revoke-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        // First try to find in the admin_license_keys table for exact match
        const adminKeyStmt = db.prepare("SELECT license_id FROM admin_license_keys WHERE plain_key = ?");
        const adminKeyResult = adminKeyStmt.get(license_key);
        
        let foundLicenseId = null;
        
        if (adminKeyResult) {
            // Found exact match in admin table
            foundLicenseId = adminKeyResult.license_id;
        } else {
            // Try bcrypt compare for all licenses (fallback)
            const stmt = db.prepare("SELECT * FROM licenses");
            const licenses = stmt.all();
            
            for (const license of licenses) {
                const isMatch = await bcrypt.compare(license_key, license.license_key);
                if (isMatch) {
                    foundLicenseId = license.id;
                    break;
                }
            }
        }
        
        if (foundLicenseId === null) {
            return res.status(404).json({ message: "License not found" });
        }
        
        // Get the license details
        const licenseStmt = db.prepare("SELECT * FROM licenses WHERE id = ?");
        const foundLicense = licenseStmt.get(foundLicenseId);
        
        // Update the license to revoked status
        const revokedAt = new Date().toISOString();
        const updateStmt = db.prepare("UPDATE licenses SET revoked = 1, revoked_at = ? WHERE id = ?");
        updateStmt.run(revokedAt, foundLicenseId);
        
        console.log(`⛔ License key revoked: ID ${foundLicenseId}`);
        return res.json({ message: "License revoked successfully" });
    } catch (error) {
        console.error("Error revoking license:", error);
        return res.status(500).json({ message: "Error revoking license" });
    }
});

// ✅ Validate License (Now checks for revocation and updates activity status)
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id } = req.body;
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing data" });
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
        
        // Check if license is revoked
        if (validLicense.revoked === 1) {
            console.log(`⛔ License key has been revoked at ${validLicense.revoked_at}`);
            return res.status(403).json({ valid: false, message: "License has been revoked", revoked: true });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            return res.status(403).json({ valid: false, message: "License expired" });
        }

        // Update the last active timestamp and set status to active
        const currentTime = new Date().toISOString();
        const updateActivityStmt = db.prepare(
            "UPDATE licenses SET last_active = ?, active_status = 1 WHERE id = ?"
        );
        updateActivityStmt.run(currentTime, validLicense.id);
        console.log(`✅ License key activity updated: ID ${validLicense.id}`);

        // Prevent reuse on another device
        if (validLicense.device_id && validLicense.device_id !== device_id) {
            // Increment device count if this is a new device
            const updateDeviceCountStmt = db.prepare(
                "UPDATE licenses SET device_count = device_count + 1 WHERE id = ?"
            );
            updateDeviceCountStmt.run(validLicense.id);
            
            console.log(`⛔ License key already used on another device: ${validLicense.device_id}`);
            return res.status(403).json({ 
                valid: false, 
                message: "License already in use by another device",
                device_count: (validLicense.device_count || 0) + 1
            });
        }

        // Bind the license to the first device that registers it
        if (!validLicense.device_id) {
            const updateStmt = db.prepare(
                "UPDATE licenses SET device_id = ?, device_count = 1 WHERE id = ?"
            );
            updateStmt.run(device_id, validLicense.id);
            console.log(`✅ License key bound to device: ${device_id}`);
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at,
                device_count: 1
            });
        }

        return res.json({ 
            valid: true, 
            message: "License validated", 
            expires_at: validLicense.expires_at,
            device_count: validLicense.device_count || 1
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// ✅ Get license monitoring information (Admin only)
app.get("/monitor-licenses", verifyAdmin, async (req, res) => {
    try {
        // Update active status based on last active timestamp
        const inactiveThreshold = new Date();
        inactiveThreshold.setMinutes(inactiveThreshold.getMinutes() - 15); // 15 minutes of inactivity = offline
        
        const updateInactiveStmt = db.prepare(
            "UPDATE licenses SET active_status = 0 WHERE last_active < ? OR last_active IS NULL"
        );
        updateInactiveStmt.run(inactiveThreshold.toISOString());
        
        // Get updated license data with plain keys from join
        const licenseDataStmt = db.prepare(`
            SELECT l.id, l.license_key, 
                   l.device_id, 
                   l.expires_at, 
                   l.revoked,
                   l.last_active,
                   l.active_status,
                   l.device_count,
                   a.plain_key
            FROM licenses l
            LEFT JOIN admin_license_keys a ON l.id = a.license_id
        `);
        const licenseData = licenseDataStmt.all();
        
        // Format data for display
        const formattedLicenses = [];
        
        for (const license of licenseData) {
            // Calculate expiry
            const expiresAt = license.expires_at ? new Date(license.expires_at) : null;
            const now = new Date();
            const isExpired = expiresAt && expiresAt < now;
            
            formattedLicenses.push({
                license_id: license.id,
                license_key: license.plain_key || `unknown-key-${license.id}`,
                status: license.revoked === 1 ? "revoked" : 
                        isExpired ? "expired" :
                        license.active_status === 1 ? "online" : "offline",
                device_id: license.device_id || "not_registered",
                device_count: license.device_count || 0,
                expires_at: license.expires_at,
                last_active: license.last_active || "never",
            });
        }
        
        return res.json({
            total_licenses: formattedLicenses.length,
            active_count: formattedLicenses.filter(l => l.status === "online").length,
            licenses: formattedLicenses
        });
    } catch (error) {
        console.error("Error during license monitoring:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Heartbeat endpoint to keep a license marked as active
app.post("/license-heartbeat", async (req, res) => {
    const { license_key, device_id } = req.body;
    if (!license_key || !device_id) {
        return res.status(400).json({ success: false, message: "Missing data" });
    }

    try {
        // Find the license
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();

        let foundLicense = null;
        for (const license of licenses) {
            const isMatch = await bcrypt.compare(license_key, license.license_key);
            if (isMatch) {
                foundLicense = license;
                break;
            }
        }

        if (!foundLicense) {
            return res.status(404).json({ success: false, message: "License not found" });
        }
        
        // Check if license is revoked or expired
        if (foundLicense.revoked === 1) {
            return res.status(403).json({ 
                success: false, 
                message: "License has been revoked", 
                revoked: true 
            });
        }
        
        if (new Date(foundLicense.expires_at) < new Date()) {
            return res.status(403).json({ 
                success: false, 
                message: "License expired" 
            });
        }
        
        // Verify device_id matches or update it if not set
        if (foundLicense.device_id && foundLicense.device_id !== device_id) {
            return res.status(403).json({ 
                success: false, 
                message: "Device ID mismatch" 
            });
        }
        
        // Update last active timestamp
        const currentTime = new Date().toISOString();
        const updateStmt = db.prepare(
            "UPDATE licenses SET last_active = ?, active_status = 1 WHERE id = ?"
        );
        updateStmt.run(currentTime, foundLicense.id);
        
        return res.json({ 
            success: true, 
            message: "Heartbeat received" 
        });
    } catch (error) {
        console.error("Error during license heartbeat:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});