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
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            revoked_at TEXT DEFAULT NULL,
            license_type TEXT DEFAULT 'regular'
        )
    `;
    db.prepare(createTableStmt).run();
    
    // Add license_type column if it doesn't exist (for backward compatibility)
    try {
        db.prepare("ALTER TABLE licenses ADD COLUMN license_type TEXT DEFAULT 'regular'").run();
        console.log("✅ Added license_type column");
    } catch (err) {
        // Column already exists, ignore error
        console.log("✅ license_type column already exists");
    }
    
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

// Test endpoint to verify server is working
app.get("/", (req, res) => {
    res.json({ 
        message: "License Server is running", 
        endpoints: [
            "POST /admin-login",
            "POST /add-license", 
            "POST /add-license-trial",
            "POST /revoke-license",
            "POST /validate-license",
            "POST /check-license-status"
        ]
    });
});

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

// ✅ Add regular license (Admin only)
app.post("/add-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30); // 30 days for regular license

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, expires_at, revoked, license_type) VALUES (?, NULL, ?, 0, 'regular')");
        const result = stmt.run(hashedKey, expiresAt.toISOString());

        console.log("✅ Regular license key added successfully.");
        return res.json({ 
            message: "Regular license key added successfully", 
            expires_at: expiresAt,
            license_id: result.lastInsertRowid,
            license_type: 'regular'
        });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// ✅ Add trial license (Admin only) - THIS IS THE MISSING ENDPOINT
app.post("/add-license-trial", verifyAdmin, async (req, res) => {
    console.log("🔄 Trial license creation request received");
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 2); // 2 days for trial license

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, expires_at, revoked, license_type) VALUES (?, NULL, ?, 0, 'trial')");
        const result = stmt.run(hashedKey, expiresAt.toISOString());

        console.log("✅ Trial license key added successfully.");
        return res.json({ 
            message: "Trial license key added successfully", 
            expires_at: expiresAt,
            license_id: result.lastInsertRowid,
            license_type: 'trial'
        });
    } catch (error) {
        console.error("❌ Error adding trial license:", error);
        return res.status(500).json({ message: "Error adding trial license" });
    }
});

// ✅ Revoke license (Admin only)
app.post("/revoke-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        // Fetch all non-revoked licenses
        const stmt = db.prepare("SELECT * FROM licenses WHERE revoked = 0");
        const licenses = stmt.all();
        
        let foundLicense = null;
        
        // Find the license by comparing with bcrypt
        for (const license of licenses) {
            const isMatch = await bcrypt.compare(license_key, license.license_key);
            if (isMatch) {
                foundLicense = license;
                break;
            }
        }
        
        if (!foundLicense) {
            return res.status(404).json({ message: "License not found or already revoked" });
        }
        
        // Update the license to revoked status
        const revokedAt = new Date().toISOString();
        const updateStmt = db.prepare("UPDATE licenses SET revoked = 1, revoked_at = ? WHERE id = ?");
        updateStmt.run(revokedAt, foundLicense.id);
        
        console.log(`⛔ License key revoked: ID ${foundLicense.id}`);
        return res.json({ 
            message: "License revoked successfully",
            license_id: foundLicense.id,
            revoked_at: revokedAt
        });
    } catch (error) {
        console.error("Error revoking license:", error);
        return res.status(500).json({ message: "Error revoking license" });
    }
});

// ✅ Check license status (for periodic checks)
app.post("/check-license-status", async (req, res) => {
    const { license_key, device_id } = req.body;
    
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing data" });
    }

    try {
        // Fetch all licenses
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
            return res.status(404).json({ valid: false, message: "License not found" });
        }
        
        // Check if license is revoked
        if (validLicense.revoked === 1) {
            return res.status(403).json({ 
                valid: false, 
                message: "Your license key has been banned please contact @AngelFinn", 
                revoked: true 
            });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            return res.status(403).json({ 
                valid: false, 
                message: "License expired", 
                expired: true 
            });
        }

        return res.json({ 
            valid: true, 
            message: "License is active",
            expires_at: validLicense.expires_at,
            license_type: validLicense.license_type || 'regular'
        });
    } catch (error) {
        console.error("Error checking license status:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// ✅ Validate License
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
            return res.status(403).json({ 
                valid: false, 
                message: "Your license key has been banned please contact @AngelFinn", 
                revoked: true 
            });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            return res.status(403).json({ valid: false, message: "License expired", expired: true });
        }

        // Prevent reuse on another device
        if (validLicense.device_id && validLicense.device_id !== device_id) {
            console.log(`⛔ License key already used on another device: ${validLicense.device_id}`);
            return res.status(403).json({ valid: false, message: "License already in use by another device" });
        }

        // Bind the license to the first device that registers it
        if (!validLicense.device_id) {
            const updateStmt = db.prepare("UPDATE licenses SET device_id = ? WHERE id = ?");
            updateStmt.run(device_id, validLicense.id);
            console.log(`✅ License key bound to device: ${device_id}`);
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at,
                license_type: validLicense.license_type || 'regular'
            });
        }

        return res.json({ 
            valid: true, 
            message: "License validated", 
            expires_at: validLicense.expires_at,
            license_type: validLicense.license_type || 'regular'
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`📋 Available endpoints:`);
    console.log(`   GET  / - Server info`);
    console.log(`   POST /admin-login - Admin authentication`);
    console.log(`   POST /add-license - Add regular license (30 days)`);
    console.log(`   POST /add-license-trial - Add trial license (2 days)`);
    console.log(`   POST /revoke-license - Revoke license`);
    console.log(`   POST /validate-license - Validate license`);
    console.log(`   POST /check-license-status - Check license status`);
});