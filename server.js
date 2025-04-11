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
    // Updated schema to include hardware_fingerprint column
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            hardware_fingerprint TEXT,
            expires_at TEXT
        )
    `;
    db.prepare(createTableStmt).run();

    // Check if hardware_fingerprint column exists, if not add it
    try {
        const columns = db.prepare("PRAGMA table_info(licenses)").all();
        const hasHwFingerprint = columns.some(col => col.name === 'hardware_fingerprint');
        
        if (!hasHwFingerprint) {
            db.prepare("ALTER TABLE licenses ADD COLUMN hardware_fingerprint TEXT").run();
            console.log("✅ Added hardware_fingerprint column to licenses table.");
        }
    } catch (err) {
        console.error("Error checking or adding hardware_fingerprint column:", err.message);
    }
    
    console.log("✅ Database initialized.");
} catch (err) {
    console.error("Error initializing database:", err.message);
}

// Security log function - saves security events related to licenses
function logSecurityEvent(eventType, licenseId, details) {
    const timestamp = new Date().toISOString();
    console.log(`[SECURITY EVENT] [${timestamp}] ${eventType} | License ID: ${licenseId} | ${details}`);
    
    // Optional: You can also save these to a database table
    try {
        // Create security_logs table if it doesn't exist
        db.prepare(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                license_id INTEGER,
                details TEXT,
                FOREIGN KEY (license_id) REFERENCES licenses (id)
            )
        `).run();
        
        // Log the event to the database
        db.prepare(
            "INSERT INTO security_logs (timestamp, event_type, license_id, details) VALUES (?, ?, ?, ?)"
        ).run(timestamp, eventType, licenseId, details);
    } catch (err) {
        console.error("Error logging security event:", err.message);
    }
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

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, hardware_fingerprint, expires_at) VALUES (?, NULL, NULL, ?)");
        stmt.run(hashedKey, expiresAt.toISOString());

        console.log("License key added successfully.");
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// ✅ Enhanced validate-license endpoint with more security features
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id, hardware_fingerprint, security_data } = req.body;
    
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing required data" });
    }

    // Hardware fingerprint is required
    if (!hardware_fingerprint) {
        return res.status(400).json({ valid: false, message: "Missing hardware fingerprint" });
    }
    
    // Enhanced security logging
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    try {
        // Fetch the license directly from the database
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();

        let validLicense = null;

        // First, find the matching license by key
        for (const license of licenses) {
            try {
                const isMatch = await bcrypt.compare(license_key, license.license_key);
                if (isMatch) {
                    validLicense = license;
                    break;
                }
            } catch (error) {
                // Individual comparison errors shouldn't fail the whole request
                console.error("Error comparing license:", error);
            }
        }

        if (!validLicense) {
            logSecurityEvent("INVALID_LICENSE", null, `Invalid license attempt from IP: ${clientIp} | UA: ${userAgent}`);
            return res.status(404).json({ valid: false, message: "License is invalid" });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            logSecurityEvent("EXPIRED_LICENSE", validLicense.id, `Expired license use attempt from IP: ${clientIp}`);
            return res.status(403).json({ valid: false, message: "License expired" });
        }

        // If this license is not yet bound to a device
        if (!validLicense.device_id) {
            // This is a first-time activation, bind device ID and hardware fingerprint
            const updateStmt = db.prepare("UPDATE licenses SET device_id = ?, hardware_fingerprint = ? WHERE id = ?");
            updateStmt.run(device_id, hardware_fingerprint, validLicense.id);
            
            logSecurityEvent("NEW_ACTIVATION", validLicense.id, 
                `License activated on device: ${device_id} | HW: ${hardware_fingerprint.substring(0, 10)}... | IP: ${clientIp}`);
                
            console.log(`✅ License key ${validLicense.id} bound to device: ${device_id} with hardware fingerprint`);
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at 
            });
        }
        
        // Device ID check - prevent reuse on another device
        if (validLicense.device_id !== device_id) {
            logSecurityEvent("DEVICE_MISMATCH", validLicense.id, 
                `Attempt to use on wrong device | Expected: ${validLicense.device_id} | Received: ${device_id} | IP: ${clientIp}`);
                
            console.log(`⛔ License key already used on another device: ${validLicense.device_id}`);
            return res.status(403).json({ valid: false, message: "License already in use by another device" });
        }
        
        // Hardware fingerprint check - prevent backup/restore on another device
        if (validLicense.hardware_fingerprint && validLicense.hardware_fingerprint !== hardware_fingerprint) {
            logSecurityEvent("FINGERPRINT_MISMATCH", validLicense.id, 
                `HW Fingerprint mismatch | Expected: ${validLicense.hardware_fingerprint} | Received: ${hardware_fingerprint} | IP: ${clientIp}`);
                
            console.log(`⛔ Hardware fingerprint mismatch for device: ${device_id}`);
            console.log(`⛔ Stored fingerprint: ${validLicense.hardware_fingerprint}`);
            console.log(`⛔ Provided fingerprint: ${hardware_fingerprint}`);
            return res.status(403).json({ valid: false, message: "Hardware verification failed" });
        }

        // Log successful verification
        logSecurityEvent("SUCCESSFUL_VERIFICATION", validLicense.id, 
            `License successfully verified | Device: ${device_id} | IP: ${clientIp}`);
            
        // All checks passed, license is valid
        return res.json({ 
            valid: true, 
            message: "License validated", 
            expires_at: validLicense.expires_at 
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// ✅ Monitor Active Licenses (Admin only)
app.get("/admin/licenses", verifyAdmin, (req, res) => {
    try {
        const stmt = db.prepare("SELECT id, device_id, hardware_fingerprint, expires_at FROM licenses");
        const licenses = stmt.all();
        
        // Alisin ang mga null values para mas madaling makita
        const formattedLicenses = licenses.map(license => {
            return {
                id: license.id,
                device_id: license.device_id || "Not activated",
                hardware_fingerprint: license.hardware_fingerprint || "Not registered",
                expires_at: license.expires_at,
                status: new Date(license.expires_at) > new Date() ? "Active" : "Expired",
                days_remaining: license.expires_at ? 
                    Math.max(0, Math.floor((new Date(license.expires_at) - new Date()) / (1000 * 60 * 60 * 24))) : 
                    "N/A"
            };
        });
        
        return res.json({ 
            total_licenses: licenses.length,
            active_licenses: formattedLicenses.filter(l => l.status === "Active").length,
            expired_licenses: formattedLicenses.filter(l => l.status === "Expired").length,
            used_licenses: formattedLicenses.filter(l => l.device_id !== "Not activated").length,
            licenses: formattedLicenses 
        });
    } catch (error) {
        console.error("Error fetching licenses:", error);
        return res.status(500).json({ message: "Error fetching licenses" });
    }
});

// ✅ Admin endpoint para ma-reset ang isang license
app.post("/admin/reset-license", verifyAdmin, async (req, res) => {
    const { license_id } = req.body;
    
    if (!license_id) {
        return res.status(400).json({ message: "License ID required" });
    }
    
    try {
        const stmt = db.prepare("UPDATE licenses SET device_id = NULL, hardware_fingerprint = NULL WHERE id = ?");
        const result = stmt.run(license_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ message: "License not found" });
        }
        
        logSecurityEvent("LICENSE_RESET", license_id, `License reset by admin`);
        return res.json({ message: "License reset successfully" });
    } catch (error) {
        console.error("Error resetting license:", error);
        return res.status(500).json({ message: "Error resetting license" });
    }
});

// View security logs endpoint (Admin only)
app.get("/admin/security-logs", verifyAdmin, (req, res) => {
    try {
        // Check if table exists first
        const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='security_logs'").get();
        
        if (!tableExists) {
            return res.json({ logs: [] });
        }
        
        // Get query parameters
        const limit = parseInt(req.query.limit) || 100;
        const page = parseInt(req.query.page) || 1;
        const offset = (page - 1) * limit;
        const event_type = req.query.event_type;
        
        let query = "SELECT * FROM security_logs";
        let countQuery = "SELECT COUNT(*) as total FROM security_logs";
        let params = [];
        
        // Add filtering if event_type is provided
        if (event_type) {
            query += " WHERE event_type = ?";
            countQuery += " WHERE event_type = ?";
            params.push(event_type);
        }
        
        // Add sorting and pagination
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);
        
        // Get logs
        const logs = db.prepare(query).all(...params);
        const totalCount = db.prepare(countQuery).get(...params.slice(0, event_type ? 1 : 0));
        
        return res.json({
            logs,
            pagination: {
                total: totalCount.total,
                page,
                limit,
                pages: Math.ceil(totalCount.total / limit)
            }
        });
    } catch (error) {
        console.error("Error fetching security logs:", error);
        return res.status(500).json({ message: "Error fetching security logs" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});