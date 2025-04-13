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
    // Create licenses table
    const createLicenseTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            device_type TEXT DEFAULT NULL,
            ip_address TEXT DEFAULT NULL,
            last_active TEXT DEFAULT NULL,
            active_status TEXT DEFAULT 'Offline',
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            revoked_at TEXT DEFAULT NULL
        )
    `;
    db.prepare(createLicenseTableStmt).run();
    
    // Create device tracking table for multi-device support
    const createDeviceTableStmt = `
        CREATE TABLE IF NOT EXISTS device_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            device_type TEXT DEFAULT 'Unknown',
            ip_address TEXT,
            first_used TEXT NOT NULL,
            last_active TEXT NOT NULL,
            active_status TEXT DEFAULT 'Offline',
            FOREIGN KEY (license_id) REFERENCES licenses(id)
        )
    `;
    db.prepare(createDeviceTableStmt).run();
    
    // Create activity log table
    const createActivityLogStmt = `
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER,
            device_id TEXT,
            ip_address TEXT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT
        )
    `;
    db.prepare(createActivityLogStmt).run();
    
    console.log("✅ Database initialized.");
} catch (err) {
    console.error("Error initializing database:", err.message);
}

// Utility function to detect device type from user agent
function detectDeviceType(userAgent) {
    if (!userAgent) return 'Unknown';
    
    const ua = userAgent.toLowerCase();
    
    if (/(android|webos|iphone|ipad|ipod|blackberry|windows phone)/i.test(ua)) {
        return 'Mobile';
    } else if (/(tablet|ipad)/i.test(ua)) {
        return 'Tablet';
    } else {
        return 'PC';
    }
}

// Utility function to log activity
function logActivity(licenseId, deviceId, ipAddress, action, details = null) {
    try {
        const stmt = db.prepare(`
            INSERT INTO activity_log (license_id, device_id, ip_address, action, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(licenseId, deviceId, ipAddress, action, new Date().toISOString(), details);
    } catch (error) {
        console.error("Error logging activity:", error);
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

        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, expires_at, revoked) VALUES (?, NULL, ?, 0)");
        const result = stmt.run(hashedKey, expiresAt.toISOString());

        logActivity(result.lastInsertRowid, null, req.ip, "License Created", `License key added with expiry: ${expiresAt.toISOString()}`);
        
        console.log("License key added successfully.");
        return res.json({ 
            message: "License key added successfully", 
            expires_at: expiresAt,
            license_id: result.lastInsertRowid 
        });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// Revoke license (Admin only)
app.post("/revoke-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        // Fetch all licenses
        const stmt = db.prepare("SELECT * FROM licenses");
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
            return res.status(404).json({ message: "License not found" });
        }
        
        // Update the license to revoked status
        const revokedAt = new Date().toISOString();
        const updateStmt = db.prepare("UPDATE licenses SET revoked = 1, revoked_at = ?, active_status = 'Revoked' WHERE id = ?");
        updateStmt.run(revokedAt, foundLicense.id);
        
        // Update all devices for this license to be offline
        const updateDevicesStmt = db.prepare("UPDATE device_usage SET active_status = 'Revoked' WHERE license_id = ?");
        updateDevicesStmt.run(foundLicense.id);
        
        logActivity(foundLicense.id, foundLicense.device_id, req.ip, "License Revoked", `License revoked at: ${revokedAt}`);
        
        console.log(`⛔ License key revoked: ID ${foundLicense.id}`);
        return res.json({ message: "License revoked successfully" });
    } catch (error) {
        console.error("Error revoking license:", error);
        return res.status(500).json({ message: "Error revoking license" });
    }
});

// Validate License (Now checks for revocation and tracks IP/device)
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id } = req.body;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const deviceType = detectDeviceType(userAgent);
    
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
            logActivity(validLicense.id, device_id, ipAddress, "Failed Validation", "License is revoked");
            console.log(`⛔ License key has been revoked at ${validLicense.revoked_at}`);
            return res.status(403).json({ valid: false, message: "License has been revoked", revoked: true });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            logActivity(validLicense.id, device_id, ipAddress, "Failed Validation", "License is expired");
            return res.status(403).json({ valid: false, message: "License expired" });
        }

        // Current timestamp
        const now = new Date().toISOString();
        
        // Look for existing device records for this license and device
        const deviceQuery = db.prepare("SELECT * FROM device_usage WHERE license_id = ? AND device_id = ?");
        const existingDevice = deviceQuery.get(validLicense.id, device_id);
        
        // Check if this is a new device for this license
        if (!existingDevice) {
            // Count how many devices are already using this license
            const deviceCountQuery = db.prepare("SELECT COUNT(*) as count FROM device_usage WHERE license_id = ?");
            const { count } = deviceCountQuery.get(validLicense.id);
            
            // If this is the first device or the license doesn't have a device yet, update the license record
            if (count === 0 || !validLicense.device_id) {
                const updateLicenseStmt = db.prepare(`
                    UPDATE licenses 
                    SET device_id = ?, device_type = ?, ip_address = ?, last_active = ?, active_status = 'Online' 
                    WHERE id = ?
                `);
                updateLicenseStmt.run(device_id, deviceType, ipAddress, now, validLicense.id);
            }
            
            // Add the new device to device_usage table
            const addDeviceStmt = db.prepare(`
                INSERT INTO device_usage 
                (license_id, device_id, device_type, ip_address, first_used, last_active, active_status) 
                VALUES (?, ?, ?, ?, ?, ?, 'Online')
            `);
            addDeviceStmt.run(validLicense.id, device_id, deviceType, ipAddress, now, now);
            
            logActivity(validLicense.id, device_id, ipAddress, "New Device Registration", 
                        `New device registered: ${deviceType} from IP: ${ipAddress}`);
            
            console.log(`✅ New device registered for license ${validLicense.id}: ${device_id} (${deviceType}) from ${ipAddress}`);
        } else {
            // Update existing device's last active time and IP address
            const updateDeviceStmt = db.prepare(`
                UPDATE device_usage 
                SET last_active = ?, ip_address = ?, active_status = 'Online' 
                WHERE license_id = ? AND device_id = ?
            `);
            updateDeviceStmt.run(now, ipAddress, validLicense.id, device_id);
            
            // Also update the main license record if this is the primary device
            if (validLicense.device_id === device_id) {
                const updateLicenseStmt = db.prepare(`
                    UPDATE licenses 
                    SET last_active = ?, ip_address = ?, active_status = 'Online' 
                    WHERE id = ?
                `);
                updateLicenseStmt.run(now, ipAddress, validLicense.id);
            }
            
            logActivity(validLicense.id, device_id, ipAddress, "License Validation", 
                        `License validated for device: ${deviceType} from IP: ${ipAddress}`);
            
            console.log(`✅ Device ${device_id} validated for license ${validLicense.id} from ${ipAddress}`);
        }
        
        // Get the count of devices using this license
        const deviceCountQuery = db.prepare("SELECT COUNT(*) as count FROM device_usage WHERE license_id = ?");
        const { count: deviceCount } = deviceCountQuery.get(validLicense.id);

        return res.json({ 
            valid: true, 
            message: "License validated", 
            expires_at: validLicense.expires_at,
            device_count: deviceCount,
            device_type: deviceType
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// New endpoint to report device going offline
app.post("/report-offline", async (req, res) => {
    const { license_key, device_id } = req.body;
    
    if (!license_key || !device_id) {
        return res.status(400).json({ success: false, message: "Missing data" });
    }

    try {
        // Find the license
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
            return res.status(404).json({ success: false, message: "License not found" });
        }
        
        // Update device status to offline
        const updateDeviceStmt = db.prepare(`
            UPDATE device_usage 
            SET active_status = 'Offline' 
            WHERE license_id = ? AND device_id = ?
        `);
        updateDeviceStmt.run(validLicense.id, device_id);
        
        // If this is the primary device, update the license record too
        if (validLicense.device_id === device_id) {
            const updateLicenseStmt = db.prepare(`
                UPDATE licenses 
                SET active_status = 'Offline' 
                WHERE id = ?
            `);
            updateLicenseStmt.run(validLicense.id);
        }
        
        logActivity(validLicense.id, device_id, req.ip, "Device Offline", "Device reported offline");
        
        return res.json({ success: true, message: "Device status updated to offline" });
    } catch (error) {
        console.error("Error updating device status:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// New endpoint to list all licenses with details (Admin only)
app.get("/list-licenses", verifyAdmin, (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT l.id, l.license_key, l.device_id, l.device_type, l.ip_address, 
                   l.last_active, l.active_status, l.expires_at, l.revoked, l.revoked_at,
                   (SELECT COUNT(*) FROM device_usage WHERE license_id = l.id) as device_count
            FROM licenses l
            ORDER BY l.id DESC
        `);
        
        const licenses = stmt.all();
        
        // We don't want to send the hashed keys to the frontend
        const sanitizedLicenses = licenses.map(license => {
            // Create a shallow copy without the license_key
            const { license_key, ...sanitizedLicense } = license;
            return sanitizedLicense;
        });
        
        return res.json({ licenses: sanitizedLicenses });
    } catch (error) {
        console.error("Error fetching licenses:", error);
        return res.status(500).json({ message: "Error fetching licenses" });
    }
});

// New endpoint to get devices for a specific license (Admin only)
app.get("/license-devices/:licenseId", verifyAdmin, (req, res) => {
    const { licenseId } = req.params;
    
    try {
        const stmt = db.prepare(`
            SELECT id, device_id, device_type, ip_address, first_used, last_active, active_status
            FROM device_usage
            WHERE license_id = ?
            ORDER BY last_active DESC
        `);
        
        const devices = stmt.all(licenseId);
        
        return res.json({ devices });
    } catch (error) {
        console.error("Error fetching devices for license:", error);
        return res.status(500).json({ message: "Error fetching devices" });
    }
});

// New endpoint to get activity log for a license (Admin only)
app.get("/license-activity/:licenseId", verifyAdmin, (req, res) => {
    const { licenseId } = req.params;
    
    try {
        const stmt = db.prepare(`
            SELECT id, device_id, ip_address, action, timestamp, details
            FROM activity_log
            WHERE license_id = ?
            ORDER BY timestamp DESC
            LIMIT 100
        `);
        
        const activities = stmt.all(licenseId);
        
        return res.json({ activities });
    } catch (error) {
        console.error("Error fetching activity log:", error);
        return res.status(500).json({ message: "Error fetching activity log" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});