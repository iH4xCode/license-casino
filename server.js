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
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const DB_FILE = process.env.DB_FILE || "licenses.db";
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');

// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: "Too many requests from this IP, please try again later"
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiter); // Apply rate limiting to all requests

// Initialize database with enhanced schema
const db = new sqlite3(DB_FILE);

try {
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
            device_fingerprint TEXT,
            expires_at TEXT,
            last_validation TEXT,
            ip_address TEXT,
            user_agent TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    `;
    db.prepare(createTableStmt).run();
    console.log("✅ Database initialized with enhanced schema.");
} catch (err) {
    console.error("Error initializing database:", err.message);
}

// Enhanced device fingerprint validation
function validateFingerprint(fingerprint) {
    if (!fingerprint || typeof fingerprint !== 'string') {
        return false;
    }
    
    // Basic pattern validation (adjust based on your client-side fingerprint format)
    const fingerprintPattern = /^d-[a-z0-9]{9}-[a-z0-9]+-[a-z0-9-]+$/i;
    return fingerprintPattern.test(fingerprint);
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
        
        // Log admin action
        const logStmt = db.prepare(`
            INSERT INTO admin_logs (action, details, ip_address) 
            VALUES (?, ?, ?)
        `);
        logStmt.run(
            req.method + ' ' + req.path,
            JSON.stringify(req.body),
            req.ip
        );
        
        next();
    } catch (error) {
        res.status(400).json({ message: "Invalid token." });
    }
}

// Admin login to get a token
app.post("/admin-login", async (req, res) => {
    const { username, password } = req.body;

    if (username !== adminUsername) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    try {
        const isPasswordCorrect = await bcrypt.compare(password, adminPasswordHash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Invalid credentials" });
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
    const { license_key, duration_days = 30 } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(duration_days));

        const stmt = db.prepare(`
            INSERT INTO licenses 
            (license_key, expires_at) 
            VALUES (?, ?)
        `);
        stmt.run(hashedKey, expiresAt.toISOString());

        return res.json({ 
            message: "License key added successfully", 
            expires_at: expiresAt 
        });
    } catch (error) {
        console.error("Error adding license:", error);
        return res.status(500).json({ message: "Error adding license" });
    }
});

// Enhanced license validation with device fingerprinting
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id, device_fingerprint, action = 'validate' } = req.body;
    
    if (!license_key || !device_id || !device_fingerprint) {
        return res.status(400).json({ 
            valid: false, 
            message: "Missing required fields (license_key, device_id, device_fingerprint)" 
        });
    }

    // Validate device fingerprint format
    if (!validateFingerprint(device_fingerprint)) {
        return res.status(400).json({ 
            valid: false, 
            message: "Invalid device fingerprint format" 
        });
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
            return res.status(404).json({ 
                valid: false, 
                message: "License is invalid" 
            });
        }

        // Check if license is active
        if (validLicense.is_active !== 1) {
            return res.status(403).json({ 
                valid: false, 
                message: "License is deactivated" 
            });
        }

        // Check if license is expired
        if (new Date(validLicense.expires_at) < new Date()) {
            return res.status(403).json({ 
                valid: false, 
                message: "License expired" 
            });
        }

        // Handle revalidation requests
        if (action === 'revalidate') {
            if (!validLicense.device_id || validLicense.device_id !== device_id) {
                return res.json({ 
                    valid: false, 
                    message: "License not valid for this device" 
                });
            }

            // Update last validation time
            const updateStmt = db.prepare(`
                UPDATE licenses 
                SET last_validation = ?, ip_address = ?, user_agent = ?
                WHERE id = ?
            `);
            updateStmt.run(
                new Date().toISOString(),
                req.ip,
                req.headers['user-agent'],
                validLicense.id
            );

            return res.json({ 
                valid: true, 
                message: "License revalidated", 
                expires_at: validLicense.expires_at 
            });
        }

        // Check for device mismatch
        if (validLicense.device_id && validLicense.device_id !== device_id) {
            console.log(`⛔ License key already used on another device: ${validLicense.device_id}`);
            return res.status(403).json({ 
                valid: false, 
                message: "License already in use by another device" 
            });
        }

        // Bind license to device if not already bound
        if (!validLicense.device_id) {
            const updateStmt = db.prepare(`
                UPDATE licenses 
                SET device_id = ?, device_fingerprint = ?, last_validation = ?, 
                    ip_address = ?, user_agent = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `);
            updateStmt.run(
                device_id,
                device_fingerprint,
                new Date().toISOString(),
                req.ip,
                req.headers['user-agent'],
                validLicense.id
            );
            
            console.log(`✅ License key bound to device: ${device_id}`);
            return res.json({ 
                valid: true, 
                message: "License activated on this device", 
                expires_at: validLicense.expires_at 
            });
        }

        // Regular validation for already bound license
        return res.json({ 
            valid: true, 
            message: "License validated", 
            expires_at: validLicense.expires_at 
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ 
            valid: false, 
            message: "Internal server error" 
        });
    }
});

// New endpoint for license management (Admin only)
app.get("/admin/licenses", verifyAdmin, (req, res) => {
    try {
        const stmt = db.prepare("SELECT * FROM licenses");
        const licenses = stmt.all();
        res.json(licenses);
    } catch (error) {
        console.error("Error fetching licenses:", error);
        res.status(500).json({ message: "Error fetching licenses" });
    }
});

// New endpoint to deactivate a license (Admin only)
app.post("/deactivate-license/:id", verifyAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const stmt = db.prepare("UPDATE licenses SET is_active = 0 WHERE id = ?");
        const result = stmt.run(id);
        
        if (result.changes === 0) {
            return res.status(404).json({ message: "License not found" });
        }
        
        res.json({ message: "License deactivated successfully" });
    } catch (error) {
        console.error("Error deactivating license:", error);
        res.status(500).json({ message: "Error deactivating license" });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.status(200).json({ 
        status: "healthy",
        timestamp: new Date().toISOString(),
        dbStatus: db ? "connected" : "disconnected"
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`🔑 Secret Key: ${SECRET_KEY.substring(0, 5)}... (for verification)`);
});