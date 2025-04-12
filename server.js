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

// Set up middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

console.log(`Starting server with configuration:
- Port: ${PORT}
- Database: ${DB_FILE}
- Environment: ${process.env.NODE_ENV || 'development'}
`);

// Initialize database connection with better error handling
let db;
try {
    db = new sqlite3(DB_FILE, { verbose: console.log });
    console.log(`✅ Connected to database: ${DB_FILE}`);
} catch (err) {
    console.error(`❌ Failed to connect to database: ${err.message}`);
    process.exit(1); // Exit if database connection fails
}

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
    
    // Device signatures table (enhanced with script_manager field)
    const createSignaturesTableStmt = `
        CREATE TABLE IF NOT EXISTS device_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            script_manager TEXT DEFAULT 'unknown',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )
    `;
    db.prepare(createSignaturesTableStmt).run();
    
    // Security log table for tracking suspicious activities
    const createSecurityLogTableStmt = `
        CREATE TABLE IF NOT EXISTS security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT,
            old_signature TEXT,
            new_signature TEXT,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )
    `;
    db.prepare(createSecurityLogTableStmt).run();
    
    // Backup detection table to track known backup attempts
    const createBackupDetectionTableStmt = `
        CREATE TABLE IF NOT EXISTS backup_detection (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            script_manager TEXT NOT NULL,
            backup_signature TEXT NOT NULL,
            detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )
    `;
    db.prepare(createBackupDetectionTableStmt).run();
    
    console.log("✅ Database tables initialized successfully.");
} catch (err) {
    console.error("❌ Error initializing database tables:", err.message);
}

// Basic health check endpoint
app.get("/health", (req, res) => {
    res.status(200).json({ status: "UP", timestamp: new Date().toISOString() });
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

    console.log(`Admin login attempt for user: ${username}`);

    if (username !== adminUsername) {
        console.log(`❌ Admin login failed: Invalid username - ${username}`);
        return res.status(401).json({ message: "Invalid username" });
    }

    try {
        const isPasswordCorrect = await bcrypt.compare(password, adminPasswordHash);
        if (!isPasswordCorrect) {
            console.log(`❌ Admin login failed: Invalid password for ${username}`);
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ role: "admin" }, SECRET_KEY, { expiresIn: "1h" });
        console.log(`✅ Admin login successful for ${username}`);
        return res.json({ token });
    } catch (error) {
        console.error("❌ Error during admin login:", error);
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

        console.log(`✅ License key added successfully: ${license_key.substring(0, 3)}...`);
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("❌ Error adding license:", error);
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
        console.error("❌ Error revoking license:", error);
        return res.status(500).json({ message: "Error revoking license" });
    }
});

// ✅ Validate License (Enhanced with script manager detection)
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id, device_signature, script_manager } = req.body;
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

        // Store or verify device signature if provided
        if (device_signature) {
            const deviceSignatureStmt = db.prepare(
                "SELECT * FROM device_signatures WHERE license_id = ? LIMIT 1"
            );
            const existingSignature = deviceSignatureStmt.get(validLicense.id);
            
            if (!existingSignature) {
                // No signature record exists yet, create one
                const insertStmt = db.prepare(
                    "INSERT INTO device_signatures (license_id, device_id, signature, script_manager) VALUES (?, ?, ?, ?)"
                );
                insertStmt.run(validLicense.id, device_id, device_signature, script_manager || "unknown");
                console.log(`✅ Device signature recorded for license ID ${validLicense.id}`);
            } else {
                // Check if script manager changed (backup detection)
                if (script_manager && existingSignature.script_manager !== script_manager) {
                    console.log(`⛔ Script manager changed from ${existingSignature.script_manager} to ${script_manager}`);
                    
                    // Log the backup attempt
                    const logStmt = db.prepare(
                        "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
                    );
                    const details = JSON.stringify({
                        old_manager: existingSignature.script_manager,
                        new_manager: script_manager
                    });
                    logStmt.run(validLicense.id, device_id, existingSignature.signature, device_signature, "script_manager_change", details);
                    
                    // Record in backup detection
                    const backupStmt = db.prepare(
                        "INSERT INTO backup_detection (license_id, device_id, script_manager, backup_signature) VALUES (?, ?, ?, ?)"
                    );
                    backupStmt.run(validLicense.id, device_id, script_manager, device_signature);
                    
                    return res.status(403).json({
                        valid: false,
                        message: "Unauthorized script manager change detected",
                        unauthorized: true,
                        backup_detected: true
                    });
                }
                
                // If same script manager but signature different, check similarity
                if (existingSignature.device_id === device_id && 
                   existingSignature.signature !== device_signature) {
                    // Check signature similarity
                    const similarityScore = calculateSimilarity(existingSignature.signature, device_signature);
                    
                    if (similarityScore < 0.7) { // Below threshold
                        console.log(`⛔ Possible unauthorized transfer detected during validation for license ${validLicense.id}`);
                        console.log(`Similarity score: ${similarityScore}`);
                        
                        // Record this attempt
                        const logStmt = db.prepare(
                            "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
                        );
                        const details = JSON.stringify({
                            similarity_score: similarityScore,
                            script_manager: script_manager
                        });
                        logStmt.run(validLicense.id, device_id, existingSignature.signature, device_signature, "validation_transfer_attempt", details);
                        
                        return res.status(403).json({
                            valid: false,
                            message: "Unauthorized license transfer detected",
                            unauthorized: true
                        });
                    }
                    
                    // Signature is similar enough, update it
                    const updateSignatureStmt = db.prepare(
                        "UPDATE device_signatures SET signature = ?, script_manager = ?, updated_at = ? WHERE id = ?"
                    );
                    updateSignatureStmt.run(
                        device_signature, 
                        script_manager || existingSignature.script_manager, 
                        currentTime, 
                        existingSignature.id
                    );
                }
            }
        }

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
        console.error("❌ Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// ✅ Verify device for anti-backup protection (Enhanced version)
app.post("/verify-device", async (req, res) => {
    const { license_key, device_id, device_signature, script_manager } = req.body;
    
    if (!license_key || !device_id || !device_signature) {
        return res.status(400).json({ 
            valid: false, 
            message: "Missing verification data",
            unauthorized: true
        });
    }

    try {
        // First try to find in admin_license_keys for exact match
        const adminKeyStmt = db.prepare("SELECT license_id FROM admin_license_keys WHERE plain_key = ?");
        const adminKeyResult = adminKeyStmt.get(license_key);
        
        let foundLicenseId = null;
        
        if (adminKeyResult) {
            // Found in admin key table
            foundLicenseId = adminKeyResult.license_id;
        } else {
            // Try bcrypt compare
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
            return res.status(404).json({ 
                valid: false, 
                message: "License not found" 
            });
        }
        
        // Get license details
        const licenseStmt = db.prepare("SELECT * FROM licenses WHERE id = ?");
        const license = licenseStmt.get(foundLicenseId);
        
        // Check if license is revoked
        if (license.revoked === 1) {
            return res.status(403).json({ 
                valid: false, 
                message: "License revoked", 
                revoked: true 
            });
        }
        
        // Check if license is expired
        if (new Date(license.expires_at) < new Date()) {
            return res.status(403).json({ 
                valid: false, 
                message: "License expired" 
            });
        }
        
        // Check for existing backup detection
        const backupStmt = db.prepare(
            "SELECT * FROM backup_detection WHERE license_id = ? AND device_id = ? AND script_manager = ?"
        );
        const existingBackup = backupStmt.get(foundLicenseId, device_id, script_manager || "unknown");
        
        if (existingBackup) {
            console.log(`⛔ Previously detected backup attempt for license ID ${foundLicenseId}`);
            return res.status(403).json({
                valid: false,
                message: "Previously identified backup transfer",
                unauthorized: true,
                backup_detected: true
            });
        }
        
        // Check device fingerprint in device signatures table
        const deviceSignatureStmt = db.prepare(
            "SELECT * FROM device_signatures WHERE license_id = ? LIMIT 1"
        );
        const existingSignature = deviceSignatureStmt.get(foundLicenseId);
        
        // If no device signature record exists yet, create one
        if (!existingSignature) {
            const insertStmt = db.prepare(
                "INSERT INTO device_signatures (license_id, device_id, signature, script_manager) VALUES (?, ?, ?, ?)"
            );
            insertStmt.run(foundLicenseId, device_id, device_signature, script_manager || "unknown");
            
            console.log(`✅ New device signature recorded for license ID ${foundLicenseId}`);
            
            return res.json({
                valid: true,
                message: "Device verified and registered"
            });
        }
        
        // Check if script manager changed
        if (script_manager && existingSignature.script_manager !== script_manager) {
            console.log(`⛔ Script manager change detected: ${existingSignature.script_manager} -> ${script_manager}`);
            
            // Record this attempt
            const logStmt = db.prepare(
                "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
            );
            const details = JSON.stringify({
                old_manager: existingSignature.script_manager,
                new_manager: script_manager
            });
            logStmt.run(foundLicenseId, device_id, existingSignature.signature, device_signature, "script_manager_change_verify", details);
            
            // Add to backup detection
            const backupInsertStmt = db.prepare(
                "INSERT INTO backup_detection (license_id, device_id, script_manager, backup_signature) VALUES (?, ?, ?, ?)"
            );
            backupInsertStmt.run(foundLicenseId, device_id, script_manager, device_signature);
            
            return res.status(403).json({
                valid: false,
                message: "Script manager change detected - possible backup/export",
                unauthorized: true,
                backup_detected: true
            });
        }
        
        // If device_id matches but signature doesn't, this could be a transfer attempt
        if (existingSignature.device_id === device_id && 
            existingSignature.signature !== device_signature) {
            
            // Check similarity - partial matches could be legitimate browser updates
            const similarityScore = calculateSimilarity(existingSignature.signature, device_signature);
            
            // If signatures are very different, likely a backup/transfer
            if (similarityScore < 0.7) { // 70% similarity threshold 
                console.log(`⛔ Possible unauthorized transfer detected for license ${foundLicenseId}`);
                console.log(`Old signature: ${existingSignature.signature.substring(0, 20)}...`);
                console.log(`New signature: ${device_signature.substring(0, 20)}...`);
                console.log(`Similarity score: ${similarityScore}`);
                
                // Record this attempt
                const logStmt = db.prepare(
                    "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
                );
                const details = JSON.stringify({
                    similarity_score: similarityScore,
                    script_manager: script_manager
                });
                logStmt.run(foundLicenseId, device_id, existingSignature.signature, device_signature, "transfer_attempt", details);
                
                return res.status(403).json({
                    valid: false,
                    message: "Possible unauthorized license transfer detected",
                    unauthorized: true
                });
            }
            
            // If signatures are similar enough, update the signature and allow
            const updateStmt = db.prepare(
                "UPDATE device_signatures SET signature = ?, updated_at = ? WHERE license_id = ?"
            );
            updateStmt.run(device_signature, new Date().toISOString(), foundLicenseId);
            
            console.log(`✅ Device signature updated for license ID ${foundLicenseId}`);
        }
        
        // If device_id doesn't match at all, this is a different device
        if (existingSignature.device_id !== device_id) {
            // If license is already bound to a different device
            if (license.device_id && license.device_id !== device_id) {
                console.log(`⛔ License already bound to different device: ${license.device_id}`);
                return res.status(403).json({
                    valid: false,
                    message: "License already bound to another device"
                });
            }
        }
        
        return res.json({
            valid: true,
            message: "Device verification successful"
        });
    } catch (error) {
        console.error("❌ Error during device verification:", error);
        return res.status(500).json({ 
            valid: false, 
            message: "Internal server error" 
        });
    }
});

// ✅ Heartbeat endpoint to keep a license marked as active (Enhanced for script manager detection)
app.post("/license-heartbeat", async (req, res) => {
    const { license_key, device_id, device_signature, script_manager } = req.body;
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
        
        // Verify device ID matches or update it if not set
        if (foundLicense.device_id && foundLicense.device_id !== device_id) {
            return res.status(403).json({ 
                success: false, 
                message: "Device ID mismatch" 
            });
        }
        
        // Check for known backup attempts
        if (script_manager) {
            const backupStmt = db.prepare(
                "SELECT * FROM backup_detection WHERE license_id = ? AND device_id = ? AND script_manager = ?"
            );
            const existingBackup = backupStmt.get(foundLicense.id, device_id, script_manager);
            
            if (existingBackup) {
                console.log(`⛔ Previously detected backup attempt during heartbeat for license ID ${foundLicense.id}`);
                return res.status(403).json({
                    success: false,
                    message: "Previously identified backup transfer",
                    unauthorized: true,
                    backup_detected: true
                });
            }
        }
        
        // Check device signature if provided
        if (device_signature) {
            const deviceSignatureStmt = db.prepare(
                "SELECT * FROM device_signatures WHERE license_id = ? LIMIT 1"
            );
            const existingSignature = deviceSignatureStmt.get(foundLicense.id);
            
            if (existingSignature) {
                // Check for script manager change
                if (script_manager && existingSignature.script_manager !== script_manager) {
                    console.log(`⛔ Script manager change detected during heartbeat: ${existingSignature.script_manager} -> ${script_manager}`);
                    
                    // Log the script manager change
                    const logStmt = db.prepare(
                        "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
                    );
                    const details = JSON.stringify({
                        old_manager: existingSignature.script_manager,
                        new_manager: script_manager
                    });
                    logStmt.run(foundLicense.id, device_id, existingSignature.signature, device_signature, "heartbeat_script_manager_change", details);
                    
                    // Record in backup detection
                    const backupStmt = db.prepare(
                        "INSERT INTO backup_detection (license_id, device_id, script_manager, backup_signature) VALUES (?, ?, ?, ?)"
                    );
                    backupStmt.run(foundLicense.id, device_id, script_manager, device_signature);
                    
                    return res.status(403).json({
                        success: false,
                        message: "Unauthorized script manager change detected",
                        unauthorized: true,
                        backup_detected: true
                    });
                }
                
                // If signatures don't match, this could be an unauthorized transfer
                if (existingSignature.signature !== device_signature) {
                    const similarityScore = calculateSimilarity(existingSignature.signature, device_signature);
                    
                    if (similarityScore < 0.7) {
                        console.log(`⛔ Possible unauthorized transfer detected during heartbeat for license ${foundLicense.id}`);
                        console.log(`Similarity score: ${similarityScore}`);
                        
                        // Record this attempt
                        const logStmt = db.prepare(
                            "INSERT INTO security_log (license_id, device_id, old_signature, new_signature, action, details) VALUES (?, ?, ?, ?, ?, ?)"
                        );
                        const details = JSON.stringify({
                            similarity_score: similarityScore,
                            script_manager: script_manager
                        });
                        logStmt.run(foundLicense.id, device_id, existingSignature.signature, device_signature, "heartbeat_transfer_attempt", details);
                        
                        return res.status(403).json({
                            success: false,
                            message: "Unauthorized license transfer detected",
                            unauthorized: true
                        });
                    }
                    
                    // Signatures are similar enough, update the record
                    const updateStmt = db.prepare(
                        "UPDATE device_signatures SET signature = ?, updated_at = ? WHERE license_id = ?"
                    );
                    updateStmt.run(device_signature, new Date().toISOString(), foundLicense.id);
                }
            } else {
                // No signature record exists, create one
                const insertStmt = db.prepare(
                    "INSERT INTO device_signatures (license_id, device_id, signature, script_manager) VALUES (?, ?, ?, ?)"
                );
                insertStmt.run(foundLicense.id, device_id, device_signature, script_manager || "unknown");
            }
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
        console.error("❌ Error during license heartbeat:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
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
                   a.plain_key,
                   d.script_manager
            FROM licenses l
            LEFT JOIN admin_license_keys a ON l.id = a.license_id
            LEFT JOIN device_signatures d ON l.id = d.license_id
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
                script_manager: license.script_manager || "unknown",
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
        console.error("❌ Error during license monitoring:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Get security log (Admin only)
app.get("/security-log", verifyAdmin, async (req, res) => {
    try {
        const securityLogStmt = db.prepare(`
            SELECT s.id, s.license_id, s.device_id, s.action, s.timestamp, s.details,
                   a.plain_key as license_key
            FROM security_log s
            LEFT JOIN admin_license_keys a ON s.license_id = a.license_id
            ORDER BY s.timestamp DESC
            LIMIT 100
        `);
        const securityLogs = securityLogStmt.all();
        
        return res.json({
            log_count: securityLogs.length,
            logs: securityLogs
        });
    } catch (error) {
        console.error("❌ Error fetching security log:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Get backup detection log (Admin only)
app.get("/backup-detections", verifyAdmin, async (req, res) => {
    try {
        const backupStmt = db.prepare(`
            SELECT b.id, b.license_id, b.device_id, b.script_manager, 
                   b.detected_at, a.plain_key as license_key
            FROM backup_detection b
            LEFT JOIN admin_license_keys a ON b.license_id = a.license_id
            ORDER BY b.detected_at DESC
        `);
        const backups = backupStmt.all();
        
        return res.json({
            count: backups.length,
            detections: backups
        });
    } catch (error) {
        console.error("❌ Error fetching backup detections:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Helper function to calculate similarity between two strings (for device signatures)
function calculateSimilarity(str1, str2) {
    if (!str1 || !str2) return 0;
    
    // Split the strings by the separator used in device signatures
    const components1 = str1.split('::');
    const components2 = str2.split('::');
    
    // Need at least some components to compare
    if (!components1.length || !components2.length) {
        return 0;
    }
    
    // Check for completely different script managers
    const scriptManagerRegex1 = /(Tampermonkey|Violentmonkey|Greasemonkey)/i;
    const scriptManagerRegex2 = /(Tampermonkey|Violentmonkey|Greasemonkey)/i;
    
    const match1 = str1.match(scriptManagerRegex1);
    const match2 = str2.match(scriptManagerRegex2);
    
    if (match1 && match2 && match1[0].toLowerCase() !== match2[0].toLowerCase()) {
        console.log(`Script manager mismatch detected: ${match1[0]} vs ${match2[0]}`);
        return 0; // Different script managers, return 0 similarity
    }
    
    // Count matching components
    let matches = 0;
    const minLength = Math.min(components1.length, components2.length);
    
    for (let i = 0; i < minLength; i++) {
        // For the first component (deviceId), check if it contains the same script manager name
        if (i === 0) {
            const deviceId1 = components1[i].toLowerCase();
            const deviceId2 = components2[i].toLowerCase();
            
            // If both contain the same script manager, give partial credit
            if ((deviceId1.includes('tampermonkey') && deviceId2.includes('tampermonkey')) ||
                (deviceId1.includes('violentmonkey') && deviceId2.includes('violentmonkey')) ||
                (deviceId1.includes('greasemonkey') && deviceId2.includes('greasemonkey'))) {
                matches += 0.5;
            } else if (deviceId1 === deviceId2) {
                matches += 1; // Exact match
            } else {
                // Different device IDs and script managers
                return 0.1; // Very low similarity
            }
        } else {
            // For other components, check similarity
            const comp1 = components1[i];
            const comp2 = components2[i];
            
            // For browser fingerprints, look for partial matches
            if (comp1 === comp2) {
                matches += 1;
            } else if (comp1 && comp2 && (comp1.includes(comp2) || comp2.includes(comp1))) {
                matches += 0.5; // Partial match
            }
        }
    }
    
    return matches / minLength;
}

// ✅ Reset backup detection for specific license (Admin only)
app.post("/reset-backup-detection", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }
    
    try {
        // Find the license ID
        const adminKeyStmt = db.prepare("SELECT license_id FROM admin_license_keys WHERE plain_key = ?");
        const adminKeyResult = adminKeyStmt.get(license_key);
        
        let foundLicenseId = null;
        
        if (adminKeyResult) {
            foundLicenseId = adminKeyResult.license_id;
        } else {
            // Try bcrypt compare
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
        
        if (!foundLicenseId) {
            return res.status(404).json({ message: "License not found" });
        }
        
        // Delete from backup detection table
        const deleteStmt = db.prepare("DELETE FROM backup_detection WHERE license_id = ?");
        const result = deleteStmt.run(foundLicenseId);
        
        // Log this admin action
        const logStmt = db.prepare(
            "INSERT INTO security_log (license_id, device_id, action, details) VALUES (?, ?, ?, ?)"
        );
        const details = JSON.stringify({ admin_action: "reset_backup_detection" });
        logStmt.run(foundLicenseId, null, "admin_reset_backup", details);
        
        return res.json({
            message: "Backup detection reset successfully",
            deletedCount: result.changes
        });
    } catch (error) {
        console.error("❌ Error resetting backup detection:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Start server with improved error handling
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
})
.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use. Try a different port.`);
    } else if (error.code === 'EACCES') {
        console.error(`❌ No permission to bind to port ${PORT}. Try running with sudo or use a port > 1024.`);
    } else {
        console.error(`❌ Server error:`, error);
    }
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    // Close database connection
    if (db) {
      db.close();
      console.log('Database connection closed');
    }
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    // Close database connection
    if (db) {
      db.close();
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});