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

// ✅ Add license (Admin only) with hashing and expiration
app.post("/add-license", verifyAdmin, async (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.status(400).json({ message: "License key required" });
    }

    try {
        const hashedKey = await bcrypt.hash(license_key, 10); // Hash the license key
        console.log("Hashed License Key before storing:", hashedKey); // Log the hashed key for debugging
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30); // Set expiration to 30 days

        db.run(
            "INSERT INTO licenses (license_key, device_id, expires_at) VALUES (?, NULL, ?)",
            [hashedKey, expiresAt.toISOString()],
            function (err) {
                if (err) {
                    console.error("Database error:", err.message);
                    return res.status(500).json({ message: "Database error" });
                }

                console.log(`License key added with ID ${this.lastID}`);
                return res.json({ message: "License key added successfully", expires_at: expiresAt });
            }
        );
    } catch (error) {
        console.error("Error hashing license key:", error);
        return res.status(500).json({ message: "Error hashing license key" });
    }
});


// ✅ Validate License
app.post("/validate-license", async (req, res) => {
    const { license_key, device_id } = req.body;
    if (!license_key || !device_id) {
        return res.status(400).json({ valid: false, message: "Missing data" });
    }

    try {
        // Fetch all licenses from the database
        db.all("SELECT * FROM licenses", async (err, rows) => {
            if (err) {
                console.error("Database error:", err.message);
                return res.status(500).json({ valid: false, message: "Database error" });
            }

            let validLicense = null;

            // Iterate through all licenses to find a match
            for (const row of rows) {
                const isMatch = await bcrypt.compare(license_key, row.license_key);
                if (isMatch) {
                    validLicense = row;
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

            // Check if license is already in use by another device
            if (validLicense.device_id && validLicense.device_id !== device_id) {
                return res.status(403).json({ valid: false, message: "License already in use by another device" });
            }

            // Bind the license to the device if it's not already bound
            if (!validLicense.device_id) {
                db.run(
                    "UPDATE licenses SET device_id = ? WHERE id = ?",
                    [device_id, validLicense.id],
                    (err) => {
                        if (err) {
                            console.error("Database error:", err.message);
                            return res.status(500).json({ valid: false, message: "Database error" });
                        }
                        return res.json({ valid: true, message: "License is valid" });
                    }
                );
            } else {
                return res.json({ valid: true, message: "License is valid" });
            }
        });
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});