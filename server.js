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
const SECRET_KEY = process.env.SECRET_KEY; // Ensure this is set in your .env file

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize database
const db = new sqlite3(DB_FILE);

try {
    // Create table if it doesn't exist
    const createTableStmt = `
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT,
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

        // Use prepare and run correctly for better-sqlite3
        const stmt = db.prepare("INSERT INTO licenses (license_key, device_id, expires_at) VALUES (?, NULL, ?)");
        stmt.run(hashedKey, expiresAt.toISOString());  // Execute the query

        console.log("License key added successfully.");
        return res.json({ message: "License key added successfully", expires_at: expiresAt });
    } catch (error) {
        console.error("Error hashing license key:", error); // Log the actual error
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
        // Prepare the query to fetch all licenses
        const stmt = db.prepare("SELECT * FROM licenses");
        const rows = stmt.all();  // Use .all() to fetch all rows synchronously

        let validLicense = null;

        // Iterate through all licenses to find a match
        for (const row of rows) {
            // Compare the provided license key with the stored hash
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
            const updateStmt = db.prepare("UPDATE licenses SET device_id = ? WHERE id = ?");
            updateStmt.run(device_id, validLicense.id); // Run the update query synchronously
            return res.json({ valid: true, message: "Successfully Entered Valid License Expired in 30 days!" });
        } else {
            return res.json({ valid: true, message: "Successfully Entered Valid License Expired in 30 days!" });
        }
    } catch (error) {
        console.error("Error during license validation:", error);
        return res.status(500).json({ valid: false, message: "Internal server error" });
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});