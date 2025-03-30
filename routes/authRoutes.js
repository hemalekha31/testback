const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
require("dotenv").config();

const router = express.Router();

// ✅ Middleware to check API key (optional for login)
function checkApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ message: "❌ Server error: missing authentication key" });
    }
    next();
}

// 🔵 REGISTER ROUTE (User Signup)
router.post("/register", checkApiKey, async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "Please provide name, email, and password" });
    }

    try {
        // 🔹 Check if user already exists
        const [existingUsers] = await db.execute("SELECT id FROM users WHERE email = ?", [email]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: "❌ Email already registered. Use a different email." });
        }

        // ✅ Hash password before storing
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        console.log(`✅ User Registered - ID: ${result.insertId}`);
        res.status(201).json({ message: "✅ User registered successfully", userId: result.insertId });

    } catch (error) {
        console.error("🔥 Registration Error:", error);
        res.status(500).json({ message: "❌ Failed to register user", error: error.message });
    }
});

// 🔵 LOGIN ROUTE (JWT Authentication)
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "❌ Please provide email and password" });
    }

    try {
        const [users] = await db.execute("SELECT id, name, email, password FROM users WHERE email = ?", [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: "❌ Invalid email or password" });
        }

        const user = users[0];

        // 🔹 Compare hashed password using bcrypt
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: "❌ Invalid email or password" });
        }

        // 🔹 Generate JWT Token
        if (!process.env.JWT_SECRET) {
            console.error("🔥 JWT_SECRET is missing in environment variables!");
            return res.status(500).json({ message: "❌ Server error: missing authentication key" });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log(`✅ Login Successful - User: ${user.email}`);
        return res.status(200).json({
            message: "✅ Login successful",
            token,
            user: {
                userId: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("🔥 Login Error:", error);
        return res.status(500).json({ message: "❌ Failed to login", error: error.message });
    }
});

module.exports = router;
