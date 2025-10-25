import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import nodemailer from "nodemailer";
import bodyParser from "body-parser";

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ MySQL Connection (Railway-compatible)
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || "localhost",
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: process.env.MYSQLDATABASE || "tin_registration",
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ✅ Email Setup (Nodemailer)
const transporter = nodemailer.createTransport({
  service: "gmail", // or your provider
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Health Check Route
app.get("/", (req, res) => {
  res.send("TIN Registration backend is running ✅");
});

// ✅ Signup Endpoint Example
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { fullname, email, phone, address, nin, gender, dob } = req.body;

    if (!fullname || !email || !nin) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const connection = await pool.getConnection();
    const [existing] = await connection.query("SELECT * FROM users WHERE email = ?", [email]);

    if (existing.length > 0) {
      connection.release();
      return res.status(400).json({ error: "Email already registered" });
    }

    await connection.query(
      "INSERT INTO users (fullname, email, phone, address, nin, gender, dob, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())",
      [fullname, email, phone, address, nin, gender, dob, "Pending"]
    );

    connection.release();

    // Send welcome email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "TIN Registration Successful",
      text: `Dear ${fullname}, your TIN registration has been received and is currently pending.`,
    });

    res.json({ success: true, message: "Registration successful" });
  } catch (error) {
    console.error("Signup Error:", error);
    res.status(500).json({ error: "Server error during signup" });
  }
});

// ✅ Login Endpoint Example
app.post("/api/login", async (req, res) => {
  try {
    const { email, nin } = req.body;
    const connection = await pool.getConnection();

    const [users] = await connection.query("SELECT * FROM users WHERE email = ? AND nin = ?", [email, nin]);
    connection.release();

    if (users.length === 0) {
      return res.status(404).json({ error: "Invalid credentials" });
    }

    res.json({ success: true, message: "Login successful", data: users[0] });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Server error during login" });
  }
});

// ✅ Check Status Endpoint
app.post("/api/check-status", async (req, res) => {
  try {
    const { email } = req.body;

    const connection = await pool.getConnection();
    const [registrations] = await connection.query("SELECT * FROM users WHERE email = ?", [email]);
    connection.release();

    if (registrations.length === 0) {
      return res.status(404).json({ error: "No registration found" });
    }

    const regData = registrations[0];
    const createdDate = new Date(regData.created_at);
    const releaseDate = new Date(createdDate.getTime() + 30 * 24 * 60 * 60 * 1000);

    res.json({
      success: true,
      data: {
        tin: regData.tin,
        status: regData.status,
        registeredDate: regData.created_at,
        expectedReleaseDate: releaseDate,
        isReady: regData.status === "Complete",
      },
    });
  } catch (error) {
    console.error("Status Check Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Dynamic Port (For Railway)
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
