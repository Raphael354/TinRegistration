// server.js - COMPLETE WITH CERTIFICATE MANAGEMENT
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/certificates', express.static('certificates')); // Serve certificate files

// File upload configuration for certificates
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const dir = 'certificates';
    try {
      await fs.mkdir(dir, { recursive: true });
      cb(null, dir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueName = `TIN_${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|jpg|jpeg|png/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only PDF and image files are allowed!'));
  }
});

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'tin_registration',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Test email configuration on startup
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error);
  } else {
    console.log('✅ Email server is ready');
  }
});

// Helper Functions
function generateTIN() {
  return 'TIN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
}

function generateReference() {
  return 'REF' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
}

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ============ AUTHENTICATION ENDPOINTS ============
// Create Account (Signup) - SENDS WELCOME EMAIL
app.post('/api/create-account', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const connection = await pool.getConnection();

    const [existingUser] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      connection.release();
      return res.status(409).json({ error: 'Email already exists. Please login.' });
    }

    // ✅ Generate a unique TIN number
    const tin = 'TIN-' + Math.floor(100000 + Math.random() * 900000); // Example: TIN-428193

    // ✅ Insert user with TIN and status
    await connection.query(
      'INSERT INTO users (email, password, tin, status, created_at) VALUES (?, ?, ?, ?, NOW())',
      [email, password, tin, 'Pending']
    );

    connection.release();

    // ✅ Send welcome email (with TIN number included)
    try {
      await transporter.sendMail({
        from: `"TIN Registration Portal" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '🎉 Welcome to TIN Registration Portal',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); padding: 30px; text-align: center;">
              <h1 style="color: white; margin: 0;">Welcome to TIN Portal!</h1>
            </div>
            <div style="padding: 30px; background: #f9f9f9;">
              <h2 style="color: #0066CC;">Account Created Successfully! 🎊</h2>
              <p>Hello,</p>
              <p>Your account has been created successfully. You can now login and register for your Tax Identification Number (TIN).</p>
              
              <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p><strong>📧 Email:</strong> ${email}</p>
                <p><strong>🆔 TIN Number:</strong> ${tin}</p>
              </div>
              
              <h3>Next Steps:</h3>
              <ol>
                <li>Login to your account</li>
                <li>Complete the TIN registration form</li>
                <li>Make payment of ₦4,000</li>
                <li>Receive your TIN certificate within 30 days</li>
              </ol>
              
              <p>Thank you for choosing our service!</p>
            </div>
            <div style="background: #333; color: white; padding: 20px; text-align: center; font-size: 12px;">
              <p>© ${new Date().getFullYear()} TIN Registration Portal. All rights reserved.</p>
            </div>
          </div>
        `,
      });
      console.log(`✅ Welcome email sent to ${email}`);
    } catch (emailError) {
      console.error('❌ Welcome email failed:', emailError);
    }

    res.status(201).json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Signup Error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});


// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM users WHERE email = ? AND password = ?',
      [email, password]
    );
    connection.release();

    if (users.length > 0) {
      res.status(200).json({ 
        success: true, 
        message: 'Login successful',
        user: {
          email: users[0].email,
          id: users[0].id
        }
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Forgot Password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      connection.release();
      return res.status(200).json({ 
        success: true, 
        message: 'If that email exists, a reset link has been sent' 
      });
    }

    const resetToken = generateResetToken();
    const resetExpiry = new Date(Date.now() + 3600000);

    await connection.query(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
      [resetToken, resetExpiry, email]
    );
    connection.release();

    await transporter.sendMail({
      from: `"TIN Portal" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '🔐 Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Request</h2>
          <p>You requested to reset your password. Your reset code is:</p>
          <div style="background: #0066CC; color: white; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 5px; border-radius: 10px;">
            ${resetToken.substring(0, 6).toUpperCase()}
          </div>
          <p>This code will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `,
    });

    res.status(200).json({ 
      success: true, 
      message: 'Password reset code sent to your email' 
    });
  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;

    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const connection = await pool.getConnection();
    
    const [users] = await connection.query(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
      [token]
    );

    if (users.length === 0) {
      connection.release();
      return res.status(400).json({ error: 'Invalid or expired reset code' });
    }

    await connection.query(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
      [newPassword, users[0].id]
    );
    connection.release();

    try {
      await transporter.sendMail({
        from: `"TIN Portal" <${process.env.EMAIL_USER}>`,
        to: users[0].email,
        subject: '✅ Password Changed Successfully',
        html: `
          <h2>Password Changed</h2>
          <p>Your password has been successfully changed.</p>
          <p>You can now login with your new password.</p>
          <p>If you didn't make this change, please contact support immediately.</p>
        `,
      });
    } catch (emailError) {
      console.error('Confirmation email failed:', emailError);
    }

    res.status(200).json({ 
      success: true, 
      message: 'Password reset successful. You can now login.' 
    });
  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ TIN REGISTRATION & PAYMENT ============

app.post('/api/initiate-payment', async (req, res) => {
  try {
    const { bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount } = req.body;

    if (!bvn || !dob || !firstName || !lastName || !nin || !state || !email || !phone || !address || !job) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const connection = await pool.getConnection();
    const [existingReg] = await connection.query(
      'SELECT * FROM registrations WHERE email = ? OR nin = ?',
      [email, nin]
    );

    if (existingReg.length > 0) {
      connection.release();
      return res.status(400).json({ error: 'Email or NIN already registered' });
    }

    const reference = generateReference();
    const tin = generateTIN();
    
    // For testing: Auto-approve payment
    await connection.query(
      `INSERT INTO registrations (bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, status, tin, created_at, paid_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, 'paid', tin]
    );
    connection.release();

    // Send TIN and payment receipt email
    await sendPaymentReceiptEmail(email, firstName, tin, { 
      firstName, lastName, email, phone, state, amount, reference 
    });

    res.json({
      success: true,
      message: 'Registration successful',
      tin: tin,
      reference: reference
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SEND PAYMENT RECEIPT + TIN EMAIL
async function sendPaymentReceiptEmail(email, firstName, tin, userData) {
  try {
    await transporter.sendMail({
      from: `"TIN Portal" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '✅ Payment Successful - Your TIN Number',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0;">Payment Successful! 🎉</h1>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #0066CC;">Hello ${firstName}!</h2>
            <p>Your payment has been received and your TIN registration is complete.</p>
            
            <!-- TIN Number -->
            <div style="background: #0066CC; color: white; padding: 20px; text-align: center; margin: 20px 0; border-radius: 10px;">
              <h2 style="margin: 0;">Your TIN Number</h2>
              <h1 style="margin: 10px 0; font-size: 32px; letter-spacing: 3px;">${tin}</h1>
            </div>
            
            <!-- Payment Receipt -->
            <div style="background: white; padding: 20px; border-radius: 10px; border: 2px solid #ddd;">
              <h3 style="color: #0066CC; margin-top: 0;">Payment Receipt</h3>
              <table style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Amount Paid:</strong></td>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;">₦${userData.amount.toLocaleString()}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Reference:</strong></td>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;">${userData.reference}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Date:</strong></td>
                  <td style="padding: 8px; border-bottom: 1px solid #eee;">${new Date().toLocaleDateString()}</td>
                </tr>
                <tr>
                  <td style="padding: 8px;"><strong>Status:</strong></td>
                  <td style="padding: 8px; color: green; font-weight: bold;">✓ PAID</td>
                </tr>
              </table>
            </div>
            
            <!-- Registration Details -->
            <div style="background: white; padding: 20px; border-radius: 10px; margin-top: 20px;">
              <h3 style="color: #0066CC; margin-top: 0;">Registration Details</h3>
              <p><strong>Name:</strong> ${userData.firstName} ${userData.lastName}</p>
              <p><strong>Email:</strong> ${userData.email}</p>
              <p><strong>Phone:</strong> ${userData.phone}</p>
              <p><strong>State:</strong> ${userData.state}</p>
            </div>
            
            <div style="background: #fffbea; border-left: 4px solid #ffc107; padding: 15px; margin-top: 20px;">
              <p style="margin: 0;"><strong>📜 Certificate Status:</strong></p>
              <p style="margin: 5px 0 0 0;">Your TIN certificate will be ready for download within 30 days. You will receive another email when it's ready.</p>
            </div>
            
            <p style="margin-top: 20px;">Thank you for using our service!</p>
          </div>
          
          <div style="background: #333; color: white; padding: 20px; text-align: center; font-size: 12px;">
            <p>© ${new Date().getFullYear()} TIN Registration Portal. All rights reserved.</p>
          </div>
        </div>
      `,
    });
    console.log(`✅ Payment receipt sent to ${email}`);
  } catch (error) {
    console.error('❌ Payment receipt email failed:', error);
  }
}

// ============ ADMIN: UPLOAD CERTIFICATE ============
app.post('/api/admin/upload-certificate', upload.single('certificate'), async (req, res) => {
  try {
    const { email, tin } = req.body;

    if (!email || !tin || !req.file) {
      return res.status(400).json({ error: 'Email, TIN, and certificate file required' });
    }

    const connection = await pool.getConnection();
    
    // Update registration with certificate path
    const certificateUrl = `/certificates/${req.file.filename}`;
    await connection.query(
      'UPDATE registrations SET certificate_path = ?, status = ? WHERE email = ? AND tin = ?',
      [certificateUrl, 'completed', email, tin]
    );

    const [user] = await connection.query(
      'SELECT * FROM registrations WHERE email = ? AND tin = ?',
      [email, tin]
    );

    connection.release();

    if (user.length > 0) {
      // Send certificate ready email
      await sendCertificateReadyEmail(email, user[0].firstName, tin, certificateUrl);
    }

    res.json({
      success: true,
      message: 'Certificate uploaded successfully',
      certificateUrl: certificateUrl
    });
  } catch (error) {
    console.error('Certificate upload error:', error);
    res.status(500).json({ error: 'Failed to upload certificate' });
  }
});

// SEND CERTIFICATE READY EMAIL
async function sendCertificateReadyEmail(email, firstName, tin, certificateUrl) {
  try {
    await transporter.sendMail({
      from: `"TIN Portal" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '🎊 Your TIN Certificate is Ready!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0;">Certificate Ready! 🎉</h1>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #28a745;">Congratulations ${firstName}!</h2>
            <p>Your TIN certificate is now ready for download.</p>
            
            <div style="background: white; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0;">
              <h3 style="color: #0066CC;">TIN: ${tin}</h3>
              <a href="${process.env.FRONTEND_URL || 'http://localhost:5000'}${certificateUrl}" 
                 style="display: inline-block; background: #0066CC; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                📥 Download Certificate
              </a>
            </div>
            
            <p>You can also download it from your portal dashboard.</p>
            <p>Thank you for using our service!</p>
          </div>
          
          <div style="background: #333; color: white; padding: 20px; text-align: center; font-size: 12px;">
            <p>© ${new Date().getFullYear()} TIN Registration Portal</p>
          </div>
        </div>
      `,
    });
    console.log(`✅ Certificate ready email sent to ${email}`);
  } catch (error) {
    console.error('❌ Certificate email failed:', error);
  }
}

// Check TIN Status
app.post('/api/check-tin-status', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const connection = await pool.getConnection();
    const [registrations] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    connection.release();

    if (registrations.length === 0) {
      return res.status(404).json({ error: 'No registration found' });
    }

    const regData = registrations[0];
    const createdDate = new Date(regData.created_at);
    const releaseDate = new Date(createdDate.getTime() + 30 * 24 * 60 * 60 * 1000);
    const isReady = regData.certificate_path !== null;

    res.json({
      success: true,
      data: {
        tin: regData.tin,
        status: regData.status,
        registeredDate: regData.created_at,
        expectedReleaseDate: releaseDate,
        isReady,
        certificateUrl: regData.certificate_path
      },
    });
  } catch (error) {
    console.error('Status Check Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// ============ DATABASE INITIALIZATION ============
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        reset_token VARCHAR(255),
        reset_token_expiry DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX(email)
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS registrations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        bvn VARCHAR(11) NOT NULL,
        dob DATE NOT NULL,
        firstName VARCHAR(100) NOT NULL,
        lastName VARCHAR(100) NOT NULL,
        nin VARCHAR(11) NOT NULL UNIQUE,
        state VARCHAR(50) NOT NULL,
        email VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        address TEXT NOT NULL,
        job VARCHAR(100) NOT NULL,
        amount INT NOT NULL,
        reference VARCHAR(50) UNIQUE NOT NULL,
        status ENUM('pending', 'paid', 'completed') DEFAULT 'pending',
        tin VARCHAR(50),
        certificate_path VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP NULL,
        INDEX(email),
        INDEX(reference),
        INDEX(tin)
      )
    `);

    connection.release();
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

// ============ START SERVER ============
const PORT = process.env.PORT || 5000;

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email: ${process.env.EMAIL_USER || 'NOT CONFIGURED'}`);
    console.log(`📁 Certificates folder: ${__dirname}/certificates`);
  });
});