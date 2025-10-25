// ============================================
// TIN REGISTRATION BACKEND - PRODUCTION VERSION
// ============================================

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Utility Functions
function generateTIN() {
  return 'TIN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
}

function generateReference() {
  return 'REF' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
}

// ============================================
// ENDPOINT 1: Health Check
// ============================================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'TIN Registration Backend API',
    version: '1.0.0',
    status: 'Running',
  });
});

// ============================================
// ENDPOINT 2: Initiate Payment & Registration
// ============================================
app.post('/api/initiate-payment', async (req, res) => {
  try {
    const { bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount } = req.body;

    // Validate required fields
    if (!bvn || !dob || !firstName || !lastName || !nin || !state || !email || !phone || !address || !job) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    const connection = await pool.getConnection();
    const [existingUser] = await connection.query(
      'SELECT * FROM registrations WHERE email = ? OR nin = ?',
      [email, nin]
    );

    if (existingUser.length > 0) {
      connection.release();
      return res.status(400).json({ error: 'Email or NIN already registered' });
    }

    const reference = generateReference();
    const tin = generateTIN();

    // Initialize Paystack payment
    try {
      const paystackResponse = await axios.post(
        'https://api.paystack.co/transaction/initialize',
        {
          email: email,
          amount: amount * 100, // Paystack expects amount in kobo
          reference: reference,
          metadata: {
            bvn,
            dob,
            firstName,
            lastName,
            nin,
            state,
            phone,
            address,
            job,
            tin,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
            'Content-Type': 'application/json',
          },
        }
      );

      // Save registration with pending status
      await connection.query(
        `INSERT INTO registrations (bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, tin, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, tin, 'pending']
      );

      connection.release();

      res.json({
        success: true,
        paymentUrl: paystackResponse.data.data.authorization_url,
        reference: reference,
        amount: amount,
        tin: tin,
      });
    } catch (paystackError) {
      connection.release();
      console.error('Paystack Error:', paystackError.response?.data || paystackError.message);
      res.status(500).json({ error: 'Payment initialization failed' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT 3: Verify Payment (Webhook)
// ============================================
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { reference } = req.body;

    if (!reference) {
      return res.status(400).json({ error: 'Reference is required' });
    }

    // Verify payment with Paystack
    const paystackResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const paymentData = paystackResponse.data.data;

    if (paymentData.status === 'success') {
      const connection = await pool.getConnection();

      // Update registration status to paid
      await connection.query(
        `UPDATE registrations SET status = ?, paid_at = NOW() WHERE reference = ?`,
        ['paid', reference]
      );

      // Get user data
      const [user] = await connection.query(
        'SELECT * FROM registrations WHERE reference = ?',
        [reference]
      );

      connection.release();

      if (user.length > 0) {
        const userData = user[0];

        // Send TIN via email
        await sendTINEmail(userData.email, userData.firstName, userData.tin, userData);

        res.json({
          success: true,
          message: 'Payment verified successfully',
          tin: userData.tin,
          email: userData.email,
        });
      } else {
        res.status(404).json({ success: false, message: 'Registration not found' });
      }
    } else {
      res.status(400).json({ success: false, message: 'Payment not successful' });
    }
  } catch (error) {
    console.error('Verification Error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============================================
// ENDPOINT 4: Send TIN Email
// ============================================
async function sendTINEmail(email, firstName, tin, userData) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your TIN Registration - Tax Identification Number',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #0066CC, #0052A3); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .tin-box { background: white; border: 2px solid #0066CC; padding: 20px; margin: 20px 0; text-align: center; border-radius: 8px; }
            .tin-number { font-size: 24px; font-weight: bold; color: #0066CC; letter-spacing: 2px; }
            .info-table { width: 100%; margin-top: 20px; }
            .info-table td { padding: 8px; border-bottom: 1px solid #ddd; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>TIN Registration Successful!</h1>
            </div>
            <div class="content">
              <h2>Hello ${firstName},</h2>
              <p>Congratulations! Your Tax Identification Number (TIN) registration has been successfully processed.</p>
              
              <div class="tin-box">
                <p>Your TIN Number:</p>
                <div class="tin-number">${tin}</div>
              </div>

              <h3>Registration Details:</h3>
              <table class="info-table">
                <tr>
                  <td><strong>Name:</strong></td>
                  <td>${userData.firstName} ${userData.lastName}</td>
                </tr>
                <tr>
                  <td><strong>Email:</strong></td>
                  <td>${userData.email}</td>
                </tr>
                <tr>
                  <td><strong>Phone:</strong></td>
                  <td>${userData.phone}</td>
                </tr>
                <tr>
                  <td><strong>State:</strong></td>
                  <td>${userData.state}</td>
                </tr>
                <tr>
                  <td><strong>Status:</strong></td>
                  <td>Processing</td>
                </tr>
              </table>

              <h3>Next Steps:</h3>
              <ol>
                <li>Your TIN certificate will be ready within <strong>30 days</strong></li>
                <li>You will receive a notification email when your certificate is ready</li>
                <li>You can download your certificate from your portal</li>
                <li>Keep this TIN number safe for all tax-related activities</li>
              </ol>

              <p><strong>Important:</strong> Please save this email for your records. Your TIN is a permanent identification number for tax purposes.</p>

              <div class="footer">
                <p>Thank you for using TIN Registration Services</p>
                <p>For support, contact us at ${process.env.EMAIL_USER}</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`TIN email sent successfully to ${email}`);
  } catch (error) {
    console.error('Email sending error:', error);
  }
}

// ============================================
// ENDPOINT 5: Check TIN Status
// ============================================
app.post('/api/check-tin-status', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT tin, email, firstName, lastName, status, paid_at, created_at FROM registrations WHERE email = ?',
      [email]
    );
    connection.release();

    if (users.length === 0) {
      return res.status(404).json({ error: 'No registration found' });
    }

    const userData = users[0];
    const createdDate = new Date(userData.created_at);
    const releaseDate = new Date(createdDate.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days
    const isReady = new Date() >= releaseDate;

    res.json({
      success: true,
      data: {
        tin: userData.tin,
        firstName: userData.firstName,
        lastName: userData.lastName,
        status: userData.status,
        registeredDate: userData.created_at,
        expectedReleaseDate: releaseDate,
        isReady: isReady,
      },
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT 6: Create Account (Simplified)
// ============================================
app.post('/api/create-account', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const connection = await pool.getConnection();
    
    // Check if email already has account
    const [existingUser] = await connection.query(
      'SELECT * FROM registrations WHERE email = ?',
      [email]
    );

    // If user doesn't exist, create placeholder
    if (existingUser.length === 0) {
      await connection.query(
        'INSERT INTO registrations (email, portal_password, status, created_at) VALUES (?, ?, ?, NOW())',
        [email, password, 'account_created']
      );
      connection.release();
      return res.json({ success: true, message: 'Account created successfully' });
    }

    // If user exists but no password, update
    if (existingUser[0].portal_password === null) {
      await connection.query(
        'UPDATE registrations SET portal_password = ? WHERE email = ?',
        [password, email]
      );
      connection.release();
      return res.json({ success: true, message: 'Account created successfully' });
    }

    // Account already exists
    connection.release();
    return res.status(400).json({ error: 'Account already exists for this email' });

  } catch (error) {
    console.error('Signup Error:', error);
    return res.status(500).json({ error: 'Server error during signup' });
  }
});

// ============================================
// ENDPOINT 7: Login
// ============================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM registrations WHERE email = ? AND portal_password = ?',
      [email, password]
    );
    connection.release();

    if (users.length > 0) {
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          email: users[0].email,
          firstName: users[0].firstName,
          lastName: users[0].lastName,
        },
      });
    } else {
      res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT 8: Admin - Get All Registrations
// ============================================
app.get('/api/admin/registrations', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [registrations] = await connection.query(
      'SELECT id, email, firstName, lastName, phone, state, status, tin, amount, reference, created_at, paid_at FROM registrations ORDER BY created_at DESC'
    );
    connection.release();

    res.json({
      success: true,
      count: registrations.length,
      data: registrations,
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// Database Initialization
// ============================================
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();

    await connection.query(`
      CREATE TABLE IF NOT EXISTS registrations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        bvn VARCHAR(11),
        dob DATE,
        firstName VARCHAR(100),
        lastName VARCHAR(100),
        nin VARCHAR(11) UNIQUE,
        state VARCHAR(50),
        email VARCHAR(100) NOT NULL UNIQUE,
        phone VARCHAR(20),
        address TEXT,
        job VARCHAR(100),
        amount INT,
        reference VARCHAR(50) UNIQUE,
        status ENUM('account_created', 'pending', 'paid', 'completed') DEFAULT 'pending',
        tin VARCHAR(50),
        portal_password VARCHAR(255),
        certificate_data LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP NULL,
        INDEX(email),
        INDEX(reference),
        INDEX(tin),
        INDEX(status)
      )
    `);

    connection.release();
    console.log('✓ Database initialized successfully');
  } catch (error) {
    console.error('✗ Database initialization error:', error);
  }
}

// ============================================
// Start Server
// ============================================
const PORT = process.env.PORT || 5000;

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('===========================================');
    console.log('  TIN REGISTRATION BACKEND');
    console.log('===========================================');
    console.log(`✓ Server running on port ${PORT}`);
    console.log(`✓ Environment: ${process.env.NODE_ENV}`);
    console.log(`✓ Database: ${process.env.DB_NAME}`);
    console.log('===========================================');
  });
});

module.exports = app;