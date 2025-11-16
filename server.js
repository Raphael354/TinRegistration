// ============================================
// ENHANCED TIN REGISTRATION BACKEND - PRODUCTION
// ============================================

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Add: npm install bcrypt
const multer = require('multer'); // Add: npm install multer
const path = require('path');
const fs = require('fs'); // Standard fs for synchronous operations (used by Express)
const fsp = require('fs').promises; // Use fsp for promise-based/async operations
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Legion_farternity1$';

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// File upload configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = './uploads/certificates';
    await fsp.mkdir(uploadDir, { recursive: true }); // ⬅️ FIX: Use fsp
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `TIN_${Date.now()}_${file.originalname}`;
    cb(null, uniqueName);
  },
});

// Add this middleware function near the top of server.js (before your routes)

const authenticateAdmin = (req, res, next) => {
  // 1. Check for the token in the Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access Denied: Token Required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // 2. Verify the token using the secret
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 3. Ensure the token belongs to an admin (assuming your login endpoint sets isAdmin: true)
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Access Denied: Not Authorized' });
    }

    req.user = decoded; // Attach admin info to request
    next(); // Proceed to the admin endpoint logic
  } catch (err) {
    // 4. Handle expired or invalid tokens
    return res.status(401).json({ message: 'Access Denied: Invalid Token' });
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|png|jpg|jpeg/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF and image files are allowed'));
    }
  },
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
    // REMOVE: service: 'gmail',
    host: 'smtp.gmail.com',  // Explicitly define the host
    port: 465,               // Use the secure SSL port
    secure: true,            // CRITICAL: Must be true for port 465

    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD, // Your Google App Password
    },
});

// Admin credentials (in production, store in database with hashed password)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@tinregistration.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH; // Store hashed password

// Utility Functions
function generateTIN() {
  return 'TIN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
}

function generateReference() {
  return 'REF' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
}

function generateReferralCode(email) {
  return email.split('@')[0].toUpperCase() + Math.random().toString(36).substr(2, 4).toUpperCase();
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ============================================
// ENDPOINT: Health Check
// ============================================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'TIN Registration Backend API',
    version: '2.0.0',
    status: 'Running',
  });
});

// ============================================
// ENDPOINT: Create Account with Email Verification
// ============================================
app.post('/api/create-account', async (req, res) => {
  try {
    const { email, password, confirmPassword, referralCode, agreedToTerms } = req.body;

    // Validation
    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (!agreedToTerms) {
      return res.status(400).json({ error: 'You must agree to Terms & Conditions' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const connection = await pool.getConnection();

    // Check if email already exists
    const [existingUser] = await connection.query(
      'SELECT * FROM registrations WHERE email = ?',
      [email.trim().toLowerCase()]
    );

    if (existingUser.length > 0 && existingUser[0].email_verified) {
      connection.release();
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const userReferralCode = generateReferralCode(email);

    // Handle referral
    let referredBy = null;
    if (referralCode) {
      const [referrer] = await connection.query(
        'SELECT id FROM registrations WHERE referral_code = ?',
        [referralCode.toUpperCase()]
      );
      if (referrer.length > 0) {
        referredBy = referrer[0].id;
        // Update referrer's referral count
        await connection.query(
          'UPDATE registrations SET referral_count = referral_count + 1 WHERE id = ?',
          [referredBy]
        );
      }
    }

    if (existingUser.length > 0 && !existingUser[0].email_verified) {
      // Update existing unverified account
      await connection.query(
        `UPDATE registrations SET 
         portal_password = ?, 
         verification_code = ?, 
         referral_code = ?,
         referred_by = ?,
         agreed_to_terms = ?
         WHERE email = ?`,
        [hashedPassword, verificationCode, userReferralCode, referredBy, true, email.trim().toLowerCase()]
      );
    } else {
      // Create new account
      await connection.query(
        `INSERT INTO registrations 
        (email, portal_password, verification_code, referral_code, referred_by, agreed_to_terms, status, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, 'account_created', NOW())`,
        [email.trim().toLowerCase(), hashedPassword, verificationCode, userReferralCode, referredBy, true]
      );
    }

    connection.release();

    // Send verification email
    await sendVerificationEmail(email, verificationCode);

    res.json({
      success: true,
      message: 'Account created! Please check your email for verification code.',
      referralCode: userReferralCode,
    });
  } catch (error) {
    console.error('Signup Error:', error);
    return res.status(500).json({ error: 'Server error during signup' });
  }
});

// ============================================
// ENDPOINT: Verify Email
// ============================================
app.post('/api/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and verification code required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM registrations WHERE email = ? AND verification_code = ?',
      [email.trim().toLowerCase(), code]
    );

    if (users.length === 0) {
      connection.release();
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    await connection.query(
      'UPDATE registrations SET email_verified = true, verification_code = NULL WHERE email = ?',
      [email.trim().toLowerCase()]
    );

    connection.release();

    res.json({
      success: true,
      message: 'Email verified successfully! You can now login.',
    });
  } catch (error) {
    console.error('Verification Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT: Resend Verification Code
// ============================================
app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM registrations WHERE email = ?',
      [email.trim().toLowerCase()]
    );

    if (users.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Email not found' });
    }

    if (users[0].email_verified) {
      connection.release();
      return res.status(400).json({ error: 'Email already verified' });
    }

    const newCode = generateVerificationCode();
    await connection.query(
      'UPDATE registrations SET verification_code = ? WHERE email = ?',
      [newCode, email.trim().toLowerCase()]
    );

    connection.release();

    await sendVerificationEmail(email, newCode);

    res.json({
      success: true,
      message: 'Verification code sent to your email',
    });
  } catch (error) {
    console.error('Resend Verification Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT: Login (Enhanced Security)
// ============================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required',
      });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT * FROM registrations WHERE email = ?',
      [email.trim().toLowerCase()]
    );
    connection.release();

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'No account found. Please sign up first.',
      });
    }

    const user = users[0];

    // Check if email is verified
    if (!user.email_verified) {
      return res.status(401).json({
        success: false,
        error: 'Please verify your email first',
        needsVerification: true,
      });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.portal_password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Incorrect password',
      });
    }

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        email: user.email,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        referralCode: user.referral_code,
        referralCount: user.referral_count || 0,
      },
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error',
    });
  }
});

// ============================================
// ENDPOINT: Initiate Payment
// ============================================
app.post('/api/initiate-payment', async (req, res) => {
  try {
    const { bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount } = req.body;

    if (!bvn || !dob || !firstName || !lastName || !nin || !state || !email || !phone || !address || !job) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const connection = await pool.getConnection();
    
    // Check for duplicates
    const [existing] = await connection.query(
  `SELECT * FROM registrations 
   WHERE (email = ? OR nin = ?) 
   AND status IN ('pending', 'paid', 'completed')`,
  [email.trim().toLowerCase(), nin]
);

    if (existing.length > 0) {
  connection.release();
  return res.status(400).json({ 
    error: 'You have already registered! Check your email for TIN details or use the Status page to track your registration.',
    alreadyRegistered: true
  });
}

    const reference = generateReference();
    const tin = generateTIN();

    const paystackResponse = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: email,
        amount: amount * 100,
        reference: reference,
        metadata: { bvn, dob, firstName, lastName, nin, state, phone, address, job, tin },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    // Update or insert registration
    await connection.query(
      `INSERT INTO registrations 
      (bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, tin, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())
      ON DUPLICATE KEY UPDATE
      bvn=VALUES(bvn), dob=VALUES(dob), firstName=VALUES(firstName), lastName=VALUES(lastName),
      nin=VALUES(nin), state=VALUES(state), phone=VALUES(phone), address=VALUES(address),
      job=VALUES(job), amount=VALUES(amount), reference=VALUES(reference), tin=VALUES(tin), status='pending'`,
      [bvn, dob, firstName, lastName, nin, state, email, phone, address, job, amount, reference, tin]
    );

    connection.release();

    res.json({
      success: true,
      paymentUrl: paystackResponse.data.data.authorization_url,
      reference: reference,
      amount: amount,
      tin: tin,
    });
  } catch (error) {
    console.error('Payment Error:', error);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

// Add this endpoint to server.js
app.post('/api/paystack-webhook', async (req, res) => {
  const secret = process.env.PAYSTACK_WEBHOOK_SECRET;
  const hash = req.headers['x-paystack-signature'];
  const event = req.body;
  const transaction = event.data;

  // 1. CRITICAL SECURITY CHECK: Verify the signature
  const crypto = require('crypto');
  const expectedHash = crypto.createHmac('sha512', secret).update(JSON.stringify(req.body)).digest('hex');

  if (hash !== expectedHash) {
    console.error('Webhook signature mismatch! Potentially unauthorized request.');
    return res.status(401).send('Unauthorized');
  }

  // 2. Process the event
  if (event.event === 'charge.success' && transaction.status === 'success') {
    const transactionReference = transaction.reference;
    const customerEmail = transaction.customer.email;

    try {
      // Find the registration using the reference stored during initiation
      const [results] = await pool.query(
        'SELECT id FROM registrations WHERE email = ? AND transaction_ref = ? AND status = ?',
        [customerEmail, transactionReference, 'pending']
      );

      if (results.length > 0) {
        // 3. Update status in the database
        await pool.query(
          'UPDATE registrations SET status = ? WHERE id = ?',
          ['paid', results[0].id]
        );
        console.log(`Successfully updated status for ${customerEmail} to 'paid'.`);
      } else {
        console.warn(`Webhook received for a transaction not found or already processed: ${transactionReference}`);
      }

    } catch (error) {
      console.error('Database update failed in webhook:', error);
      // Respond 200 so Paystack doesn't keep sending the notification
    }
  }

  // 4. IMPORTANT: Always return a 200 OK status to Paystack
  res.status(200).send();
});

// ============================================
// ENDPOINT: Check TIN Status
// ============================================
app.post('/api/check-tin-status', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const connection = await pool.getConnection();
    
    // Query for user with registration (excluding account_created status)
    const [users] = await connection.query(
      `SELECT tin, email, firstName, lastName, status, paid_at, created_at 
       FROM registrations 
       WHERE email = ? AND status != ?`,
      [email.trim().toLowerCase(), 'account_created']
    );
    
    connection.release();

    if (users.length === 0) {
      return res.status(404).json({ 
        error: 'No TIN registration found for this email. Please complete your registration first.',
        noRegistration: true 
      });
    }

    const userData = users[0];
    
    // Calculate expected release date (30 days from registration)
    const createdDate = new Date(userData.created_at);
    const releaseDate = new Date(createdDate.getTime() + 30 * 24 * 60 * 60 * 1000);
    const isReady = userData.status === 'completed';

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
    console.error('Check TIN Status Error:', error);
    res.status(500).json({ error: 'Server error while checking status' });
  }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (email !== ADMIN_EMAIL) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({
      success: true,
      message: 'Admin login successful',
      token: 'admin_session_token', // In production, use JWT
    });
  } catch (error) {
    console.error('Admin Login Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get All Registrations (Admin)
app.get('/api/admin/registrations', authenticateAdmin, async (req, res) => {
  try {
    const { status, state, fromDate, toDate, search } = req.query;

    let query = 'SELECT * FROM registrations WHERE 1=1';
    const params = [];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (state) {
      query += ' AND state = ?';
      params.push(state);
    }

    if (fromDate) {
      query += ' AND created_at >= ?';
      params.push(fromDate);
    }

    if (toDate) {
      query += ' AND created_at <= ?';
      params.push(toDate);
    }

    if (search) {
      query += ' AND (email LIKE ? OR firstName LIKE ? OR lastName LIKE ? OR tin LIKE ?)';
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    query += ' ORDER BY created_at DESC';

    const connection = await pool.getConnection();
    const [registrations] = await connection.query(query, params);
    connection.release();

    res.json({
      success: true,
      count: registrations.length,
      data: registrations,
    });
  } catch (error) {
    console.error('Admin Get Registrations Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Single Registration (Admin)
app.get('/api/admin/registration/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const connection = await pool.getConnection();
    const [registration] = await connection.query(
      'SELECT * FROM registrations WHERE id = ?',
      [id]
    );
    connection.release();

    if (registration.length === 0) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json({
      success: true,
      data: registration[0],
    });
  } catch (error) {
    console.error('Admin Get Registration Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Registration Status (Admin)
app.put('/api/admin/registration/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'paid', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE registrations SET status = ? WHERE id = ?',
      [status, id]
    );

    // If status is completed, send notification
    if (status === 'completed') {
      const [user] = await connection.query(
        'SELECT email, firstName, tin FROM registrations WHERE id = ?',
        [id]
      );
      if (user.length > 0) {
        await sendCertificateReadyEmail(user[0].email, user[0].firstName, user[0].tin, user[0].certificate_path);
      }
    }

    connection.release();

    res.json({
      success: true,
      message: 'Status updated successfully',
    });
  } catch (error) {
    console.error('Admin Update Status Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload Certificate (Admin)
app.post('/api/admin/upload-certificate/:id', authenticateAdmin, upload.single('certificate'), async (req, res) => {
  try {
    const { id } = req.params;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const certificatePath = req.file.path;

    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE registrations SET certificate_path = ?, status = ? WHERE id = ?',
      [certificatePath, 'completed', id]
    );

    const [user] = await connection.query(
      'SELECT email, firstName, tin FROM registrations WHERE id = ?',
      [id]
    );

    connection.release();

    if (user.length > 0) {
      await sendCertificateReadyEmail(user[0].email, user[0].firstName, user[0].tin, user[0].certificate_path);
    }

    res.json({
      success: true,
      message: 'Certificate uploaded successfully',
      filePath: certificatePath,
    });
  } catch (error) {
    console.error('Admin Upload Certificate Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT: Download Certificate
// ============================================
app.get('/api/download-certificate/:tin', async (req, res) => {
  try {
    const { tin } = req.params;

    const connection = await pool.getConnection();
    const [registration] = await connection.query(
      'SELECT certificate_path, firstName, lastName, status, email FROM registrations WHERE tin = ?',
      [tin]
    );
    connection.release();

    // Check 1: TIN exists
    if (registration.length === 0) {
      return res.status(404).json({ error: 'TIN not found' });
    }

    // Check 2: Status is completed
    if (registration[0].status !== 'completed') {
      return res.status(400).json({ error: 'Certificate not ready yet. Current status: ' + registration[0].status });
    }

    // Check 3: Certificate file path exists
    if (!registration[0].certificate_path) {
      return res.status(404).json({ error: 'Certificate file path not found in database' });
    }

    // Create absolute path
    const absolutePath = path.resolve(__dirname, registration[0].certificate_path);
    
    // Check 4: File actually exists on disk
    if (!fs.existsSync(absolutePath)) {
      console.error('File not found at path:', absolutePath);
      return res.status(404).json({ 
        error: 'Certificate file not found on server',
        path: registration[0].certificate_path 
      });
    }

    const fileName = `TIN_Certificate_${tin}.pdf`;

    // Set proper headers for download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);

    // Stream the file
    const fileStream = fs.createReadStream(absolutePath);
    fileStream.pipe(res);

    fileStream.on('error', (err) => {
      console.error('File stream error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Error streaming certificate' });
      }
    });

  } catch (error) {
    console.error('Certificate Download Error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Server error: ' + error.message });
    }
  }
});

// ============================================
// EMAIL FUNCTIONS
// ============================================

async function sendVerificationEmail(email, code) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email - TIN Registration',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #0066CC, #0052A3); color: white; padding: 30px; text-align: center;">
            <h1>Email Verification</h1>
          </div>
          <div style="padding: 30px; background: #f9f9f9;">
            <h2>Welcome to TIN Registration!</h2>
            <p>Your verification code is:</p>
            <div style="background: white; border: 2px solid #0066CC; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; color: #0066CC; letter-spacing: 5px;">
              ${code}
            </div>
            <p style="margin-top: 20px;">Enter this code in the app to verify your email address.</p>
            <p><strong>This code expires in 24 hours.</strong></p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Verification Email Error:', error);
  }
}

async function sendCertificateReadyEmail(email, firstName, tin, certificatePath) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your TIN Certificate is Ready!',
      html: `...existing html content...`,
      attachments: [
        {
          filename: `TIN_Certificate_${tin}.pdf`,
          path: certificatePath, // Path to the certificate file
        },
      ],
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Certificate Ready Email Error:', error);
  }
}

// ============================================
// DATABASE INITIALIZATION
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
        status ENUM('account_created', 'pending', 'paid', 'completed') DEFAULT 'account_created',
        tin VARCHAR(50),
        portal_password VARCHAR(255),
        email_verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(10),
        referral_code VARCHAR(20) UNIQUE,
        referred_by INT,
        referral_count INT DEFAULT 0,
        agreed_to_terms BOOLEAN DEFAULT FALSE,
        certificate_path VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP NULL,
        INDEX(email),
        INDEX(reference),
        INDEX(tin),
        INDEX(status),
        INDEX(referral_code)
      )
    `);

    connection.release();
    console.log('✓ Database initialized');
  } catch (error) {
    console.error('✗ Database error:', error);
  }
}

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 5000;

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('===========================================');
    console.log('  TIN REGISTRATION BACKEND v2.0');
    console.log('===========================================');
    console.log(`✓ Server: http://localhost:${PORT}`);
    console.log(`✓ Environment: ${process.env.NODE_ENV}`);
    console.log(`✓ WhatsApp Support: +2349047143643`);
    console.log('===========================================');
  });
});

module.exports = app;