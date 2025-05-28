'use strict';

// Core dependencies
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Third-party dependencies
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { ethers } = require('ethers');

// Constants
const PORT = process.env.PORT || 3000;
const JWT_SECRET = '17581758Na.%';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '17581758..';
const FIXED_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const MONGO_URI = 'mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const MAILTRAP_CONFIG = {
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
};
const SYSTEM_SETTINGS_FILE = path.join(__dirname, 'system-settings.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Initialize system settings
const initializeSystemSettings = () => {
  const defaultSettings = {
    maintenanceMode: false,
    registrationEnabled: true,
    tradingEnabled: true,
    withdrawalEnabled: true,
    depositEnabled: true,
    kycRequired: false,
    maxWithdrawal: 10000,
    minDeposit: 10,
    feePercentage: 0.1,
    coins: [
      { symbol: 'BTC', name: 'Bitcoin', price: 50000, change24h: 2.5 },
      { symbol: 'ETH', name: 'Ethereum', price: 3000, change24h: -1.2 },
      { symbol: 'BNB', name: 'Binance Coin', price: 400, change24h: 0.8 },
      { symbol: 'XRP', name: 'Ripple', price: 0.5, change24h: 3.1 },
      { symbol: 'SOL', name: 'Solana', price: 100, change24h: 5.7 },
      { symbol: 'ADA', name: 'Cardano', price: 0.45, change24h: -0.3 },
      { symbol: 'DOGE', name: 'Dogecoin', price: 0.08, change24h: 10.2 },
      { symbol: 'DOT', name: 'Polkadot', price: 7, change24h: 1.5 },
      { symbol: 'SHIB', name: 'Shiba Inu', price: 0.00001, change24h: -2.8 },
      { symbol: 'AVAX', name: 'Avalanche', price: 35, change24h: 4.2 }
    ],
    exchangeRates: {
      BTC: { ETH: 16.67, BNB: 125, XRP: 100000, SOL: 500, ADA: 111111, DOGE: 625000, DOT: 7143, SHIB: 500000000, AVAX: 1429 },
      ETH: { BTC: 0.06, BNB: 7.5, XRP: 6000, SOL: 30, ADA: 6667, DOGE: 37500, DOT: 429, SHIB: 30000000, AVAX: 86 },
      BNB: { BTC: 0.008, ETH: 0.133, XRP: 800, SOL: 4, ADA: 889, DOGE: 5000, DOT: 57, SHIB: 4000000, AVAX: 11 },
      XRP: { BTC: 0.00001, ETH: 0.000167, BNB: 0.00125, SOL: 0.005, ADA: 1.11, DOGE: 6.25, DOT: 0.071, SHIB: 5000, AVAX: 0.014 },
      SOL: { BTC: 0.002, ETH: 0.033, BNB: 0.25, XRP: 200, ADA: 222, DOGE: 1250, DOT: 14, SHIB: 1000000, AVAX: 2.86 },
      ADA: { BTC: 0.000009, ETH: 0.00015, BNB: 0.001125, XRP: 0.9, SOL: 0.0045, DOGE: 5.63, DOT: 0.064, SHIB: 4500, AVAX: 0.013 },
      DOGE: { BTC: 0.0000016, ETH: 0.000027, BNB: 0.0002, XRP: 0.16, SOL: 0.0008, ADA: 0.178, DOT: 0.011, SHIB: 800, AVAX: 0.0023 },
      DOT: { BTC: 0.00014, ETH: 0.00233, BNB: 0.0175, XRP: 14, SOL: 0.07, ADA: 15.56, DOGE: 87.5, SHIB: 70000, AVAX: 0.2 },
      SHIB: { BTC: 0.000000002, ETH: 0.000000033, BNB: 0.00000025, XRP: 0.0002, SOL: 0.000001, ADA: 0.000222, DOGE: 0.00125, DOT: 0.000014, AVAX: 0.0000004 },
      AVAX: { BTC: 0.0007, ETH: 0.0116, BNB: 0.0875, XRP: 70, SOL: 0.35, ADA: 77.78, DOGE: 437.5, DOT: 5, SHIB: 2500000 }
    }
  };

  if (!fs.existsSync(SYSTEM_SETTINGS_FILE)) {
    fs.writeFileSync(SYSTEM_SETTINGS_FILE, JSON.stringify(defaultSettings, null, 2));
    return defaultSettings;
  }

  try {
    return JSON.parse(fs.readFileSync(SYSTEM_SETTINGS_FILE));
  } catch (err) {
    console.error('Error reading system settings, using defaults:', err);
    return defaultSettings;
  }
};

const systemSettings = initializeSystemSettings();

// Database models
const userSchema = new mongoose.Schema({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  email: { type: String, unique: true, trim: true, lowercase: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true, trim: true },
  country: { type: String, trim: true },
  currency: { type: String, default: 'USD', trim: true },
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  kycDocuments: [{
    type: { type: String, enum: ['id', 'proof_of_address', 'selfie'] },
    url: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
  }],
  settings: {
    twoFactorEnabled: { type: Boolean, default: false },
    notificationsEnabled: { type: Boolean, default: true },
    theme: { type: String, default: 'light', enum: ['light', 'dark'] }
  },
  apiKey: { type: String, unique: true, default: () => crypto.randomBytes(32).toString('hex') },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  lastActivity: Date
}, { timestamps: true });

const supportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: { type: String, required: true, trim: true },
  message: { type: String, required: true, trim: true },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
  attachments: [String],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true, trim: true },
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const faqSchema = new mongoose.Schema({
  question: { type: String, required: true, trim: true },
  answer: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true }
}, { timestamps: true });

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true, uppercase: true, trim: true },
  toCoin: { type: String, required: true, uppercase: true, trim: true },
  amount: { type: Number, required: true, min: 0.00000001 },
  rate: { type: Number, required: true, min: 0.00000001 },
  convertedAmount: { type: Number, required: true, min: 0.00000001 },
  fee: { type: Number, required: true, min: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String, unique: true, sparse: true, trim: true }
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion'], required: true },
  amount: { type: Number, required: true, min: 0.00000001 },
  currency: { type: String, required: true, uppercase: true, trim: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String, unique: true, sparse: true, trim: true },
  address: { type: String, trim: true },
  memo: { type: String, trim: true }
}, { timestamps: true });

const walletSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  coin: { type: String, required: true, uppercase: true, trim: true },
  balance: { type: Number, default: 0, min: 0 },
  address: { type: String, trim: true }
}, { timestamps: true });

const adminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true, trim: true },
  target: { type: String, trim: true },
  details: mongoose.Schema.Types.Mixed
}, { timestamps: true });

// Create models
const User = mongoose.model('User', userSchema);
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
const FAQ = mongoose.model('FAQ', faqSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Wallet = mongoose.model('Wallet', walletSchema);
const AdminLog = mongoose.model('AdminLog', adminLogSchema);

// Initialize Express
const app = express();

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: 'Too many login attempts, please try again later'
});
app.use('/api/v1/auth/', authLimiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and PDF are allowed.'));
    }
  }
});

// Email transporter
const transporter = nodemailer.createTransport(MAILTRAP_CONFIG);

// Helper functions
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('+lastActivity');
    if (!user) return res.status(401).json({ error: 'Invalid user' });

    // Update last activity
    user.lastActivity = new Date();
    await user.save();

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired, please login again' });
    }
    return res.status(401).json({ error: 'Invalid authentication token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid authentication token' });
  }
};

const sendEmail = async (to, subject, text, html) => {
  try {
    await transporter.sendMail({
      from: '"Crypto Platform" <no-reply@cryptoplatform.com>',
      to,
      subject,
      text,
      html
    });
    return true;
  } catch (err) {
    console.error('Email send error:', err);
    return false;
  }
};

const updateSystemSettings = (newSettings) => {
  try {
    const updatedSettings = { ...systemSettings, ...newSettings };
    fs.writeFileSync(SYSTEM_SETTINGS_FILE, JSON.stringify(updatedSettings, null, 2));
    Object.assign(systemSettings, updatedSettings);
    return true;
  } catch (err) {
    console.error('Error updating system settings:', err);
    return false;
  }
};

// WebSocket server
const wss = new WebSocket.Server({ server }); // Attach to HTTP server

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection');

  // Optional: Authenticate via token (if needed)
  const token = req.url.split('token=')[1];
  if (!token) {
    ws.close(1008, 'Unauthorized: No token provided');
    return;
  }

  // Verify JWT (example)
  jwt.verify(token, '17581758Na.##', (err, decoded) => {
    if (err) {
      ws.close(1008, 'Unauthorized: Invalid token');
      return;
    }
    // Success: Store user info in WebSocket session
    ws.userId = decoded.userId;
  });

  ws.on('message', (message) => {
    console.log('Received:', message);
    ws.send(`Echo: ${message}`); // Example echo response
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});
    
    // Close any existing connection for this user
    if (clients.has(userId)) {
      clients.get(userId).close();
    }
    
    clients.set(userId, ws);
    
    ws.on('close', () => {
      clients.delete(userId);
    });
    
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      clients.delete(userId);
    });
     catch (err) {
    ws.close(1008, 'Invalid authentication token');
  }
});

const notifyUser = (userId, event, data) => {
  const ws = clients.get(userId.toString());
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ event, data }));
  }
};

const broadcastToAdmins = (event, data) => {
  clients.forEach((ws, userId) => {
    if (ws.readyState === WebSocket.OPEN) {
      User.findById(userId).then(user => {
        if (user && user.isAdmin) {
          ws.send(JSON.stringify({ event, data }));
        }
      });
    }
  });
};

// Initialize database and admin user
const initializeDatabase = async () => {
  try {
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000
    });

    // Create admin user if not exists
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await User.create({
        firstName: 'Admin',
        lastName: 'System',
        email: ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true,
        isVerified: true,
        kycStatus: 'approved'
      });
      console.log('Admin user created');
    }

    // Create default FAQs if none exist
    const faqCount = await FAQ.countDocuments();
    if (faqCount === 0) {
      await FAQ.insertMany([
        {
          question: 'How do I create an account?',
          answer: 'Click on the "Sign Up" button and follow the registration process.',
          category: 'Account'
        },
        {
          question: 'What cryptocurrencies can I trade?',
          answer: 'We currently support Bitcoin (BTC), Ethereum (ETH), and other major cryptocurrencies.',
          category: 'Trading'
        },
        {
          question: 'How do I reset my password?',
          answer: 'Go to the login page and click "Forgot Password" to receive a reset link via email.',
          category: 'Account'
        }
      ]);
      console.log('Default FAQs created');
    }

    console.log('Database initialization complete');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  }
};
// ===== CORS CONFIG (PUT THIS BEFORE ROUTES) =====
const allowedOrigins = [
  'https://website-xi-ten-52.vercel.app', // Your frontend
  'http://localhost:3000' // For local testing
];
const corsOptions = {
  origin: function (origin, callback) {
    if (allowedOrigins.includes(origin) || !origin) { // Allow local testing (Postman, etc.)
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Required for cookies/sessions
  optionsSuccessStatus: 200 // Legacy browsers choke on 204
};

app.use(cors(corsOptions)); // Enable CORS for all routes
app.options('*', cors(corsOptions)); // Handle preflight requests

// Routes
// Add this to your authentication routes
app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isAdmin: user.isAdmin,
      isVerified: user.isVerified
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 1. Auth status check
app.get('/api/v1/auth/status', authenticate, (req, res) => {
  res.json({
    isAuthenticated: true,
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      username: req.user.username,
      email: req.user.email,
      walletAddress: req.user.walletAddress,
      isAdmin: req.user.isAdmin,
      isVerified: req.user.isVerified,
      kycStatus: req.user.kycStatus,
      settings: req.user.settings
    }
  });
});

// 2. Login with email/password
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email }).select('+password +lastActivity');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (systemSettings.maintenanceMode && !user.isAdmin) {
      return res.status(503).json({ error: 'System is under maintenance' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 3. Wallet login - get nonce
app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    if (!walletAddress || !ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ error: 'Valid wallet address is required' });
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    res.json({ nonce });
  } catch (err) {
    console.error('Nonce generation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 4. Wallet login - verify signature
app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature, nonce } = req.body;
    
    if (!walletAddress || !signature || !nonce) {
      return res.status(400).json({ error: 'Wallet address, signature, and nonce are required' });
    }

    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ error: 'Invalid wallet address' });
    }

    // Verify signature
    const recoveredAddress = ethers.utils.verifyMessage(nonce, signature);
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    // Find or create user
    let user = await User.findOne({ walletAddress }).select('+lastActivity');
    if (!user) {
      if (systemSettings.maintenanceMode) {
        return res.status(503).json({ error: 'System is under maintenance' });
      }

      if (systemSettings.registrationEnabled === false) {
        return res.status(403).json({ error: 'New registrations are currently disabled' });
      }

      user = new User({
        walletAddress,
        isVerified: true
      });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 5. Signup with email/password
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    if (systemSettings.maintenanceMode) {
      return res.status(503).json({ error: 'System is under maintenance' });
    }

    if (systemSettings.registrationEnabled === false) {
      return res.status(403).json({ error: 'New registrations are currently disabled' });
    }

    const { firstName, lastName, email, country, currency, password, confirmPassword } = req.body;
    
    if (!firstName || !lastName || !email || !country || !currency || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency
    });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    // Send verification email
    const verificationLink = `https://yourplatform.com/verify-email?token=${token}`;
    await sendEmail(
      email,
      'Welcome to Crypto Platform - Verify Your Email',
      `Hello ${firstName},\n\nPlease verify your email by clicking this link: ${verificationLink}`,
      `<p>Hello ${firstName},</p><p>Please verify your email by clicking this link: <a href="${verificationLink}">Verify Email</a></p>`
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 6. Wallet signup
app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    if (systemSettings.maintenanceMode) {
      return res.status(503).json({ error: 'System is under maintenance' });
    }

    if (systemSettings.registrationEnabled === false) {
      return res.status(403).json({ error: 'New registrations are currently disabled' });
    }

    const { walletAddress, signature, nonce } = req.body;
    
    if (!walletAddress || !signature || !nonce) {
      return res.status(400).json({ error: 'Wallet address, signature, and nonce are required' });
    }

    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ error: 'Invalid wallet address' });
    }

    // Verify signature
    const recoveredAddress = ethers.utils.verifyMessage(nonce, signature);
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ error: 'Wallet already registered' });
    }

    const user = new User({
      walletAddress,
      isVerified: true
    });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Wallet signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 7. Forgot password
app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (user) {
      const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
      const resetLink = `https://yourplatform.com/reset-password?token=${resetToken}`;
      
      await sendEmail(
        email,
        'Password Reset Request',
        `Hello,\n\nYou requested a password reset. Click this link to reset your password: ${resetLink}\n\nIf you didn't request this, please ignore this email.`,
        `<p>Hello,</p><p>You requested a password reset. Click this link to reset your password: <a href="${resetLink}">Reset Password</a></p><p>If you didn't request this, please ignore this email.</p>`
      );
    }

    // Always return success to prevent email enumeration
    res.json({ message: 'If an account exists with this email, a reset link has been sent' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 8. Reset password
app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('+password');
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset token has expired' });
    }
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 9. Update password
app.patch('/api/v1/auth/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }

    const user = await User.findById(req.user._id).select('+password');
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 10. Logout
app.post('/api/v1/auth/logout', authenticate, (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// 11. Get user profile
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      walletAddress: user.walletAddress,
      country: user.country,
      currency: user.currency,
      isVerified: user.isVerified,
      kycStatus: user.kycStatus,
      settings: user.settings,
      createdAt: user.createdAt
    });
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 12. Update user profile
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const wallets = await Wallet.find({ userId: req.user._id });
    
    res.json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      balance: wallets.find(w => w.coin === 'USD')?.balance || 0, // Default to 0
      wallets // Include all wallets
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load user data' });
  }
});

// 13. Get user settings
app.get('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json(user.settings);
  } catch (err) {
    console.error('Get user settings error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 14. Update user settings
app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { twoFactorEnabled, notificationsEnabled, theme } = req.body;
    const updates = { settings: {} };
    
    if (twoFactorEnabled !== undefined) updates.settings.twoFactorEnabled = twoFactorEnabled;
    if (notificationsEnabled !== undefined) updates.settings.notificationsEnabled = notificationsEnabled;
    if (theme !== undefined) updates.settings.theme = theme;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    );

    res.json(user.settings);
  } catch (err) {
    console.error('Update user settings error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 15. Get API key
app.get('/api/v1/users/api-key', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({ apiKey: user.apiKey });
  } catch (err) {
    console.error('Get API key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 16. Generate new API key
app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.apiKey = crypto.randomBytes(32).toString('hex');
    await user.save();
    res.json({ apiKey: user.apiKey });
  } catch (err) {
    console.error('Generate API key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 17. Submit KYC documents
app.post('/api/v1/users/kyc', authenticate, upload.array('documents', 3), async (req, res) => {
  try {
    if (systemSettings.kycRequired === false) {
      return res.status(400).json({ error: 'KYC submissions are currently not required' });
    }

    const documentTypes = req.body.types || [];
    const files = req.files;

    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'At least one document is required' });
    }

    // Validate document types
    const validTypes = ['id', 'proof_of_address', 'selfie'];
    if (documentTypes.some(type => !validTypes.includes(type))) {
      return res.status(400).json({ error: 'Invalid document type' });
    }

    const user = await User.findById(req.user._id);
    user.kycDocuments = files.map((file, index) => ({
      type: documentTypes[index] || 'id',
      url: `/uploads/${file.filename}`,
      status: 'pending'
    }));
    user.kycStatus = 'pending';
    await user.save();

    // Notify admins
    broadcastToAdmins('kyc_submission', {
      userId: user._id,
      name: `${user.firstName} ${user.lastName}`,
      documents: user.kycDocuments
    });

    res.json({ 
      message: 'KYC documents submitted for review',
      status: user.kycStatus
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 18. Get KYC status
app.get('/api/v1/users/kyc-status', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({ 
      status: user.kycStatus,
      documents: user.kycDocuments
    });
  } catch (err) {
    console.error('Get KYC status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 19. Request data export
app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 });
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 });
    const wallets = await Wallet.find({ userId: user._id });

    // Create CSV data
    let csvData = 'Type,Date,Amount,Currency,Status\n';
    transactions.forEach(tx => {
      csvData += `${tx.type},${tx.createdAt.toISOString()},${tx.amount},${tx.currency},${tx.status}\n`;
    });

    csvData += '\nTrade ID,From,To,Amount,Rate,Converted Amount,Fee,Status,Date\n';
    trades.forEach(trade => {
      csvData += `${trade._id},${trade.fromCoin},${trade.toCoin},${trade.amount},${trade.rate},${trade.convertedAmount},${trade.fee},${trade.status},${trade.createdAt.toISOString()}\n`;
    });

    csvData += '\nCoin,Balance,Address\n';
    wallets.forEach(wallet => {
      csvData += `${wallet.coin},${wallet.balance},${wallet.address || ''}\n`;
    });

    // Send email with CSV attachment
    await transporter.sendMail({
      from: '"Crypto Platform" <no-reply@cryptoplatform.com>',
      to: user.email,
      subject: 'Your Data Export',
      text: 'Please find attached your exported data from Crypto Platform.',
      html: '<p>Please find attached your exported data from Crypto Platform.</p>',
      attachments: [{
        filename: `user-data-${Date.now()}.csv`,
        content: csvData
      }]
    });

    res.json({ message: 'Data export request received. You will receive an email shortly.' });
  } catch (err) {
    console.error('Data export error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 20. Delete account
app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { confirmation } = req.body;
    if (confirmation !== 'DELETE') {
      return res.status(400).json({ error: 'Confirmation text is required' });
    }

    const userId = req.user._id;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Delete all user data
      await Promise.all([
        Wallet.deleteMany({ userId }).session(session),
        Trade.deleteMany({ userId }).session(session),
        Transaction.deleteMany({ userId }).session(session),
        SupportTicket.deleteMany({ userId }).session(session),
        User.deleteOne({ _id: userId }).session(session)
      ]);

      await session.commitTransaction();
      session.endSession();

      res.clearCookie('token');
      res.json({ message: 'Account and all associated data deleted successfully' });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 21. Get platform statistics
app.get('/api/v1/stats', async (req, res) => {
  try {
    const [totalUsers, activeUsers, totalTrades, totalVolume, pendingKYC, openTickets] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ lastActivity: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
      Trade.countDocuments(),
      Trade.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      User.countDocuments({ kycStatus: 'pending' }),
      SupportTicket.countDocuments({ status: { $in: ['open', 'in_progress'] } })
    ]);

    res.json({
      totalUsers,
      activeUsers,
      totalTrades,
      totalVolume: totalVolume[0]?.total || 0,
      pendingKYC,
      openTickets,
      coins: systemSettings.coins
    });
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 22. Get all coins
app.get('/api/v1/exchange/coins', (req, res) => {
  res.json(systemSettings.coins);
});

// 23. Get all exchange rates
app.get('/api/v1/exchange/rates', (req, res) => {
  res.json(systemSettings.exchangeRates);
});

// 24. Get specific exchange rate
app.get('/api/v1/exchange/rate', (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ error: 'From and to currency codes are required' });
    }

    const fromUpper = from.toUpperCase();
    const toUpper = to.toUpperCase();

    if (!systemSettings.exchangeRates[fromUpper] || !systemSettings.exchangeRates[fromUpper][toUpper]) {
      return res.status(400).json({ error: 'Exchange rate not available for this pair' });
    }

    res.json({
      from: fromUpper,
      to: toUpper,
      rate: systemSettings.exchangeRates[fromUpper][toUpper]
    });
  } catch (err) {
    console.error('Get exchange rate error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 25. Convert coins
app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    if (systemSettings.tradingEnabled === false) {
      return res.status(403).json({ error: 'Trading is currently disabled' });
    }

    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({ error: 'From currency, to currency, and amount are required' });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }

    const fromUpper = from.toUpperCase();
    const toUpper = to.toUpperCase();

    // Check if coins exist
    const fromCoin = systemSettings.coins.find(c => c.symbol === fromUpper);
    const toCoin = systemSettings.coins.find(c => c.symbol === toUpper);
    
    if (!fromCoin || !toCoin) {
      return res.status(400).json({ error: 'Invalid currency code' });
    }

    // Check exchange rate
    const rate = systemSettings.exchangeRates[fromUpper]?.[toUpper];
    if (!rate) {
      return res.status(400).json({ error: 'Exchange rate not available for this pair' });
    }

    // Check wallet balance
    const fromWallet = await Wallet.findOne({ userId: req.user._id, coin: fromUpper });
    if (!fromWallet || fromWallet.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Calculate converted amount with fee
    const fee = amount * systemSettings.feePercentage;
    const convertedAmount = (amount - fee) * rate;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from source wallet
      fromWallet.balance -= amount;
      await fromWallet.save({ session });

      // Add to destination wallet (or create if doesn't exist)
      let toWallet = await Wallet.findOne({ userId: req.user._id, coin: toUpper }).session(session);
      if (!toWallet) {
        toWallet = new Wallet({
          userId: req.user._id,
          coin: toUpper,
          balance: 0
        });
      }
      toWallet.balance += convertedAmount;
      await toWallet.save({ session });

      // Create trade record
      const trade = new Trade({
        userId: req.user._id,
        fromCoin: fromUpper,
        toCoin: toUpper,
        amount,
        rate,
        convertedAmount,
        fee,
        status: 'completed',
        txHash: crypto.randomBytes(16).toString('hex')
      });
      await trade.save({ session });

      // Create transaction records
      const transactions = [
        new Transaction({
          userId: req.user._id,
          type: 'conversion',
          amount: -amount,
          currency: fromUpper,
          status: 'completed',
          txHash: trade.txHash
        }),
        new Transaction({
          userId: req.user._id,
          type: 'conversion',
          amount: convertedAmount,
          currency: toUpper,
          status: 'completed',
          txHash: trade.txHash
        })
      ];
      await Transaction.insertMany(transactions, { session });

      await session.commitTransaction();
      session.endSession();

      // Notify user
      notifyUser(req.user._id, 'balance_update', {
        [fromUpper]: fromWallet.balance,
        [toUpper]: toWallet.balance
      });

      res.json({
        from: fromUpper,
        to: toUpper,
        amount,
        convertedAmount,
        fee,
        newFromBalance: fromWallet.balance,
        newToBalance: toWallet.balance,
        txHash: trade.txHash
      });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Convert coins error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 26. Get conversion history
app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const [trades, total] = await Promise.all([
      Trade.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Trade.countDocuments({ userId: req.user._id })
    ]);

    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get conversion history error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 27. Get market data
app.get('/api/v1/market/data', (req, res) => {
  res.json(systemSettings.coins);
});

// 28. Get detailed market data
app.get('/api/v1/market/detailed', (req, res) => {
  const detailedData = systemSettings.coins.map(coin => ({
    ...coin,
    marketCap: coin.price * (1000000 + Math.random() * 100000),
    volume24h: coin.price * (10000 + Math.random() * 10000),
    circulatingSupply: 1000000 + Math.random() * 100000,
    allTimeHigh: coin.price * (1 + Math.random() * 0.5),
    allTimeLow: coin.price * (1 - Math.random() * 0.3)
  }));
  res.json(detailedData);
});

// 29. Get deposit address
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    const { coin } = req.query;
    if (!coin) {
      return res.status(400).json({ error: 'Coin is required' });
    }

    const coinUpper = coin.toUpperCase();
    const coinExists = systemSettings.coins.some(c => c.symbol === coinUpper);
    if (!coinExists) {
      return res.status(400).json({ error: 'Invalid coin' });
    }

    res.json({
      address: FIXED_DEPOSIT_ADDRESS,
      memo: req.user._id.toString()
    });
  } catch (err) {
    console.error('Get deposit address error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 30. Request withdrawal
app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    if (systemSettings.withdrawalEnabled === false) {
      return res.status(403).json({ error: 'Withdrawals are currently disabled' });
    }

    const { coin, amount, address } = req.body;
    if (!coin || !amount || !address) {
      return res.status(400).json({ error: 'Coin, amount, and address are required' });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }

    if (amount > systemSettings.maxWithdrawal) {
      return res.status(400).json({ error: `Amount exceeds maximum withdrawal limit of ${systemSettings.maxWithdrawal}` });
    }

    const coinUpper = coin.toUpperCase();
    const coinExists = systemSettings.coins.some(c => c.symbol === coinUpper);
    if (!coinExists) {
      return res.status(400).json({ error: 'Invalid coin' });
    }

    // Check wallet balance
    const wallet = await Wallet.findOne({ userId: req.user._id, coin: coinUpper });
    if (!wallet || wallet.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from wallet
      wallet.balance -= amount;
      await wallet.save({ session });

      // Create transaction
      const transaction = new Transaction({
        userId: req.user._id,
        type: 'withdrawal',
        amount: -amount,
        currency: coinUpper,
        status: 'pending',
        address
      });
      await transaction.save({ session });

      await session.commitTransaction();
      session.endSession();

      // Notify user
      notifyUser(req.user._id, 'balance_update', {
        [coinUpper]: wallet.balance
      });

      // Notify admins
      broadcastToAdmins('withdrawal_request', {
        userId: req.user._id,
        coin: coinUpper,
        amount,
        address,
        transactionId: transaction._id
      });

      res.json({
        message: 'Withdrawal request submitted',
        newBalance: wallet.balance,
        transactionId: transaction._id
      });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 31. Get wallet balances
app.get('/api/v1/wallet/balances', authenticate, async (req, res) => {
  try {
    const wallets = await Wallet.find({ userId: req.user._id });
    res.json(wallets);
  } catch (err) {
    console.error('Get wallet balances error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 32. Get transaction history
app.get('/api/v1/wallet/transactions', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status } = req.query;
    const skip = (page - 1) * limit;

    const query = { userId: req.user._id };
    if (type) query.type = type;
    if (status) query.status = status;

    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Transaction.countDocuments(query)
    ]);

    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get transaction history error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 33. Get active trades
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: 'pending'
    }).sort({ createdAt: -1 });
    
    res.json(trades || []); // Always return array
  } catch (err) {
    res.status(500).json({ error: 'Failed to load trades' });
  }
});

// 34. Get trade history
app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const [trades, total] = await Promise.all([
      Trade.find({ userId: req.user._id, status: 'completed' })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Trade.countDocuments({ userId: req.user._id, status: 'completed' })
    ]);

    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 35. Execute buy trade
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    if (systemSettings.tradingEnabled === false) {
      return res.status(403).json({ error: 'Trading is currently disabled' });
    }

    const { coin, amount } = req.body;
    if (!coin || !amount) {
      return res.status(400).json({ error: 'Coin and amount are required' });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }

    const coinUpper = coin.toUpperCase();
    const coinData = systemSettings.coins.find(c => c.symbol === coinUpper);
    if (!coinData) {
      return res.status(400).json({ error: 'Invalid coin' });
    }

    // Check USD balance
    const usdWallet = await Wallet.findOne({ userId: req.user._id, coin: 'USD' });
    if (!usdWallet || usdWallet.balance < amount) {
      return res.status(400).json({ error: 'Insufficient USD balance' });
    }

    // Calculate quantity with fee
    const fee = amount * systemSettings.feePercentage;
    const quantity = (amount - fee) / coinData.price;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from USD wallet
      usdWallet.balance -= amount;
      await usdWallet.save({ session });

      // Add to coin wallet (or create if doesn't exist)
      let coinWallet = await Wallet.findOne({ userId: req.user._id, coin: coinUpper }).session(session);
      if (!coinWallet) {
        coinWallet = new Wallet({
          userId: req.user._id,
          coin: coinUpper,
          balance: 0
        });
      }
      coinWallet.balance += quantity;
      await coinWallet.save({ session });

      // Create trade record
      const trade = new Trade({
        userId: req.user._id,
        fromCoin: 'USD',
        toCoin: coinUpper,
        amount,
        rate: 1 / coinData.price,
        convertedAmount: quantity,
        fee,
        status: 'completed',
        txHash: crypto.randomBytes(16).toString('hex')
      });
      await trade.save({ session });

      // Create transaction records
      const transactions = [
        new Transaction({
          userId: req.user._id,
          type: 'trade',
          amount: -amount,
          currency: 'USD',
          status: 'completed',
          txHash: trade.txHash
        }),
        new Transaction({
          userId: req.user._id,
          type: 'trade',
          amount: quantity,
          currency: coinUpper,
          status: 'completed',
          txHash: trade.txHash
        })
      ];
      await Transaction.insertMany(transactions, { session });

      await session.commitTransaction();
      session.endSession();

      // Notify user
      notifyUser(req.user._id, 'balance_update', {
        USD: usdWallet.balance,
        [coinUpper]: coinWallet.balance
      });

      res.json({
        message: 'Trade executed successfully',
        newUsdBalance: usdWallet.balance,
        newCoinBalance: coinWallet.balance,
        txHash: trade.txHash
      });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Buy trade error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 36. Execute sell trade
app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    if (systemSettings.tradingEnabled === false) {
      return res.status(403).json({ error: 'Trading is currently disabled' });
    }

    const { coin, amount } = req.body;
    if (!coin || !amount) {
      return res.status(400).json({ error: 'Coin and amount are required' });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }

    const coinUpper = coin.toUpperCase();
    const coinData = systemSettings.coins.find(c => c.symbol === coinUpper);
    if (!coinData) {
      return res.status(400).json({ error: 'Invalid coin' });
    }

    // Check coin balance
    const coinWallet = await Wallet.findOne({ userId: req.user._id, coin: coinUpper });
    if (!coinWallet || coinWallet.balance < amount) {
      return res.status(400).json({ error: 'Insufficient coin balance' });
    }

    // Calculate USD amount with fee
    const usdAmount = amount * coinData.price;
    const fee = usdAmount * systemSettings.feePercentage;
    const netAmount = usdAmount - fee;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from coin wallet
      coinWallet.balance -= amount;
      await coinWallet.save({ session });

      // Add to USD wallet (or create if doesn't exist)
      let usdWallet = await Wallet.findOne({ userId: req.user._id, coin: 'USD' }).session(session);
      if (!usdWallet) {
        usdWallet = new Wallet({
          userId: req.user._id,
          coin: 'USD',
          balance: 0
        });
      }
      usdWallet.balance += netAmount;
      await usdWallet.save({ session });

      // Create trade record
      const trade = new Trade({
        userId: req.user._id,
        fromCoin: coinUpper,
        toCoin: 'USD',
        amount,
        rate: coinData.price,
        convertedAmount: netAmount,
        fee,
        status: 'completed',
        txHash: crypto.randomBytes(16).toString('hex')
      });
      await trade.save({ session });

      // Create transaction records
      const transactions = [
        new Transaction({
          userId: req.user._id,
          type: 'trade',
          amount: -amount,
          currency: coinUpper,
          status: 'completed',
          txHash: trade.txHash
        }),
        new Transaction({
          userId: req.user._id,
          type: 'trade',
          amount: netAmount,
          currency: 'USD',
          status: 'completed',
          txHash: trade.txHash
        })
      ];
      await Transaction.insertMany(transactions, { session });

      await session.commitTransaction();
      session.endSession();

      // Notify user
      notifyUser(req.user._id, 'balance_update', {
        USD: usdWallet.balance,
        [coinUpper]: coinWallet.balance
      });

      res.json({
        message: 'Trade executed successfully',
        newUsdBalance: usdWallet.balance,
        newCoinBalance: coinWallet.balance,
        txHash: trade.txHash
      });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Sell trade error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 37. Get portfolio
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const wallets = await Wallet.find({ userId: req.user._id });
    
    const portfolio = wallets.map(wallet => {
      const coinData = systemSettings.coins.find(c => c.symbol === wallet.coin);
      return {
        coin: wallet.coin,
        balance: wallet.balance,
        value: wallet.balance * (coinData?.price || 0),
        change24h: coinData?.change24h || 0
      };
    });

    // Add USD if not present
    if (!portfolio.some(item => item.coin === 'USD')) {
      const usdWallet = await Wallet.findOne({ userId: req.user._id, coin: 'USD' });
      portfolio.push({
        coin: 'USD',
        balance: usdWallet?.balance || 0,
        value: usdWallet?.balance || 0,
        change24h: 0
      });
    }

    const totalValue = portfolio.reduce((sum, item) => sum + item.value, 0);
    
    res.json({
      portfolio,
      totalValue
    });
  } catch (err) {
    console.error('Get portfolio error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 38. Get all FAQs
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ category: 1, createdAt: -1 });
    res.json(faqs);
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 39. Submit support ticket (unauthenticated)
app.post('/api/v1/support/contact', upload.array('attachments', 3), async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'Name, email, subject, and message are required' });
    }

    const ticket = new SupportTicket({
      subject,
      message,
      attachments: req.files?.map(file => `/uploads/${file.filename}`) || []
    });
    await ticket.save();

    // Send confirmation email
    await sendEmail(
      email,
      'Support Ticket Received',
      `Hello ${name},\n\nThank you for contacting us. Your support ticket has been received and we will respond shortly.\n\nTicket ID: ${ticket._id}\nSubject: ${subject}`,
      `<p>Hello ${name},</p><p>Thank you for contacting us. Your support ticket has been received and we will respond shortly.</p><p><strong>Ticket ID:</strong> ${ticket._id}</p><p><strong>Subject:</strong> ${subject}</p>`
    );

    // Notify admins
    broadcastToAdmins('new_ticket', {
      ticketId: ticket._id,
      subject,
      message
    });

    res.status(201).json({
      message: 'Support ticket submitted successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Submit support ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 40. Submit support ticket (authenticated)
app.post('/api/v1/support/tickets', authenticate, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }

    const ticket = new SupportTicket({
      userId: req.user._id,
      subject,
      message,
      attachments: req.files?.map(file => `/uploads/${file.filename}`) || []
    });
    await ticket.save();

    // Send confirmation email
    await sendEmail(
      req.user.email,
      'Support Ticket Received',
      `Hello ${req.user.firstName},\n\nThank you for contacting us. Your support ticket has been received and we will respond shortly.\n\nTicket ID: ${ticket._id}\nSubject: ${subject}`,
      `<p>Hello ${req.user.firstName},</p><p>Thank you for contacting us. Your support ticket has been received and we will respond shortly.</p><p><strong>Ticket ID:</strong> ${ticket._id}</p><p><strong>Subject:</strong> ${subject}</p>`
    );

    // Notify admins
    broadcastToAdmins('new_ticket', {
      ticketId: ticket._id,
      userId: req.user._id,
      name: `${req.user.firstName} ${req.user.lastName}`,
      subject,
      message
    });

    res.status(201).json({
      message: 'Support ticket submitted successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Submit support ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 41. Get user's support tickets
app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (page - 1) * limit;

    const query = { userId: req.user._id };
    if (status) query.status = status;

    const [tickets, total] = await Promise.all([
      SupportTicket.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      SupportTicket.countDocuments(query)
    ]);

    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get user tickets error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 42. Get support ticket details
app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).populate('responses.userId', 'firstName lastName');

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    res.json(ticket);
  } catch (err) {
    console.error('Get ticket details error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 43. Add response to support ticket
app.post('/api/v1/support/tickets/:id/respond', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    ticket.responses.push({
      userId: req.user._id,
      message
    });

    if (ticket.status === 'open') {
      ticket.status = 'in_progress';
    }

    await ticket.save();

    // Notify admins
    broadcastToAdmins('ticket_response', {
      ticketId: ticket._id,
      userId: req.user._id,
      name: `${req.user.firstName} ${req.user.lastName}`,
      message
    });

    res.json({
      message: 'Response added successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Add ticket response error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 44. Close support ticket
app.post('/api/v1/support/tickets/:id/close', authenticate, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    if (ticket.status === 'closed') {
      return res.status(400).json({ error: 'Ticket is already closed' });
    }

    ticket.status = 'closed';
    await ticket.save();

    // Notify admins
    broadcastToAdmins('ticket_closed', {
      ticketId: ticket._id,
      userId: req.user._id,
      name: `${req.user.firstName} ${req.user.lastName}`
    });

    res.json({
      message: 'Ticket closed successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Close ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 45. Admin login
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email, isAdmin: true }).select('+password +lastActivity');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    res.json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 46. Admin verify token
app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
  res.json({
    isAuthenticated: true,
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      walletAddress: req.user.walletAddress,
      isAdmin: req.user.isAdmin,
      isVerified: req.user.isVerified,
      kycStatus: req.user.kycStatus,
      settings: req.user.settings
    }
  });
});

// 47. Get admin dashboard stats
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const [totalUsers, newUsers, activeUsers, totalTrades, totalVolume, pendingKYC, openTickets, recentTransactions] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
      User.countDocuments({ lastActivity: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
      Trade.countDocuments(),
      Trade.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      User.countDocuments({ kycStatus: 'pending' }),
      SupportTicket.countDocuments({ status: { $in: ['open', 'in_progress'] } }),
      Transaction.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('userId', 'firstName lastName email')
    ]);

    res.json({
      totalUsers,
      newUsers,
      activeUsers,
      totalTrades,
      totalVolume: totalVolume[0]?.total || 0,
      pendingKYC,
      openTickets,
      recentTransactions,
      systemSettings: {
        maintenanceMode: systemSettings.maintenanceMode,
        registrationEnabled: systemSettings.registrationEnabled,
        tradingEnabled: systemSettings.tradingEnabled,
        withdrawalEnabled: systemSettings.withdrawalEnabled,
        depositEnabled: systemSettings.depositEnabled,
        kycRequired: systemSettings.kycRequired
      }
    });
  } catch (err) {
    console.error('Get admin stats error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 48. Get all users (admin)
app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, sortBy, sortOrder, kycStatus, isVerified } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    if (kycStatus) query.kycStatus = kycStatus;
    if (isVerified !== undefined) query.isVerified = isVerified === 'true';

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [users, total] = await Promise.all([
      User.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      User.countDocuments(query)
    ]);

    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 49. Get user details (admin)
app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const [user, wallets, trades, transactions, tickets] = await Promise.all([
      User.findById(req.params.id),
      Wallet.find({ userId: req.params.id }),
      Trade.find({ userId: req.params.id })
        .sort({ createdAt: -1 })
        .limit(10),
      Transaction.find({ userId: req.params.id })
        .sort({ createdAt: -1 })
        .limit(10),
      SupportTicket.find({ userId: req.params.id })
        .sort({ createdAt: -1 })
        .limit(5)
    ]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user,
      wallets,
      trades,
      transactions,
      tickets
    });
  } catch (err) {
    console.error('Get admin user details error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 50. Update user (admin)
app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { isVerified, kycStatus, isAdmin } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (isVerified !== undefined) user.isVerified = isVerified;
    if (kycStatus !== undefined) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;

    await user.save();

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_user',
      target: user._id,
      details: req.body
    });

    // Notify user if KYC status changed
    if (kycStatus && kycStatus !== user.kycStatus) {
      notifyUser(user._id, 'kyc_update', { status: kycStatus });
    }

    res.json(user);
  } catch (err) {
    console.error('Update admin user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 51. Get all trades (admin)
app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, status, fromCoin, toCoin, sortBy, sortOrder } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (userId) query.userId = userId;
    if (status) query.status = status;
    if (fromCoin) query.fromCoin = fromCoin.toUpperCase();
    if (toCoin) query.toCoin = toCoin.toUpperCase();

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [trades, total] = await Promise.all([
      Trade.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('userId', 'firstName lastName email'),
      Trade.countDocuments(query)
    ]);

    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin trades error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 52. Get all transactions (admin)
app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status, currency, sortBy, sortOrder } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    if (currency) query.currency = currency.toUpperCase();

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('userId', 'firstName lastName email'),
      Transaction.countDocuments(query)
    ]);

    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin transactions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 53. Update transaction status (admin)
app.put('/api/v1/admin/transactions/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status === status) {
      return res.status(400).json({ error: 'Transaction already has this status' });
    }

    // For withdrawals, we need to update wallet balance if completing
    if (transaction.type === 'withdrawal' && status === 'completed' && transaction.status !== 'completed') {
      const wallet = await Wallet.findOne({
        userId: transaction.userId,
        coin: transaction.currency
      });

      if (!wallet) {
        return res.status(400).json({ error: 'Wallet not found' });
      }

      // The amount is already negative for withdrawals
      wallet.balance -= transaction.amount;
      await wallet.save();
    }

    transaction.status = status;
    await transaction.save();

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_transaction',
      target: transaction._id,
      details: { status }
    });

    // Notify user
    notifyUser(transaction.userId, 'transaction_update', transaction);

    res.json(transaction);
  } catch (err) {
    console.error('Update admin transaction error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 54. Get all support tickets (admin)
app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, userId, sortBy, sortOrder } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (status) query.status = status;
    if (userId) query.userId = userId;

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [tickets, total] = await Promise.all([
      SupportTicket.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('userId', 'firstName lastName email')
        .populate('responses.userId', 'firstName lastName'),
      SupportTicket.countDocuments(query)
    ]);

    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin tickets error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 55. Get support ticket details (admin)
app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email')
      .populate('responses.userId', 'firstName lastName');

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    res.json(ticket);
  } catch (err) {
    console.error('Get admin ticket details error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 56. Update support ticket (admin)
app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    if (ticket.status === status) {
      return res.status(400).json({ error: 'Ticket already has this status' });
    }

    ticket.status = status;
    await ticket.save();

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_ticket',
      target: ticket._id,
      details: { status }
    });

    // Notify user if ticket is closed
    if (status === 'closed' && ticket.userId) {
      notifyUser(ticket.userId, 'ticket_update', ticket);
    }

    res.json(ticket);
  } catch (err) {
    console.error('Update admin ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 57. Add response to ticket (admin)
app.post('/api/v1/admin/tickets/:id/respond', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    ticket.responses.push({
      userId: req.user._id,
      message
    });

    if (ticket.status === 'open') {
      ticket.status = 'in_progress';
    }

    await ticket.save();

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'respond_to_ticket',
      target: ticket._id,
      details: { message }
    });

    // Notify user
    if (ticket.userId) {
      notifyUser(ticket.userId, 'ticket_update', ticket);
    }

    res.json({
      message: 'Response added successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Add admin ticket response error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 58. Get all KYC submissions (admin)
app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, sortBy, sortOrder } = req.query;
    const skip = (page - 1) * limit;

    let query = { kycStatus: { $ne: 'none' } };
    if (status) query.kycStatus = status;

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [users, total] = await Promise.all([
      User.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      User.countDocuments(query)
    ]);

    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin KYC submissions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 59. Get KYC details (admin)
app.get('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.kycStatus === 'none') {
      return res.status(404).json({ error: 'KYC submission not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('Get admin KYC details error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 60. Update KYC status (admin)
app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, documentStatuses } = req.body;
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const user = await User.findById(req.params.id);
    if (!user || user.kycStatus === 'none') {
      return res.status(404).json({ error: 'KYC submission not found' });
    }

    if (user.kycStatus === status) {
      return res.status(400).json({ error: 'KYC already has this status' });
    }

    // Update document statuses if provided
    if (documentStatuses && Array.isArray(documentStatuses)) {
      documentStatuses.forEach(docStatus => {
        const doc = user.kycDocuments.id(docStatus._id);
        if (doc) {
          doc.status = docStatus.status;
        }
      });
    }

    user.kycStatus = status;
    await user.save();

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_kyc',
      target: user._id,
      details: { status, documentStatuses }
    });

    // Notify user
    notifyUser(user._id, 'kyc_update', { status: user.kycStatus });

    res.json(user);
  } catch (err) {
    console.error('Update admin KYC error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 61. Get admin logs
app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, action, adminId, target, sortBy, sortOrder } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (action) query.action = action;
    if (adminId) query.adminId = adminId;
    if (target) query.target = target;

    let sort = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const [logs, total] = await Promise.all([
      AdminLog.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('adminId', 'firstName lastName email'),
      AdminLog.countDocuments(query)
    ]);

    res.json({
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Get admin logs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 62. Send broadcast message
app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message, title } = req.body;
    if (!message || !title) {
      return res.status(400).json({ error: 'Message and title are required' });
    }

    // Send to all connected users
    clients.forEach((ws, userId) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          event: 'broadcast',
          data: { title, message }
        }));
      }
    });

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'broadcast',
      details: { title, message }
    });

    res.json({ message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error('Send broadcast error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 63. Get system settings
app.get('/api/v1/admin/settings', authenticateAdmin, (req, res) => {
  res.json({
    maintenanceMode: systemSettings.maintenanceMode,
    registrationEnabled: systemSettings.registrationEnabled,
    tradingEnabled: systemSettings.tradingEnabled,
    withdrawalEnabled: systemSettings.withdrawalEnabled,
    depositEnabled: systemSettings.depositEnabled,
    kycRequired: systemSettings.kycRequired,
    maxWithdrawal: systemSettings.maxWithdrawal,
    minDeposit: systemSettings.minDeposit,
    feePercentage: systemSettings.feePercentage,
    coins: systemSettings.coins
  });
});

// 64. Update system settings
app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const {
      maintenanceMode,
      registrationEnabled,
      tradingEnabled,
      withdrawalEnabled,
      depositEnabled,
      kycRequired,
      maxWithdrawal,
      minDeposit,
      feePercentage
    } = req.body;

    const newSettings = {
      maintenanceMode,
      registrationEnabled,
      tradingEnabled,
      withdrawalEnabled,
      depositEnabled,
      kycRequired,
      maxWithdrawal,
      minDeposit,
      feePercentage
    };

    // Validate numeric fields
    if (maxWithdrawal !== undefined && isNaN(maxWithdrawal)) {
      return res.status(400).json({ error: 'Max withdrawal must be a number' });
    }
    if (minDeposit !== undefined && isNaN(minDeposit)) {
      return res.status(400).json({ error: 'Min deposit must be a number' });
    }
    if (feePercentage !== undefined && (isNaN(feePercentage) || feePercentage < 0 || feePercentage > 1)) {
      return res.status(400).json({ error: 'Fee percentage must be between 0 and 1' });
    }

    const success = updateSystemSettings(newSettings);
    if (!success) {
      return res.status(500).json({ error: 'Failed to update system settings' });
    }

    // Log admin action
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_settings',
      details: newSettings
    });

    // Notify all users if maintenance mode changed
    if (maintenanceMode !== undefined) {
      broadcastToAdmins('settings_update', newSettings);
      clients.forEach((ws, userId) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            event: 'maintenance_mode',
            data: { enabled: maintenanceMode }
          }));
        }
      });
    }

    res.json({ message: 'System settings updated successfully' });
  } catch (err) {
    console.error('Update system settings error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 65. Export data (users)
app.get('/api/v1/admin/export/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find().lean();

    // Convert to CSV
    let csv = 'ID,First Name,Last Name,Email,Wallet Address,Country,Currency,Verified,KYC Status,Admin,Created At\n';
    users.forEach(user => {
      csv += `${user._id},${user.firstName || ''},${user.lastName || ''},${user.email || ''},${user.walletAddress || ''},${user.country || ''},${user.currency || ''},${user.isVerified},${user.kycStatus},${user.isAdmin},${user.createdAt}\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment('users-export.csv');
    res.send(csv);
  } catch (err) {
    console.error('Export users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 66. Export data (trades)
app.get('/api/v1/admin/export/trades', authenticateAdmin, async (req, res) => {
  try {
    const trades = await Trade.find()
      .populate('userId', 'email')
      .lean();

    // Convert to CSV
    let csv = 'ID,User Email,From Coin,To Coin,Amount,Rate,Converted Amount,Fee,Status,Date\n';
    trades.forEach(trade => {
      csv += `${trade._id},${trade.userId?.email || ''},${trade.fromCoin},${trade.toCoin},${trade.amount},${trade.rate},${trade.convertedAmount},${trade.fee},${trade.status},${trade.createdAt.toISOString()}\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment('trades-export.csv');
    res.send(csv);
  } catch (err) {
    console.error('Export trades error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 67. Export data (transactions)
app.get('/api/v1/admin/export/transactions', authenticateAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('userId', 'email')
      .lean();

    // Convert to CSV
    let csv = 'ID,User Email,Type,Amount,Currency,Status,Tx Hash,Address,Date\n';
    transactions.forEach(tx => {
      csv += `${tx._id},${tx.userId?.email || ''},${tx.type},${tx.amount},${tx.currency},${tx.status},${tx.txHash || ''},${tx.address || ''},${tx.createdAt.toISOString()}\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment('transactions-export.csv');
    res.send(csv);
  } catch (err) {
    console.error('Export transactions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve static files
app.use(express.static('public'));

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Handle errors
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize server
const server = app.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`Server running on port ${PORT}`);
});

// Handle WebSocket upgrade
server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
