require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const http = require('http');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const redis = require('redis');
const winston = require('winston');
const xss = require('xss-clean');
const ethUtil = require('ethereumjs-util');
const CryptoJS = require('crypto-js');
const cloudinary = require('cloudinary').v2;

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Security middleware
app.use(helmet());
app.use(xss());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => logger.info('MongoDB connected successfully'))
.catch(err => logger.error('MongoDB connection error:', err));

// Redis client for caching and rate limiting
const redisClient = redis.createClient({
  url: 'redis://default:redis@localhost:6379'
});
redisClient.on('error', (err) => logger.error('Redis Client Error', err));
redisClient.connect();

// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRE = '30d';

// Mail transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Cloudinary configuration
cloudinary.config({
  cloud_name: 'your_cloud_name',
  api_key: 'your_api_key',
  api_secret: 'your_api_secret'
});

// Models
const User = require('./models/User')(mongoose);
const Trade = require('./models/Trade')(mongoose);
const Transaction = require('./models/Transaction')(mongoose);
const SupportTicket = require('./models/SupportTicket')(mongoose);
const KYC = require('./models/KYC')(mongoose);
const Admin = require('./models/Admin')(mongoose);
const Coin = require('./models/Coin')(mongoose);

// Initialize WebSocket server
const wss = new WebSocketServer({ server, path: '/ws' });
const adminWss = new WebSocketServer({ server, path: '/api/v1/admin/ws' });

// WebSocket connections map
const connections = new Map();
const adminConnections = new Map();

// Broadcast function for WebSocket
function broadcast(data, isAdmin = false) {
  const targetConnections = isAdmin ? adminConnections : connections;
  targetConnections.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(data));
    }
  });
}

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const token = req.headers['sec-websocket-protocol'];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    connections.set(decoded.id, ws);
    
    ws.on('close', () => {
      connections.delete(decoded.id);
    });
    
    ws.on('message', (message) => {
      // Handle incoming messages from clients
      try {
        const data = JSON.parse(message);
        // Process message based on type
      } catch (err) {
        logger.error('WebSocket message error:', err);
      }
    });
    
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Admin WebSocket connection handler
adminWss.on('connection', (ws, req) => {
  const token = req.headers['sec-websocket-protocol'];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    Admin.findById(decoded.id).then(admin => {
      if (!admin) {
        ws.close(1008, 'Admin not found');
        return;
      }
      
      adminConnections.set(decoded.id, ws);
      
      ws.on('close', () => {
        adminConnections.delete(decoded.id);
      });
      
      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          // Process admin messages
        } catch (err) {
          logger.error('Admin WebSocket message error:', err);
        }
      });
    });
    
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Utility functions
const generateNonce = () => crypto.randomBytes(16).toString('hex');
const generateApiKey = () => crypto.randomBytes(32).toString('hex');
const encryptData = (data) => CryptoJS.AES.encrypt(data, JWT_SECRET).toString();
const decryptData = (data) => CryptoJS.AES.decrypt(data, JWT_SECRET).toString(CryptoJS.enc.Utf8);

// Middleware
const authenticate = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (err) {
    logger.error('Authentication error:', err);
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = await Admin.findById(decoded.id).select('-password');
    next();
  } catch (err) {
    logger.error('Admin authentication error:', err);
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }
};

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'), false);
    }
  }
});

// Routes

// 🔒 Core Authentication & Session
app.post('/api/v1/auth/signup', [
  body('firstName').notEmpty().trim().escape(),
  body('lastName').notEmpty().trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('country').notEmpty().trim().escape(),
  body('currency').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      balances: { BTC: 0, ETH: 0, USDT: 0 }, // Default balances
      walletAddress: `user-${uuidv4()}`
    });
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Broadcast new user to admin dashboard
    broadcast({ type: 'NEW_USER', data: user }, true);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        balances: user.balances,
        walletAddress: user.walletAddress
      }
    });
    
  } catch (err) {
    logger.error('Signup error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-signup', [
  body('walletAddress').notEmpty().trim().escape(),
  body('signature').notEmpty().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature
    const message = `Welcome to Crypto Platform! Please sign this message to verify your wallet. Nonce: ${await redisClient.get(`nonce:${walletAddress}`)}`;
    const recoveredAddress = ethUtil.verifyMessage(message, signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({ success: false, message: 'Invalid signature' });
    }
    
    // Check if wallet is already registered
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Wallet already registered' });
    }
    
    // Create user
    const user = await User.create({
      walletAddress,
      isWalletUser: true,
      balances: { BTC: 0, ETH: 0, USDT: 0 } // Default balances
    });
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Broadcast new user to admin dashboard
    broadcast({ type: 'NEW_USER', data: user }, true);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        balances: user.balances
      }
    });
    
  } catch (err) {
    logger.error('Wallet signup error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        balances: user.balances,
        walletAddress: user.walletAddress
      }
    });
    
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    res.clearCookie('token');
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Logout error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (err) {
    logger.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/auth/verify', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (err) {
    logger.error('Verify token error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/status', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      isAuthenticated: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        walletAddress: req.user.walletAddress
      }
    });
  } catch (err) {
    logger.error('Auth status error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/check', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      isAuthenticated: true
    });
  } catch (err) {
    logger.error('Auth check error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user doesn't exist for security
      return res.status(200).json({ success: true, message: 'If an account exists, a reset email has been sent' });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();
    
    // Send email
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      to: user.email,
      from: 'no-reply@cryptoplatform.com',
      subject: 'Password Reset Request',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        ${resetUrl}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ success: true, message: 'If an account exists, a reset email has been sent' });
    
  } catch (err) {
    logger.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/nonce', [
  body('walletAddress').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { walletAddress } = req.body;
    const nonce = generateNonce();
    
    await redisClient.set(`nonce:${walletAddress}`, nonce, { EX: 300 }); // 5 minutes expiry
    
    res.status(200).json({
      success: true,
      nonce,
      message: `Welcome to Crypto Platform! Please sign this message to verify your wallet. Nonce: ${nonce}`
    });
    
  } catch (err) {
    logger.error('Nonce generation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-login', [
  body('walletAddress').notEmpty().trim().escape(),
  body('signature').notEmpty().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature
    const message = `Welcome to Crypto Platform! Please sign this message to verify your wallet. Nonce: ${await redisClient.get(`nonce:${walletAddress}`)}`;
    const recoveredAddress = ethUtil.verifyMessage(message, signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({ success: false, message: 'Invalid signature' });
    }
    
    // Find user
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Wallet not registered' });
    }
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        balances: user.balances
      }
    });
    
  } catch (err) {
    logger.error('Wallet login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/validate', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      isValid: true,
      user: req.user
    });
  } catch (err) {
    logger.error('Token validation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 👤 User Management
app.get('/users/me', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (err) {
    logger.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      settings: {
        notifications: req.user.notifications || true,
        twoFactor: req.user.twoFactor || false,
        preferredCurrency: req.user.currency || 'USD',
        language: req.user.language || 'en',
        theme: req.user.theme || 'light'
      }
    });
  } catch (err) {
    logger.error('Get user settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { notifications, twoFactor, preferredCurrency, language, theme } = req.body;
    
    const updates = {};
    if (notifications !== undefined) updates.notifications = notifications;
    if (twoFactor !== undefined) updates.twoFactor = twoFactor;
    if (preferredCurrency) updates.currency = preferredCurrency;
    if (language) updates.language = language;
    if (theme) updates.theme = theme;
    
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    
    res.status(200).json({
      success: true,
      settings: {
        notifications: user.notifications,
        twoFactor: user.twoFactor,
        preferredCurrency: user.currency,
        language: user.language,
        theme: user.theme
      }
    });
    
  } catch (err) {
    logger.error('Update user settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/auth/update-password', authenticate, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }
    
    // Update password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    res.status(200).json({ success: true, message: 'Password updated successfully' });
    
  } catch (err) {
    logger.error('Update password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.array('documents', 3), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ success: false, message: 'Please upload at least one document' });
    }
    
    // Upload documents to Cloudinary
    const uploadPromises = files.map(file => {
      return new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream({ resource_type: 'auto' }, (error, result) => {
          if (error) reject(error);
          else resolve(result.secure_url);
        }).end(file.buffer);
      });
    });
    
    const documentUrls = await Promise.all(uploadPromises);
    
    // Create KYC record
    const kyc = await KYC.create({
      user: req.user._id,
      documentType,
      documentNumber,
      documentImages: documentUrls,
      status: 'pending'
    });
    
    // Update user KYC status
    await User.findByIdAndUpdate(req.user._id, { kycStatus: 'pending' });
    
    // Broadcast new KYC submission to admin dashboard
    broadcast({ type: 'NEW_KYC', data: kyc }, true);
    
    res.status(201).json({
      success: true,
      message: 'KYC documents submitted for review'
    });
    
  } catch (err) {
    logger.error('KYC submission error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const apiKey = generateApiKey();
    const encryptedKey = encryptData(apiKey);
    
    await User.findByIdAndUpdate(req.user._id, { apiKey: encryptedKey });
    
    res.status(201).json({
      success: true,
      apiKey,
      message: 'API key generated successfully. Please store it securely as it will not be shown again.'
    });
    
  } catch (err) {
    logger.error('API key generation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).lean();
    const trades = await Trade.find({ user: req.user._id }).lean();
    const transactions = await Transaction.find({ user: req.user._id }).lean();
    
    const data = {
      user,
      trades,
      transactions
    };
    
    // In a real app, you would generate a file and email it to the user
    // For this example, we'll just return the JSON data
    
    res.status(200).json({
      success: true,
      data,
      message: 'Data export request received. You will receive an email with your data shortly.'
    });
    
  } catch (err) {
    logger.error('Data export error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    // In a real app, you would soft delete or anonymize the data
    await User.findByIdAndDelete(req.user._id);
    
    // Clear trades and transactions (or anonymize them)
    await Trade.deleteMany({ user: req.user._id });
    await Transaction.deleteMany({ user: req.user._id });
    
    res.clearCookie('token');
    res.status(200).json({ success: true, message: 'Account deleted successfully' });
    
  } catch (err) {
    logger.error('Delete account error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 🛠️ Admin Routes
app.post('/api/v1/admin/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email }).select('+password');
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, { expiresIn: '8h' });
    
    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role
      }
    });
    
  } catch (err) {
    logger.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      admin: req.admin
    });
  } catch (err) {
    logger.error('Admin verify error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ lastActive: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    const newUsersCount = await User.countDocuments({ createdAt: { $gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } });
    const tradesCount = await Trade.countDocuments();
    const pendingKycCount = await KYC.countDocuments({ status: 'pending' });
    const pendingTicketsCount = await SupportTicket.countDocuments({ status: 'open' });
    
    const stats = {
      users: usersCount,
      activeUsers: activeUsersCount,
      newUsers: newUsersCount,
      trades: tradesCount,
      pendingKyc: pendingKycCount,
      pendingTickets: pendingTicketsCount
    };
    
    res.status(200).json({
      success: true,
      stats
    });
    
  } catch (err) {
    logger.error('Admin dashboard stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status) {
      query.status = status;
    }
    
    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .select('-password');
    
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
    
  } catch (err) {
    logger.error('Admin get users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const trades = await Trade.find({ user: user._id }).sort({ createdAt: -1 }).limit(10);
    const transactions = await Transaction.find({ user: user._id }).sort({ createdAt: -1 }).limit(10);
    const kyc = await KYC.findOne({ user: user._id });
    
    res.status(200).json({
      success: true,
      user,
      trades,
      transactions,
      kyc
    });
    
  } catch (err) {
    logger.error('Admin get user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, kycStatus, isVerified, isBlocked } = req.body;
    
    const updates = {};
    if (status) updates.status = status;
    if (kycStatus) updates.kycStatus = kycStatus;
    if (isVerified !== undefined) updates.isVerified = isVerified;
    if (isBlocked !== undefined) updates.isBlocked = isBlocked;
    
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    
    // Broadcast user update to all connected clients
    broadcast({ type: 'USER_UPDATED', data: user });
    
    res.status(200).json({
      success: true,
      user
    });
    
  } catch (err) {
    logger.error('Admin update user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (userId) query.user = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const trades = await Trade.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('user', 'email walletAddress');
    
    const total = await Trade.countDocuments(query);
    
    res.status(200).json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
    
  } catch (err) {
    logger.error('Admin get trades error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (userId) query.user = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('user', 'email walletAddress');
    
    const total = await Transaction.countDocuments(query);
    
    res.status(200).json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
    
  } catch (err) {
    logger.error('Admin get transactions error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('user', 'email walletAddress');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    res.status(200).json({
      success: true,
      ticket
    });
    
  } catch (err) {
    logger.error('Admin get ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = req.body;
    
    const updates = {};
    if (status) updates.status = status;
    if (response) {
      updates.responses = [...(ticket.responses || []), {
        admin: req.admin._id,
        message: response,
        createdAt: new Date()
      }];
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(req.params.id, updates, { new: true })
      .populate('user', 'email walletAddress');
    
    // Notify user about ticket update
    if (ticket.user && connections.has(ticket.user._id.toString())) {
      const ws = connections.get(ticket.user._id.toString());
      ws.send(JSON.stringify({
        type: 'TICKET_UPDATE',
        data: ticket
      }));
    }
    
    res.status(200).json({
      success: true,
      ticket
    });
    
  } catch (err) {
    logger.error('Admin update ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('user', 'email walletAddress firstName lastName');
    
    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC not found' });
    }
    
    res.status(200).json({
      success: true,
      kyc
    });
    
  } catch (err) {
    logger.error('Admin get KYC error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, reason } = req.body;
    
    if (!status || !['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    
    const kyc = await KYC.findByIdAndUpdate(req.params.id, { status, reason }, { new: true })
      .populate('user', 'email walletAddress firstName lastName');
    
    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, { 
      kycStatus: status,
      isVerified: status === 'approved'
    });
    
    // Notify user about KYC status
    if (connections.has(kyc.user._id.toString())) {
      const ws = connections.get(kyc.user._id.toString());
      ws.send(JSON.stringify({
        type: 'KYC_STATUS',
        data: { status, reason }
      }));
    }
    
    res.status(200).json({
      success: true,
      kyc
    });
    
  } catch (err) {
    logger.error('Admin update KYC error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would query your logging system
    // For this example, we'll simulate log data
    const logs = [
      { timestamp: new Date(), level: 'info', message: 'System started' },
      { timestamp: new Date(Date.now() - 1000), level: 'info', message: 'New user registered' },
      { timestamp: new Date(Date.now() - 2000), level: 'warning', message: 'Failed login attempt' }
    ];
    
    res.status(200).json({
      success: true,
      logs
    });
    
  } catch (err) {
    logger.error('Admin get logs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message, type = 'info', target = 'all' } = req.body;
    
    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }
    
    const notification = {
      id: uuidv4(),
      type,
      message,
      timestamp: new Date(),
      admin: req.admin._id
    };
    
    // Broadcast to all users or specific target
    broadcast({ type: 'BROADCAST', data: notification }, target === 'admins');
    
    res.status(200).json({
      success: true,
      notification
    });
    
  } catch (err) {
    logger.error('Admin broadcast error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would fetch from a settings collection
    const settings = {
      maintenanceMode: false,
      registrationEnabled: true,
      tradingEnabled: true,
      withdrawalEnabled: true,
      depositEnabled: true,
      kycRequired: true
    };
    
    res.status(200).json({
      success: true,
      settings
    });
    
  } catch (err) {
    logger.error('Admin get settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const { maintenanceMode, registrationEnabled, tradingEnabled, withdrawalEnabled, depositEnabled, kycRequired } = req.body;
    
    // In a real app, you would update a settings collection
    const settings = {
      maintenanceMode: maintenanceMode || false,
      registrationEnabled: registrationEnabled !== undefined ? registrationEnabled : true,
      tradingEnabled: tradingEnabled !== undefined ? tradingEnabled : true,
      withdrawalEnabled: withdrawalEnabled !== undefined ? withdrawalEnabled : true,
      depositEnabled: depositEnabled !== undefined ? depositEnabled : true,
      kycRequired: kycRequired !== undefined ? kycRequired : true
    };
    
    // Broadcast settings change
    broadcast({ type: 'SETTINGS_UPDATE', data: settings }, true);
    
    res.status(200).json({
      success: true,
      settings
    });
    
  } catch (err) {
    logger.error('Admin update settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 💱 Exchange & Market
app.get('/exchange/coins', async (req, res) => {
  try {
    // In a real app, you would fetch from your database or external API
    const coins = [
      { symbol: 'BTC', name: 'Bitcoin', price: 50000, change24h: 2.5 },
      { symbol: 'ETH', name: 'Ethereum', price: 3000, change24h: -1.2 },
      { symbol: 'USDT', name: 'Tether', price: 1, change24h: 0 }
    ];
    
    res.status(200).json({
      success: true,
      coins
    });
    
  } catch (err) {
    logger.error('Get coins error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/exchange/rates', async (req, res) => {
  try {
    // In a real app, you would calculate based on market data
    const rates = {
      BTC: { ETH: 16.67, USDT: 50000 },
      ETH: { BTC: 0.06, USDT: 3000 },
      USDT: { BTC: 0.00002, ETH: 0.00033 }
    };
    
    res.status(200).json({
      success: true,
      rates
    });
    
  } catch (err) {
    logger.error('Get rates error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ success: false, message: 'Both from and to parameters are required' });
    }
    
    // In a real app, you would fetch the current rate
    const rate = from === 'BTC' && to === 'ETH' ? 16.67 :
                 from === 'ETH' && to === 'BTC' ? 0.06 :
                 from === 'BTC' && to === 'USDT' ? 50000 :
                 from === 'USDT' && to === 'BTC' ? 0.00002 :
                 from === 'ETH' && to === 'USDT' ? 3000 :
                 from === 'USDT' && to === 'ETH' ? 0.00033 : 1;
    
    res.status(200).json({
      success: true,
      from,
      to,
      rate
    });
    
  } catch (err) {
    logger.error('Get rate error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/exchange/convert', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be positive' });
    }
    
    // Get current rate
    const rateResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/exchange/rate?from=${from}&to=${to}`);
    const rateData = await rateResponse.json();
    
    if (!rateData.success) {
      return res.status(400).json({ success: false, message: 'Failed to get exchange rate' });
    }
    
    const rate = rateData.rate;
    const convertedAmount = amount * rate;
    
    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances[from] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Update balances
    user.balances[from] -= amount;
    user.balances[to] = (user.balances[to] || 0) + convertedAmount;
    await user.save();
    
    // Create trade record
    const trade = await Trade.create({
      user: user._id,
      type: 'exchange',
      from,
      to,
      amount,
      rate,
      convertedAmount,
      status: 'completed'
    });
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: 'exchange',
      amount: convertedAmount,
      currency: to,
      status: 'completed',
      details: `Converted ${amount} ${from} to ${convertedAmount} ${to}`
    });
    
    // Broadcast balance update
    broadcast({ type: 'BALANCE_UPDATE', data: { userId: user._id, balances: user.balances } });
    
    res.status(200).json({
      success: true,
      from,
      to,
      amount,
      rate,
      convertedAmount,
      newBalances: user.balances
    });
    
  } catch (err) {
    logger.error('Convert error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/exchange/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.status(200).json({
      success: true,
      trades
    });
    
  } catch (err) {
    logger.error('Get exchange history error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/market/data', async (req, res) => {
  try {
    // In a real app, you would fetch from your database or external API
    const marketData = {
      BTC: { price: 50000, change24h: 2.5, volume: 1000000000 },
      ETH: { price: 3000, change24h: -1.2, volume: 500000000 },
      USDT: { price: 1, change24h: 0, volume: 2000000000 }
    };
    
    res.status(200).json({
      success: true,
      marketData
    });
    
  } catch (err) {
    logger.error('Get market data error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/market/detailed', async (req, res) => {
  try {
    // In a real app, you would fetch detailed market data
    const detailedData = {
      BTC: {
        price: 50000,
        change24h: 2.5,
        volume: 1000000000,
        high: 51000,
        low: 49500,
        marketCap: 1000000000000,
        circulatingSupply: 19000000
      },
      ETH: {
        price: 3000,
        change24h: -1.2,
        volume: 500000000,
        high: 3100,
        low: 2950,
        marketCap: 360000000000,
        circulatingSupply: 120000000
      }
    };
    
    res.status(200).json({
      success: true,
      detailedData
    });
    
  } catch (err) {
    logger.error('Get detailed market data error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 💼 Wallet & Portfolio
app.get('/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    // Fixed deposit address as specified
    const depositAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
    
    res.status(200).json({
      success: true,
      depositAddress
    });
    
  } catch (err) {
    logger.error('Get deposit address error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { currency, amount, address } = req.body;
    
    if (!currency || !amount || !address) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be positive' });
    }
    
    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances[currency] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // In a real app, you would process the withdrawal
    // For this example, we'll just deduct the balance
    
    user.balances[currency] -= amount;
    await user.save();
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending',
      details: `Withdrawal request for ${amount} ${currency} to ${address}`
    });
    
    // Broadcast balance update
    broadcast({ type: 'BALANCE_UPDATE', data: { userId: user._id, balances: user.balances } });
    
    // Notify admin about new withdrawal
    broadcast({ type: 'NEW_WITHDRAWAL', data: transaction }, true);
    
    res.status(200).json({
      success: true,
      message: 'Withdrawal request submitted',
      transaction
    });
    
  } catch (err) {
    logger.error('Withdraw error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const trades = await Trade.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    // Calculate portfolio value
    const ratesResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/exchange/rates`);
    const ratesData = await ratesResponse.json();
    const rates = ratesData.success ? ratesData.rates : {};
    
    let totalValue = 0;
    const portfolio = {};
    
    for (const [currency, balance] of Object.entries(user.balances)) {
      if (balance > 0) {
        const value = rates[currency]?.USDT ? balance * rates[currency].USDT : balance;
        portfolio[currency] = {
          balance,
          value,
          change24h: rates[currency]?.change24h || 0
        };
        totalValue += value;
      }
    }
    
    res.status(200).json({
      success: true,
      portfolio,
      totalValue,
      recentTrades: trades
    });
    
  } catch (err) {
    logger.error('Get portfolio error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 📈 Trading
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { currency, amount } = req.body;
    
    if (!currency || !amount) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be positive' });
    }
    
    // Get current rate (assuming buying with USDT)
    const rateResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/exchange/rate?from=USDT&to=${currency}`);
    const rateData = await rateResponse.json();
    
    if (!rateData.success) {
      return res.status(400).json({ success: false, message: 'Failed to get exchange rate' });
    }
    
    const rate = rateData.rate;
    const cost = amount / rate; // Cost in USDT
    
    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances['USDT'] < cost) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Update balances
    user.balances['USDT'] -= cost;
    user.balances[currency] = (user.balances[currency] || 0) + amount;
    await user.save();
    
    // Create trade record
    const trade = await Trade.create({
      user: user._id,
      type: 'buy',
      from: 'USDT',
      to: currency,
      amount: cost,
      rate,
      convertedAmount: amount,
      status: 'completed'
    });
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: 'buy',
      amount,
      currency,
      status: 'completed',
      details: `Bought ${amount} ${currency} for ${cost} USDT`
    });
    
    // Broadcast balance update
    broadcast({ type: 'BALANCE_UPDATE', data: { userId: user._id, balances: user.balances } });
    
    res.status(200).json({
      success: true,
      currency,
      amount,
      rate,
      cost,
      newBalances: user.balances
    });
    
  } catch (err) {
    logger.error('Buy error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { currency, amount } = req.body;
    
    if (!currency || !amount) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be positive' });
    }
    
    // Get current rate (assuming selling for USDT)
    const rateResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/exchange/rate?from=${currency}&to=USDT`);
    const rateData = await rateResponse.json();
    
    if (!rateData.success) {
      return res.status(400).json({ success: false, message: 'Failed to get exchange rate' });
    }
    
    const rate = rateData.rate;
    const proceeds = amount * rate; // Proceeds in USDT
    
    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances[currency] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Update balances
    user.balances[currency] -= amount;
    user.balances['USDT'] = (user.balances['USDT'] || 0) + proceeds;
    await user.save();
    
    // Create trade record
    const trade = await Trade.create({
      user: user._id,
      type: 'sell',
      from: currency,
      to: 'USDT',
      amount,
      rate,
      convertedAmount: proceeds,
      status: 'completed'
    });
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: 'sell',
      amount: proceeds,
      currency: 'USDT',
      status: 'completed',
      details: `Sold ${amount} ${currency} for ${proceeds} USDT`
    });
    
    // Broadcast balance update
    broadcast({ type: 'BALANCE_UPDATE', data: { userId: user._id, balances: user.balances } });
    
    res.status(200).json({
      success: true,
      currency,
      amount,
      rate,
      proceeds,
      newBalances: user.balances
    });
    
  } catch (err) {
    logger.error('Sell error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ 
      user: req.user._id,
      status: { $in: ['pending', 'processing'] }
    }).sort({ createdAt: -1 });
    
    res.status(200).json({
      success: true,
      trades
    });
    
  } catch (err) {
    logger.error('Get active trades error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({
      success: true,
      transactions
    });
    
  } catch (err) {
    logger.error('Get recent transactions error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 💬 Support & Contact
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, you would fetch from database
    const faqs = [
      {
        category: 'General',
        questions: [
          { question: 'How do I create an account?', answer: 'Click on the Sign Up button and follow the instructions.' },
          { question: 'Is there a mobile app?', answer: 'Yes, our mobile app is available on both iOS and Android.' }
        ]
      },
      {
        category: 'Trading',
        questions: [
          { question: 'How do I buy cryptocurrency?', answer: 'Navigate to the Buy section and follow the instructions.' },
          { question: 'What are the trading fees?', answer: 'Our trading fees are 0.1% per trade.' }
        ]
      }
    ];
    
    res.status(200).json({
      success: true,
      faqs
    });
    
  } catch (err) {
    logger.error('Get FAQs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support/contact', [
  body('name').notEmpty().trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('subject').notEmpty().trim().escape(),
  body('message').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { name, email, subject, message } = req.body;
    
    // Create support ticket
    const ticket = await SupportTicket.create({
      name,
      email,
      subject,
      message,
      status: 'open'
    });
    
    // Notify admin about new ticket
    broadcast({ type: 'NEW_TICKET', data: ticket }, true);
    
    res.status(201).json({
      success: true,
      message: 'Your message has been submitted. We will respond shortly.'
    });
    
  } catch (err) {
    logger.error('Contact support error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support/tickets', authenticate, [
  body('subject').notEmpty().trim().escape(),
  body('message').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { subject, message } = req.body;
    
    // Create support ticket
    const ticket = await SupportTicket.create({
      user: req.user._id,
      name: `${req.user.firstName} ${req.user.lastName}`,
      email: req.user.email,
      subject,
      message,
      status: 'open'
    });
    
    // Notify admin about new ticket
    broadcast({ type: 'NEW_TICKET', data: ticket }, true);
    
    res.status(201).json({
      success: true,
      message: 'Your support ticket has been submitted. We will respond shortly.',
      ticket
    });
    
  } catch (err) {
    logger.error('Create support ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ user: req.user._id })
      .sort({ createdAt: -1 });
    
    res.status(200).json({
      success: true,
      tickets
    });
    
  } catch (err) {
    logger.error('Get user tickets error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support', authenticate, upload.array('attachments', 3), [
  body('subject').notEmpty().trim().escape(),
  body('message').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { subject, message } = req.body;
    const files = req.files;
    
    // Upload attachments if any
    let attachments = [];
    if (files && files.length > 0) {
      const uploadPromises = files.map(file => {
        return new Promise((resolve, reject) => {
          cloudinary.uploader.upload_stream({ resource_type: 'auto' }, (error, result) => {
            if (error) reject(error);
            else resolve(result.secure_url);
          }).end(file.buffer);
        });
      });
      
      attachments = await Promise.all(uploadPromises);
    }
    
    // Create support ticket
    const ticket = await SupportTicket.create({
      user: req.user._id,
      name: `${req.user.firstName} ${req.user.lastName}`,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    // Notify admin about new ticket
    broadcast({ type: 'NEW_TICKET', data: ticket }, true);
    
    res.status(201).json({
      success: true,
      message: 'Your support ticket has been submitted. We will respond shortly.',
      ticket
    });
    
  } catch (err) {
    logger.error('Create support ticket with attachments error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 👥 Team & Stats
app.get('/api/v1/team', async (req, res) => {
  try {
    // In a real app, you would fetch from database
    const team = [
      {
        name: 'John Doe',
        position: 'CEO',
        bio: 'Founder and CEO with 10+ years in blockchain technology.',
        image: 'https://example.com/team/john.jpg'
      },
      {
        name: 'Jane Smith',
        position: 'CTO',
        bio: 'Technology expert specializing in cryptocurrency systems.',
        image: 'https://example.com/team/jane.jpg'
      }
    ];
    
    res.status(200).json({
      success: true,
      team
    });
    
  } catch (err) {
    logger.error('Get team error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const tradesCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.status(200).json({
      success: true,
      stats: {
        users: usersCount,
        trades: tradesCount,
        volume: totalVolume[0]?.total || 0
      }
    });
    
  } catch (err) {
    logger.error('Get stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Resource not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

// Models (would normally be in separate files)
module.exports = {
  User: (mongoose) => {
    const userSchema = new mongoose.Schema({
      firstName: { type: String, trim: true },
      lastName: { type: String, trim: true },
      email: { type: String, unique: true, lowercase: true, trim: true },
      password: { type: String, select: false },
      walletAddress: { type: String, unique: true, sparse: true },
      isWalletUser: { type: Boolean, default: false },
      country: { type: String },
      currency: { type: String, default: 'USD' },
      balances: { type: Object, default: { BTC: 0, ETH: 0, USDT: 0 } },
      kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
      isVerified: { type: Boolean, default: false },
      isBlocked: { type: Boolean, default: false },
      status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
      notifications: { type: Boolean, default: true },
      twoFactor: { type: Boolean, default: false },
      language: { type: String, default: 'en' },
      theme: { type: String, default: 'light' },
      apiKey: { type: String, select: false },
      resetPasswordToken: { type: String, select: false },
      resetPasswordExpires: { type: Date, select: false },
      lastActive: { type: Date, default: Date.now }
    }, { timestamps: true });
    
    return mongoose.model('User', userSchema);
  },
  
  Trade: (mongoose) => {
    const tradeSchema = new mongoose.Schema({
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      type: { type: String, enum: ['buy', 'sell', 'exchange'], required: true },
      from: { type: String, required: true },
      to: { type: String, required: true },
      amount: { type: Number, required: true },
      rate: { type: Number, required: true },
      convertedAmount: { type: Number, required: true },
      status: { type: String, enum: ['pending', 'processing', 'completed', 'failed'], default: 'pending' },
      fee: { type: Number, default: 0 }
    }, { timestamps: true });
    
    return mongoose.model('Trade', tradeSchema);
  },
  
  Transaction: (mongoose) => {
    const transactionSchema = new mongoose.Schema({
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      type: { type: String, enum: ['deposit', 'withdrawal', 'buy', 'sell', 'exchange', 'transfer'], required: true },
      amount: { type: Number, required: true },
      currency: { type: String, required: true },
      address: { type: String },
      txHash: { type: String },
      status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
      details: { type: String }
    }, { timestamps: true });
    
    return mongoose.model('Transaction', transactionSchema);
  },
  
  SupportTicket: (mongoose) => {
    const supportTicketSchema = new mongoose.Schema({
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      name: { type: String, required: true },
      email: { type: String, required: true },
      subject: { type: String, required: true },
      message: { type: String, required: true },
      attachments: { type: [String] },
      responses: [{
        admin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        message: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
      }],
      status: { type: String, enum: ['open', 'in-progress', 'resolved', 'closed'], default: 'open' }
    }, { timestamps: true });
    
    return mongoose.model('SupportTicket', supportTicketSchema);
  },
  
  KYC: (mongoose) => {
    const kycSchema = new mongoose.Schema({
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      documentType: { type: String, required: true },
      documentNumber: { type: String, required: true },
      documentImages: { type: [String], required: true },
      status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
      reason: { type: String },
      reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
      reviewedAt: { type: Date }
    }, { timestamps: true });
    
    return mongoose.model('KYC', kycSchema);
  },
  
  Admin: (mongoose) => {
    const adminSchema = new mongoose.Schema({
      email: { type: String, unique: true, required: true },
      password: { type: String, required: true, select: false },
      role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
      lastLogin: { type: Date },
      isActive: { type: Boolean, default: true }
    }, { timestamps: true });
    
    return mongoose.model('Admin', adminSchema);
  },
  
  Coin: (mongoose) => {
    const coinSchema = new mongoose.Schema({
      symbol: { type: String, unique: true, required: true },
      name: { type: String, required: true },
      price: { type: Number, required: true },
      change24h: { type: Number, required: true },
      volume: { type: Number, required: true },
      marketCap: { type: Number },
      circulatingSupply: { type: Number },
      lastUpdated: { type: Date, default: Date.now }
    });
    
    return mongoose.model('Coin', coinSchema);
  }
};
