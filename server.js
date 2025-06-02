require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.%)';
const MONGO_URI = 'mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Configure rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(cors({
  origin: 'https://website-xi-ten-52.vercel.app',
  credentials: true
}));
app.use(helmet());
app.use(limiter);
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Database Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, select: false },
  walletAddress: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  kycStatus: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'not_submitted'], 
    default: 'not_submitted' 
  },
  kycDocuments: [{
    documentType: String,
    documentNumber: String,
    frontImage: String,
    backImage: String,
    selfie: String,
    submittedAt: { type: Date, default: Date.now }
  }],
  isAdmin: { type: Boolean, default: false },
  apiKey: { type: String, select: false },
  twoFactorEnabled: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  deletedAt: { type: Date }
}, { timestamps: true });

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ walletAddress: 1 }, { sparse: true });

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  convertedAmount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  txHash: { type: String },
  notes: { type: String }
}, { timestamps: true });

TradeSchema.index({ userId: 1 });
TradeSchema.index({ status: 1 });
TradeSchema.index({ createdAt: -1 });

const Trade = mongoose.model('Trade', TradeSchema);

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'trade', 'bonus', 'fee'], 
    required: true 
  },
  amount: { type: Number, required: true },
  coin: { type: String, required: true },
  address: { type: String },
  txHash: { type: String },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  relatedTrade: { type: mongoose.Schema.Types.ObjectId, ref: 'Trade' },
  notes: { type: String }
}, { timestamps: true });

TransactionSchema.index({ userId: 1 });
TransactionSchema.index({ type: 1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['open', 'in_progress', 'resolved', 'closed'], 
    default: 'open' 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'critical'], 
    default: 'medium' 
  },
  attachments: [String],
  responses: [{
    message: String,
    isAdmin: Boolean,
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

SupportTicketSchema.index({ userId: 1 });
SupportTicketSchema.index({ status: 1 });
SupportTicketSchema.index({ priority: 1 });
SupportTicketSchema.index({ createdAt: -1 });

const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

const AdminNotificationSchema = new mongoose.Schema({
  type: { 
    type: String, 
    enum: ['withdrawal', 'kyc', 'support', 'system', 'deposit'], 
    required: true 
  },
  message: { type: String, required: true },
  data: { type: mongoose.Schema.Types.Mixed },
  isRead: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

AdminNotificationSchema.index({ isRead: 1 });
AdminNotificationSchema.index({ createdAt: -1 });
AdminNotificationSchema.index({ type: 1 });

const AdminNotification = mongoose.model('AdminNotification', AdminNotificationSchema);

const SystemLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ipAddress: { type: String },
  userAgent: { type: String },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true });

SystemLogSchema.index({ action: 1 });
SystemLogSchema.index({ userId: 1 });
SystemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

// Configure file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Email configuration
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  },
  pool: true,
  rateLimit: 5, // max 5 messages per second
  maxConnections: 5
});

// Create default admin account on startup
async function initializeDatabase() {
  try {
    const adminExists = await User.findOne({ email: 'Admin@youngblood.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('17581758..', 12);
      await User.create({
        firstName: 'Admin',
        lastName: 'Youngblood',
        email: 'Admin@youngblood.com',
        password: hashedPassword,
        isAdmin: true,
        balance: 0,
        kycStatus: 'approved'
      });
      console.log('Default admin account created');
    }

    // Create indexes if they don't exist
    await User.init();
    await Trade.init();
    await Transaction.init();
    await SupportTicket.init();
    await AdminNotification.init();
    await SystemLog.init();

    console.log('Database initialization complete');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  }
}

initializeDatabase();

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('+apiKey');
    if (!user || user.deletedAt) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    console.error('Authentication error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const adminOnly = async (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server available at wss://website-backendd-1.onrender.com`);
});

const wss = new WebSocket.Server({ 
  server,
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    threshold: 1024,
    concurrencyLimit: 10
  }
});

const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');
  
  try {
    if (!token) {
      ws.close(1008, 'Authentication required');
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId.toString();
    
    // Close any existing connection for this user
    if (clients.has(userId)) {
      clients.get(userId).close();
    }

    clients.set(userId, ws);

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (err) {
        console.error('WebSocket message parsing error:', err);
      }
    });

    ws.on('close', () => {
      clients.delete(userId);
    });

    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      clients.delete(userId);
    });

    // Send initial connection confirmation
    ws.send(JSON.stringify({ 
      type: 'connection_established',
      timestamp: Date.now()
    }));

    console.log(`New WebSocket connection for user ${userId}`);
  } catch (err) {
    console.error('WebSocket authentication error:', err);
    ws.close(1008, 'Invalid token');
  }
});

// Heartbeat to keep connections alive
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    }
  });
}, 30000);

function sendWebSocketMessage(userId, type, data) {
  const ws = clients.get(userId.toString());
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({ type, data }));
    } catch (err) {
      console.error('WebSocket send error:', err);
    }
  }
}

// Broadcast to all admin clients
function broadcastToAdmins(type, data) {
  clients.forEach((ws, userId) => {
    if (ws.readyState === WebSocket.OPEN) {
      User.findById(userId).then(user => {
        if (user && user.isAdmin) {
          ws.send(JSON.stringify({ type, data }));
        }
      });
    }
  });
}

// Coin prices (mocked - would normally come from an external API)
const COIN_PRICES = {
  BTC: { price: 50000, change24h: 2.5 },
  ETH: { price: 3000, change24h: -1.2 },
  SOL: { price: 100, change24h: 5.7 },
  USDT: { price: 1, change24h: 0 },
  BNB: { price: 400, change24h: 3.1 },
  XRP: { price: 0.5, change24h: -0.8 },
  ADA: { price: 0.4, change24h: 1.2 },
  DOGE: { price: 0.1, change24h: 10.5 },
  DOT: { price: 7, change24h: -2.3 },
  UNI: { price: 10, change24h: 0.9 }
};

// Calculate conversion rate with a small spread
function getConversionRate(fromCoin, toCoin) {
  const fromPrice = COIN_PRICES[fromCoin]?.price || 0;
  const toPrice = COIN_PRICES[toCoin]?.price || 0;
  
  if (fromPrice === 0 || toPrice === 0) {
    throw new Error('Invalid coin pair');
  }
  
  // Add a 0.2% spread
  return (fromPrice / toPrice) * 0.998;
}

// Helper functions
async function notifyAdmin(type, message, data = {}) {
  try {
    const notification = await AdminNotification.create({ 
      type, 
      message, 
      data,
      userId: data.userId
    });
    
    broadcastToAdmins('admin_notification', {
      id: notification._id,
      type,
      message,
      data,
      createdAt: notification.createdAt
    });
    
    return notification;
  } catch (err) {
    console.error('Notification error:', err);
  }
}

async function logAction(action, userId, req, metadata = {}) {
  try {
    await SystemLog.create({
      action,
      userId,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata
    });
  } catch (err) {
    console.error('Logging error:', err);
  }
}

// Routes

// ======================
// 1. Authentication (8)
// ======================

app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    // Validation
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
      country,
      currency: currency || 'USD'
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    await logAction('user_signup', user._id, req);
    
    res.json({ 
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        kycStatus: user.kycStatus,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;
    
    if (!walletAddress || !signature || !email) {
      return res.status(400).json({ error: 'Wallet address, signature and email are required' });
    }
    
    // In production, verify the signature here
    const existingUser = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() }, 
        { walletAddress }
      ] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'Email or wallet already in use' });
    }
    
    const user = await User.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      walletAddress,
      country,
      currency: currency || 'USD'
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    await logAction('wallet_signup', user._id, req);
    
    res.json({ 
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        kycStatus: user.kycStatus,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Wallet signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    await logAction('user_login', user._id, req);
    
    res.json({ 
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        kycStatus: user.kycStatus,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ error: 'Wallet address and signature are required' });
    }
    
    // In production, verify the signature here
    const user = await User.findOne({ walletAddress });
    
    if (!user) {
      return res.status(401).json({ error: 'Wallet not registered' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    await logAction('wallet_login', user._id, req);
    
    res.json({ 
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        kycStatus: user.kycStatus,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    await logAction('user_logout', req.user._id, req);
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        isAdmin: req.user.isAdmin,
        walletAddress: req.user.walletAddress,
        country: req.user.country,
        currency: req.user.currency,
        createdAt: req.user.createdAt
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      // Don't reveal whether email exists
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }
    
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    await transporter.sendMail({
      from: '"Youngblood Support" <support@youngblood.com>',
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>Hello ${user.firstName},</p>
        <p>You requested to reset your password. Click the link below to proceed:</p>
        <p><a href="${resetUrl}">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });
    
    await logAction('password_reset_request', user._id, req);
    
    res.json({ message: 'If an account exists with this email, a reset link has been sent' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();
    
    await logAction('password_reset', user._id, req);
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Token expired' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(400).json({ error: 'Invalid token' });
    }
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================
// 2. User (10)
// ================

app.get('/api/v1/users/profile', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        walletAddress: req.user.walletAddress,
        country: req.user.country,
        currency: req.user.currency,
        createdAt: req.user.createdAt
      }
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/users/profile', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    
    if (firstName) req.user.firstName = firstName;
    if (lastName) req.user.lastName = lastName;
    if (country) req.user.country = country;
    if (currency) req.user.currency = currency;
    
    await req.user.save();
    
    await logAction('profile_update', req.user._id, req);
    
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        walletAddress: req.user.walletAddress,
        country: req.user.country,
        currency: req.user.currency
      }
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.fields([
  { name: 'frontImage', maxCount: 1 },
  { name: 'backImage', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    const files = req.files;
    
    if (!documentType || !documentNumber) {
      return res.status(400).json({ error: 'Document type and number are required' });
    }
    
    if (!files?.frontImage || !files?.backImage || !files?.selfie) {
      return res.status(400).json({ error: 'All document images are required' });
    }
    
    req.user.kycDocuments.push({
      documentType,
      documentNumber,
      frontImage: files.frontImage[0].path,
      backImage: files.backImage[0].path,
      selfie: files.selfie[0].path
    });
    
    req.user.kycStatus = 'pending';
    await req.user.save();
    
    await notifyAdmin('kyc', 'New KYC submission', {
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });
    
    await logAction('kyc_submission', req.user._id, req);
    
    res.json({ 
      message: 'KYC documents submitted successfully', 
      kycStatus: req.user.kycStatus 
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/users/kyc-status', authenticate, async (req, res) => {
  try {
    res.json({ 
      kycStatus: req.user.kycStatus,
      documents: req.user.kycDocuments.map(doc => ({
        documentType: doc.documentType,
        documentNumber: doc.documentNumber,
        submittedAt: doc.submittedAt
      }))
    });
  } catch (err) {
    console.error('KYC status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const apiKey = jwt.sign({ userId: req.user._id }, JWT_SECRET, { expiresIn: '365d' });
    req.user.apiKey = apiKey;
    await req.user.save();
    
    await logAction('api_key_generated', req.user._id, req);
    
    res.json({ apiKey });
  } catch (err) {
    console.error('API key generation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/v1/users/revoke-api-key', authenticate, async (req, res) => {
  try {
    req.user.apiKey = undefined;
    await req.user.save();
    
    await logAction('api_key_revoked', req.user._id, req);
    
    res.json({ message: 'API key revoked successfully' });
  } catch (err) {
    console.error('API key revocation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const userData = {
      profile: {
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        country: req.user.country,
        currency: req.user.currency,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      },
      balance: req.user.balance,
      kycStatus: req.user.kycStatus,
      kycDocuments: req.user.kycDocuments.map(doc => ({
        documentType: doc.documentType,
        submittedAt: doc.submittedAt
      }))
    };
    
    // In production, you would send this via email or generate a downloadable file
    await transporter.sendMail({
      from: '"Youngblood Support" <support@youngblood.com>',
      to: req.user.email,
      subject: 'Your Data Export',
      html: `
        <p>Hello ${req.user.firstName},</p>
        <p>Here is your requested data export:</p>
        <pre>${JSON.stringify(userData, null, 2)}</pre>
        <p>If you didn't request this, please contact our support team immediately.</p>
      `
    });
    
    await logAction('data_export', req.user._id, req);
    
    res.json({ message: 'Data export generated and sent to your email' });
  } catch (err) {
    console.error('Data export error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    
    const isMatch = await bcrypt.compare(currentPassword, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    req.user.password = hashedPassword;
    await req.user.save();
    
    await logAction('password_change', req.user._id, req);
    
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    
    const isMatch = await bcrypt.compare(password, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Password is incorrect' });
    }
    
    // Soft delete
    req.user.deletedAt = new Date();
    await req.user.save();
    
    await logAction('account_deletion', req.user._id, req);
    
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================
// 3. Wallet (8)
// ================

app.get('/api/v1/wallet/balance', authenticate, async (req, res) => {
  try {
    res.json({ balance: req.user.balance });
  } catch (err) {
    console.error('Get balance error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    // In production, this would generate a unique address per user
    res.json({ 
      address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
      memo: req.user._id.toString()
    });
  } catch (err) {
    console.error('Get deposit address error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/wallet/deposit', authenticate, async (req, res) => {
  try {
    const { amount, txHash } = req.body;
    
   if (!amount || isNaN(amount)) {  // Fixed this line
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    // In production, verify the txHash on the blockchain
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'deposit',
      amount,
      coin: 'BTC',
      txHash,
      status: 'pending'
    });
    
    await notifyAdmin('deposit', 'New deposit request', {
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`,
      amount,
      txHash
    });
    
    await logAction('deposit_request', req.user._id, req, { amount, txHash });
    
    res.json({ 
      message: 'Deposit request received', 
      transactionId: transaction._id 
    });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { amount, address } = req.body;
    
    if (!amount || isNaN(amount)) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    if (!address) {
      return res.status(400).json({ error: 'Address is required' });
    }
    
    if (req.user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // In production, validate the address format
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'withdrawal',
      amount,
      coin: 'BTC',
      address,
      status: 'pending'
    });
    
    await notifyAdmin('withdrawal', 'New withdrawal request', {
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`,
      amount,
      address
    });
    
    await logAction('withdrawal_request', req.user._id, req, { amount, address });
    
    res.json({ 
      message: 'Withdrawal request received', 
      transactionId: transaction._id 
    });
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/wallet/transactions', authenticate, async (req, res) => {
  try {
    const { type, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (type) query.type = type;
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .lean();
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/wallet/transaction/:id', authenticate, async (req, res) => {
  try {
    const transaction = await Transaction.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).lean();
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(transaction);
  } catch (err) {
    console.error('Get transaction error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/v1/wallet/transfer', authenticate, async (req, res) => {
  try {
    const { amount, recipientEmail } = req.body;
    
   if (!amount || isNaN(amount)) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    if (!recipientEmail) {
      return res.status(400).json({ error: 'Recipient email is required' });
    }
    
    if (req.user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const recipient = await User.findOne({ email: recipientEmail.toLowerCase() });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    if (recipient._id.equals(req.user._id)) {
      return res.status(400).json({ error: 'Cannot transfer to yourself' });
    }
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct from sender
      req.user.balance -= amount;
      await req.user.save({ session });
      
      // Add to recipient
      recipient.balance += amount;
      await recipient.save({ session });
      
      // Create transactions
      const senderTx = new Transaction({
        userId: req.user._id,
        type: 'withdrawal',
        amount,
        coin: 'BTC',
        status: 'completed',
        notes: `Transfer to ${recipient.email}`
      });
      
      const recipientTx = new Transaction({
        userId: recipient._id,
        type: 'deposit',
        amount,
        coin: 'BTC',
        status: 'completed',
        notes: `Transfer from ${req.user.email}`
      });
      
      await senderTx.save({ session });
      await recipientTx.save({ session });
      
      await session.commitTransaction();
      
      // Notify both users
      sendWebSocketMessage(req.user._id.toString(), 'balance_update', { balance: req.user.balance });
      sendWebSocketMessage(recipient._id.toString(), 'balance_update', { balance: recipient.balance });
      
      await logAction('wallet_transfer', req.user._id, req, { amount, recipient: recipient._id });
      
      res.json({ 
        message: 'Transfer completed successfully',
        newBalance: req.user.balance
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    console.error('Transfer error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// ================
// 4. Exchange (8)
// ================

app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = Object.keys(COIN_PRICES).map(symbol => ({
      symbol,
      name: getCoinName(symbol),
      price: COIN_PRICES[symbol].price,
      change24h: COIN_PRICES[symbol].change24h
    }));
    
    res.json(coins);
  } catch (err) {
    console.error('Get coins error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

function getCoinName(symbol) {
  const names = {
    BTC: 'Bitcoin',
    ETH: 'Ethereum',
    SOL: 'Solana',
    USDT: 'Tether',
    BNB: 'Binance Coin',
    XRP: 'Ripple',
    ADA: 'Cardano',
    DOGE: 'Dogecoin',
    DOT: 'Polkadot',
    UNI: 'Uniswap'
  };
  return names[symbol] || symbol;
}

app.get('/api/v1/exchange/rate/:from/:to', async (req, res) => {
  try {
    const { from, to } = req.params;
    
    if (!COIN_PRICES[from] || !COIN_PRICES[to]) {
      return res.status(400).json({ error: 'Invalid coin pair' });
    }
    
    const rate = getConversionRate(from, to);
    
    res.json({ 
      from, 
      to, 
      rate,
      timestamp: Date.now()
    });
  } catch (err) {
    console.error('Get rate error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount || isNaN(amount)) {
      return res.status(400).json({ error: 'Valid fromCoin, toCoin and amount are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    if (fromCoin === toCoin) {
      return res.status(400).json({ error: 'Cannot convert to the same coin' });
    }
    
    const rate = getConversionRate(fromCoin, toCoin);
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.001; // 0.1% fee
    
    if (fromCoin === 'USDT') {
      // Converting from USDT to another coin - need sufficient USDT balance
      if (req.user.balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
    } else {
      // For other coins, we'd need to check holdings in a real app
      return res.status(400).json({ error: 'Only USDT conversions are currently supported' });
    }
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct from balance
      req.user.balance -= amount;
      await req.user.save({ session });
      
      // Create trade record
      const trade = new Trade({
        userId: req.user._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        convertedAmount: convertedAmount - fee,
        fee,
        status: 'completed'
      });
      
      await trade.save({ session });
      
      // Create transaction records
      const outgoingTx = new Transaction({
        userId: req.user._id,
        type: 'trade',
        amount,
        coin: fromCoin,
        status: 'completed',
        relatedTrade: trade._id,
        notes: `Converted to ${toCoin}`
      });
      
      const incomingTx = new Transaction({
        userId: req.user._id,
        type: 'trade',
        amount: convertedAmount - fee,
        coin: toCoin,
        status: 'completed',
        relatedTrade: trade._id,
        notes: `Converted from ${fromCoin}`
      });
      
      const feeTx = new Transaction({
        userId: req.user._id,
        type: 'fee',
        amount: fee,
        coin: toCoin,
        status: 'completed',
        relatedTrade: trade._id,
        notes: `Conversion fee for ${fromCoin} to ${toCoin}`
      });
      
      await outgoingTx.save({ session });
      await incomingTx.save({ session });
      await feeTx.save({ session });
      
      await session.commitTransaction();
      
      // Update user's balance if converting to USDT
      if (toCoin === 'USDT') {
        req.user.balance += convertedAmount - fee;
        await req.user.save();
      }
      
      // Send WebSocket update
      sendWebSocketMessage(req.user._id.toString(), 'balance_update', { balance: req.user.balance });
      sendWebSocketMessage(req.user._id.toString(), 'trade_update', { tradeId: trade._id });
      
      await logAction('coin_conversion', req.user._id, req, { fromCoin, toCoin, amount });
      
      res.json({
        message: 'Conversion completed successfully',
        tradeId: trade._id,
        convertedAmount: convertedAmount - fee,
        fee,
        newBalance: req.user.balance
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    console.error('Conversion error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/exchange/trades', authenticate, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (status) query.status = status;
    
    const trades = await Trade.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .lean();
    
    const total = await Trade.countDocuments(query);
    
    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get trades error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/exchange/trade/:id', authenticate, async (req, res) => {
  try {
    const trade = await Trade.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).lean();
    
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found' });
    }
    
    res.json(trade);
  } catch (err) {
    console.error('Get trade error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
  try {
    const { limit = 10, page = 1 } = req.query;
    
    const history = await Transaction.find({ userId: req.user._id, type: 'trade' })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .populate('relatedTrade')
      .lean();
    
    const total = await Transaction.countDocuments({ userId: req.user._id, type: 'trade' });
    
    res.json({
      history,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get history error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/exchange/market-data', async (req, res) => {
  try {
    const marketData = Object.entries(COIN_PRICES).map(([symbol, data]) => ({
      symbol,
      name: getCoinName(symbol),
      price: data.price,
      change24h: data.change24h,
      volume: Math.random() * 1000000000, // Mock volume
      marketCap: Math.random() * 100000000000 // Mock market cap
    }));
    
    res.json(marketData);
  } catch (err) {
    console.error('Get market data error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================
// 5. Support (8)
// ================

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }
    
    const attachments = req.files?.map(file => file.path) || [];
    
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments
    });
    
    await notifyAdmin('support', 'New support ticket', {
      ticketId: ticket._id,
      subject,
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });
    
    await logAction('support_ticket_created', req.user._id, req, { ticketId: ticket._id });
    
    res.json({
      message: 'Support ticket created successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Create ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (status) query.status = status;
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .lean();
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/ticket/:id', authenticate, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).lean();
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json(ticket);
  } catch (err) {
    console.error('Get ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/support/ticket/:id/reply', authenticate, upload.array('attachments'), async (req, res) => {
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
    
    const attachments = req.files?.map(file => file.path) || [];
    
    ticket.responses.push({
      message,
      isAdmin: false,
      attachments
    });
    
    ticket.status = 'in_progress';
    await ticket.save();
    
    await notifyAdmin('support', 'New ticket reply', {
      ticketId: ticket._id,
      subject: ticket.subject,
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });
    
    await logAction('support_ticket_reply', req.user._id, req, { ticketId: ticket._id });
    
    res.json({
      message: 'Reply added successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'General',
        questions: [
          {
            question: 'What is Youngblood?',
            answer: 'Youngblood is a cryptocurrency trading platform that allows users to buy, sell, and convert various digital assets.'
          },
          {
            question: 'Is Youngblood regulated?',
            answer: 'Yes, we operate in full compliance with all applicable regulations in the jurisdictions we serve.'
          }
        ]
      },
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I create an account?',
            answer: 'Click the "Sign Up" button and follow the instructions to create your account.'
          },
          {
            question: 'What is KYC verification?',
            answer: 'KYC (Know Your Customer) is a process that requires you to verify your identity to use certain platform features.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'What cryptocurrencies can I trade?',
            answer: 'We support BTC, ETH, SOL, USDT, and several other major cryptocurrencies.'
          },
          {
            question: 'Are there trading fees?',
            answer: 'Yes, we charge a small fee of 0.1% per trade.'
          }
        ]
      }
    ];
    
    res.json(faqs);
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/support/contact', upload.array('attachments'), async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const attachments = req.files?.map(file => file.path) || [];
    
    const ticket = await SupportTicket.create({
      email,
      subject,
      message,
      attachments,
      notes: `From: ${name}`
    });
    
    await notifyAdmin('support', 'New contact form submission', {
      ticketId: ticket._id,
      subject,
      name,
      email
    });
    
    await logAction('contact_form_submission', null, req, { ticketId: ticket._id, email });
    
    res.json({
      message: 'Your message has been received',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Contact form error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/status', authenticate, async (req, res) => {
  try {
    const openTickets = await SupportTicket.countDocuments({ 
      userId: req.user._id,
      status: { $in: ['open', 'in_progress'] }
    });
    
    res.json({ openTickets });
  } catch (err) {
    console.error('Get support status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================
// 6. Admin (15)
// ================

app.get('/api/v1/admin/dashboard', authenticate, adminOnly, async (req, res) => {
  try {
    const [users, trades, deposits, withdrawals] = await Promise.all([
      User.countDocuments(),
      Trade.countDocuments(),
      Transaction.countDocuments({ type: 'deposit' }),
      Transaction.countDocuments({ type: 'withdrawal' })
    ]);
    
    const recentTrades = await Trade.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const pendingActions = await AdminNotification.countDocuments({ isRead: false });
    
    res.json({
      stats: {
        users,
        trades,
        deposits,
        withdrawals,
        pendingActions
      },
      recentTrades
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const { search, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .lean();
    
    const total = await User.countDocuments(query);
    
    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/user/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const [trades, transactions] = await Promise.all([
      Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10).lean(),
      Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10).lean()
    ]);
    
    res.json({
      user,
      trades,
      transactions
    });
  } catch (err) {
    console.error('Admin get user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/user/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const { balance, kycStatus, isAdmin } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (balance !== undefined) user.balance = parseFloat(balance);
    if (kycStatus !== undefined) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    
    await user.save();
    
    if (balance !== undefined) {
      sendWebSocketMessage(user._id.toString(), 'balance_update', { balance: user.balance });
    }
    
    await logAction('admin_user_update', req.user._id, req, { userId: user._id, updates: req.body });
    
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    console.error('Admin update user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/trades', authenticate, adminOnly, async (req, res) => {
  try {
    const { status, userId, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    if (userId) query.userId = userId;
    
    const trades = await Trade.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const total = await Trade.countDocuments(query);
    
    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get trades error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/transactions', authenticate, adminOnly, async (req, res) => {
  try {
    const { type, status, userId, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    if (userId) query.userId = userId;
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get transactions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/transaction/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    const transaction = await Transaction.findById(req.params.id)
      .populate('userId');
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    // Handle deposit completion
    if (transaction.type === 'deposit' && status === 'completed' && transaction.status === 'pending') {
      const session = await mongoose.startSession();
      session.startTransaction();
      
      try {
        transaction.userId.balance += transaction.amount;
        await transaction.userId.save({ session });
        
        transaction.status = 'completed';
        await transaction.save({ session });
        
        await session.commitTransaction();
        
        sendWebSocketMessage(transaction.userId._id.toString(), 'balance_update', { 
          balance: transaction.userId.balance 
        });
        
        await logAction('admin_deposit_approval', req.user._id, req, { 
          transactionId: transaction._id,
          userId: transaction.userId._id,
          amount: transaction.amount
        });
        
        return res.json({ message: 'Deposit approved successfully' });
      } catch (err) {
        await session.abortTransaction();
        throw err;
      } finally {
        session.endSession();
      }
    }
    
    // Handle withdrawal completion
    if (transaction.type === 'withdrawal' && status === 'completed' && transaction.status === 'pending') {
      transaction.status = 'completed';
      await transaction.save();
      
      await notifyAdmin('withdrawal', 'Withdrawal processed', {
        userId: transaction.userId._id,
        amount: transaction.amount,
        address: transaction.address
      });
      
      await logAction('admin_withdrawal_approval', req.user._id, req, { 
        transactionId: transaction._id,
        userId: transaction.userId._id,
        amount: transaction.amount
      });
      
      return res.json({ message: 'Withdrawal approved successfully' });
    }
    
    // For other cases
    transaction.status = status;
    await transaction.save();
    
    await logAction('admin_transaction_update', req.user._id, req, { 
      transactionId: transaction._id,
      status
    });
    
    res.json({ message: 'Transaction updated successfully' });
  } catch (err) {
    console.error('Admin update transaction error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/kyc', authenticate, adminOnly, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = { kycStatus: status || 'pending' };
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .lean();
    
    const total = await User.countDocuments(query);
    
    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get KYC error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/kyc/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const { status, reason } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.kycStatus = status;
    await user.save();
    
    // Notify user via email
    await transporter.sendMail({
      from: '"Youngblood KYC" <kyc@youngblood.com>',
      to: user.email,
      subject: `Your KYC verification is ${status}`,
      html: `
        <p>Hello ${user.firstName},</p>
        <p>Your KYC verification has been ${status}.</p>
        ${reason ? `<p>Reason: ${reason}</p>` : ''}
        <p>Thank you,</p>
        <p>The Youngblood Team</p>
      `
    });
    
    // Notify user via WebSocket
    sendWebSocketMessage(user._id.toString(), 'kyc_update', { status });
    
    await logAction('admin_kyc_update', req.user._id, req, { 
      userId: user._id,
      status,
      reason
    });
    
    res.json({ message: 'KYC status updated successfully' });
  } catch (err) {
    console.error('Admin update KYC error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/tickets', authenticate, adminOnly, async (req, res) => {
  try {
    const { status, priority, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    if (priority) query.priority = priority;
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get tickets error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/ticket/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email')
      .lean();
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json(ticket);
  } catch (err) {
    console.error('Admin get ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/admin/ticket/:id/reply', authenticate, adminOnly, upload.array('attachments'), async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    const attachments = req.files?.map(file => file.path) || [];
    
    ticket.responses.push({
      message,
      isAdmin: true,
      attachments
    });
    
    ticket.status = 'in_progress';
    await ticket.save();
    
    // Notify user if they have an active WebSocket connection
    if (ticket.userId) {
      sendWebSocketMessage(ticket.userId.toString(), 'support_ticket_update', {
        ticketId: ticket._id,
        hasNewReply: true
      });
    }
    
    await logAction('admin_ticket_reply', req.user._id, req, { ticketId: ticket._id });
    
    res.json({
      message: 'Reply added successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Admin reply to ticket error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/ticket/:id/status', authenticate, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    await logAction('admin_ticket_status_update', req.user._id, req, { 
      ticketId: ticket._id,
      status
    });
    
    res.json({ message: 'Ticket status updated successfully' });
  } catch (err) {
    console.error('Admin update ticket status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/notifications', authenticate, adminOnly, async (req, res) => {
  try {
    const { read, type, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (read !== undefined) query.isRead = read === 'true';
    if (type) query.type = type;
    
    const notifications = await AdminNotification.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const total = await AdminNotification.countDocuments(query);
    
    res.json({
      notifications,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get notifications error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/notification/:id/read', authenticate, adminOnly, async (req, res) => {
  try {
    const notification = await AdminNotification.findById(req.params.id);
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    notification.isRead = true;
    await notification.save();
    
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error('Admin mark notification as read error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/logs', authenticate, adminOnly, async (req, res) => {
  try {
    const { action, userId, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (action) query.action = action;
    if (userId) query.userId = userId;
    
    const logs = await SystemLog.find(query)
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .lean();
    
    const total = await SystemLog.countDocuments(query);
    
    res.json({
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Admin get logs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================
// 7. System (10)
// ================

app.get('/api/v1/system/stats', async (req, res) => {
  try {
    const [users, trades, volume] = await Promise.all([
      User.countDocuments(),
      Trade.countDocuments(),
      Transaction.aggregate([
        { $match: { type: 'trade', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);
    
    res.json({
      users,
      trades,
      volume: volume[0]?.total || 0
    });
  } catch (err) {
    console.error('Get system stats error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/system/status', async (req, res) => {
  try {
    // Check database connection
    const dbPing = await mongoose.connection.db.admin().ping();
    
    // Check email service
    let emailStatus = 'ok';
    try {
      await transporter.verify();
    } catch (err) {
      emailStatus = 'error';
    }
    
    res.json({
      status: 'operational',
      components: {
        database: dbPing.ok ? 'operational' : 'degraded',
        email: emailStatus,
        websocket: wss.clients.size
      },
      uptime: process.uptime(),
      timestamp: new Date()
    });
  } catch (err) {
    console.error('Get system status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
