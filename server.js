require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { ethers } = require('ethers');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

// MongoDB Connection
mongoose.connect('mongodb+srv://mosesmwainaina1994:<password>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
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
// Initialize default admin account
async function initializeDefaultAdmin() {
  try {
    const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com';
    const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@1234';
    
    const existingAdmin = await Admin.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      
      await Admin.create({
        email: adminEmail,
        password: hashedPassword,
        permissions: [
          'users:read', 'users:write', 'trades:read', 'trades:write',
          'transactions:read', 'transactions:write', 'kyc:verify',
          'support:manage', 'settings:manage', 'admin:manage'
        ]
      });
      
      console.log('Default admin account created');
    }
  } catch (err) {
    console.error('Error initializing default admin:', err);
  }
}

// Call the initialization function after DB connection
mongoose.connection.once('open', () => {
  initializeDefaultAdmin();
});

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '7d';
const COOKIE_EXPIRES = 7 * 24 * 60 * 60 * 1000; // 7 days

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  },
  tls: {
    rejectUnauthorized: false
  }
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, JPG and PDF are allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'] },
  lastName: { type: String, required: [true, 'Last name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address`
    }
  },
  password: { 
    type: String,
    select: false,
    minlength: [8, 'Password must be at least 8 characters'],
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character'
    }
  },
  walletAddress: { 
    type: String,
    unique: true,
    sparse: true,
    validate: {
      validator: function(v) {
        return ethers.utils.isAddress(v);
      },
      message: props => `${props.value} is not a valid Ethereum address`
    }
  },
  country: { type: String, required: [true, 'Country is required'] },
  currency: { type: String, default: 'USD', enum: ['USD', 'EUR', 'GBP', 'BTC', 'ETH'] },
  balance: {
    BTC: { type: Number, default: 0, min: 0 },
    ETH: { type: Number, default: 0, min: 0 },
    BNB: { type: Number, default: 0, min: 0 },
    USDT: { type: Number, default: 0, min: 0 },
    XRP: { type: Number, default: 0, min: 0 },
    SOL: { type: Number, default: 0, min: 0 },
    ADA: { type: Number, default: 0, min: 0 },
    DOGE: { type: Number, default: 0, min: 0 },
    DOT: { type: Number, default: 0, min: 0 },
    MATIC: { type: Number, default: 0, min: 0 }
  },
  kycStatus: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'not_submitted'], 
    default: 'not_submitted' 
  },
  kycDocuments: [{
    type: { type: String, enum: ['id', 'passport', 'driver_license', 'proof_of_address'] },
    url: { type: String },
    verified: { type: Boolean, default: false }
  }],
  apiKey: { type: String, select: false },
  isAdmin: { type: Boolean, default: false },
  settings: {
    theme: { type: String, default: 'light', enum: ['light', 'dark'] },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    twoFA: { type: Boolean, default: false },
    twoFASecret: { type: String, select: false }
  },
  resetPasswordToken: { type: String, select: false },
  resetPasswordExpires: { type: Date, select: false },
  lastLogin: { type: Date },
  loginAttempts: { type: Number, default: 0, select: false },
  lockUntil: { type: Date, select: false },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ walletAddress: 1 }, { unique: true, sparse: true });
UserSchema.index({ createdAt: -1 });

// Password hashing middleware
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Account lockout for failed login attempts
UserSchema.methods.incrementLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil > Date.now()) {
    throw new Error('Account is temporarily locked due to too many failed login attempts');
  }

  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5) {
    updates.$set = { lockUntil: Date.now() + 30 * 60 * 1000 }; // Lock for 30 minutes
  }

  await this.updateOne(updates);
};

UserSchema.methods.resetLoginAttempts = async function() {
  await this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 }
  });
};

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User ID is required'] 
  },
  type: { 
    type: String, 
    enum: ['buy', 'sell'], 
    required: [true, 'Trade type is required'] 
  },
  fromCoin: { 
    type: String, 
    required: [true, 'From coin is required'],
    enum: ['BTC', 'ETH', 'BNB', 'USDT', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC']
  },
  toCoin: { 
    type: String, 
    required: [true, 'To coin is required'],
    enum: ['BTC', 'ETH', 'BNB', 'USDT', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC']
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'],
    min: [0.00000001, 'Amount must be greater than 0']
  },
  rate: { 
    type: Number, 
    required: [true, 'Rate is required'],
    min: [0.00000001, 'Rate must be greater than 0']
  },
  fee: { 
    type: Number, 
    default: 0.001, // 0.1% fee
    min: 0
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  txHash: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
}, {
  timestamps: true
});

TradeSchema.index({ userId: 1 });
TradeSchema.index({ status: 1 });
TradeSchema.index({ createdAt: -1 });

const Trade = mongoose.model('Trade', TradeSchema);

const TransactionSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User ID is required'] 
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'trade', 'transfer', 'fee'], 
    required: [true, 'Transaction type is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'],
    min: [0.00000001, 'Amount must be greater than 0']
  },
  currency: { 
    type: String, 
    required: [true, 'Currency is required'],
    enum: ['BTC', 'ETH', 'BNB', 'USDT', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC']
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  txHash: { type: String },
  address: { type: String },
  metadata: { type: Object },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
}, {
  timestamps: true
});

TransactionSchema.index({ userId: 1 });
TransactionSchema.index({ type: 1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address`
    }
  },
  subject: { 
    type: String, 
    required: [true, 'Subject is required'],
    maxlength: [100, 'Subject cannot be longer than 100 characters']
  },
  message: { 
    type: String, 
    required: [true, 'Message is required'],
    maxlength: [2000, 'Message cannot be longer than 2000 characters']
  },
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
  attachments: [{
    url: { type: String },
    name: { type: String },
    size: { type: Number }
  }],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    attachments: [{
      url: { type: String },
      name: { type: String },
      size: { type: Number }
    }],
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date }
}, {
  timestamps: true
});

SupportTicketSchema.index({ userId: 1 });
SupportTicketSchema.index({ status: 1 });
SupportTicketSchema.index({ priority: 1 });
SupportTicketSchema.index({ createdAt: -1 });

const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

const SystemLogSchema = new mongoose.Schema({
  action: { 
    type: String, 
    required: [true, 'Action is required'],
    enum: [
      'user_signup', 'user_login', 'user_logout', 'password_reset', 'password_change',
      'trade_executed', 'deposit_initiated', 'withdrawal_requested', 'kyc_submitted',
      'admin_login', 'admin_action', 'system_event', 'api_call', 'security_event'
    ]
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ip: { type: String },
  userAgent: { type: String },
  metadata: { type: Object },
  createdAt: { type: Date, default: Date.now }
});

SystemLogSchema.index({ action: 1 });
SystemLogSchema.index({ userId: 1 });
SystemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

const AdminSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address`
    }
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    select: false,
    minlength: [12, 'Password must be at least 12 characters'],
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/.test(v);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character'
    }
  },
  permissions: { 
    type: [String], 
    default: [],
    enum: [
      'users:read', 'users:write', 'trades:read', 'trades:write',
      'transactions:read', 'transactions:write', 'kyc:verify',
      'support:manage', 'settings:manage', 'admin:manage'
    ]
  },
  lastLogin: { type: Date },
  loginAttempts: { type: Number, default: 0, select: false },
  lockUntil: { type: Date, select: false },
  createdAt: { type: Date, default: Date.now }
});

AdminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const Admin = mongoose.model('Admin', AdminSchema);

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection');
  
  // Authenticate via token
  const token = req.url.split('token=')[1];
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    ws.userId = decoded.id;
    ws.isAdmin = decoded.isAdmin;
    
    console.log(`Authenticated WebSocket connection for ${ws.isAdmin ? 'admin' : 'user'} ${ws.userId}`);
    
    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message);
        
        if (data.type === 'subscribe') {
          // Handle subscription to different channels
          ws.subscriptions = data.channels;
          console.log(`User ${ws.userId} subscribed to channels: ${data.channels.join(', ')}`);
        }
        
        // Add more message handlers as needed
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    });
    
    ws.on('close', () => {
      console.log(`WebSocket connection closed for ${ws.isAdmin ? 'admin' : 'user'} ${ws.userId}`);
    });
    
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
    });
  } catch (err) {
    console.error('WebSocket authentication error:', err);
    ws.close(1008, 'Invalid token');
  }
});

// Upgrade HTTP server to WebSocket
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  const pathname = request.url.split('?')[0];
  
  if (pathname === '/ws' || pathname === '/api/v1/admin/ws') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

// Broadcast functions for WebSocket
const broadcastToUser = (userId, event, data) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && 
        client.userId === userId && 
        (!client.subscriptions || client.subscriptions.includes(event.split(':')[0]))) {
      client.send(JSON.stringify({ event, data }));
    }
  });
};

const broadcastToAdmins = (event, data) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && 
        client.isAdmin && 
        (!client.subscriptions || client.subscriptions.includes(event.split(':')[0]))) {
      client.send(JSON.stringify({ event, data }));
    }
  });
};

// Coin prices (mocked as per requirements)
const COIN_PRICES = {
  BTC: 50000,
  ETH: 3000,
  BNB: 400,
  USDT: 1,
  XRP: 0.5,
  SOL: 100,
  ADA: 0.4,
  DOGE: 0.1,
  DOT: 6,
  MATIC: 1.5
};

const getConversionRate = (from, to) => {
  if (from === to) return 1;
  if (!COIN_PRICES[from] || !COIN_PRICES[to]) {
    throw new Error('Invalid coin symbols');
  }
  return COIN_PRICES[from] / COIN_PRICES[to];
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'AUTH_REQUIRED',
      message: 'Authentication required' 
    });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('+loginAttempts +lockUntil');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(403).json({ 
        success: false, 
        error: 'ACCOUNT_LOCKED',
        message: `Account is temporarily locked. Please try again in ${remainingTime} minutes.` 
      });
    }
    
    req.user = user;
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'TOKEN_EXPIRED',
        message: 'Session expired. Please log in again.' 
      });
    }
    
    return res.status(401).json({ 
      success: false, 
      error: 'INVALID_TOKEN',
      message: 'Invalid authentication token' 
    });
  }
};

const authenticateAdmin = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'AUTH_REQUIRED',
      message: 'Authentication required' 
    });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (!decoded.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        error: 'ADMIN_ACCESS_REQUIRED',
        message: 'Admin access required' 
      });
    }
    
    const admin = await Admin.findById(decoded.id).select('+loginAttempts +lockUntil');
    
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        error: 'ADMIN_NOT_FOUND',
        message: 'Admin not found' 
      });
    }
    
    // Check if admin account is locked
    if (admin.lockUntil && admin.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((admin.lockUntil - Date.now()) / 1000 / 60);
      return res.status(403).json({ 
        success: false, 
        error: 'ACCOUNT_LOCKED',
        message: `Admin account is temporarily locked. Please try again in ${remainingTime} minutes.` 
      });
    }
    
    req.admin = admin;
    next();
  } catch (err) {
    console.error('Admin authentication error:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'TOKEN_EXPIRED',
        message: 'Session expired. Please log in again.' 
      });
    }
    
    return res.status(401).json({ 
      success: false, 
      error: 'INVALID_TOKEN',
      message: 'Invalid authentication token' 
    });
  }
};

// Check permissions middleware
const checkPermissions = (requiredPermissions) => {
  return (req, res, next) => {
    if (!req.admin) {
      return res.status(403).json({ 
        success: false, 
        error: 'ADMIN_ACCESS_REQUIRED',
        message: 'Admin access required' 
      });
    }
    
    const hasPermission = requiredPermissions.every(perm => 
      req.admin.permissions.includes(perm)
    );
    
    if (!hasPermission) {
      return res.status(403).json({ 
        success: false, 
        error: 'PERMISSION_DENIED',
        message: 'You do not have permission to perform this action' 
      });
    }
    
    next();
  };
};

// API Endpoints Implementation

// Authentication & Sessions Endpoints
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    // Validate input
    if (!firstName || !lastName || !email || !password || !confirmPassword || !country) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'All fields are required' 
      });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        error: 'PASSWORD_MISMATCH',
        message: 'Passwords do not match' 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        error: 'USER_EXISTS',
        message: 'User already exists with this email' 
      });
    }
    
    // Create new user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency: currency || 'USD'
    });
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { 
      expiresIn: JWT_EXPIRES_IN 
    });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Log the signup
    await SystemLog.create({
      action: 'user_signup',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { method: 'email' }
    });
    
    // Broadcast new user to admin dashboard
    broadcastToAdmins('users:new', {
      userId: user._id,
      email: user.email,
      createdAt: user.createdAt
    });
    
    // Return response
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(el => el.message);
      return res.status(400).json({ 
        success: false, 
        error: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;
    
    // Validate input
    if (!walletAddress || !signature) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Wallet address and signature are required' 
      });
    }
    
    // Verify wallet address
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_ADDRESS',
        message: 'Invalid wallet address' 
      });
    }
    
    // Check if wallet is already registered
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        error: 'WALLET_REGISTERED',
        message: 'Wallet address is already registered' 
      });
    }
    
    // Verify signature (simplified for example)
    // In production, you would verify the signature against a nonce
    const signer = ethers.utils.verifyMessage('Welcome to our platform', signature);
    if (signer.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_SIGNATURE',
        message: 'Signature verification failed' 
      });
    }
    
    // Create new user
    const user = await User.create({
      firstName,
      lastName,
      email,
      walletAddress,
      country,
      currency: currency || 'USD'
    });
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { 
      expiresIn: JWT_EXPIRES_IN 
    });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Log the signup
    await SystemLog.create({
      action: 'user_signup',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { method: 'wallet' }
    });
    
    // Broadcast new user to admin dashboard
    broadcastToAdmins('users:new', {
      userId: user._id,
      walletAddress: user.walletAddress,
      createdAt: user.createdAt
    });
    
    // Return response
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Wallet signup error:', err);
    
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(el => el.message);
      return res.status(400).json({ 
        success: false, 
        error: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Email and password are required' 
      });
    }
    
    // Find user
    const user = await User.findOne({ email }).select('+password +loginAttempts +lockUntil');
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password' 
      });
    }
    
    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(403).json({ 
        success: false, 
        error: 'ACCOUNT_LOCKED',
        message: `Account is temporarily locked. Please try again in ${remainingTime} minutes.` 
      });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Increment failed login attempts
      await user.incrementLoginAttempts();
      
      const attemptsLeft = 5 - (user.loginAttempts + 1);
      
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_CREDENTIALS',
        message: `Invalid email or password. ${attemptsLeft > 0 ? `${attemptsLeft} attempts left` : 'Account will be locked after too many failed attempts'}` 
      });
    }
    
    // Reset login attempts on successful login
    await user.resetLoginAttempts();
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { 
      expiresIn: JWT_EXPIRES_IN 
    });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Log the login
    await SystemLog.create({
      action: 'user_login',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { method: 'email' }
    });
    
    // Return response
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // Clear cookie
    res.clearCookie('token');
    
    // Log the logout
    await SystemLog.create({
      action: 'user_logout',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        error: 'TOKEN_REQUIRED',
        message: 'No token provided' 
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    res.status(200).json({ 
      success: true, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Token verification error:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'TOKEN_EXPIRED',
        message: 'Token expired' 
      });
    }
    
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_TOKEN',
        message: 'Invalid token' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/auth/status', authenticate, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      isAuthenticated: true, 
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings
      }
    });
  } catch (err) {
    console.error('Auth status error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/auth/check', authenticate, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      message: 'Session is valid' 
    });
  } catch (err) {
    console.error('Session check error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: 'EMAIL_REQUIRED',
        message: 'Email is required' 
      });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if the email exists
      return res.status(200).json({ 
        success: true, 
        message: 'If an account exists with this email, a reset link has been sent' 
      });
    }
    
    // Generate reset token (expires in 1 hour)
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();
    
    // Send email with reset link
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      to: user.email,
      from: 'noreply@yourdomain.com',
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your account.</p>
        <p>Click this link to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Log the password reset request
    await SystemLog.create({
      action: 'password_reset',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'If an account exists with this email, a reset link has been sent' 
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({ 
        success: false, 
        error: 'ADDRESS_REQUIRED',
        message: 'Wallet address is required' 
      });
    }
    
    // Verify wallet address
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_ADDRESS',
        message: 'Invalid wallet address' 
      });
    }
    
    // Generate a random nonce and store it (in production, you'd store this in Redis with expiration)
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // In production, you would store this nonce associated with the wallet address
    // For this example, we'll just return it
    
    res.status(200).json({ 
      success: true, 
      nonce 
    });
  } catch (err) {
    console.error('Nonce generation error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Wallet address and signature are required' 
      });
    }
    
    // Verify wallet address
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_ADDRESS',
        message: 'Invalid wallet address' 
      });
    }
    
    // Find user by wallet address
    const user = await User.findOne({ walletAddress }).select('+loginAttempts +lockUntil');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'WALLET_NOT_REGISTERED',
        message: 'Wallet address not registered' 
      });
    }
    
    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(403).json({ 
        success: false, 
        error: 'ACCOUNT_LOCKED',
        message: `Account is temporarily locked. Please try again in ${remainingTime} minutes.` 
      });
    }
    
    // Verify signature (in production, you would verify against the stored nonce)
    const signer = ethers.utils.verifyMessage('Welcome to our platform', signature);
    if (signer.toLowerCase() !== walletAddress.toLowerCase()) {
      // Increment failed login attempts
      await user.incrementLoginAttempts();
      
      const attemptsLeft = 5 - (user.loginAttempts + 1);
      
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_SIGNATURE',
        message: `Invalid signature. ${attemptsLeft > 0 ? `${attemptsLeft} attempts left` : 'Account will be locked after too many failed attempts'}` 
      });
    }
    
    // Reset login attempts on successful login
    await user.resetLoginAttempts();
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { 
      expiresIn: JWT_EXPIRES_IN 
    });
    
    // Set cookie
    res.cookie('token', token, {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Log the login
    await SystemLog.create({
      action: 'user_login',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { method: 'wallet' }
    });
    
    // Return response
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// User Management Endpoints
app.get('/users/me', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings
      }
    });
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      settings: req.user.settings
    });
  } catch (err) {
    console.error('Get user settings error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { theme, notifications, twoFA } = req.body;
    
    const updates = {};
    if (theme) updates['settings.theme'] = theme;
    if (notifications) {
      if (notifications.email !== undefined) updates['settings.notifications.email'] = notifications.email;
      if (notifications.push !== undefined) updates['settings.notifications.push'] = notifications.push;
    }
    if (twoFA !== undefined) updates['settings.twoFA'] = twoFA;
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true }
    );
    
    // Log settings update
    await SystemLog.create({
      action: 'user_settings_update',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { updates }
    });
    
    // Broadcast settings change to user's active sessions
    broadcastToUser(req.user._id, 'settings:updated', user.settings);
    
    res.status(200).json({
      success: true,
      settings: user.settings
    });
  } catch (err) {
    console.error('Update user settings error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.patch('/api/v1/auth/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Current and new password are required' 
      });
    }
    
    const user = await User.findById(req.user._id).select('+password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_PASSWORD',
        message: 'Current password is incorrect' 
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    user.password = hashedPassword;
    await user.save();
    
    // Log password change
    await SystemLog.create({
      action: 'password_change',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    // Invalidate all other sessions (in production, you might track sessions and invalidate them)
    broadcastToUser(req.user._id, 'auth:password_changed', { timestamp: new Date() });
    
    res.status(200).json({ 
      success: true, 
      message: 'Password updated successfully' 
    });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.array('documents', 5), async (req, res) => {
  try {
    const { documentType } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'NO_DOCUMENTS',
        message: 'No documents uploaded' 
      });
    }
    
    if (!documentType) {
      return res.status(400).json({ 
        success: false, 
        error: 'DOCUMENT_TYPE_REQUIRED',
        message: 'Document type is required' 
      });
    }
    
    const documents = files.map(file => ({
      type: documentType,
      url: `/uploads/${file.filename}`,
      name: file.originalname,
      size: file.size
    }));
    
    await User.findByIdAndUpdate(req.user._id, {
      kycStatus: 'pending',
      $push: { kycDocuments: { $each: documents } }
    });
    
    // Log KYC submission
    await SystemLog.create({
      action: 'kyc_submitted',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { documentCount: files.length }
    });
    
    // Notify admin about new KYC submission
    broadcastToAdmins('kyc:new', {
      userId: req.user._id,
      documentCount: files.length,
      submittedAt: new Date()
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'KYC documents submitted for review' 
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    
    // Clean up uploaded files if there was an error
    if (req.files) {
      req.files.forEach(file => {
        try {
          fs.unlinkSync(file.path);
        } catch (unlinkErr) {
          console.error('Error cleaning up uploaded file:', unlinkErr);
        }
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(32).toString('hex');
    
    await User.findByIdAndUpdate(req.user._id, { apiKey });
    
    // Log API key generation
    await SystemLog.create({
      action: 'api_key_generated',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({ 
      success: true, 
      apiKey 
    });
  } catch (err) {
    console.error('Generate API key error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Get additional user data
    const trades = await Trade.find({ userId: user._id }).limit(100);
    const transactions = await Transaction.find({ userId: user._id }).limit(100);
    const tickets = await SupportTicket.find({ userId: user._id }).limit(100);
    
    // Create export data
    const exportData = {
      user: user.toObject(),
      trades,
      transactions,
      tickets
    };
    
    // Create a unique filename
    const filename = `user-export-${user._id}-${Date.now()}.json`;
    const filePath = path.join(__dirname, 'exports', filename);
    
    // Ensure exports directory exists
    if (!fs.existsSync(path.join(__dirname, 'exports'))) {
      fs.mkdirSync(path.join(__dirname, 'exports'));
    }
    
    // Write export file
    fs.writeFileSync(filePath, JSON.stringify(exportData, null, 2));
    
    // Send email with download link
    const downloadUrl = `https://website-xi-ten-52.vercel.app/download-export?token=${encodeURIComponent(jwt.sign({ file: filename, userId: user._id }, JWT_SECRET, { expiresIn: '1h' }))}`;
    
    const mailOptions = {
      to: user.email,
      from: 'noreply@yourdomain.com',
      subject: 'Your Data Export',
      html: `
        <p>Your data export is ready.</p>
        <p>Click this link to download your data:</p>
        <a href="${downloadUrl}">Download Data Export</a>
        <p>This link will expire in 1 hour.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Log data export
    await SystemLog.create({
      action: 'data_export',
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Data export initiated. You will receive an email with your data shortly.' 
    });
  } catch (err) {
    console.error('Export data error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ 
        success: false, 
        error: 'PASSWORD_REQUIRED',
        message: 'Password is required' 
      });
    }
    
    const user = await User.findById(req.user._id).select('+password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_PASSWORD',
        message: 'Password is incorrect' 
      });
    }
    
    // Anonymize user data instead of deleting for compliance
    const anonymizedEmail = `deleted-${crypto.randomBytes(8).toString('hex')}@deleted.com`;
    const anonymizedWallet = `0x${crypto.randomBytes(20).toString('hex')}`;
    
    await User.findByIdAndUpdate(req.user._id, {
      email: anonymizedEmail,
      walletAddress: anonymizedWallet,
      firstName: 'Deleted',
      lastName: 'User',
      password: crypto.randomBytes(32).toString('hex'), // Invalidate password
      isActive: false,
      deletedAt: new Date()
    });
    
    // Log account deletion
    await SystemLog.create({
      action: 'account_deleted',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    // Notify admin about account deletion
    broadcastToAdmins('users:deleted', {
      userId: req.user._id,
      deletedAt: new Date()
    });
    
    // Clear cookie
    res.clearCookie('token');
    
    res.status(200).json({ 
      success: true, 
      message: 'Account deleted successfully' 
    });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Admin Endpoints
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Email and password are required' 
      });
    }
    
    const admin = await Admin.findOne({ email }).select('+password +loginAttempts +lockUntil');
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password' 
      });
    }
    
    // Check if account is locked
    if (admin.lockUntil && admin.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((admin.lockUntil - Date.now()) / 1000 / 60);
      return res.status(403).json({ 
        success: false, 
        error: 'ACCOUNT_LOCKED',
        message: `Admin account is temporarily locked. Please try again in ${remainingTime} minutes.` 
      });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      // Increment failed login attempts
      admin.loginAttempts += 1;
      
      if (admin.loginAttempts >= 5) {
        admin.lockUntil = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
      }
      
      await admin.save();
      
      const attemptsLeft = 5 - admin.loginAttempts;
      
      return res.status(401).json({ 
        success: false, 
        error: 'INVALID_CREDENTIALS',
        message: `Invalid email or password. ${attemptsLeft > 0 ? `${attemptsLeft} attempts left` : 'Account will be locked after too many failed attempts'}` 
      });
    }
    
    // Reset login attempts
    admin.loginAttempts = 0;
    admin.lockUntil = undefined;
    admin.lastLogin = new Date();
    await admin.save();
    
    const token = jwt.sign({ id: admin._id, isAdmin: true }, JWT_SECRET, { 
      expiresIn: JWT_EXPIRES_IN 
    });
    
    res.cookie('token', token, {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    // Log admin login
    await SystemLog.create({
      action: 'admin_login',
      adminId: admin._id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        permissions: admin.permissions
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      admin: {
        id: req.admin._id,
        email: req.admin.email,
        permissions: req.admin.permissions
      }
    });
  } catch (err) {
    console.error('Admin verify error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, checkPermissions(['users:read', 'trades:read', 'transactions:read']), async (req, res) => {
  try {
    const [totalUsers, newUsersToday, pendingKYC, totalTrades, completedTrades, totalVolume, openTickets] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } }),
      User.countDocuments({ kycStatus: 'pending' }),
      Trade.countDocuments(),
      Trade.countDocuments({ status: 'completed' }),
      Trade.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } } }
      ]),
      SupportTicket.countDocuments({ status: 'open' })
    ]);
    
    res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        newUsersToday,
        pendingKYC,
        totalTrades,
        completedTrades,
        totalVolume: totalVolume[0]?.total || 0,
        openTickets
      }
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, checkPermissions(['users:read']), async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', sort = '-createdAt', status } = req.query;
    
    const query = {};
    
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status) {
      if (status === 'active') {
        query.isActive = true;
      } else if (status === 'inactive') {
        query.isActive = false;
      } else if (status === 'kyc_pending') {
        query.kycStatus = 'pending';
      }
    }
    
    const users = await User.find(query)
      .select('-password')
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();
    
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      success: true,
      users,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('Admin get users error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, checkPermissions(['users:read']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .lean();
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    const [trades, transactions, tickets] = await Promise.all([
      Trade.find({ userId: user._id })
        .sort('-createdAt')
        .limit(10)
        .lean(),
      Transaction.find({ userId: user._id })
        .sort('-createdAt')
        .limit(10)
        .lean(),
      SupportTicket.find({ userId: user._id })
        .sort('-createdAt')
        .limit(5)
        .lean()
    ]);
    
    res.status(200).json({
      success: true,
      user,
      recentActivity: {
        trades,
        transactions,
        tickets
      }
    });
  } catch (err) {
    console.error('Admin get user error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, checkPermissions(['users:write']), async (req, res) => {
  try {
    const { kycStatus, isActive, balanceAdjustments } = req.body;
    
    const updates = {};
    if (kycStatus) updates.kycStatus = kycStatus;
    if (isActive !== undefined) updates.isActive = isActive;
    
    // Apply balance adjustments if provided
    if (balanceAdjustments && typeof balanceAdjustments === 'object') {
      const validCoins = ['BTC', 'ETH', 'BNB', 'USDT', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC'];
      
      for (const [coin, adjustment] of Object.entries(balanceAdjustments)) {
        if (validCoins.includes(coin) && typeof adjustment === 'number') {
          updates[`balance.${coin}`] = adjustment;
        }
      }
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Log admin action
    await SystemLog.create({
      action: 'admin_user_update',
      adminId: req.admin._id,
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { updates }
    });
    
    // Notify user about changes if their balance was adjusted
    if (balanceAdjustments) {
      broadcastToUser(user._id, 'balance:adjusted', {
        adjustments: balanceAdjustments,
        updatedAt: new Date()
      });
    }
    
    res.status(200).json({
      success: true,
      user
    });
  } catch (err) {
    console.error('Admin update user error:', err);
    
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(el => el.message);
      return res.status(400).json({ 
        success: false, 
        error: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, checkPermissions(['trades:read']), async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status, sort = '-createdAt' } = req.query;
    
    const query = {};
    
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();
    
    const total = await Trade.countDocuments(query);
    
    res.status(200).json({
      success: true,
      trades,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('Admin get trades error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, checkPermissions(['transactions:read']), async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status, sort = '-createdAt' } = req.query;
    
    const query = {};
    
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();
    
    const total = await Transaction.countDocuments(query);
    
    res.status(200).json({
      success: true,
      transactions,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('Admin get transactions error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, checkPermissions(['support:manage']), async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email')
      .populate('responses.userId', 'firstName lastName email')
      .lean();
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false, 
        error: 'TICKET_NOT_FOUND',
        message: 'Ticket not found' 
      });
    }
    
    res.status(200).json({
      success: true,
      ticket
    });
  } catch (err) {
    console.error('Admin get ticket error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, checkPermissions(['support:manage']), async (req, res) => {
  try {
    const { status, priority, response } = req.body;
    
    const updates = {};
    if (status) updates.status = status;
    if (priority) updates.priority = priority;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ 
        success: false, 
        error: 'TICKET_NOT_FOUND',
        message: 'Ticket not found' 
      });
    }
    
    if (response) {
      ticket.responses.push({
        userId: req.admin._id,
        message: response,
        isAdmin: true
      });
    }
    
    Object.assign(ticket, updates);
    ticket.updatedAt = new Date();
    await ticket.save();
    
    // Log admin action
    await SystemLog.create({
      action: 'admin_ticket_update',
      adminId: req.admin._id,
      ticketId: ticket._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { updates }
    });
    
    // Notify user about ticket update
    if (ticket.userId) {
      broadcastToUser(ticket.userId, 'ticket:updated', {
        ticketId: ticket._id,
        status: ticket.status,
        updatedAt: ticket.updatedAt
      });
    }
    
    res.status(200).json({
      success: true,
      ticket
    });
  } catch (err) {
    console.error('Admin update ticket error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/kyc/:id', authenticateAdmin, checkPermissions(['kyc:verify']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('kycStatus kycDocuments firstName lastName email')
      .lean();
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    res.status(200).json({
      success: true,
      kycData: {
        status: user.kycStatus,
        documents: user.kycDocuments,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });
  } catch (err) {
    console.error('Admin get KYC error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, checkPermissions(['kyc:verify']), async (req, res) => {
  try {
    const { status, documentVerifications } = req.body;
    
    if (!status || !['approved', 'rejected', 'pending'].includes(status)) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_STATUS',
        message: 'Valid KYC status is required' 
      });
    }
    
    const updates = {
      kycStatus: status
    };
    
    if (documentVerifications && Array.isArray(documentVerifications)) {
      updates.kycDocuments = documentVerifications;
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true }
    ).select('kycStatus kycDocuments firstName lastName email');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Log admin action
    await SystemLog.create({
      action: 'admin_kyc_update',
      adminId: req.admin._id,
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { status }
    });
    
    // Notify user about KYC status change
    broadcastToUser(user._id, 'kyc:status_changed', {
      status: user.kycStatus,
      updatedAt: new Date()
    });
    
    res.status(200).json({
      success: true,
      kycData: {
        status: user.kycStatus,
        documents: user.kycDocuments,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });
  } catch (err) {
    console.error('Admin update KYC error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, checkPermissions(['admin:manage']), async (req, res) => {
  try {
    const { page = 1, limit = 50, action, userId, adminId, sort = '-createdAt' } = req.query;
    
    const query = {};
    
    if (action) query.action = action;
    if (userId) query.userId = userId;
    if (adminId) query.adminId = adminId;
    
    const logs = await SystemLog.find(query)
      .populate('userId', 'firstName lastName email')
      .populate('adminId', 'email')
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();
    
    const total = await SystemLog.countDocuments(query);
    
    res.status(200).json({
      success: true,
      logs,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('Admin get logs error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, checkPermissions(['admin:manage']), async (req, res) => {
  try {
    const { title, message, type = 'info', target = 'all' } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Title and message are required' 
      });
    }
    
    const notification = {
      id: uuidv4(),
      title,
      message,
      type,
      timestamp: new Date()
    };
    
    // Broadcast to all connected clients
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        if (target === 'all' || 
            (target === 'admins' && client.isAdmin) || 
            (target === 'users' && !client.isAdmin)) {
          client.send(JSON.stringify({
            event: 'admin:broadcast',
            data: notification
          }));
        }
      }
    });
    
    // Log broadcast
    await SystemLog.create({
      action: 'admin_broadcast',
      adminId: req.admin._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { title, type, target }
    });
    
    res.status(200).json({
      success: true,
      notification
    });
  } catch (err) {
    console.error('Admin broadcast error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/admin/settings', authenticateAdmin, checkPermissions(['settings:manage']), async (req, res) => {
  try {
    // In a real app, you would get these from a database
    const settings = {
      tradeFee: 0.001, // 0.1%
      withdrawalFee: 0.005, // 0.5%
      minWithdrawal: {
        BTC: 0.001,
        ETH: 0.01,
        USDT: 10
      },
      maintenanceMode: false,
      registrationEnabled: true,
      kycRequired: false
    };
    
    res.status(200).json({
      success: true,
      settings
    });
  } catch (err) {
    console.error('Admin get settings error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/admin/settings', authenticateAdmin, checkPermissions(['settings:manage']), async (req, res) => {
  try {
    const { settings } = req.body;
    
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_SETTINGS',
        message: 'Valid settings object is required' 
      });
    }
    
    // In a real app, you would save these to a database
    const updatedSettings = {
      tradeFee: settings.tradeFee || 0.001,
      withdrawalFee: settings.withdrawalFee || 0.005,
      minWithdrawal: settings.minWithdrawal || {
        BTC: 0.001,
        ETH: 0.01,
        USDT: 10
      },
      maintenanceMode: settings.maintenanceMode !== undefined ? settings.maintenanceMode : false,
      registrationEnabled: settings.registrationEnabled !== undefined ? settings.registrationEnabled : true,
      kycRequired: settings.kycRequired !== undefined ? settings.kycRequired : false
    };
    
    // Broadcast settings change to all admins
    broadcastToAdmins('settings:updated', updatedSettings);
    
    // Log settings update
    await SystemLog.create({
      action: 'admin_settings_update',
      adminId: req.admin._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { settings: updatedSettings }
    });
    
    res.status(200).json({
      success: true,
      settings: updatedSettings
    });
  } catch (err) {
    console.error('Admin update settings error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Exchange & Market Endpoints
app.get('/exchange/coins', async (req, res) => {
  try {
    const coins = [
      { symbol: 'BTC', name: 'Bitcoin', price: COIN_PRICES.BTC },
      { symbol: 'ETH', name: 'Ethereum', price: COIN_PRICES.ETH },
      { symbol: 'BNB', name: 'Binance Coin', price: COIN_PRICES.BNB },
      { symbol: 'USDT', name: 'Tether', price: COIN_PRICES.USDT },
      { symbol: 'XRP', name: 'Ripple', price: COIN_PRICES.XRP },
      { symbol: 'SOL', name: 'Solana', price: COIN_PRICES.SOL },
      { symbol: 'ADA', name: 'Cardano', price: COIN_PRICES.ADA },
      { symbol: 'DOGE', name: 'Dogecoin', price: COIN_PRICES.DOGE },
      { symbol: 'DOT', name: 'Polkadot', price: COIN_PRICES.DOT },
      { symbol: 'MATIC', name: 'Polygon', price: COIN_PRICES.MATIC }
    ];
    
    res.status(200).json({
      success: true,
      coins
    });
  } catch (err) {
    console.error('Get coins error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/exchange/rates', async (req, res) => {
  try {
    const rates = {};
    const coins = ['BTC', 'ETH', 'BNB', 'USDT', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC'];
    
    for (const from of coins) {
      rates[from] = {};
      for (const to of coins) {
        rates[from][to] = getConversionRate(from, to);
      }
    }
    
    res.status(200).json({
      success: true,
      rates
    });
  } catch (err) {
    console.error('Get rates error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_PARAMS',
        message: 'From and to parameters are required' 
      });
    }
    
    const rate = getConversionRate(from.toUpperCase(), to.toUpperCase());
    
    res.status(200).json({
      success: true,
      from,
      to,
      rate
    });
  } catch (err) {
    console.error('Get rate error:', err);
    
    if (err.message === 'Invalid coin symbols') {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_COINS',
        message: 'Invalid coin symbols provided' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/exchange/convert', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'From, to and amount are required' 
      });
    }
    
    if (from === to) {
      return res.status(400).json({ 
        success: false, 
        error: 'SAME_CURRENCY',
        message: 'Cannot convert between the same currency' 
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_AMOUNT',
        message: 'Amount must be greater than 0' 
      });
    }
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Check if user has sufficient balance
    if (user.balance[from] < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'INSUFFICIENT_BALANCE',
        message: `Insufficient ${from} balance` 
      });
    }
    
    // Get conversion rate
    const rate = getConversionRate(from, to);
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.001; // 0.1% fee
    const finalAmount = convertedAmount - fee;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update user balances
      user.balance[from] -= amount;
      user.balance[to] += finalAmount;
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        userId: user._id,
        type: 'buy',
        fromCoin: from,
        toCoin: to,
        amount,
        rate,
        fee,
        status: 'completed'
      }], { session });
      
      // Create transaction records
      await Transaction.create([
        {
          userId: user._id,
          type: 'trade',
          amount: -amount,
          currency: from,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Converted ${amount} ${from} to ${to}`
          }
        },
        {
          userId: user._id,
          type: 'trade',
          amount: finalAmount,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Received from ${amount} ${from} conversion`
          }
        },
        {
          userId: user._id,
          type: 'fee',
          amount: -fee,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Conversion fee for ${amount} ${from} to ${to}`
          }
        }
      ], { session });
      
      // Commit transaction
      await session.commitTransaction();
      session.endSession();
      
      // Log the trade
      await SystemLog.create({
        action: 'trade_executed',
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: {
          from,
          to,
          amount,
          rate,
          fee
        }
      });
      
      // Broadcast balance update to user
      broadcastToUser(user._id, 'balance:updated', {
        [from]: user.balance[from],
        [to]: user.balance[to],
        updatedAt: new Date()
      });
      
      // Notify admin about new trade
      broadcastToAdmins('trades:new', {
        userId: user._id,
        from,
        to,
        amount,
        rate,
        fee,
        timestamp: new Date()
      });
      
      res.status(200).json({
        success: true,
        from,
        to,
        amount,
        rate,
        fee,
        finalAmount,
        newBalances: {
          [from]: user.balance[from],
          [to]: user.balance[to]
        }
      });
    } catch (err) {
      // If any error occurs, abort the transaction
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Convert error:', err);
    
    if (err.message === 'Invalid coin symbols') {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_COINS',
        message: 'Invalid coin symbols provided' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/exchange/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    
    const query = { userId: req.user._id };
    if (type) query.type = type;
    
    const trades = await Trade.find(query)
      .sort('-createdAt')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();
    
    const total = await Trade.countDocuments(query);
    
    res.status(200).json({
      success: true,
      trades,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/market/data', async (req, res) => {
  try {
    const marketData = [
      { symbol: 'BTC', name: 'Bitcoin', price: COIN_PRICES.BTC, change24h: 2.5 },
      { symbol: 'ETH', name: 'Ethereum', price: COIN_PRICES.ETH, change24h: -1.2 },
      { symbol: 'BNB', name: 'Binance Coin', price: COIN_PRICES.BNB, change24h: 0.8 },
      { symbol: 'USDT', name: 'Tether', price: COIN_PRICES.USDT, change24h: 0.0 },
      { symbol: 'XRP', name: 'Ripple', price: COIN_PRICES.XRP, change24h: 3.1 },
      { symbol: 'SOL', name: 'Solana', price: COIN_PRICES.SOL, change24h: 5.7 },
      { symbol: 'ADA', name: 'Cardano', price: COIN_PRICES.ADA, change24h: -2.3 },
      { symbol: 'DOGE', name: 'Dogecoin', price: COIN_PRICES.DOGE, change24h: 10.5 },
      { symbol: 'DOT', name: 'Polkadot', price: COIN_PRICES.DOT, change24h: -0.5 },
      { symbol: 'MATIC', name: 'Polygon', price: COIN_PRICES.MATIC, change24h: 1.8 }
    ];
    
    res.status(200).json({
      success: true,
      marketData
    });
  } catch (err) {
    console.error('Get market data error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/market/detailed', async (req, res) => {
  try {
    const detailedData = [
      { 
        symbol: 'BTC', 
        name: 'Bitcoin', 
        price: COIN_PRICES.BTC, 
        change24h: 2.5,
        high24h: COIN_PRICES.BTC * 1.03,
        low24h: COIN_PRICES.BTC * 0.98,
        volume: 2500000000,
        marketCap: 950000000000
      },
      { 
        symbol: 'ETH', 
        name: 'Ethereum', 
        price: COIN_PRICES.ETH, 
        change24h: -1.2,
        high24h: COIN_PRICES.ETH * 1.02,
        low24h: COIN_PRICES.ETH * 0.97,
        volume: 1200000000,
        marketCap: 350000000000
      },
      // Add other coins with similar structure
      // ...
    ];
    
    res.status(200).json({
      success: true,
      detailedData
    });
  } catch (err) {
    console.error('Get detailed market data error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Wallet & Portfolio Endpoints
app.get('/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
      memo: req.user._id.toString(),
      note: 'Include your user ID as the memo when depositing'
    });
  } catch (err) {
    console.error('Get deposit address error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { currency, amount, address } = req.body;
    
    if (!currency || !amount || !address) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Currency, amount and address are required' 
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_AMOUNT',
        message: 'Amount must be greater than 0' 
      });
    }
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Check if user has sufficient balance
    if (user.balance[currency] < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'INSUFFICIENT_BALANCE',
        message: `Insufficient ${currency} balance` 
      });
    }
    
    // Calculate fee (0.5% withdrawal fee)
    const fee = amount * 0.005;
    const totalDeduction = amount + fee;
    
    // Check if user has enough balance to cover amount + fee
    if (user.balance[currency] < totalDeduction) {
      return res.status(400).json({ 
        success: false, 
        error: 'INSUFFICIENT_BALANCE_FEE',
        message: `Insufficient ${currency} balance to cover withdrawal and fee` 
      });
    }
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update user balance
      user.balance[currency] -= totalDeduction;
      await user.save({ session });
      
      // Create withdrawal transaction
      const transaction = await Transaction.create([{
        userId: user._id,
        type: 'withdrawal',
        amount: -amount,
        currency,
        status: 'pending',
        address,
        fee,
        metadata: {
          note: 'Withdrawal request processing'
        }
      }], { session });
      
      // Create fee transaction
      await Transaction.create([{
        userId: user._id,
        type: 'fee',
        amount: -fee,
        currency,
        status: 'completed',
        metadata: {
          relatedTx: transaction[0]._id,
          note: 'Withdrawal fee'
        }
      }], { session });
      
      // Commit transaction
      await session.commitTransaction();
      session.endSession();
      
      // Log the withdrawal request
      await SystemLog.create({
        action: 'withdrawal_requested',
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: {
          currency,
          amount,
          address,
          fee
        }
      });
      
      // Broadcast balance update to user
      broadcastToUser(user._id, 'balance:updated', {
        [currency]: user.balance[currency],
        updatedAt: new Date()
      });
      
      // Notify admin about new withdrawal request
      broadcastToAdmins('withdrawals:new', {
        userId: user._id,
        currency,
        amount,
        address,
        fee,
        timestamp: new Date()
      });
      
      res.status(200).json({
        success: true,
        message: 'Withdrawal request submitted',
        transactionId: transaction[0]._id,
        newBalance: user.balance[currency]
      });
    } catch (err) {
      // If any error occurs, abort the transaction
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Withdraw error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Calculate portfolio value in USD
    let totalValueUSD = 0;
    const portfolio = Object.entries(user.balance).map(([currency, amount]) => {
      const value = amount * COIN_PRICES[currency];
      totalValueUSD += value;
      
      return {
        currency,
        amount,
        value,
        price: COIN_PRICES[currency]
      };
    });
    
    // Get recent transactions
    const transactions = await Transaction.find({ userId: user._id })
      .sort('-createdAt')
      .limit(5)
      .lean();
    
    // Get active trades
    const activeTrades = await Trade.find({ 
      userId: user._id,
      status: { $in: ['pending'] }
    })
    .sort('-createdAt')
    .limit(5)
    .lean();
    
    res.status(200).json({
      success: true,
      portfolio,
      totalValueUSD,
      recentTransactions: transactions,
      activeTrades
    });
  } catch (err) {
    console.error('Get portfolio error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Trading Endpoints
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'From, to and amount are required' 
      });
    }
    
    if (from === to) {
      return res.status(400).json({ 
        success: false, 
        error: 'SAME_CURRENCY',
        message: 'Cannot trade between the same currency' 
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_AMOUNT',
        message: 'Amount must be greater than 0' 
      });
    }
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Check if user has sufficient balance
    if (user.balance[from] < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'INSUFFICIENT_BALANCE',
        message: `Insufficient ${from} balance` 
      });
    }
    
    // Get current market rate
    const rate = getConversionRate(from, to);
    const expectedAmount = amount * rate;
    const fee = expectedAmount * 0.001; // 0.1% fee
    const finalAmount = expectedAmount - fee;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update user balances
      user.balance[from] -= amount;
      user.balance[to] += finalAmount;
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        userId: user._id,
        type: 'buy',
        fromCoin: from,
        toCoin: to,
        amount,
        rate,
        fee,
        status: 'completed'
      }], { session });
      
      // Create transaction records
      await Transaction.create([
        {
          userId: user._id,
          type: 'trade',
          amount: -amount,
          currency: from,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Traded ${amount} ${from} for ${to}`
          }
        },
        {
          userId: user._id,
          type: 'trade',
          amount: finalAmount,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Received from ${amount} ${from} trade`
          }
        },
        {
          userId: user._id,
          type: 'fee',
          amount: -fee,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Trade fee for ${amount} ${from} to ${to}`
          }
        }
      ], { session });
      
      // Commit transaction
      await session.commitTransaction();
      session.endSession();
      
      // Log the trade
      await SystemLog.create({
        action: 'trade_executed',
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: {
          type: 'buy',
          from,
          to,
          amount,
          rate,
          fee
        }
      });
      
      // Broadcast balance update to user
      broadcastToUser(user._id, 'balance:updated', {
        [from]: user.balance[from],
        [to]: user.balance[to],
        updatedAt: new Date()
      });
      
      // Notify admin about new trade
      broadcastToAdmins('trades:new', {
        userId: user._id,
        type: 'buy',
        from,
        to,
        amount,
        rate,
        fee,
        timestamp: new Date()
      });
      
      res.status(200).json({
        success: true,
        trade: {
          id: trade[0]._id,
          type: 'buy',
          from,
          to,
          amount,
          rate,
          fee,
          finalAmount,
          status: 'completed'
        },
        newBalances: {
          [from]: user.balance[from],
          [to]: user.balance[to]
        }
      });
    } catch (err) {
      // If any error occurs, abort the transaction
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Buy trade error:', err);
    
    if (err.message === 'Invalid coin symbols') {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_COINS',
        message: 'Invalid coin symbols provided' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'From, to and amount are required' 
      });
    }
    
    if (from === to) {
      return res.status(400).json({ 
        success: false, 
        error: 'SAME_CURRENCY',
        message: 'Cannot trade between the same currency' 
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_AMOUNT',
        message: 'Amount must be greater than 0' 
      });
    }
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'USER_NOT_FOUND',
        message: 'User not found' 
      });
    }
    
    // Check if user has sufficient balance
    if (user.balance[from] < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'INSUFFICIENT_BALANCE',
        message: `Insufficient ${from} balance` 
      });
    }
    
    // Get current market rate
    const rate = getConversionRate(from, to);
    const expectedAmount = amount * rate;
    const fee = expectedAmount * 0.001; // 0.1% fee
    const finalAmount = expectedAmount - fee;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update user balances
      user.balance[from] -= amount;
      user.balance[to] += finalAmount;
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        userId: user._id,
        type: 'sell',
        fromCoin: from,
        toCoin: to,
        amount,
        rate,
        fee,
        status: 'completed'
      }], { session });
      
      // Create transaction records
      await Transaction.create([
        {
          userId: user._id,
          type: 'trade',
          amount: -amount,
          currency: from,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Traded ${amount} ${from} for ${to}`
          }
        },
        {
          userId: user._id,
          type: 'trade',
          amount: finalAmount,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Received from ${amount} ${from} trade`
          }
        },
        {
          userId: user._id,
          type: 'fee',
          amount: -fee,
          currency: to,
          status: 'completed',
          metadata: {
            tradeId: trade[0]._id,
            description: `Trade fee for ${amount} ${from} to ${to}`
          }
        }
      ], { session });
      
      // Commit transaction
      await session.commitTransaction();
      session.endSession();
      
      // Log the trade
      await SystemLog.create({
        action: 'trade_executed',
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: {
          type: 'sell',
          from,
          to,
          amount,
          rate,
          fee
        }
      });
      
      // Broadcast balance update to user
      broadcastToUser(user._id, 'balance:updated', {
        [from]: user.balance[from],
        [to]: user.balance[to],
        updatedAt: new Date()
      });
      
      // Notify admin about new trade
      broadcastToAdmins('trades:new', {
        userId: user._id,
        type: 'sell',
        from,
        to,
        amount,
        rate,
        fee,
        timestamp: new Date()
      });
      
      res.status(200).json({
        success: true,
        trade: {
          id: trade[0]._id,
          type: 'sell',
          from,
          to,
          amount,
          rate,
          fee,
          finalAmount,
          status: 'completed'
        },
        newBalances: {
          [from]: user.balance[from],
          [to]: user.balance[to]
        }
      });
    } catch (err) {
      // If any error occurs, abort the transaction
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    console.error('Sell trade error:', err);
    
    if (err.message === 'Invalid coin symbols') {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_COINS',
        message: 'Invalid coin symbols provided' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['pending'] }
    })
    .sort('-createdAt')
    .lean();
    
    res.status(200).json({
      success: true,
      trades
    });
  } catch (err) {
    console.error('Get active trades error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({
      userId: req.user._id
    })
    .sort('-createdAt')
    .limit(10)
    .lean();
    
    res.status(200).json({
      success: true,
      transactions
    });
  } catch (err) {
    console.error('Get recent transactions error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Support & Contact Endpoints
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'General',
        questions: [
          {
            question: 'What is this platform?',
            answer: 'This is a cryptocurrency trading platform where you can buy, sell, and trade various digital assets.'
          },
          {
            question: 'How do I get started?',
            answer: 'Sign up for an account, complete the verification process, and you can start trading immediately.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'What cryptocurrencies can I trade?',
            answer: 'We support BTC, ETH, BNB, USDT, XRP, SOL, ADA, DOGE, DOT, and MATIC.'
          },
          {
            question: 'What are the trading fees?',
            answer: 'Our trading fee is 0.1% per trade.'
          }
        ]
      },
      {
        category: 'Security',
        questions: [
          {
            question: 'How is my account secured?',
            answer: 'We use industry-standard security measures including encryption, 2FA, and cold storage for funds.'
          },
          {
            question: 'What should I do if I suspect unauthorized access?',
            answer: 'Immediately change your password and enable 2FA. Contact our support team for further assistance.'
          }
        ]
      }
    ];
    
    res.status(200).json({
      success: true,
      faqs
    });
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/support/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'All fields are required' 
      });
    }
    
    // Validate email
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ 
        success: false, 
        error: 'INVALID_EMAIL',
        message: 'Please provide a valid email address' 
      });
    }
    
    // Create support ticket (unauthenticated user)
    const ticket = await SupportTicket.create({
      email,
      subject,
      message,
      metadata: {
        name,
        isAuthenticated: false
      }
    });
    
    // Send confirmation email
    const mailOptions = {
      to: email,
      from: 'support@yourdomain.com',
      subject: 'Support Ticket Received',
      html: `
        <p>Hello ${name},</p>
        <p>We've received your support ticket with the following details:</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong> ${message}</p>
        <p>Our support team will get back to you as soon as possible.</p>
        <p>Ticket ID: ${ticket._id}</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Notify admin about new ticket
    broadcastToAdmins('tickets:new', {
      ticketId: ticket._id,
      subject,
      email,
      createdAt: ticket.createdAt
    });
    
    res.status(200).json({
      success: true,
      message: 'Support ticket submitted successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Submit contact form error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Subject and message are required' 
      });
    }
    
    // Create support ticket (authenticated user)
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message
    });
    
    // Send confirmation email
    const mailOptions = {
      to: req.user.email,
      from: 'support@yourdomain.com',
      subject: 'Support Ticket Received',
      html: `
        <p>Hello ${req.user.firstName},</p>
        <p>We've received your support ticket with the following details:</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong> ${message}</p>
        <p>Our support team will get back to you as soon as possible.</p>
        <p>Ticket ID: ${ticket._id}</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Notify admin about new ticket
    broadcastToAdmins('tickets:new', {
      ticketId: ticket._id,
      subject,
      email: req.user.email,
      userId: req.user._id,
      createdAt: ticket.createdAt
    });
    
    res.status(200).json({
      success: true,
      message: 'Support ticket submitted successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Submit support ticket error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({
      userId: req.user._id
    })
    .sort('-createdAt')
    .lean();
    
    res.status(200).json({
      success: true,
      tickets
    });
  } catch (err) {
    console.error('Get user tickets error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.post('/api/v1/support', authenticate, upload.array('attachments', 5), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const files = req.files;
    
    if (!subject || !message) {
      // Clean up uploaded files if validation fails
      if (files) {
        files.forEach(file => {
          try {
            fs.unlinkSync(file.path);
          } catch (unlinkErr) {
            console.error('Error cleaning up uploaded file:', unlinkErr);
          }
        });
      }
      
      return res.status(400).json({ 
        success: false, 
        error: 'MISSING_FIELDS',
        message: 'Subject and message are required' 
      });
    }
    
    const attachments = files?.map(file => ({
      url: `/uploads/${file.filename}`,
      name: file.originalname,
      size: file.size
    })) || [];
    
    // Create support ticket with attachments
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments
    });
    
    // Send confirmation email
    const mailOptions = {
      to: req.user.email,
      from: 'support@yourdomain.com',
      subject: 'Support Ticket Received',
      html: `
        <p>Hello ${req.user.firstName},</p>
        <p>We've received your support ticket with the following details:</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong> ${message}</p>
        <p><strong>Attachments:</strong> ${attachments.length} file(s)</p>
        <p>Our support team will get back to you as soon as possible.</p>
        <p>Ticket ID: ${ticket._id}</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Notify admin about new ticket
    broadcastToAdmins('tickets:new', {
      ticketId: ticket._id,
      subject,
      email: req.user.email,
      userId: req.user._id,
      attachments: attachments.length,
      createdAt: ticket.createdAt
    });
    
    res.status(200).json({
      success: true,
      message: 'Support ticket submitted successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error('Submit support ticket with attachments error:', err);
    
    // Clean up uploaded files if there was an error
    if (req.files) {
      req.files.forEach(file => {
        try {
          fs.unlinkSync(file.path);
        } catch (unlinkErr) {
          console.error('Error cleaning up uploaded file:', unlinkErr);
        }
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Team & Stats Endpoints
app.get('/api/v1/team', async (req, res) => {
  try {
    const team = [
      {
        name: 'John Doe',
        position: 'CEO & Founder',
        bio: 'Blockchain enthusiast with 10+ years of experience in fintech and cryptocurrency.',
        avatar: '/images/team/john-doe.jpg'
      },
      {
        name: 'Jane Smith',
        position: 'CTO',
        bio: 'Expert in blockchain technology and security with a background in software engineering.',
        avatar: '/images/team/jane-smith.jpg'
      },
      {
        name: 'Mike Johnson',
        position: 'Head of Trading',
        bio: 'Former Wall Street trader with deep knowledge of cryptocurrency markets.',
        avatar: '/images/team/mike-johnson.jpg'
      }
    ];
    
    res.status(200).json({
      success: true,
      team
    });
  } catch (err) {
    console.error('Get team error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

app.get('/api/v1/stats', async (req, res) => {
  try {
    const [totalUsers, activeTrades, totalVolume] = await Promise.all([
      User.countDocuments(),
      Trade.countDocuments({ status: 'completed' }),
      Trade.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } } }
      ])
    ]);
    
    res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        activeTrades,
        totalVolume: totalVolume[0]?.total || 0
      }
    });
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'SERVER_ERROR',
      message: 'Internal server error' 
    });
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      success: false, 
      error: 'FILE_UPLOAD_ERROR',
      message: err.message 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    error: 'SERVER_ERROR',
    message: 'Internal server error' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'NOT_FOUND',
    message: 'Endpoint not found' 
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

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
