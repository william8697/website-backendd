// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const validator = require('validator');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.##';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '17581758..';

// Enhanced Security Middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(hpp());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// MongoDB Connection with Retry Logic
const connectWithRetry = () => {
  mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000
  })
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    setTimeout(connectWithRetry, 5000);
  });
};
connectWithRetry();

// Models with Enhanced Validation
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'], trim: true },
  lastName: { type: String, required: [true, 'Last name is required'], trim: true },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: 8,
    select: false
  },
  walletAddress: { type: String, unique: true, sparse: true },
  isAdmin: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  kycDocuments: [String],
  apiKey: { type: String, unique: true },
  settings: { type: Object, default: {} },
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  accountLocked: { type: Boolean, default: false },
  lockUntil: Date,
  twoFactorSecret: String,
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Pre-save hooks for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model('User', userSchema);

// Other models with similar enhancements...
const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  pair: { type: String, required: true },
  amount: { type: Number, required: true, min: 0 },
  price: { type: Number, required: true, min: 0 },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
  fee: { type: Number, default: 0 },
  netAmount: Number,
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true }));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: String,
  address: String,
  confirmations: { type: Number, default: 0 },
  networkFee: Number,
  metadata: Object,
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true }));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  attachments: [String],
  status: { type: String, enum: ['open', 'in-progress', 'resolved', 'closed'], default: 'open' },
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
  }],
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true }));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true }));

// Initialize Admin User with enhanced security
async function initializeAdmin() {
  try {
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await User.create({
        firstName: 'Admin',
        lastName: 'Youngblood',
        email: ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true,
        apiKey: uuidv4(),
        kycStatus: 'approved'
      });
      console.log('Admin user created successfully');
    }
  } catch (err) {
    console.error('Error creating admin user:', err);
  }
}

initializeAdmin();

// Enhanced Auth Middleware with rate limiting and brute force protection
const authenticate = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'You are not logged in! Please log in to get access.' 
      });
    }

    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.userId).select('+accountLocked +lockUntil');
    
    if (!currentUser) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'The user belonging to this token no longer exists.' 
      });
    }

    if (currentUser.accountLocked && currentUser.lockUntil > Date.now()) {
      return res.status(403).json({
        status: 'fail',
        message: 'Your account is locked. Please try again later or contact support.'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Invalid token. Please log in again.' 
      });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Your token has expired! Please log in again.' 
      });
    }
    res.status(500).json({ 
      status: 'error', 
      message: 'Something went wrong with authentication' 
    });
  }
};

const authenticateAdmin = async (req, res, next) => {
  authenticate(req, res, () => {
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        status: 'fail', 
        message: 'You do not have permission to perform this action' 
      });
    }
    next();
  });
};

// Secure File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
    cb(null, filename);
  }
});

const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png|pdf/;
  const mimetype = filetypes.test(file.mimetype);
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  
  if (mimetype && extname) {
    return cb(null, true);
  }
  cb(new Error('Only images (JPEG, JPG, PNG) and PDF files are allowed'));
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// WebSocket Server with Enhanced Security
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

const wss = new WebSocket.Server({ 
  server,
  verifyClient: (info, done) => {
    const token = info.req.url.split('token=')[1];
    if (!token) {
      return done(false, 401, 'Unauthorized');
    }
    
    try {
      jwt.verify(token, JWT_SECRET);
      done(true);
    } catch (err) {
      done(false, 401, 'Invalid token');
    }
  }
});

const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  
  clients.set(decoded.userId, ws);
  console.log(`New WebSocket connection for user ${decoded.userId}`);
  
  // Send initial data
  ws.send(JSON.stringify({ 
    type: 'connection', 
    status: 'established',
    timestamp: new Date().toISOString()
  }));
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      // Process incoming messages with validation
      console.log('Received message:', data);
    } catch (err) {
      console.error('Error processing WebSocket message:', err);
    }
  });
  
  ws.on('close', () => {
    clients.delete(decoded.userId);
    console.log(`WebSocket connection closed for user ${decoded.userId}`);
  });
  
  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
    clients.delete(decoded.userId);
  });
});

function broadcastToUser(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(data));
    } catch (err) {
      console.error('Error sending WebSocket message:', err);
    }
  }
}

function broadcastToAdmins(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// API Endpoints with Enhanced Security and Validation

// AUTH ENDPOINTS
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    
    // Validation
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Please provide all required fields' 
      });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Passwords do not match' 
      });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Please provide a valid email address' 
      });
    }
    
    if (!validator.isStrongPassword(password, { 
      minLength: 8, 
      minLowercase: 1, 
      minUppercase: 1, 
      minNumbers: 1, 
      minSymbols: 1 
    })) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one number, and one symbol' 
      });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Email already in use' 
      });
    }
    
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      apiKey: uuidv4()
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    
    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isAdmin: user.isAdmin,
          createdAt: user.createdAt
        }
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'An error occurred during signup' 
    });
  }
});

// Other auth endpoints with similar enhancements...

// USER ENDPOINTS
app.get('/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -__v -accountLocked -lockUntil -loginAttempts');
      
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'An error occurred while fetching user data' 
    });
  }
});

// Other user endpoints with similar enhancements...

// ADMIN ENDPOINTS
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Please provide email and password' 
      });
    }
    
    const user = await User.findOne({ email }).select('+password +accountLocked +lockUntil +loginAttempts');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Incorrect email or password' 
      });
    }
    
    if (!user.isAdmin) {
      return res.status(403).json({ 
        status: 'fail', 
        message: 'You do not have admin privileges' 
      });
    }
    
    if (user.accountLocked && user.lockUntil > Date.now()) {
      return res.status(403).json({ 
        status: 'fail', 
        message: 'Account is locked. Please try again later.' 
      });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    
    // Reset login attempts
    user.loginAttempts = 0;
    user.accountLocked = false;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });
    
    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isAdmin: user.isAdmin,
          lastLogin: user.lastLogin
        }
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'An error occurred during login' 
    });
  }
});

// Other admin endpoints with similar enhancements...

// TRADING ENDPOINTS
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { pair, amount, price } = req.body;
    
    if (!pair || !amount || !price) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Please provide pair, amount, and price' 
      });
    }
    
    if (amount <= 0 || price <= 0) {
      return res.status(400).json({ 
        status: 'fail', 
        message: 'Amount and price must be positive values' 
      });
    }
    
    // Additional validation (e.g., check user balance, market price, etc.)
    
    const trade = await Trade.create({
      userId: req.user._id,
      type: 'buy',
      pair,
      amount,
      price,
      status: 'pending'
    });
    
    // Process trade (would integrate with exchange in real implementation)
    
    // Broadcast trade event
    broadcastToUser(req.user._id, {
      type: 'trade_update',
      tradeId: trade._id,
      status: 'pending',
      timestamp: new Date().toISOString()
    });
    
    res.status(201).json({
      status: 'success',
      data: { trade }
    });
  } catch (err) {
    console.error('Buy trade error:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'An error occurred while processing your trade' 
    });
  }
});

// Other trading endpoints with similar enhancements...

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      status: 'fail', 
      message: 'File upload error: ' + err.message 
    });
  }
  
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(el => el.message);
    return res.status(400).json({ 
      status: 'fail', 
      message: 'Validation error: ' + errors.join('. ') 
    });
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Something went wrong on the server' 
  });
});

// 404 Handler
app.all('*', (req, res) => {
  res.status(404).json({ 
    status: 'fail', 
    message: `Can't find ${req.originalUrl} on this server` 
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});
