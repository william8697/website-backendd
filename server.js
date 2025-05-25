require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced MongoDB connection with error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
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

// Security middleware
app.use(helmet());
app.use(morgan('dev'));
app.use(cookieParser());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting configuration
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later',
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: 'Too many requests from this IP, please try again later'
});

app.use('/api/v1/auth/', authLimiter);
app.use('/api/v1/', apiLimiter);

// Email configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8,
    select: false
  },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String, select: false },
  verificationTokenExpires: { type: Date, select: false },
  resetPasswordToken: { type: String, select: false },
  resetPasswordExpires: { type: Date, select: false },
  balance: { type: Number, default: 0, min: 0 },
  portfolio: [{
    coinId: { type: String, required: true },
    symbol: { type: String, required: true },
    name: { type: String, required: true },
    amount: { type: Number, required: true, default: 0, min: 0 }
  }],
  transactions: [{
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion'], required: true },
    amount: { type: Number, required: true },
    coin: { type: String, required: true },
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    details: { type: mongoose.Schema.Types.Mixed }
  }],
  trades: [{
    type: { type: String, enum: ['buy', 'sell', 'convert'], required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    amount: { type: Number, required: true },
    rate: { type: Number, required: true },
    value: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' }
  }],
  settings: {
    theme: { type: String, enum: ['light', 'dark'], default: 'light' },
    currency: { type: String, default: 'USD' },
    notifications: {
      email: { type: Boolean, default: true },
      trade: { type: Boolean, default: true },
      balance: { type: Boolean, default: true }
    }
  },
  kyc: {
    status: { type: String, enum: ['pending', 'verified', 'rejected', 'none'], default: 'none' },
    submittedAt: { type: Date },
    verifiedAt: { type: Date },
    documents: [{
      type: { type: String, enum: ['id', 'passport', 'driver_license', 'proof_of_address'] },
      url: { type: String },
      status: { type: String, enum: ['pending', 'approved', 'rejected'] }
    }]
  },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const AdminSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8,
    select: false
  },
  role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved', 'closed'], default: 'open' },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security', 'general'] },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Create HTTP server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// WebSocket Server
const wss = new WebSocket.Server({ server, path: '/ws' });

const clients = new Map();
const adminClients = new Set();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.adminId) {
      adminClients.add(ws);
      ws.on('close', () => adminClients.delete(ws));
    } else if (decoded.userId) {
      clients.set(decoded.userId.toString(), ws);
      ws.on('close', () => clients.delete(decoded.userId.toString()));
    } else {
      ws.close(1008, 'Invalid token');
    }
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
      }
    });
    
  } catch (err) {
    console.error('WebSocket authentication error:', err);
    ws.close(1008, 'Invalid token');
  }
});

// WebSocket helper functions
const sendToUser = (userId, type, data) => {
  const ws = clients.get(userId.toString());
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
};

const broadcastToAdmins = (type, data) => {
  adminClients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, data }));
    }
  });
};

// Utility functions
const generateToken = () => crypto.randomBytes(32).toString('hex');

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: '"Crypto Trading Platform" <no-reply@cryptotrading.com>',
      to,
      subject,
      html
    });
    return true;
  } catch (err) {
    console.error('Email sending error:', err);
    return false;
  }
};

const generateVerificationEmail = (email, token) => {
  const verificationUrl = `https://website-xi-ten-52.vercel.app/verify?token=${token}`;
  return {
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2c3e50;">Email Verification</h2>
        <p>Thank you for registering with Crypto Trading Platform!</p>
        <p>Please click the button below to verify your email address:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background-color: #3498db; color: white; padding: 12px 24px; 
                    text-decoration: none; border-radius: 4px; font-weight: bold;">
            Verify Email
          </a>
        </p>
        <p>If you didn't create an account with us, please ignore this email.</p>
        <p style="margin-top: 30px; font-size: 0.9em; color: #7f8c8d;">
          This link will expire in 1 hour.
        </p>
      </div>
    `
  };
};

const generatePasswordResetEmail = (email, token) => {
  const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${token}`;
  return {
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2c3e50;">Password Reset</h2>
        <p>We received a request to reset your password for your Crypto Trading Platform account.</p>
        <p>Please click the button below to reset your password:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #e74c3c; color: white; padding: 12px 24px; 
                    text-decoration: none; border-radius: 4px; font-weight: bold;">
            Reset Password
          </a>
        </p>
        <p>If you didn't request a password reset, please ignore this email or contact support.</p>
        <p style="margin-top: 30px; font-size: 0.9em; color: #7f8c8d;">
          This link will expire in 1 hour.
        </p>
      </div>
    `
  };
};

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.token) {
      token = req.cookies.token;
    }
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        error: 'Not authorized to access this resource'
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.adminId) {
      const admin = await Admin.findById(decoded.adminId).select('+lastLogin');
      if (!admin) {
        return res.status(401).json({ 
          success: false,
          error: 'Not authorized, admin not found'
        });
      }
      
      req.admin = admin;
    } else if (decoded.userId) {
      const user = await User.findById(decoded.userId).select('+lastLogin');
      if (!user) {
        return res.status(401).json({ 
          success: false,
          error: 'Not authorized, user not found'
        });
      }
      
      req.user = user;
    } else {
      return res.status(401).json({ 
        success: false,
        error: 'Not authorized, invalid token'
      });
    }
    
    req.token = token;
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    return res.status(401).json({ 
      success: false,
      error: 'Not authorized, token failed'
    });
  }
};

const authorizeAdmin = (req, res, next) => {
  if (!req.admin) {
    return res.status(403).json({ 
      success: false,
      error: 'Not authorized as admin'
    });
  }
  next();
};

const authorizeUser = (req, res, next) => {
  if (!req.user) {
    return res.status(403).json({ 
      success: false,
      error: 'Not authorized as user'
    });
  }
  next();
};

// API Routes

// Authentication Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide all required fields'
      });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Passwords do not match'
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 8 characters'
      });
    }
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'Email already in use'
      });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const verificationToken = generateToken();
    const verificationTokenExpires = Date.now() + 3600000;
    
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires
    });
    
    await user.save();
    
    const emailContent = generateVerificationEmail(email, verificationToken);
    await sendEmail(email, emailContent.subject, emailContent.html);
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please check your email to verify your account.',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isVerified: user.isVerified,
        createdAt: user.createdAt
      }
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during registration'
    });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide email and password'
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +lastLogin');
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    if (!user.isVerified) {
      return res.status(401).json({ 
        success: false,
        error: 'Please verify your email first'
      });
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during login'
    });
  }
});

app.get('/api/v1/auth/verify', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ 
        success: false,
        error: 'Verification token is required'
      });
    }
    
    const user = await User.findOne({ 
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid or expired verification token'
      });
    }
    
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();
    
    res.json({
      success: true,
      message: 'Email verified successfully'
    });
    
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during email verification'
    });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        error: 'Email is required'
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.json({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent'
      });
    }
    
    const resetToken = generateToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();
    
    const emailContent = generatePasswordResetEmail(email, resetToken);
    await sendEmail(email, emailContent.subject, emailContent.html);
    
    res.json({
      success: true,
      message: 'Password reset link sent to your email'
    });
    
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during password reset request'
    });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    
    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Token, new password and confirmation are required'
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Passwords do not match'
      });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 8 characters'
      });
    }
    
    const user = await User.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid or expired reset token'
      });
    }
    
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    res.json({
      success: true,
      message: 'Password reset successfully'
    });
    
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during password reset'
    });
  }
});

app.post('/api/v1/auth/logout', authenticate, authorizeUser, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during logout'
    });
  }
});

app.get('/api/v1/auth/me', authenticate, authorizeUser, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings,
        kyc: user.kyc,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('Get current user error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching user data'
    });
  }
});

app.get('/api/v1/auth/check', authenticate, (req, res) => {
  try {
    if (req.user) {
      res.json({
        success: true,
        isAuthenticated: true,
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          isVerified: req.user.isVerified,
          balance: req.user.balance,
          portfolio: req.user.portfolio,
          settings: req.user.settings,
          kyc: req.user.kyc,
          lastLogin: req.user.lastLogin,
          createdAt: req.user.createdAt
        }
      });
    } else if (req.admin) {
      res.json({
        success: true,
        isAuthenticated: true,
        admin: {
          id: req.admin._id,
          email: req.admin.email,
          role: req.admin.role,
          lastLogin: req.admin.lastLogin
        }
      });
    } else {
      res.json({
        success: true,
        isAuthenticated: false
      });
    }
  } catch (err) {
    console.error('Check auth error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error checking authentication'
    });
  }
});

// Admin Authentication
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide email and password'
      });
    }
    
    const admin = await Admin.findOne({ email: email.toLowerCase() }).select('+password +lastLogin');
    if (!admin) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    admin.lastLogin = new Date();
    await admin.save();
    
    const token = jwt.sign({ adminId: admin._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role,
        lastLogin: admin.lastLogin,
        createdAt: admin.createdAt
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during admin login'
    });
  }
});

// User Routes
app.get('/api/v1/users/me', authenticate, authorizeUser, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        transactions: user.transactions,
        trades: user.trades,
        settings: user.settings,
        kyc: user.kyc,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching user profile'
    });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', authenticate, authorizeUser, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      balance: user.balance,
      portfolio: user.portfolio
    });
  } catch (err) {
    console.error('Get portfolio error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching portfolio'
    });
  }
});

// Trading Routes
app.post('/api/v1/trades/buy', authenticate, authorizeUser, async (req, res) => {
  try {
    const { coinId, symbol, name, amount, price } = req.body;
    const user = req.user;
    
    if (!coinId || !symbol || !name || !amount || !price) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required'
      });
    }
    
    if (amount <= 0 || price <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Amount and price must be positive'
      });
    }
    
    const totalCost = amount * price;
    
    if (user.balance < totalCost) {
      return res.status(400).json({ 
        success: false,
        error: 'Insufficient balance'
      });
    }
    
    user.balance -= totalCost;
    
    const coinIndex = user.portfolio.findIndex(item => item.coinId === coinId);
    if (coinIndex >= 0) {
      user.portfolio[coinIndex].amount += amount;
    } else {
      user.portfolio.push({ coinId, symbol, name, amount });
    }
    
    user.transactions.push({
      type: 'trade',
      amount: totalCost,
      coin: coinId,
      status: 'completed',
      details: {
        type: 'buy',
        amount,
        price,
        total: totalCost
      }
    });
    
    user.trades.push({
      type: 'buy',
      fromCoin: 'USD',
      toCoin: coinId,
      amount,
      rate: price,
      value: totalCost,
      status: 'completed'
    });
    
    await user.save();
    
    sendToUser(user._id.toString(), 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id.toString(), 'PORTFOLIO_UPDATE', { portfolio: user.portfolio });
    sendToUser(user._id.toString(), 'TRADE_EXECUTED', {
      type: 'buy',
      coin: coinId,
      amount,
      price,
      total: totalCost
    });
    
    res.json({ 
      success: true,
      message: 'Buy order executed successfully',
      balance: user.balance,
      portfolio: user.portfolio
    });
  } catch (err) {
    console.error('Buy trade error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error executing buy order'
    });
  }
});

app.post('/api/v1/trades/sell', authenticate, authorizeUser, async (req, res) => {
  try {
    const { coinId, amount, price } = req.body;
    const user = req.user;
    
    if (!coinId || !amount || !price) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required'
      });
    }
    
    if (amount <= 0 || price <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Amount and price must be positive'
      });
    }
    
    const coinIndex = user.portfolio.findIndex(item => item.coinId === coinId);
    if (coinIndex < 0 || user.portfolio[coinIndex].amount < amount) {
      return res.status(400).json({ 
        success: false,
        error: 'Insufficient coins'
      });
    }
    
    const totalValue = amount * price;
    
    user.balance += totalValue;
    
    user.portfolio[coinIndex].amount -= amount;
    if (user.portfolio[coinIndex].amount === 0) {
      user.portfolio.splice(coinIndex, 1);
    }
    
    user.transactions.push({
      type: 'trade',
      amount: totalValue,
      coin: coinId,
      status: 'completed',
      details: {
        type: 'sell',
        amount,
        price,
        total: totalValue
      }
    });
    
    user.trades.push({
      type: 'sell',
      fromCoin: coinId,
      toCoin: 'USD',
      amount,
      rate: price,
      value: totalValue,
      status: 'completed'
    });
    
    await user.save();
    
    sendToUser(user._id.toString(), 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id.toString(), 'PORTFOLIO_UPDATE', { portfolio: user.portfolio });
    sendToUser(user._id.toString(), 'TRADE_EXECUTED', {
      type: 'sell',
      coin: coinId,
      amount,
      price,
      total: totalValue
    });
    
    res.json({ 
      success: true,
      message: 'Sell order executed successfully',
      balance: user.balance,
      portfolio: user.portfolio
    });
  } catch (err) {
    console.error('Sell trade error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error executing sell order'
    });
  }
});

// Exchange Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = [
      { id: 'bitcoin', symbol: 'btc', name: 'Bitcoin' },
      { id: 'ethereum', symbol: 'eth', name: 'Ethereum' },
      { id: 'ripple', symbol: 'xrp', name: 'XRP' },
      { id: 'litecoin', symbol: 'ltc', name: 'Litecoin' },
      { id: 'cardano', symbol: 'ada', name: 'Cardano' },
      { id: 'usd', symbol: 'usd', name: 'US Dollar' }
    ];
    
    res.json({ 
      success: true,
      coins 
    });
  } catch (err) {
    console.error('Get coins error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching available coins'
    });
  }
});

// Market Data Routes
app.get('/api/v1/market/data', async (req, res) => {
  try {
    const marketData = [
      { 
        id: 'bitcoin', 
        symbol: 'btc', 
        name: 'Bitcoin', 
        price: 50000, 
        change24h: 2.5,
        marketCap: 950000000000,
        volume: 25000000000,
        circulatingSupply: 19000000,
        allTimeHigh: 69000,
        allTimeLow: 0.01
      },
      { 
        id: 'ethereum', 
        symbol: 'eth', 
        name: 'Ethereum', 
        price: 3000, 
        change24h: -1.2,
        marketCap: 360000000000,
        volume: 15000000000,
        circulatingSupply: 120000000,
        allTimeHigh: 4800,
        allTimeLow: 0.5
      }
    ];
    
    res.json({ 
      success: true,
      marketData 
    });
  } catch (err) {
    console.error('Get market data error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching market data'
    });
  }
});

// Wallet Routes
app.post('/api/v1/wallet/deposit', authenticate, authorizeUser, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = req.user;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid amount is required'
      });
    }
    
    user.balance += amount;
    
    user.transactions.push({
      type: 'deposit',
      amount,
      coin: 'USD',
      status: 'completed',
      details: {
        method: 'bank_transfer',
        reference: `DEP-${Date.now()}`
      }
    });
    
    await user.save();
    
    sendToUser(user._id.toString(), 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id.toString(), 'DEPOSIT_SUCCESS', { amount });
    
    res.json({ 
      success: true,
      message: 'Deposit successful',
      balance: user.balance
    });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during deposit'
    });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', authenticate, authorizeUser, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const user = req.user;
    
    if (!subject || !message) {
      return res.status(400).json({ 
        success: false,
        error: 'Subject and message are required'
      });
    }
    
    const ticket = new SupportTicket({
      userId: user._id,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    broadcastToAdmins('NEW_SUPPORT_TICKET', {
      ticketId: ticket._id,
      subject,
      userId: user._id,
      email: user.email,
      createdAt: ticket.createdAt
    });
    
    res.json({
      success: true,
      message: 'Ticket submitted successfully',
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        status: ticket.status,
        createdAt: ticket.createdAt
      }
    });
  } catch (err) {
    console.error('Create ticket error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error creating support ticket'
    });
  }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const activeUsers = await User.countDocuments({ lastLogin: { $gte: thirtyDaysAgo } });
    
    const totalBalanceResult = await User.aggregate([
      { $group: { _id: null, total: { $sum: "$balance" } } }
    ]);
    const totalBalance = totalBalanceResult[0]?.total || 0;
    
    const totalTradesResult = await User.aggregate([
      { $unwind: "$trades" },
      { $group: { _id: null, count: { $sum: 1 } } }
    ]);
    const totalTrades = totalTradesResult[0]?.count || 0;
    
    const totalVolumeResult = await User.aggregate([
      { $unwind: "$trades" },
      { $group: { _id: null, total: { $sum: "$trades.value" } } }
    ]);
    const totalVolume = totalVolumeResult[0]?.total || 0;
    
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentSignups = await User.find({ 
      createdAt: { $gte: sevenDaysAgo } 
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .select('firstName lastName email createdAt');
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        verifiedUsers,
        activeUsers,
        totalBalance,
        totalTrades,
        totalVolume
      },
      recentSignups
    });
  } catch (err) {
    console.error('Get dashboard stats error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching dashboard stats'
    });
  }
});

// Initialize Admin Account
const initializeAdmin = async () => {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@cryptotrading.com' });
    if (!adminExists) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('admin123', salt);
      
      const admin = new Admin({
        email: 'admin@cryptotrading.com',
        password: hashedPassword,
        role: 'admin'
      });
      
      await admin.save();
      console.log('Admin account created');
    }
  } catch (err) {
    console.error('Error creating admin account:', err);
  }
};

initializeAdmin();

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false,
    error: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    error: 'Endpoint not found'
  });
});
