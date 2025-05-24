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

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced MongoDB connection with error handling
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
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
app.use(morgan('combined'));
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
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

// Email configuration with Mailtrap
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Enhanced Models with validation
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'], trim: true },
  lastName: { type: String, required: [true, 'Last name is required'], trim: true },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  walletAddress: { type: String, default: '', trim: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String, select: false },
  verificationTokenExpires: { type: Date, select: false },
  resetPasswordToken: { type: String, select: false },
  resetPasswordExpires: { type: Date, select: false },
  balance: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
  portfolio: [{
    coinId: { type: String, required: true },
    symbol: { type: String, required: true },
    name: { type: String, required: true },
    amount: { type: Number, required: true, default: 0, min: [0, 'Amount cannot be negative'] }
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
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

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
  permissions: [{
    module: { type: String },
    access: { type: String, enum: ['read', 'write', 'delete'] }
  }],
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved', 'closed'], default: 'open' },
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
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '7d';

// WebSocket Server with enhanced functionality
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server running on ws://localhost:${PORT}`);
});

const wss = new WebSocket.Server({ server, path: '/api/v1/ws' });

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
      // Admin connection
      adminClients.add(ws);
      ws.on('close', () => adminClients.delete(ws));
    } else if (decoded.userId) {
      // User connection
      clients.set(decoded.userId, ws);
      ws.on('close', () => clients.delete(decoded.userId));
    } else {
      ws.close(1008, 'Invalid token');
    }
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        // Handle ping/pong for connection keep-alive
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
  const ws = clients.get(userId);
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
    
    // Check Authorization header first
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Check cookies if no header
    else if (req.cookies && req.cookies.token) {
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
      
      // Update last login if more than 5 minutes ago
      if (!admin.lastLogin || (Date.now() - admin.lastLogin.getTime()) > 300000) {
        admin.lastLogin = new Date();
        await admin.save();
      }
      
      req.admin = admin;
    } 
    else if (decoded.userId) {
      const user = await User.findById(decoded.userId).select('+lastLogin');
      if (!user) {
        return res.status(401).json({ 
          success: false,
          error: 'Not authorized, user not found'
        });
      }
      
      // Update last login if more than 5 minutes ago
      if (!user.lastLogin || (Date.now() - user.lastLogin.getTime()) > 300000) {
        user.lastLogin = new Date();
        await user.save();
      }
      
      req.user = user;
    } 
    else {
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

// ======================
// Authentication Routes
// ======================

/**
 * @api {post} /api/v1/auth/signup Register a new user
 * @apiName SignupUser
 * @apiGroup Authentication
 * 
 * @apiParam {String} firstName User's first name
 * @apiParam {String} lastName User's last name
 * @apiParam {String} email User's email
 * @apiParam {String} password User's password
 * @apiParam {String} confirmPassword Password confirmation
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {String} token JWT token
 * @apiSuccess {Object} user User data
 */
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    
    // Validation
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
    
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'Email already in use'
      });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create verification token
    const verificationToken = generateToken();
    const verificationTokenExpires = Date.now() + 3600000; // 1 hour
    
    // Create user
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires
    });
    
    await user.save();
    
    // Send verification email
    const emailContent = generateVerificationEmail(email, verificationToken);
    await sendEmail(email, emailContent.subject, emailContent.html);
    
    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    // Respond without sensitive data
    const userResponse = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      isVerified: user.isVerified,
      createdAt: user.createdAt
    };
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please check your email to verify your account.',
      token,
      user: userResponse
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during registration'
    });
  }
});

/**
 * @api {post} /api/v1/auth/login Authenticate user
 * @apiName LoginUser
 * @apiGroup Authentication
 * 
 * @apiParam {String} email User's email
 * @apiParam {String} password User's password
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {String} token JWT token
 * @apiSuccess {Object} user User data
 */
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide email and password'
      });
    }
    
    // Check if user exists
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +lastLogin');
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    // Check if email is verified
    if (!user.isVerified) {
      return res.status(401).json({ 
        success: false,
        error: 'Please verify your email first'
      });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    // Respond without sensitive data
    const userResponse = {
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
    };
    
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userResponse
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during login'
    });
  }
});

/**
 * @api {get} /api/v1/auth/verify Verify email
 * @apiName VerifyEmail
 * @apiGroup Authentication
 * 
 * @apiParam {String} token Verification token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
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
    
    // Mark as verified
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

/**
 * @api {post} /api/v1/auth/forgot-password Request password reset
 * @apiName ForgotPassword
 * @apiGroup Authentication
 * 
 * @apiParam {String} email User's email
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
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
    
    // Don't reveal if user doesn't exist (security measure)
    if (!user) {
      return res.json({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent'
      });
    }
    
    // Generate reset token
    const resetToken = generateToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
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

/**
 * @api {post} /api/v1/auth/reset-password Reset password
 * @apiName ResetPassword
 * @apiGroup Authentication
 * 
 * @apiParam {String} token Reset token
 * @apiParam {String} newPassword New password
 * @apiParam {String} confirmPassword Password confirmation
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
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
    
    // Hash new password
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

/**
 * @api {post} /api/v1/auth/logout Logout user
 * @apiName LogoutUser
 * @apiGroup Authentication
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
app.post('/api/v1/auth/logout', authenticate, authorizeUser, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token
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

/**
 * @api {get} /api/v1/auth/me Get current user
 * @apiName GetCurrentUser
 * @apiGroup Authentication
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} user User data
 */
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

/**
 * @api {get} /api/v1/auth/check Check authentication
 * @apiName CheckAuth
 * @apiGroup Authentication
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Boolean} isAuthenticated Authentication status
 * @apiSuccess {Object} user User data if authenticated
 */
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

// ======================
// Admin Authentication
// ======================

/**
 * @api {post} /api/v1/admin/login Authenticate admin
 * @apiName LoginAdmin
 * @apiGroup Admin
 * 
 * @apiParam {String} email Admin's email
 * @apiParam {String} password Admin's password
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {String} token JWT token
 * @apiSuccess {Object} admin Admin data
 */
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide email and password'
      });
    }
    
    // Check if admin exists
    const admin = await Admin.findOne({ email: email.toLowerCase() }).select('+password +lastLogin');
    if (!admin) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    // Check if password matches
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    // Update last login
    admin.lastLogin = new Date();
    await admin.save();
    
    // Generate JWT token
    const token = jwt.sign({ adminId: admin._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    // Respond without sensitive data
    const adminResponse = {
      id: admin._id,
      email: admin.email,
      role: admin.role,
      lastLogin: admin.lastLogin,
      createdAt: admin.createdAt
    };
    
    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: adminResponse
    });
    
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during admin login'
    });
  }
});

// ======================
// User Routes
// ======================

/**
 * @api {get} /api/v1/users/me Get current user profile
 * @apiName GetUserProfile
 * @apiGroup User
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} user User data
 */
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

/**
 * @api {patch} /api/v1/users/update-password Update user password
 * @apiName UpdateUserPassword
 * @apiGroup User
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} currentPassword Current password
 * @apiParam {String} newPassword New password
 * @apiParam {String} confirmPassword Password confirmation
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
app.patch('/api/v1/users/update-password', authenticate, authorizeUser, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const user = req.user;
    
    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Current password, new password and confirmation are required'
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'New passwords do not match'
      });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 8 characters'
      });
    }
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        error: 'Current password is incorrect'
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();
    
    res.json({
      success: true,
      message: 'Password updated successfully'
    });
    
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating password'
    });
  }
});

/**
 * @api {patch} /api/v1/users/update-profile Update user profile
 * @apiName UpdateUserProfile
 * @apiGroup User
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} [firstName] First name
 * @apiParam {String} [lastName] Last name
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user data
 */
app.patch('/api/v1/users/update-profile', authenticate, authorizeUser, async (req, res) => {
  try {
    const { firstName, lastName } = req.body;
    const user = req.user;
    
    // Validation
    if (!firstName && !lastName) {
      return res.status(400).json({ 
        success: false,
        error: 'At least one field to update is required'
      });
    }
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    });
    
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating profile'
    });
  }
});

/**
 * @api {patch} /api/v1/users/update-settings Update user settings
 * @apiName UpdateUserSettings
 * @apiGroup User
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} [theme] Theme preference (light/dark)
 * @apiParam {String} [currency] Currency preference
 * @apiParam {Object} [notifications] Notification preferences
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} settings Updated settings
 */
app.patch('/api/v1/users/update-settings', authenticate, authorizeUser, async (req, res) => {
  try {
    const { theme, currency, notifications } = req.body;
    const user = req.user;
    
    // Validation
    if (!theme && !currency && !notifications) {
      return res.status(400).json({ 
        success: false,
        error: 'At least one setting to update is required'
      });
    }
    
    if (theme) user.settings.theme = theme;
    if (currency) user.settings.currency = currency;
    if (notifications) {
      if (notifications.email !== undefined) user.settings.notifications.email = notifications.email;
      if (notifications.trade !== undefined) user.settings.notifications.trade = notifications.trade;
      if (notifications.balance !== undefined) user.settings.notifications.balance = notifications.balance;
    }
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: user.settings
    });
    
  } catch (err) {
    console.error('Update settings error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating settings'
    });
  }
});

/**
 * @api {post} /api/v1/users/kyc Submit KYC documents
 * @apiName SubmitKYC
 * @apiGroup User
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Object[]} documents KYC documents
 * @apiParam {String} documents.type Document type (id/passport/driver_license/proof_of_address)
 * @apiParam {String} documents.url Document URL
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} kyc Updated KYC status
 */
app.post('/api/v1/users/kyc', authenticate, authorizeUser, async (req, res) => {
  try {
    const { documents } = req.body;
    const user = req.user;
    
    // Validation
    if (!documents || !Array.isArray(documents) || documents.length === 0) {
      return res.status(400).json({ 
        success: false,
        error: 'At least one KYC document is required'
      });
    }
    
    // Validate each document
    for (const doc of documents) {
      if (!doc.type || !doc.url) {
        return res.status(400).json({ 
          success: false,
          error: 'Each document must have type and url'
        });
      }
      
      if (!['id', 'passport', 'driver_license', 'proof_of_address'].includes(doc.type)) {
        return res.status(400).json({ 
          success: false,
          error: 'Invalid document type'
        });
      }
    }
    
    // Update KYC status
    user.kyc = {
      status: 'pending',
      submittedAt: new Date(),
      documents
    };
    
    await user.save();
    
    // Notify admins
    broadcastToAdmins('KYC_SUBMITTED', {
      userId: user._id,
      email: user.email,
      submittedAt: user.kyc.submittedAt
    });
    
    res.json({
      success: true,
      message: 'KYC documents submitted successfully',
      kyc: user.kyc
    });
    
  } catch (err) {
    console.error('Submit KYC error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error submitting KYC'
    });
  }
});

// ======================
// Portfolio Routes
// ======================

/**
 * @api {get} /api/v1/portfolio Get user portfolio
 * @apiName GetPortfolio
 * @apiGroup Portfolio
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Number} balance User balance
 * @apiSuccess {Object[]} portfolio Portfolio items
 */
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

// ======================
// Trading Routes
// ======================

/**
 * @api {post} /api/v1/trades/buy Buy crypto
 * @apiName BuyCrypto
 * @apiGroup Trading
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} coinId Coin ID
 * @apiParam {String} symbol Coin symbol
 * @apiParam {String} name Coin name
 * @apiParam {Number} amount Amount to buy
 * @apiParam {Number} price Price per unit
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Number} balance Updated balance
 * @apiSuccess {Object[]} portfolio Updated portfolio
 */
app.post('/api/v1/trades/buy', authenticate, authorizeUser, async (req, res) => {
  try {
    const { coinId, symbol, name, amount, price } = req.body;
    const user = req.user;
    
    // Validation
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
    
    // Update user balance
    user.balance -= totalCost;
    
    // Update portfolio
    const coinIndex = user.portfolio.findIndex(item => item.coinId === coinId);
    if (coinIndex >= 0) {
      user.portfolio[coinIndex].amount += amount;
    } else {
      user.portfolio.push({ coinId, symbol, name, amount });
    }
    
    // Add transaction
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
    
    // Add trade
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
    
    // Send WebSocket updates
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: user.portfolio });
    sendToUser(user._id, 'TRADE_EXECUTED', {
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

/**
 * @api {post} /api/v1/trades/sell Sell crypto
 * @apiName SellCrypto
 * @apiGroup Trading
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} coinId Coin ID
 * @apiParam {Number} amount Amount to sell
 * @apiParam {Number} price Price per unit
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Number} balance Updated balance
 * @apiSuccess {Object[]} portfolio Updated portfolio
 */
app.post('/api/v1/trades/sell', authenticate, authorizeUser, async (req, res) => {
  try {
    const { coinId, amount, price } = req.body;
    const user = req.user;
    
    // Validation
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
    
    // Check if user has enough coins
    const coinIndex = user.portfolio.findIndex(item => item.coinId === coinId);
    if (coinIndex < 0 || user.portfolio[coinIndex].amount < amount) {
      return res.status(400).json({ 
        success: false,
        error: 'Insufficient coins'
      });
    }
    
    const totalValue = amount * price;
    
    // Update user balance
    user.balance += totalValue;
    
    // Update portfolio
    user.portfolio[coinIndex].amount -= amount;
    if (user.portfolio[coinIndex].amount === 0) {
      user.portfolio.splice(coinIndex, 1);
    }
    
    // Add transaction
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
    
    // Add trade
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
    
    // Send WebSocket updates
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: user.portfolio });
    sendToUser(user._id, 'TRADE_EXECUTED', {
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

/**
 * @api {get} /api/v1/trades/active Get active trades
 * @apiName GetActiveTrades
 * @apiGroup Trading
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} trades List of trades
 */
app.get('/api/v1/trades/active', authenticate, authorizeUser, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      trades: user.trades
    });
    
  } catch (err) {
    console.error('Get active trades error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching trades'
    });
  }
});

// ======================
// Exchange Routes
// ======================

/**
 * @api {get} /api/v1/exchange/coins Get available coins
 * @apiName GetAvailableCoins
 * @apiGroup Exchange
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} coins List of available coins
 */
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    // In a real app, you would fetch this from a crypto API
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

/**
 * @api {get} /api/v1/exchange/rate Get exchange rate
 * @apiName GetExchangeRate
 * @apiGroup Exchange
 * 
 * @apiParam {String} from Source coin
 * @apiParam {String} to Target coin
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} from Source coin
 * @apiSuccess {String} to Target coin
 * @apiSuccess {Number} rate Exchange rate
 */
app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ 
        success: false,
        error: 'Both from and to parameters are required'
      });
    }
    
    // In a real app, you would fetch real rates from an API
    // This is a simplified version with mock data
    const rates = {
      bitcoin: { 
        ethereum: 15, 
        ripple: 50000, 
        litecoin: 200, 
        cardano: 50000, 
        usd: 50000 
      },
      ethereum: { 
        bitcoin: 0.066, 
        ripple: 3000, 
        litecoin: 15, 
        cardano: 3000, 
        usd: 3000 
      },
      ripple: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        litecoin: 0.004, 
        cardano: 1, 
        usd: 1 
      },
      litecoin: { 
        bitcoin: 0.005, 
        ethereum: 0.066, 
        ripple: 250, 
        cardano: 250, 
        usd: 250 
      },
      cardano: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        ripple: 1, 
        litecoin: 0.004, 
        usd: 1 
      },
      usd: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        ripple: 1, 
        litecoin: 0.004, 
        cardano: 1 
      }
    };
    
    const rate = rates[from]?.[to] || 0;
    
    if (!rate) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid coin pair'
      });
    }
    
    res.json({ 
      success: true,
      from,
      to,
      rate
    });
    
  } catch (err) {
    console.error('Get exchange rate error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching exchange rate'
    });
  }
});

/**
 * @api {post} /api/v1/exchange/convert Convert between coins
 * @apiName ConvertCoins
 * @apiGroup Exchange
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} fromCoin Source coin
 * @apiParam {String} toCoin Target coin
 * @apiParam {Number} amount Amount to convert
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {String} fromCoin Source coin
 * @apiSuccess {String} toCoin Target coin
 * @apiSuccess {Number} amount Original amount
 * @apiSuccess {Number} convertedAmount Converted amount
 * @apiSuccess {Number} rate Conversion rate
 * @apiSuccess {Number} balance Updated balance
 * @apiSuccess {Object[]} portfolio Updated portfolio
 */
app.post('/api/v1/exchange/convert', authenticate, authorizeUser, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = req.user;
    
    // Validation
    if (!fromCoin || !toCoin || !amount) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Amount must be positive'
      });
    }
    
    // Get conversion rate
    const rates = {
      bitcoin: { 
        ethereum: 15, 
        ripple: 50000, 
        litecoin: 200, 
        cardano: 50000, 
        usd: 50000 
      },
      ethereum: { 
        bitcoin: 0.066, 
        ripple: 3000, 
        litecoin: 15, 
        cardano: 3000, 
        usd: 3000 
      },
      ripple: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        litecoin: 0.004, 
        cardano: 1, 
        usd: 1 
      },
      litecoin: { 
        bitcoin: 0.005, 
        ethereum: 0.066, 
        ripple: 250, 
        cardano: 250, 
        usd: 250 
      },
      cardano: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        ripple: 1, 
        litecoin: 0.004, 
        usd: 1 
      },
      usd: { 
        bitcoin: 0.00002, 
        ethereum: 0.00033, 
        ripple: 1, 
        litecoin: 0.004, 
        cardano: 1 
      }
    };
    
    const rate = rates[fromCoin]?.[toCoin] || 0;
    
    if (!rate) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid coin pair'
      });
    }
    
    // Check if user has enough coins (if not converting from USD)
    if (fromCoin !== 'usd') {
      const fromCoinIndex = user.portfolio.findIndex(item => item.coinId === fromCoin);
      if (fromCoinIndex < 0 || user.portfolio[fromCoinIndex].amount < amount) {
        return res.status(400).json({ 
          success: false,
          error: 'Insufficient coins'
        });
      }
    } else {
      // If converting from USD, check balance
      if (user.balance < amount) {
        return res.status(400).json({ 
          success: false,
          error: 'Insufficient balance'
        });
      }
    }
    
    // Calculate converted amount
    const convertedAmount = amount * rate;
    
    // Update portfolio
    if (fromCoin !== 'usd') {
      // Remove fromCoin from portfolio
      user.portfolio = user.portfolio.map(item => {
        if (item.coinId === fromCoin) {
          return { ...item, amount: item.amount - amount };
        }
        return item;
      }).filter(item => item.amount > 0);
    } else {
      // Deduct from balance if converting from USD
      user.balance -= amount;
    }
    
    // Add toCoin to portfolio or balance
    if (toCoin !== 'usd') {
      const toCoinIndex = user.portfolio.findIndex(item => item.coinId === toCoin);
      if (toCoinIndex >= 0) {
        user.portfolio[toCoinIndex].amount += convertedAmount;
      } else {
        // Get coin details for new portfolio item
        const coins = {
          bitcoin: { symbol: 'btc', name: 'Bitcoin' },
          ethereum: { symbol: 'eth', name: 'Ethereum' },
          ripple: { symbol: 'xrp', name: 'XRP' },
          litecoin: { symbol: 'ltc', name: 'Litecoin' },
          cardano: { symbol: 'ada', name: 'Cardano' }
        };
        
        const coinDetails = coins[toCoin] || { symbol: toCoin, name: toCoin };
        user.portfolio.push({ 
          coinId: toCoin, 
          symbol: coinDetails.symbol, 
          name: coinDetails.name, 
          amount: convertedAmount 
        });
      }
    } else {
      // Add to balance if converting to USD
      user.balance += convertedAmount;
    }
    
    // Add transaction
    user.transactions.push({
      type: 'conversion',
      amount,
      coin: `${fromCoin}_to_${toCoin}`,
      status: 'completed',
      details: {
        fromCoin,
        toCoin,
        amount,
        rate,
        convertedAmount
      }
    });
    
    // Add trade
    user.trades.push({
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate,
      value: convertedAmount,
      status: 'completed'
    });
    
    await user.save();
    
    // Send WebSocket updates
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: user.portfolio });
    sendToUser(user._id, 'CONVERSION_COMPLETE', {
      fromCoin,
      toCoin,
      amount,
      convertedAmount,
      rate
    });
    
    res.json({ 
      success: true,
      message: 'Conversion successful',
      fromCoin,
      toCoin,
      amount,
      convertedAmount,
      rate,
      balance: user.balance,
      portfolio: user.portfolio
    });
    
  } catch (err) {
    console.error('Convert coins error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during conversion'
    });
  }
});

/**
 * @api {get} /api/v1/exchange/history Get conversion history
 * @apiName GetConversionHistory
 * @apiGroup Exchange
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} trades List of conversion trades
 */
app.get('/api/v1/exchange/history', authenticate, authorizeUser, async (req, res) => {
  try {
    const user = req.user;
    
    // Filter conversion trades
    const conversionTrades = user.trades.filter(trade => trade.type === 'convert');
    
    res.json({
      success: true,
      trades: conversionTrades
    });
    
  } catch (err) {
    console.error('Get conversion history error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching conversion history'
    });
  }
});

// ======================
// Market Data Routes
// ======================

/**
 * @api {get} /api/v1/market/data Get market data
 * @apiName GetMarketData
 * @apiGroup Market
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} marketData List of market data
 */
app.get('/api/v1/market/data', async (req, res) => {
  try {
    // In a real app, you would fetch this from a crypto API
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
      },
      { 
        id: 'ripple', 
        symbol: 'xrp', 
        name: 'XRP', 
        price: 1, 
        change24h: 0.5,
        marketCap: 50000000000,
        volume: 2000000000,
        circulatingSupply: 50000000000,
        allTimeHigh: 3.5,
        allTimeLow: 0.002
      },
      { 
        id: 'litecoin', 
        symbol: 'ltc', 
        name: 'Litecoin', 
        price: 250, 
        change24h: 3.1,
        marketCap: 17500000000,
        volume: 1000000000,
        circulatingSupply: 70000000,
        allTimeHigh: 400,
        allTimeLow: 1
      },
      { 
        id: 'cardano', 
        symbol: 'ada', 
        name: 'Cardano', 
        price: 1, 
        change24h: -0.8,
        marketCap: 35000000000,
        volume: 500000000,
        circulatingSupply: 35000000000,
        allTimeHigh: 3,
        allTimeLow: 0.02
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

/**
 * @api {get} /api/v1/market/detailed Get detailed market data
 * @apiName GetDetailedMarketData
 * @apiGroup Market
 * 
 * @apiParam {String} coinId Coin ID
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} coin Detailed coin data
 */
app.get('/api/v1/market/detailed', async (req, res) => {
  try {
    const { coinId } = req.query;
    
    if (!coinId) {
      return res.status(400).json({ 
        success: false,
        error: 'Coin ID is required'
      });
    }
    
    // In a real app, you would fetch this from a crypto API
    const coins = {
      bitcoin: { 
        id: 'bitcoin', 
        symbol: 'btc', 
        name: 'Bitcoin', 
        price: 50000, 
        change24h: 2.5,
        marketCap: 950000000000,
        volume: 25000000000,
        circulatingSupply: 19000000,
        maxSupply: 21000000,
        allTimeHigh: 69000,
        allTimeLow: 0.01,
        description: 'Bitcoin is a decentralized digital currency, without a central bank or single administrator.',
        website: 'https://bitcoin.org',
        whitepaper: 'https://bitcoin.org/bitcoin.pdf',
        explorers: ['https://blockchain.info', 'https://blockstream.info'],
        community: {
          twitter: 'https://twitter.com/bitcoin',
          reddit: 'https://reddit.com/r/bitcoin',
          telegram: 'https://t.me/bitcoin'
        },
        chartData: {
          labels: ['1h', '24h', '7d', '30d', '90d', '1y'],
          prices: [49800, 48750, 45500, 42000, 38000, 29000]
        }
      },
      ethereum: { 
        id: 'ethereum', 
        symbol: 'eth', 
        name: 'Ethereum', 
        price: 3000, 
        change24h: -1.2,
        marketCap: 360000000000,
        volume: 15000000000,
        circulatingSupply: 120000000,
        maxSupply: null,
        allTimeHigh: 4800,
        allTimeLow: 0.5,
        description: 'Ethereum is a decentralized, open-source blockchain with smart contract functionality.',
        website: 'https://ethereum.org',
        whitepaper: 'https://ethereum.org/en/whitepaper/',
        explorers: ['https://etherscan.io', 'https://ethplorer.io'],
        community: {
          twitter: 'https://twitter.com/ethereum',
          reddit: 'https://reddit.com/r/ethereum',
          telegram: 'https://t.me/ethereum'
        },
        chartData: {
          labels: ['1h', '24h', '7d', '30d', '90d', '1y'],
          prices: [3020, 3035, 2950, 2800, 2500, 1800]
        }
      }
    };
    
    const coin = coins[coinId];
    
    if (!coin) {
      return res.status(404).json({ 
        success: false,
        error: 'Coin not found'
      });
    }
    
    res.json({ 
      success: true,
      coin 
    });
    
  } catch (err) {
    console.error('Get detailed market data error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching detailed market data'
    });
  }
});

// ======================
// Wallet Routes
// ======================

/**
 * @api {post} /api/v1/wallet/deposit Deposit funds
 * @apiName DepositFunds
 * @apiGroup Wallet
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} amount Amount to deposit
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Number} balance Updated balance
 */
app.post('/api/v1/wallet/deposit', authenticate, authorizeUser, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = req.user;
    
    // Validation
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid amount is required'
      });
    }
    
    // Update user balance
    user.balance += amount;
    
    // Add transaction
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
    
    // Send WebSocket update
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id, 'DEPOSIT_SUCCESS', { amount });
    
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

/**
 * @api {get} /api/v1/wallet/deposit-address Get deposit address
 * @apiName GetDepositAddress
 * @apiGroup Wallet
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} coin Coin to deposit
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} address Deposit address
 * @apiSuccess {String} memo Memo (if required)
 */
app.get('/api/v1/wallet/deposit-address', authenticate, authorizeUser, async (req, res) => {
  try {
    const { coin } = req.query;
    const user = req.user;
    
    if (!coin) {
      return res.status(400).json({ 
        success: false,
        error: 'Coin is required'
      });
    }
    
    // In a real app, you would generate or fetch a real deposit address
    const address = `DEPOSIT-${coin.toUpperCase()}-${user._id.toString().slice(-8)}`;
    const memo = coin === 'xrp' || coin === 'xlm' ? user._id.toString() : undefined;
    
    res.json({
      success: true,
      address,
      memo
    });
    
  } catch (err) {
    console.error('Get deposit address error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching deposit address'
    });
  }
});

/**
 * @api {post} /api/v1/wallet/withdraw Withdraw funds
 * @apiName WithdrawFunds
 * @apiGroup Wallet
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} amount Amount to withdraw
 * @apiParam {String} address Withdrawal address
 * @apiParam {String} [memo] Memo (if required)
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Number} balance Updated balance
 */
app.post('/api/v1/wallet/withdraw', authenticate, authorizeUser, async (req, res) => {
  try {
    const { amount, address, memo } = req.body;
    const user = req.user;
    
    // Validation
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid amount is required'
      });
    }
    
    if (!address) {
      return res.status(400).json({ 
        success: false,
        error: 'Withdrawal address is required'
      });
    }
    
    if (user.balance < amount) {
      return res.status(400).json({ 
        success: false,
        error: 'Insufficient balance'
      });
    }
    
    // Update user balance
    user.balance -= amount;
    
    // Add transaction
    user.transactions.push({
      type: 'withdrawal',
      amount,
      coin: 'USD',
      status: 'pending',
      details: {
        address,
        memo,
        reference: `WDR-${Date.now()}`
      }
    });
    
    await user.save();
    
    // Send WebSocket update
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    sendToUser(user._id, 'WITHDRAWAL_REQUESTED', { amount });
    
    // In a real app, you would process the withdrawal here
    
    res.json({ 
      success: true,
      message: 'Withdrawal request submitted',
      balance: user.balance
    });
    
  } catch (err) {
    console.error('Withdraw error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error during withdrawal'
    });
  }
});

/**
 * @api {get} /api/v1/transactions/recent Get recent transactions
 * @apiName GetRecentTransactions
 * @apiGroup Wallet
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} [limit=10] Number of transactions to return
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} transactions List of transactions
 */
app.get('/api/v1/transactions/recent', authenticate, authorizeUser, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const user = req.user;
    
    // Get most recent transactions
    const transactions = user.transactions
      .sort((a, b) => b.date - a.date)
      .slice(0, parseInt(limit));
    
    res.json({
      success: true,
      transactions
    });
    
  } catch (err) {
    console.error('Get recent transactions error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching transactions'
    });
  }
});

// ======================
// Support Routes
// ======================

/**
 * @api {get} /api/v1/support/faqs Get FAQs
 * @apiName GetFAQs
 * @apiGroup Support
 * 
 * @apiParam {String} [category] Filter by category
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} faqs List of FAQs
 */
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const { category } = req.query;
    let query = { isActive: true };
    
    if (category) {
      query.category = category;
    }
    
    const faqs = await FAQ.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      faqs
    });
    
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching FAQs'
    });
  }
});

/**
 * @api {post} /api/v1/support/tickets Create support ticket
 * @apiName CreateSupportTicket
 * @apiGroup Support
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} subject Ticket subject
 * @apiParam {String} message Ticket message
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} ticket Created ticket
 */
app.post('/api/v1/support/tickets', authenticate, authorizeUser, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const user = req.user;
    
    // Validation
    if (!subject || !message) {
      return res.status(400).json({ 
        success: false,
        error: 'Subject and message are required'
      });
    }
    
    // Create ticket
    const ticket = new SupportTicket({
      userId: user._id,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    // Notify admins
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

/**
 * @api {get} /api/v1/support/tickets Get user support tickets
 * @apiName GetSupportTickets
 * @apiGroup Support
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} [status] Filter by status
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} tickets List of tickets
 */
app.get('/api/v1/support/tickets', authenticate, authorizeUser, async (req, res) => {
  try {
    const { status } = req.query;
    const user = req.user;
    
    let query = { userId: user._id };
    if (status) {
      query.status = status;
    }
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .select('-responses');
    
    res.json({
      success: true,
      tickets
    });
    
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching support tickets'
    });
  }
});

/**
 * @api {get} /api/v1/support/tickets/:id Get ticket details
 * @apiName GetTicketDetails
 * @apiGroup Support
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} ticket Ticket details
 * @apiSuccess {Object[]} responses Ticket responses
 */
app.get('/api/v1/support/tickets/:id', authenticate, authorizeUser, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    res.json({
      success: true,
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        message: ticket.message,
        status: ticket.status,
        createdAt: ticket.createdAt,
        updatedAt: ticket.updatedAt
      },
      responses: ticket.responses
    });
    
  } catch (err) {
    console.error('Get ticket details error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching ticket details'
    });
  }
});

/**
 * @api {post} /api/v1/support/tickets/:id/reply Reply to ticket
 * @apiName ReplyToTicket
 * @apiGroup Support
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} message Reply message
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} response New response
 */
app.post('/api/v1/support/tickets/:id/reply', authenticate, authorizeUser, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ 
        success: false,
        error: 'Message is required'
      });
    }
    
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    if (ticket.status === 'closed') {
      return res.status(400).json({ 
        success: false,
        error: 'Cannot reply to closed ticket'
      });
    }
    
    // Add response
    ticket.responses.push({
      userId: req.user._id,
      message,
      isAdmin: false,
      createdAt: new Date()
    });
    
    // Update status
    ticket.status = 'pending';
    ticket.updatedAt = new Date();
    
    await ticket.save();
    
    // Notify admins
    broadcastToAdmins('TICKET_REPLY', {
      ticketId: ticket._id,
      subject: ticket.subject,
      userId: req.user._id,
      email: req.user.email
    });
    
    const newResponse = ticket.responses[ticket.responses.length - 1];
    
    res.json({
      success: true,
      message: 'Reply submitted successfully',
      response: {
        id: newResponse._id,
        message: newResponse.message,
        isAdmin: newResponse.isAdmin,
        createdAt: newResponse.createdAt
      }
    });
    
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error replying to ticket'
    });
  }
});

// ======================
// Admin Routes
// ======================

/**
 * @api {get} /api/v1/admin/dashboard-stats Get dashboard stats
 * @apiName GetDashboardStats
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Number} totalUsers Total users
 * @apiSuccess {Number} verifiedUsers Verified users
 * @apiSuccess {Number} activeUsers Active users (last 30 days)
 * @apiSuccess {Number} totalBalance Total platform balance
 * @apiSuccess {Number} totalTrades Total trades
 * @apiSuccess {Number} totalVolume Total trading volume
 * @apiSuccess {Object[]} recentSignups Recent signups
 */
app.get('/api/v1/admin/dashboard-stats', authenticate, authorizeAdmin, async (req, res) => {
  try {
    // Total users
    const totalUsers = await User.countDocuments();
    
    // Verified users
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    
    // Active users (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const activeUsers = await User.countDocuments({ lastLogin: { $gte: thirtyDaysAgo } });
    
    // Total platform balance
    const totalBalanceResult = await User.aggregate([
      { $group: { _id: null, total: { $sum: "$balance" } } }
    ]);
    const totalBalance = totalBalanceResult[0]?.total || 0;
    
    // Total trades
    const totalTradesResult = await User.aggregate([
      { $unwind: "$trades" },
      { $group: { _id: null, count: { $sum: 1 } } }
    ]);
    const totalTrades = totalTradesResult[0]?.count || 0;
    
    // Total volume
    const totalVolumeResult = await User.aggregate([
      { $unwind: "$trades" },
      { $group: { _id: null, total: { $sum: "$trades.value" } } }
    ]);
    const totalVolume = totalVolumeResult[0]?.total || 0;
    
    // Recent signups (last 7 days)
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

/**
 * @api {get} /api/v1/admin/users Get all users
 * @apiName GetAllUsers
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} [page=1] Page number
 * @apiParam {Number} [limit=10] Users per page
 * @apiParam {String} [search] Search query
 * @apiParam {String} [sort] Sort field
 * @apiParam {String} [order=asc] Sort order (asc/desc)
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} users List of users
 * @apiSuccess {Number} total Total users count
 * @apiSuccess {Number} page Current page
 * @apiSuccess {Number} pages Total pages
 */
app.get('/api/v1/admin/users', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, sort, order = 'asc' } = req.query;
    
    let query = {};
    let sortOption = { createdAt: -1 };
    
    // Search
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Sort
    if (sort) {
      sortOption = { [sort]: order === 'asc' ? 1 : -1 };
    }
    
    // Count total users
    const total = await User.countDocuments(query);
    
    // Calculate pagination
    const pages = Math.ceil(total / limit);
    const skip = (page - 1) * limit;
    
    // Get users
    const users = await User.find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -verificationToken -resetPasswordToken');
    
    res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages
    });
    
  } catch (err) {
    console.error('Get all users error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching users'
    });
  }
});

/**
 * @api {get} /api/v1/admin/users/:id Get user details
 * @apiName GetUserDetails
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} user User details
 */
app.get('/api/v1/admin/users/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -verificationToken -resetPasswordToken');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    res.json({
      success: true,
      user
    });
    
  } catch (err) {
    console.error('Get user details error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching user details'
    });
  }
});

/**
 * @api {patch} /api/v1/admin/users/:id/status Update user status
 * @apiName UpdateUserStatus
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Boolean} isActive User active status
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user
 */
app.patch('/api/v1/admin/users/:id/status', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { isActive } = req.body;
    
    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ 
        success: false,
        error: 'isActive must be a boolean'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive },
      { new: true }
    ).select('-password -verificationToken -resetPasswordToken');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'User status updated',
      user
    });
    
  } catch (err) {
    console.error('Update user status error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating user status'
    });
  }
});

/**
 * @api {patch} /api/v1/admin/users/:id/balance Update user balance
 * @apiName UpdateUserBalance
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} balance New balance
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user
 */
app.patch('/api/v1/admin/users/:id/balance', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { balance } = req.body;
    
    if (typeof balance !== 'number' || balance < 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Balance must be a positive number'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { balance },
      { new: true }
    ).select('-password -verificationToken -resetPasswordToken');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    // Send WebSocket update to user
    sendToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    
    res.json({
      success: true,
      message: 'User balance updated',
      user
    });
    
  } catch (err) {
    console.error('Update user balance error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating user balance'
    });
  }
});

/**
 * @api {post} /api/v1/admin/users/:id/reset-password Reset user password
 * @apiName ResetUserPassword
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
app.post('/api/v1/admin/users/:id/reset-password', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    // Generate a random password
    const newPassword = crypto.randomBytes(8).toString('hex');
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    await user.save();
    
    // Send email with new password
    const emailContent = {
      subject: 'Your Password Has Been Reset',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Password Reset</h2>
          <p>Your password has been reset by an administrator.</p>
          <p>Your new temporary password is: <strong>${newPassword}</strong></p>
          <p>Please log in and change your password immediately for security reasons.</p>
        </div>
      `
    };
    
    await sendEmail(user.email, emailContent.subject, emailContent.html);
    
    res.json({
      success: true,
      message: 'Password reset and email sent'
    });
    
  } catch (err) {
    console.error('Reset user password error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error resetting password'
    });
  }
});

/**
 * @api {get} /api/v1/admin/tickets Get all support tickets
 * @apiName GetAllSupportTickets
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {Number} [page=1] Page number
 * @apiParam {Number} [limit=10] Tickets per page
 * @apiParam {String} [status] Filter by status
 * @apiParam {String} [search] Search query
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} tickets List of tickets
 * @apiSuccess {Number} total Total tickets count
 * @apiSuccess {Number} page Current page
 * @apiSuccess {Number} pages Total pages
 */
app.get('/api/v1/admin/tickets', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, search } = req.query;
    
    let query = {};
    
    // Status filter
    if (status) {
      query.status = status;
    }
    
    // Search
    if (search) {
      query.$or = [
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } },
        { 'user.email': { $regex: search, $options: 'i' } }
      ];
    }
    
    // Count total tickets
    const total = await SupportTicket.countDocuments(query);
    
    // Calculate pagination
    const pages = Math.ceil(total / limit);
    const skip = (page - 1) * limit;
    
    // Get tickets with user info
    const tickets = await SupportTicket.aggregate([
      { $match: query },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: parseInt(limit) },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      { $unwind: '$user' },
      {
        $project: {
          _id: 1,
          subject: 1,
          status: 1,
          createdAt: 1,
          updatedAt: 1,
          'user._id': 1,
          'user.firstName': 1,
          'user.lastName': 1,
          'user.email': 1
        }
      }
    ]);
    
    res.json({
      success: true,
      tickets,
      total,
      page: parseInt(page),
      pages
    });
    
  } catch (err) {
    console.error('Get all tickets error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching support tickets'
    });
  }
});

/**
 * @api {get} /api/v1/admin/tickets/:id Get ticket details
 * @apiName GetAdminTicketDetails
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} ticket Ticket details
 * @apiSuccess {Object} user User details
 * @apiSuccess {Object[]} responses Ticket responses
 */
app.get('/api/v1/admin/tickets/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    // Get user info
    const user = await User.findById(ticket.userId)
      .select('firstName lastName email createdAt');
    
    res.json({
      success: true,
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        message: ticket.message,
        status: ticket.status,
        createdAt: ticket.createdAt,
        updatedAt: ticket.updatedAt
      },
      user,
      responses: ticket.responses
    });
    
  } catch (err) {
    console.error('Get ticket details error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching ticket details'
    });
  }
});

/**
 * @api {post} /api/v1/admin/tickets/:id/assign Assign ticket
 * @apiName AssignTicket
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} adminId Admin ID to assign
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} ticket Updated ticket
 */
app.post('/api/v1/admin/tickets/:id/assign', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { adminId } = req.body;
    
    if (!adminId) {
      return res.status(400).json({ 
        success: false,
        error: 'Admin ID is required'
      });
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { assignedTo: adminId, status: 'pending' },
      { new: true }
    );
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    // Notify user
    sendToUser(ticket.userId, 'TICKET_UPDATED', {
      ticketId: ticket._id,
      status: ticket.status,
      assignedTo: adminId
    });
    
    res.json({
      success: true,
      message: 'Ticket assigned successfully',
      ticket: {
        id: ticket._id,
        status: ticket.status,
        assignedTo: ticket.assignedTo
      }
    });
    
  } catch (err) {
    console.error('Assign ticket error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error assigning ticket'
    });
  }
});

/**
 * @api {post} /api/v1/admin/tickets/:id/reply Admin reply to ticket
 * @apiName AdminReplyToTicket
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} message Reply message
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} response New response
 */
app.post('/api/v1/admin/tickets/:id/reply', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ 
        success: false,
        error: 'Message is required'
      });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    if (ticket.status === 'closed') {
      return res.status(400).json({ 
        success: false,
        error: 'Cannot reply to closed ticket'
      });
    }
    
    // Add response
    ticket.responses.push({
      userId: req.admin._id,
      message,
      isAdmin: true,
      createdAt: new Date()
    });
    
    // Update status
    ticket.status = 'pending';
    ticket.updatedAt = new Date();
    
    await ticket.save();
    
    // Notify user
    sendToUser(ticket.userId, 'TICKET_REPLY', {
      ticketId: ticket._id,
      subject: ticket.subject
    });
    
    const newResponse = ticket.responses[ticket.responses.length - 1];
    
    res.json({
      success: true,
      message: 'Reply submitted successfully',
      response: {
        id: newResponse._id,
        message: newResponse.message,
        isAdmin: newResponse.isAdmin,
        createdAt: newResponse.createdAt
      }
    });
    
  } catch (err) {
    console.error('Admin reply to ticket error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error replying to ticket'
    });
  }
});

/**
 * @api {patch} /api/v1/admin/tickets/:id/status Update ticket status
 * @apiName UpdateTicketStatus
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} status New status
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} ticket Updated ticket
 */
app.patch('/api/v1/admin/tickets/:id/status', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['open', 'pending', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid status'
      });
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!ticket) {
      return res.status(404).json({ 
        success: false,
        error: 'Ticket not found'
      });
    }
    
    // Notify user if status changed to resolved or closed
    if (status === 'resolved' || status === 'closed') {
      sendToUser(ticket.userId, 'TICKET_UPDATED', {
        ticketId: ticket._id,
        status: ticket.status
      });
    }
    
    res.json({
      success: true,
      message: 'Ticket status updated',
      ticket: {
        id: ticket._id,
        status: ticket.status
      }
    });
    
  } catch (err) {
    console.error('Update ticket status error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error updating ticket status'
    });
  }
});

/**
 * @api {get} /api/v1/admin/kyc Get KYC submissions
 * @apiName GetKYCSubmissions
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} [status] Filter by status
 * @apiParam {Number} [page=1] Page number
 * @apiParam {Number} [limit=10] Items per page
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} submissions List of KYC submissions
 * @apiSuccess {Number} total Total submissions count
 * @apiSuccess {Number} page Current page
 * @apiSuccess {Number} pages Total pages
 */
app.get('/api/v1/admin/kyc', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    let query = {};
    
    // Status filter
    if (status) {
      query['kyc.status'] = status;
    } else {
      query['kyc.status'] = { $ne: 'none' };
    }
    
    // Count total submissions
    const total = await User.countDocuments(query);
    
    // Calculate pagination
    const pages = Math.ceil(total / limit);
    const skip = (page - 1) * limit;
    
    // Get submissions with user info
    const submissions = await User.find(query)
      .sort({ 'kyc.submittedAt': -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('firstName lastName email kyc createdAt');
    
    res.json({
      success: true,
      submissions,
      total,
      page: parseInt(page),
      pages
    });
    
  } catch (err) {
    console.error('Get KYC submissions error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching KYC submissions'
    });
  }
});

/**
 * @api {get} /api/v1/admin/kyc/:id Get KYC details
 * @apiName GetKYCDetails
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} user User details
 * @apiSuccess {Object} kyc KYC details
 */
app.get('/api/v1/admin/kyc/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('firstName lastName email kyc createdAt');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    if (user.kyc.status === 'none') {
      return res.status(404).json({ 
        success: false,
        error: 'No KYC submission found for this user'
      });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        createdAt: user.createdAt
      },
      kyc: user.kyc
    });
    
  } catch (err) {
    console.error('Get KYC details error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching KYC details'
    });
  }
});

/**
 * @api {post} /api/v1/admin/kyc/:id/approve Approve KYC
 * @apiName ApproveKYC
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
app.post('/api/v1/admin/kyc/:id/approve', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    if (user.kyc.status !== 'pending') {
      return res.status(400).json({ 
        success: false,
        error: 'KYC is not in pending status'
      });
    }
    
    // Update KYC status
    user.kyc.status = 'verified';
    user.kyc.verifiedAt = new Date();
    
    await user.save();
    
    // Notify user
    sendToUser(user._id, 'KYC_APPROVED', {
      status: user.kyc.status,
      verifiedAt: user.kyc.verifiedAt
    });
    
    res.json({
      success: true,
      message: 'KYC approved successfully'
    });
    
  } catch (err) {
    console.error('Approve KYC error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error approving KYC'
    });
  }
});

/**
 * @api {post} /api/v1/admin/kyc/:id/reject Reject KYC
 * @apiName RejectKYC
 * @apiGroup Admin
 * 
 * @apiHeader {String} Authorization Bearer token
 * 
 * @apiParam {String} reason Rejection reason
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {String} message Success message
 */
app.post('/api/v1/admin/kyc/:id/reject', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ 
        success: false,
        error: 'Reason is required'
      });
    }
    
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }
    
    if (user.kyc.status !== 'pending') {
      return res.status(400).json({ 
        success: false,
        error: 'KYC is not in pending status'
      });
    }
    
    // Update KYC status
    user.kyc.status = 'rejected';
    user.kyc.rejectionReason = reason;
    
    await user.save();
    
    // Notify user
    sendToUser(user._id, 'KYC_REJECTED', {
      status: user.kyc.status,
      rejectionReason: user.kyc.rejectionReason
    });
    
    res.json({
      success: true,
      message: 'KYC rejected successfully'
    });
    
  } catch (err) {
    console.error('Reject KYC error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error rejecting KYC'
    });
  }
});

// ======================
// About Page Routes
// ======================

/**
 * @api {get} /api/v1/about Get about page data
 * @apiName GetAboutData
 * @apiGroup About
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object} stats Platform statistics
 * @apiSuccess {Object[]} team Team members
 */
app.get('/api/v1/about', async (req, res) => {
  try {
    // Platform statistics
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const totalBalanceResult = await User.aggregate([
      { $group: { _id: null, total: { $sum: "$balance" } } }
    ]);
    const totalBalance = totalBalanceResult[0]?.total || 0;
    const totalTradesResult = await User.aggregate([
      { $unwind: "$trades" },
      { $group: { _id: null, count: { $sum: 1 } } }
    ]);
    const totalTrades = totalTradesResult[0]?.count || 0;
    
    // Team members (hardcoded for this example)
    const team = [
      {
        id: 1,
        name: 'John Doe',
        position: 'CEO & Founder',
        bio: 'Blockchain expert with 10+ years of experience in cryptocurrency trading.',
        avatar: 'https://website-xi-ten-52.vercel.app/images/team/john.jpg'
      },
      {
        id: 2,
        name: 'Jane Smith',
        position: 'CTO',
        bio: 'Full-stack developer specializing in blockchain technologies and security.',
        avatar: 'https://website-xi-ten-52.vercel.app/images/team/jane.jpg'
      },
      {
        id: 3,
        name: 'Mike Johnson',
        position: 'Lead Trader',
        bio: 'Professional trader with extensive experience in crypto arbitrage strategies.',
        avatar: 'https://website-xi-ten-52.vercel.app/images/team/mike.jpg'
      }
    ];
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        verifiedUsers,
        totalBalance,
        totalTrades
      },
      team
    });
    
  } catch (err) {
    console.error('Get about data error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching about data'
    });
  }
});

// ======================
// FAQ Routes
// ======================

/**
 * @api {get} /api/v1/faqs Get all FAQs
 * @apiName GetFAQs
 * @apiGroup FAQ
 * 
 * @apiParam {String} [category] Filter by category
 * 
 * @apiSuccess {Boolean} success Request status
 * @apiSuccess {Object[]} faqs List of FAQs
 */
app.get('/api/v1/faqs', async (req, res) => {
  try {
    const { category } = req.query;
    let query = { isActive: true };
    
    if (category) {
      query.category = category;
    }
    
    const faqs = await FAQ.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      faqs
    });
    
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Server error fetching FAQs'
    });
  }
});

// ======================
// Initialize Admin Account
// ======================

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
