require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const morgan = require('morgan');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');

// Environment configuration
const config = {
  PORT: process.env.PORT || 3000,
  MONGODB_URI: 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0',
  JWT_SECRET: '17581758Na.%',
  JWT_EXPIRES_IN: '30d',
  REDIS_CONFIG: {
    host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
    port: 14450,
    password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
  },
  SMTP_CONFIG: {
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
      user: '7c707ac161af1c',
      pass: '6c08aa4f2c679a'
    }
  },
  FRONTEND_URL: 'https://bithhash.vercel.app',
  GOOGLE_CLIENT_ID: '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  BTC_DEPOSIT_ADDRESS: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
  ADMIN_EMAIL: 'admin@bithash.com',
  ADMIN_PASSWORD: 'BithashAdmin@2023!'
};

// Initialize Redis client
const redis = new Redis(config.REDIS_CONFIG);

// Initialize SMTP transporter
const transporter = nodemailer.createTransport(config.SMTP_CONFIG);

// Initialize Google OAuth client
const googleClient = new OAuth2Client(config.GOOGLE_CLIENT_ID);

// MongoDB connection
mongoose.connect(config.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
  maxPoolSize: 50
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// MongoDB models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  googleId: { type: String, unique: true, sparse: true },
  city: { type: String },
  balance: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    savings: { type: Number, default: 0 }
  },
  isVerified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  twoFactorEnabled: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
}, { timestamps: true });

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'earning', 'bonus', 'loan'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'BTC' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String },
  address: { type: String },
  txHash: { type: String },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const InvestmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planId: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  expectedReturn: { type: Number, required: true }
});

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  returnRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number },
  isActive: { type: Boolean, default: true }
});

const KYCSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  documentType: { type: String, required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNotes: { type: String },
  submittedAt: { type: Date, default: Date.now },
  reviewedAt: { type: Date }
});

const AdminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  details: { type: Object },
  ipAddress: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Investment = mongoose.model('Investment', InvestmentSchema);
const Plan = mongoose.model('Plan', PlanSchema);
const KYC = mongoose.model('KYC', KYCSchema);
const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

// Initialize default admin
async function initializeAdmin() {
  try {
    const adminExists = await User.findOne({ email: config.ADMIN_EMAIL });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(config.ADMIN_PASSWORD, 12);
      const admin = new User({
        firstName: 'Admin',
        lastName: 'Bithash',
        email: config.ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true,
        isVerified: true,
        referralCode: crypto.randomBytes(4).toString('hex').toUpperCase(),
        balance: {
          main: 1000,
          active: 0,
          matured: 0,
          savings: 0
        }
      });
      await admin.save();
      console.log('Default admin account created');
    }
  } catch (err) {
    console.error('Error initializing admin:', err);
  }
}

// Initialize default plans
async function initializePlans() {
  try {
    const plans = await Plan.countDocuments();
    if (plans === 0) {
      const defaultPlans = [
        {
          name: 'Starter Plan',
          description: 'Perfect for beginners in crypto mining',
          returnRate: 5,
          duration: 7,
          minAmount: 0.01,
          maxAmount: 0.5
        },
        {
          name: 'Advanced Plan',
          description: 'For experienced investors with higher returns',
          returnRate: 8,
          duration: 14,
          minAmount: 0.5,
          maxAmount: 2
        },
        {
          name: 'Professional Plan',
          description: 'Maximum returns for serious investors',
          returnRate: 12,
          duration: 30,
          minAmount: 2,
          maxAmount: 10
        }
      ];
      await Plan.insertMany(defaultPlans);
      console.log('Default investment plans created');
    }
  } catch (err) {
    console.error('Error initializing plans:', err);
  }
}

// Express app setup
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res) => {
    res.status(429).json({
      status: 'error',
      message: 'Too many requests, please try again later.'
    });
  }
});

// Apply rate limiting to API routes
app.use('/api/', apiLimiter);

// Logging
app.use(morgan('combined'));

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: 'You are not logged in. Please log in to get access.'
      });
    }

    // Check Redis for blacklisted tokens
    const isBlacklisted = await redis.get(`blacklist:${token}`);
    if (isBlacklisted) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid token. Please log in again.'
      });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);
    const currentUser = await User.findById(decoded.id).select('+lastLogin');

    if (!currentUser) {
      return res.status(401).json({
        status: 'error',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({
      status: 'error',
      message: 'You do not have permission to perform this action.'
    });
  }
  next();
};

// Helper functions
const signToken = (id) => {
  return jwt.sign({ id }, config.JWT_SECRET, {
    expiresIn: config.JWT_EXPIRES_IN
  });
};

const sendEmail = async (to, subject, text, html) => {
  try {
    await transporter.sendMail({
      from: '"Bithash Support" <support@bithash.com>',
      to,
      subject,
      text,
      html
    });
  } catch (err) {
    console.error('Error sending email:', err);
  }
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Bithash API is running'
  });
});

// Auth routes
app.post('/api/auth/signup', [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, password, city, referredBy } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'error',
        message: 'Email already in use'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate referral code
    const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();

    // Create user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      referralCode,
      referredBy: referredBy || null
    });

    await newUser.save();

    // Send welcome email
    const welcomeEmail = `
      <h1>Welcome to Bithash, ${firstName}!</h1>
      <p>Your account has been successfully created.</p>
      <p>Start investing in our Bitcoin mining plans today!</p>
      <p>Your referral code: <strong>${referralCode}</strong></p>
    `;
    await sendEmail(email, 'Welcome to Bithash', `Welcome to Bithash, ${firstName}!`, welcomeEmail);

    // Sign token
    const token = signToken(newUser._id);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email,
          isVerified: newUser.isVerified,
          balance: newUser.balance
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

app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Incorrect email or password'
      });
    }

    // Check if password is correct
    const isCorrect = await bcrypt.compare(password, user.password);
    if (!isCorrect) {
      return res.status(401).json({
        status: 'error',
        message: 'Incorrect email or password'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Sign token
    const token = signToken(user._id);

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isAdmin: user.isAdmin,
          isVerified: user.isVerified,
          balance: user.balance
        }
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
    });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: config.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();

    // Check if user exists
    let user = await User.findOne({ email: payload.email });

    if (!user) {
      // Create new user
      const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
      user = new User({
        firstName: payload.given_name,
        lastName: payload.family_name,
        email: payload.email,
        googleId: payload.sub,
        isVerified: true,
        referralCode
      });
      await user.save();

      // Send welcome email
      const welcomeEmail = `
        <h1>Welcome to Bithash, ${payload.given_name}!</h1>
        <p>Your account has been successfully created with Google.</p>
        <p>Start investing in our Bitcoin mining plans today!</p>
        <p>Your referral code: <strong>${referralCode}</strong></p>
      `;
      await sendEmail(payload.email, 'Welcome to Bithash', `Welcome to Bithash, ${payload.given_name}!`, welcomeEmail);
    } else if (!user.googleId) {
      // Update existing user with Google ID
      user.googleId = payload.sub;
      await user.save();
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Sign token
    const jwtToken = signToken(user._id);

    res.status(200).json({
      status: 'success',
      token: jwtToken,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isVerified: user.isVerified,
          balance: user.balance
        }
      }
    });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during Google authentication'
    });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // Add token to Redis blacklist
    const token = req.headers.authorization.split(' ')[1];
    await redis.set(`blacklist:${token}`, 'logged out', 'EX', 3600); // Expire in 1 hour

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during logout'
    });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'No user found with that email'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = Date.now() + 3600000; // 1 hour from now

    // Store token in Redis
    await redis.set(`reset:${resetToken}`, user._id.toString(), 'EX', 3600);

    // Send email with reset link
    const resetUrl = `${config.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const emailContent = `
      <h1>Password Reset Request</h1>
      <p>You requested a password reset for your Bithash account.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 1 hour.</p>
    `;
    await sendEmail(email, 'Password Reset Request', `Password Reset Link: ${resetUrl}`, emailContent);

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing your request'
    });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { token, password } = req.body;

    // Verify token
    const userId = await redis.get(`reset:${token}`);
    if (!userId) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid or expired token'
      });
    }

    // Update password
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    user.password = await bcrypt.hash(password, 12);
    await user.save();

    // Delete token from Redis
    await redis.del(`reset:${token}`);

    // Send confirmation email
    const emailContent = `
      <h1>Password Updated</h1>
      <p>Your Bithash account password has been successfully updated.</p>
      <p>If you did not make this change, please contact support immediately.</p>
    `;
    await sendEmail(user.email, 'Password Updated', 'Your password has been updated', emailContent);

    res.status(200).json({
      status: 'success',
      message: 'Password updated successfully'
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting your password'
    });
  }
});

// User routes
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -__v');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user data'
    });
  }
});

app.put('/api/users/profile', authenticate, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty'),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty'),
  body('city').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, city } = req.body;
    const user = await User.findById(req.user._id);

    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (city) user.city = city;

    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          city: user.city
        }
      }
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating your profile'
    });
  }
});

app.put('/api/users/password', authenticate, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    // Verify current password
    const isCorrect = await bcrypt.compare(currentPassword, user.password);
    if (!isCorrect) {
      return res.status(401).json({
        status: 'error',
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    // Send email notification
    const emailContent = `
      <h1>Password Changed</h1>
      <p>Your Bithash account password was successfully changed.</p>
      <p>If you did not make this change, please contact support immediately.</p>
    `;
    await sendEmail(user.email, 'Password Changed', 'Your password has been changed', emailContent);

    res.status(200).json({
      status: 'success',
      message: 'Password updated successfully'
    });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while changing your password'
    });
  }
});

// Balance and transaction routes
app.get('/api/users/balance', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('balance');

    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance
      }
    });
  } catch (err) {
    console.error('Get balance error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching your balance'
    });
  }
});

app.post('/api/transactions/deposit', authenticate, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('method').isIn(['btc', 'card']).withMessage('Invalid deposit method')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { amount, method } = req.body;
    const user = req.user;

    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      method,
      status: method === 'btc' ? 'pending' : 'completed',
      address: method === 'btc' ? config.BTC_DEPOSIT_ADDRESS : null
    });

    await transaction.save();

    // If card payment, update balance immediately
    if (method === 'card') {
      user.balance.main += amount;
      await user.save();
    }

    // Send email notification
    const emailContent = `
      <h1>Deposit Initiated</h1>
      <p>Your deposit of ${amount} BTC has been initiated.</p>
      ${method === 'btc' ? `<p>Please send the funds to: <strong>${config.BTC_DEPOSIT_ADDRESS}</strong></p>` : ''}
      <p>Transaction ID: ${transaction._id}</p>
    `;
    await sendEmail(user.email, 'Deposit Initiated', `Deposit of ${amount} BTC initiated`, emailContent);

    res.status(201).json({
      status: 'success',
      data: {
        transaction,
        depositAddress: method === 'btc' ? config.BTC_DEPOSIT_ADDRESS : null
      }
    });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing your deposit'
    });
  }
});

app.post('/api/transactions/withdraw', authenticate, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('address').notEmpty().withMessage('Withdrawal address is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { amount, address, notes } = req.body;
    const user = await User.findById(req.user._id);

    // Check sufficient balance
    if (user.balance.main < amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient balance for withdrawal'
      });
    }

    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      method: 'btc',
      status: 'pending',
      address,
      notes
    });

    await transaction.save();

    // Deduct from balance
    user.balance.main -= amount;
    await user.save();

    // Send email notification
    const emailContent = `
      <h1>Withdrawal Requested</h1>
      <p>Your withdrawal of ${amount} BTC has been requested.</p>
      <p>Destination address: <strong>${address}</strong></p>
      <p>Transaction ID: ${transaction._id}</p>
      <p>Note: Withdrawals may take up to 24 hours to process.</p>
    `;
    await sendEmail(user.email, 'Withdrawal Requested', `Withdrawal of ${amount} BTC requested`, emailContent);

    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing your withdrawal'
    });
  }
});

app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const { type, limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const query = { userId: req.user._id };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching transactions'
    });
  }
});

// Investment routes
app.get('/api/plans', async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true });

    res.status(200).json({
      status: 'success',
      data: {
        plans
      }
    });
  } catch (err) {
    console.error('Get plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investment plans'
    });
  }
});

app.post('/api/investments', authenticate, [
  body('planId').notEmpty().withMessage('Plan ID is required'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { planId, amount } = req.body;
    const user = await User.findById(req.user._id);

    // Get plan
    const plan = await Plan.findById(planId);
    if (!plan || !plan.isActive) {
      return res.status(404).json({
        status: 'error',
        message: 'Investment plan not found'
      });
    }

    // Check minimum amount
    if (amount < plan.minAmount) {
      return res.status(400).json({
        status: 'error',
        message: `Minimum investment amount is ${plan.minAmount} BTC`
      });
    }

    // Check maximum amount if defined
    if (plan.maxAmount && amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'error',
        message: `Maximum investment amount is ${plan.maxAmount} BTC`
      });
    }

    // Check sufficient balance
    if (user.balance.main < amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient balance for investment'
      });
    }

    // Calculate end date and expected return
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + plan.duration);
    const expectedReturn = amount * (1 + plan.returnRate / 100);

    // Create investment
    const investment = new Investment({
      userId: user._id,
      planId: plan._id,
      amount,
      endDate,
      expectedReturn
    });

    // Deduct from main balance and add to active balance
    user.balance.main -= amount;
    user.balance.active += amount;
    await user.save();

    await investment.save();

    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'investment',
      amount,
      status: 'completed'
    });
    await transaction.save();

    // Send email notification
    const emailContent = `
      <h1>Investment Created</h1>
      <p>You have successfully invested ${amount} BTC in the ${plan.name} plan.</p>
      <p>Expected return: ${expectedReturn.toFixed(8)} BTC in ${plan.duration} days.</p>
      <p>Investment ID: ${investment._id}</p>
    `;
    await sendEmail(user.email, 'Investment Created', `Investment of ${amount} BTC created`, emailContent);

    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (err) {
    console.error('Create investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating your investment'
    });
  }
});

app.get('/api/investments', authenticate, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const query = { userId: req.user._id };
    if (status) query.status = status;

    const investments = await Investment.find(query)
      .populate('planId', 'name returnRate duration')
      .sort({ startDate: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Investment.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        investments,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investments'
    });
  }
});

// KYC routes
app.post('/api/kyc', authenticate, [
  body('documentType').isIn(['passport', 'id_card', 'drivers_license']).withMessage('Invalid document type'),
  body('documentFront').notEmpty().withMessage('Document front image is required'),
  body('selfie').notEmpty().withMessage('Selfie image is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { documentType, documentFront, documentBack, selfie } = req.body;
    const user = req.user;

    // Check if user already has pending or approved KYC
    const existingKYC = await KYC.findOne({ userId: user._id, status: { $in: ['pending', 'approved'] } });
    if (existingKYC) {
      return res.status(400).json({
        status: 'error',
        message: existingKYC.status === 'pending' 
          ? 'You already have a pending KYC submission' 
          : 'Your KYC is already approved'
      });
    }

    // Create KYC submission
    const kyc = new KYC({
      userId: user._id,
      documentType,
      documentFront,
      documentBack,
      selfie
    });

    await kyc.save();

    // Update user KYC status
    user.kycStatus = 'pending';
    await user.save();

    // Send email notification
    const emailContent = `
      <h1>KYC Submitted</h1>
      <p>Your KYC documents have been successfully submitted for verification.</p>
      <p>This process may take up to 48 hours. You will be notified once your verification is complete.</p>
    `;
    await sendEmail(user.email, 'KYC Submitted', 'Your KYC has been submitted', emailContent);

    res.status(201).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while submitting your KYC'
    });
  }
});

app.get('/api/kyc', authenticate, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ userId: req.user._id });

    res.status(200).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    console.error('Get KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching your KYC status'
    });
  }
});

// Referral routes
app.get('/api/referrals', authenticate, async (req, res) => {
  try {
    const referrals = await User.find({ referredBy: req.user._id }).select('firstName lastName email createdAt');
    const referralEarnings = await Transaction.aggregate([
      { $match: { userId: req.user._id, type: 'bonus' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        referrals,
        referralEarnings: referralEarnings.length ? referralEarnings[0].total : 0,
        referralCode: req.user.referralCode,
        referralLink: `${config.FRONTEND_URL}/signup?ref=${req.user.referralCode}`
      }
    });
  } catch (err) {
    console.error('Get referrals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching referral data'
    });
  }
});

// Admin routes


// ======================
// Admin API Routes
// ======================

// Admin CSRF Protection Middleware
const adminCsrfProtection = (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }

    const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
    if (!csrfToken || !req.session.csrfToken || csrfToken !== req.session.csrfToken) {
        return res.status(403).json({
            success: false,
            message: 'Invalid CSRF token'
        });
    }
    next();
};

// Admin Authentication Middleware
const adminAuth = async (req, res, next) => {
    try {
        const token = req.cookies.admin_jwt;
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Not authorized, no token'
            });
        }

        const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET || '17581758Na.%');
        req.admin = decoded;

        // Verify admin exists in database
        const admin = await Admin.findById(decoded.id);
        if (!admin) {
            return res.status(401).json({
                success: false,
                message: 'Not authorized, admin not found'
            });
        }

        next();
    } catch (err) {
        console.error('Admin auth error:', err);
        return res.status(401).json({
            success: false,
            message: 'Not authorized, token failed'
        });
    }
};

// Generate CSRF Token
router.get('/api/csrf-token', (req, res) => {
    try {
        // Generate a CSRF token and store in session
        const csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.csrfToken = csrfToken;
        
        res.json({
            success: true,
            csrfToken
        });
    } catch (err) {
        console.error('CSRF token generation error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to generate CSRF token'
        });
    }
});

// Admin Login
router.post('/api/admin/auth/login', async (req, res) => {
    try {
        const { email, password, two_factor_code } = req.body;
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        // Check for admin
        const admin = await Admin.findOne({ email }).select('+password +twoFactorSecret');
        if (!admin) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check 2FA if enabled
        if (admin.twoFactorEnabled && two_factor_code) {
            const verified = speakeasy.totp.verify({
                secret: admin.twoFactorSecret,
                encoding: 'base32',
                token: two_factor_code,
                window: 1
            });
            
            if (!verified) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid 2FA code'
                });
            }
        } else if (admin.twoFactorEnabled) {
            return res.status(400).json({
                success: false,
                message: '2FA code required'
            });
        }

        // Create JWT token
        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: 'admin' },
            process.env.ADMIN_JWT_SECRET || '17581758Na.%',
            { expiresIn: process.env.ADMIN_JWT_EXPIRE || '30d' }
        );

        // Set cookie options
        const cookieOptions = {
            expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        };

        // Generate new CSRF token for session
        const csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.csrfToken = csrfToken;

        res.cookie('admin_jwt', token, cookieOptions).json({
            success: true,
            token,
            csrfToken,
            user: {
                id: admin._id,
                name: admin.name,
                email: admin.email,
                avatar: admin.avatar,
                twoFactorEnabled: admin.twoFactorEnabled
            }
        });
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

// Admin Logout
router.post('/api/admin/auth/logout', adminAuth, (req, res) => {
    try {
        // Clear cookie and session
        res.clearCookie('admin_jwt');
        req.session.csrfToken = null;
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (err) {
        console.error('Admin logout error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error during logout'
        });
    }
});

// Verify Admin Token (for persistent sessions)
router.get('/api/admin/auth/verify', adminAuth, (req, res) => {
    try {
        // Generate new CSRF token for session
        const csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.csrfToken = csrfToken;
        
        res.json({
            success: true,
            csrfToken,
            user: {
                id: req.admin.id,
                name: req.admin.name,
                email: req.admin.email,
                avatar: req.admin.avatar,
                twoFactorEnabled: req.admin.twoFactorEnabled
            }
        });
    } catch (err) {
        console.error('Admin token verify error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error during token verification'
        });
    }
});


app.get('/api/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const { search, status, limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    if (status === 'active') query.isVerified = true;
    if (status === 'pending') query.isVerified = false;

    const users = await User.find(query)
      .select('-password -__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        users,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Admin get users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching users'
    });
  }
});

app.get('/api/admin/users/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -__v');
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    console.error('Admin get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user'
    });
  }
});

app.put('/api/admin/users/:id/balance', authenticate, adminOnly, [
  body('balanceType').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid balance type'),
  body('amount').isFloat().withMessage('Amount must be a number'),
  body('action').isIn(['add', 'subtract', 'set']).withMessage('Invalid action'),
  body('reason').notEmpty().withMessage('Reason is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { balanceType, amount, action, reason } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Perform balance operation
    let newBalance = user.balance[balanceType];
    if (action === 'add') {
      newBalance += amount;
    } else if (action === 'subtract') {
      if (newBalance < amount) {
        return res.status(400).json({
          status: 'error',
          message: 'Insufficient balance to subtract'
        });
      }
      newBalance -= amount;
    } else if (action === 'set') {
      newBalance = amount;
    }

    // Update balance
    user.balance[balanceType] = newBalance;
    await user.save();

    // Create admin log
    const adminLog = new AdminLog({
      adminId: req.user._id,
      action: 'balance_update',
      targetUserId: user._id,
      details: {
        balanceType,
        amount,
        action,
        reason,
        newBalance
      },
      ipAddress: req.ip
    });
    await adminLog.save();

    // Create transaction for the user
    const transaction = new Transaction({
      userId: user._id,
      type: action === 'add' ? 'bonus' : 'adjustment',
      amount,
      status: 'completed',
      notes: `Admin adjustment: ${reason}`
    });
    await transaction.save();

    // Send email notification to user
    const emailContent = `
      <h1>Account Balance Updated</h1>
      <p>Your ${balanceType} balance has been updated by an administrator.</p>
      <p>Action: ${action === 'add' ? 'Added' : action === 'subtract' ? 'Subtracted' : 'Set to'} ${amount} BTC</p>
      <p>New ${balanceType} balance: ${newBalance} BTC</p>
      <p>Reason: ${reason}</p>
    `;
    await sendEmail(user.email, 'Balance Updated', 'Your account balance has been updated', emailContent);

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          email: user.email,
          balance: user.balance
        }
      }
    });
  } catch (err) {
    console.error('Admin update balance error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating user balance'
    });
  }
});

app.put('/api/admin/users/:id/status', authenticate, adminOnly, [
  body('status').isIn(['active', 'suspended']).withMessage('Invalid status'),
  body('reason').notEmpty().withMessage('Reason is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { status, reason } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Update status
    user.status = status;
    await user.save();

    // Create admin log
    const adminLog = new AdminLog({
      adminId: req.user._id,
      action: 'status_update',
      targetUserId: user._id,
      details: {
        status,
        reason
      },
      ipAddress: req.ip
    });
    await adminLog.save();

    // Send email notification to user
    const emailContent = `
      <h1>Account Status Updated</h1>
      <p>Your account status has been updated to: <strong>${status}</strong></p>
      <p>Reason: ${reason}</p>
      ${status === 'suspended' ? '<p>Please contact support if you believe this is an error.</p>' : ''}
    `;
    await sendEmail(user.email, 'Account Status Updated', `Your account has been ${status}`, emailContent);

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          email: user.email,
          status: user.status
        }
      }
    });
  } catch (err) {
    console.error('Admin update status error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating user status'
    });
  }
});

app.get('/api/admin/transactions', authenticate, adminOnly, async (req, res) => {
  try {
    const { type, status, userId, limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    if (userId) query.userId = userId;

    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Admin get transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching transactions'
    });
  }
});

app.put('/api/admin/transactions/:id/status', authenticate, adminOnly, [
  body('status').isIn(['pending', 'completed', 'failed', 'cancelled']).withMessage('Invalid status'),
  body('notes').optional()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { status, notes } = req.body;
    const transaction = await Transaction.findById(req.params.id).populate('userId', 'email firstName');
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }

    // Update transaction status
    transaction.status = status;
    if (notes) transaction.notes = notes;
    await transaction.save();

    // If deposit is completed, update user balance
    if (transaction.type === 'deposit' && status === 'completed') {
      const user = await User.findById(transaction.userId);
      user.balance.main += transaction.amount;
      await user.save();
    }

    // Create admin log
    const adminLog = new AdminLog({
      adminId: req.user._id,
      action: 'transaction_update',
      targetUserId: transaction.userId._id,
      details: {
        transactionId: transaction._id,
        status,
        notes
      },
      ipAddress: req.ip
    });
    await adminLog.save();

    // Send email notification to user
    const emailContent = `
      <h1>Transaction Status Updated</h1>
      <p>Your ${transaction.type} transaction (ID: ${transaction._id}) has been updated to: <strong>${status}</strong></p>
      ${notes ? `<p>Notes: ${notes}</p>` : ''}
    `;
    await sendEmail(transaction.userId.email, 'Transaction Status Updated', `Your transaction is now ${status}`, emailContent);

    res.status(200).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    console.error('Admin update transaction error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating transaction'
    });
  }
});

app.get('/api/admin/kyc/pending', authenticate, adminOnly, async (req, res) => {
  try {
    const { limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const kycSubmissions = await KYC.find({ status: 'pending' })
      .populate('userId', 'firstName lastName email')
      .sort({ submittedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await KYC.countDocuments({ status: 'pending' });

    res.status(200).json({
      status: 'success',
      data: {
        kycSubmissions,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Admin get pending KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching pending KYC submissions'
    });
  }
});

app.post('/api/admin/kyc/:id/review', authenticate, adminOnly, [
  body('decision').isIn(['approved', 'rejected']).withMessage('Invalid decision'),
  body('notes').optional()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array()
    });
  }

  try {
    const { decision, notes } = req.body;
    const kyc = await KYC.findById(req.params.id).populate('userId', 'email firstName lastName');
    if (!kyc) {
      return res.status(404).json({
        status: 'error',
        message: 'KYC submission not found'
      });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({
        status: 'error',
        message: 'KYC submission has already been reviewed'
      });
    }

    // Update KYC status
    kyc.status = decision;
    kyc.reviewedBy = req.user._id;
    kyc.reviewNotes = notes;
    kyc.reviewedAt = new Date();
    await kyc.save();

    // Update user KYC status
    const user = await User.findById(kyc.userId._id);
    user.kycStatus = decision === 'approved' ? 'verified' : 'rejected';
    await user.save();

    // Create admin log
    const adminLog = new AdminLog({
      adminId: req.user._id,
      action: 'kyc_review',
      targetUserId: kyc.userId._id,
      details: {
        decision,
        notes
      },
      ipAddress: req.ip
    });
    await adminLog.save();

    // Send email notification to user
    const emailContent = `
      <h1>KYC Verification ${decision === 'approved' ? 'Approved' : 'Rejected'}</h1>
      <p>Your KYC submission has been ${decision}.</p>
      ${notes ? `<p>Notes: ${notes}</p>` : ''}
      ${decision === 'rejected' ? '<p>You may submit new documents for verification.</p>' : ''}
    `;
    await sendEmail(kyc.userId.email, `KYC ${decision === 'approved' ? 'Approved' : 'Rejected'}`, `Your KYC has been ${decision}`, emailContent);

    res.status(200).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    console.error('Admin review KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while reviewing KYC'
    });
  }
});

// Stats routes
app.get('/api/stats', authenticate, adminOnly, async (req, res) => {
  try {
    // Get total users
    const totalUsers = await User.countDocuments();

    // Get active users (logged in last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const activeUsers = await User.countDocuments({ lastLogin: { $gte: thirtyDaysAgo } });

    // Get total deposits
    const depositsResult = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalDeposits = depositsResult.length ? depositsResult[0].total : 0;

    // Get total withdrawals
    const withdrawalsResult = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = withdrawalsResult.length ? withdrawalsResult[0].total : 0;

    // Get total investments
    const investmentsResult = await Investment.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalInvestments = investmentsResult.length ? investmentsResult[0].total : 0;

    // Get recent signups (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentSignups = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });

    res.status(200).json({
      status: 'success',
      data: {
        totalUsers,
        activeUsers,
        totalDeposits,
        totalWithdrawals,
        totalInvestments,
        recentSignups
      }
    });
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// Cluster mode for production
if (cluster.isMaster && process.env.NODE_ENV === 'production') {
  console.log(`Master ${process.pid} is running`);

  // Fork workers
  const numCPUs = os.cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    cluster.fork(); // Create a new worker
  });
} else {
  // Initialize data and start server
  const startServer = async () => {
    await initializeAdmin();
    await initializePlans();

    app.listen(config.PORT, () => {
      console.log(`Server running on port ${config.PORT}`);
      if (cluster.worker) {
        console.log(`Worker ${process.pid} started`);
      }
    });
  };

  startServer();
}
