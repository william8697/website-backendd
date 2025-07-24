require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const moment = require('moment');
const validator = require('validator');
const { body, validationResult } = require('express-validator');

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: 'https://bithhash.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// CSRF protection for admin routes
const csrfProtection = csrf({ cookie: true });
const adminCSRF = csrf({ cookie: true });

// Database connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Redis connection
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Google OAuth client
const googleClient = new OAuth2Client('634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com');

// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, validate: [validator.isEmail, 'Please provide a valid email'] },
  phone: { type: String, trim: true },
  country: { type: String, trim: true },
  city: { type: String, trim: true },
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  password: { type: String, select: false },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  googleId: String,
  isVerified: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  kycStatus: {
    identity: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    address: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    facial: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' }
  },
  kycDocuments: {
    identityFront: String,
    identityBack: String,
    proofOfAddress: String,
    selfie: String
  },
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String
  },
  balances: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    savings: { type: Number, default: 0 },
    loan: { type: Number, default: 0 }
  },
  referralCode: String,
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  apiKeys: [{
    name: String,
    key: String,
    permissions: [String],
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  }],
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  notifications: [{
    title: String,
    message: String,
    type: { type: String, enum: ['info', 'warning', 'error', 'success'] },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    theme: { type: String, enum: ['light', 'dark'], default: 'dark' }
  }
}, { timestamps: true });

UserSchema.index({ email: 1 });
UserSchema.index({ status: 1 });
UserSchema.index({ 'kycStatus.identity': 1, 'kycStatus.address': 1, 'kycStatus.facial': 1 });
UserSchema.index({ referredBy: 1 });

const User = mongoose.model('User', UserSchema);

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  name: { type: String, required: true },
  role: { type: String, enum: ['super', 'support', 'finance', 'kyc'], required: true },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  permissions: [String],
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String
  }
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  percentage: { type: Number, required: true },
  duration: { type: Number, required: true }, // in hours
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number, required: true },
  isActive: { type: Boolean, default: true },
  referralBonus: { type: Number, default: 5 }
});

const Plan = mongoose.model('Plan', PlanSchema);

const InvestmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  expectedReturn: { type: Number, required: true },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  referralBonusPaid: { type: Boolean, default: false },
  referralBonusAmount: { type: Number, default: 0 }
});

InvestmentSchema.index({ user: 1 });
InvestmentSchema.index({ status: 1 });
InvestmentSchema.index({ endDate: 1 });

const Investment = mongoose.model('Investment', InvestmentSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  reference: { type: String, required: true, unique: true },
  details: mongoose.Schema.Types.Mixed,
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  btcAmount: { type: Number },
  btcAddress: { type: String },
  bankDetails: {
    accountName: String,
    accountNumber: String,
    bankName: String,
    iban: String,
    swift: String
  },
  cardDetails: {
    last4: String,
    brand: String
  },
  adminNotes: String,
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: Date
}, { timestamps: true });

TransactionSchema.index({ user: 1 });
TransactionSchema.index({ type: 1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ reference: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const LoanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  collateralAmount: { type: Number, required: true },
  collateralCurrency: { type: String, default: 'BTC' },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], default: 'pending' },
  startDate: Date,
  endDate: Date,
  repaymentAmount: { type: Number },
  adminNotes: String,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: Date
}, { timestamps: true });

LoanSchema.index({ user: 1 });
LoanSchema.index({ status: 1 });

const Loan = mongoose.model('Loan', LoanSchema);

const KYCSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['identity', 'address', 'facial'], required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewedAt: Date,
  rejectionReason: String
}, { timestamps: true });

KYCSchema.index({ user: 1 });
KYCSchema.index({ status: 1 });
KYCSchema.index({ type: 1 });

const KYC = mongoose.model('KYC', KYCSchema);

const SystemLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  entity: { type: String, required: true },
  entityId: mongoose.Schema.Types.ObjectId,
  performedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'performedByModel' },
  performedByModel: { type: String, enum: ['User', 'Admin'] },
  ip: String,
  device: String,
  location: String,
  changes: mongoose.Schema.Types.Mixed,
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

SystemLogSchema.index({ action: 1 });
SystemLogSchema.index({ entity: 1 });
SystemLogSchema.index({ performedBy: 1 });
SystemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

const NewsletterSubscriberSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, validate: [validator.isEmail, 'Please provide a valid email'] },
  isActive: { type: Boolean, default: true },
  subscribedAt: { type: Date, default: Date.now },
  unsubscribedAt: Date
});

const NewsletterSubscriber = mongoose.model('NewsletterSubscriber', NewsletterSubscriberSchema);

// Helper functions
const generateJWT = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const verifyJWT = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

const createPasswordResetToken = () => {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  const tokenExpires = Date.now() + 60 * 60 * 1000; // 1 hour
  return { resetToken, hashedToken, tokenExpires };
};

const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

const generateReferralCode = () => {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
};

const sendEmail = async (options) => {
  try {
    await transporter.sendMail({
      from: 'BitHash <no-reply@bithash.com>',
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    });
  } catch (err) {
    console.error('Error sending email:', err);
  }
};

const getUserDeviceInfo = (req) => {
  return {
    ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
    device: req.headers['user-agent'],
    location: req.headers['geo-location'] || 'Unknown'
  };
};

const logActivity = async (action, entity, entityId, performedBy, performedByModel, req, changes = {}) => {
  const deviceInfo = getUserDeviceInfo(req);
  await SystemLog.create({
    action,
    entity,
    entityId,
    performedBy,
    performedByModel,
    ip: deviceInfo.ip,
    device: deviceInfo.device,
    location: deviceInfo.location,
    changes
  });
};

// Initialize default admin
const initializeAdmin = async () => {
  const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('SecureAdminPassword123!', 12);
    await Admin.create({
      email: 'admin@bithash.com',
      password: hashedPassword,
      name: 'Super Admin',
      role: 'super',
      permissions: ['all']
    });
    console.log('Default admin created');
  }
};

// Initialize investment plans
const initializePlans = async () => {
  const plans = [
    {
      name: 'Starter Plan',
      description: '20% After 10 hours',
      percentage: 20,
      duration: 10,
      minAmount: 30,
      maxAmount: 499,
      referralBonus: 5
    },
    {
      name: 'Gold Plan',
      description: '40% After 24 hours',
      percentage: 40,
      duration: 24,
      minAmount: 500,
      maxAmount: 1999,
      referralBonus: 5
    },
    {
      name: 'Advance Plan',
      description: '60% After 48 hours',
      percentage: 60,
      duration: 48,
      minAmount: 2000,
      maxAmount: 9999,
      referralBonus: 5
    },
    {
      name: 'Exclusive Plan',
      description: '80% After 72 hours',
      percentage: 80,
      duration: 72,
      minAmount: 10000,
      maxAmount: 30000,
      referralBonus: 5
    },
    {
      name: 'Expert Plan',
      description: '100% After 96 hours',
      percentage: 100,
      duration: 96,
      minAmount: 50000,
      maxAmount: 1000000,
      referralBonus: 5
    }
  ];

  for (const plan of plans) {
    const existingPlan = await Plan.findOne({ name: plan.name });
    if (!existingPlan) {
      await Plan.create(plan);
    }
  }
};

// Initialize data
initializeAdmin();
initializePlans();

// Middleware
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    const decoded = verifyJWT(token);
    const currentUser = await User.findById(decoded.id).select('+passwordChangedAt');

    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (currentUser.passwordChangedAt && decoded.iat < currentUser.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
      });
    }

    if (currentUser.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const adminProtect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.adminJwt) {
      token = req.cookies.adminJwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    const decoded = verifyJWT(token);
    const currentAdmin = await Admin.findById(decoded.id).select('+passwordChangedAt');

    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

const checkCSRF = (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  if (!csrfToken || !req.session.csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({
      status: 'fail',
      message: 'Invalid CSRF token'
    });
  }
  next();
};

// Routes

// User Authentication
app.post('/api/signup', [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character'),
  body('city').trim().notEmpty().withMessage('City is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, password, city, referredBy } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const referralCode = generateReferralCode();

    let referredByUser = null;
    if (referredBy) {
      referredByUser = await User.findOne({ referralCode: referredBy });
    }

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      referralCode,
      referredBy: referredByUser ? referredByUser._id : undefined
    });

    const token = generateJWT(newUser._id);

    // Send welcome email
    const welcomeMessage = `Welcome to BitHash, ${firstName}! Your account has been successfully created.`;
    await sendEmail({
      email: newUser.email,
      subject: 'Welcome to BitHash',
      message: welcomeMessage,
      html: `<p>${welcomeMessage}</p>`
    });

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email
        }
      }
    });

    await logActivity('signup', 'user', newUser._id, newUser._id, 'User', req);
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during signup'
    });
  }
});

app.post('/api/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, rememberMe } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    if (user.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    const token = generateJWT(user._id);

    // Update last login
    user.lastLogin = new Date();
    user.loginHistory.push(getUserDeviceInfo(req));
    await user.save();

    res.cookie('jwt', token, {
      expires: rememberMe ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : undefined,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });

    await logActivity('login', 'user', user._id, user._id, 'User', req);
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
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com'
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub } = payload;

    let user = await User.findOne({ email });
    if (!user) {
      // Create new user with Google auth
      const referralCode = generateReferralCode();
      user = await User.create({
        firstName: given_name,
        lastName: family_name,
        email,
        googleId: sub,
        isVerified: true,
        referralCode
      });
    } else if (!user.googleId) {
      // Existing user, add Google auth
      user.googleId = sub;
      user.isVerified = true;
      await user.save();
    }

    const token = generateJWT(user._id);

    // Update last login
    user.lastLogin = new Date();
    user.loginHistory.push(getUserDeviceInfo(req));
    await user.save();

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });

    await logActivity('google-login', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during Google authentication'
    });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    const { resetToken, hashedToken, tokenExpires } = createPasswordResetToken();
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = tokenExpires;
    await user.save();

    const resetURL = `https://bithhash.vercel.app/reset-password?token=${resetToken}`;
    const message = `Forgot your password? Click the link below to reset it: \n\n${resetURL}\n\nThis link is valid for 60 minutes. If you didn't request this, please ignore this email.`;

    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 60 minutes)',
      message,
      html: `<p>Forgot your password? Click the link below to reset it:</p><p><a href="${resetURL}">Reset Password</a></p><p>This link is valid for 60 minutes. If you didn't request this, please ignore this email.</p>`
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });

    await logActivity('forgot-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, password } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    user.password = await bcrypt.hash(password, 12);
    user.passwordChangedAt = Date.now();
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const newToken = generateJWT(user._id);

    res.status(200).json({
      status: 'success',
      token: newToken,
      message: 'Password updated successfully'
    });

    await logActivity('reset-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting the password'
    });
  }
});

// User Endpoints
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

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

app.put('/api/users/profile', protect, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty'),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty'),
  body('phone').optional().trim(),
  body('country').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, phone, country } = req.body;
    const updates = {};

    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (phone) updates.phone = phone;
    if (country) updates.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-profile', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating profile'
    });
  }
});

app.put('/api/users/address', protect, [
  body('street').optional().trim(),
  body('city').optional().trim(),
  body('state').optional().trim(),
  body('postalCode').optional().trim(),
  body('country').optional().trim()
], async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;
    const updates = { address: {} };

    if (street) updates.address.street = street;
    if (city) updates.address.city = city;
    if (state) updates.address.state = state;
    if (postalCode) updates.address.postalCode = postalCode;
    if (country) updates.address.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-address', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update address error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating address'
    });
  }
});

app.put('/api/users/password', protect, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id).select('+password');

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Current password is incorrect'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordChangedAt = Date.now();
    await user.save();

    const token = generateJWT(user._id);

    res.status(200).json({
      status: 'success',
      token,
      message: 'Password updated successfully'
    });

    await logActivity('change-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while changing password'
    });
  }
});

app.post('/api/users/api-keys', protect, [
  body('name').trim().notEmpty().withMessage('API key name is required'),
  body('permissions').isArray().withMessage('Permissions must be an array'),
  body('expiresAt').optional().isISO8601().withMessage('Invalid expiration date format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { name, permissions, expiresAt } = req.body;
    const apiKey = generateApiKey();

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        $push: {
          apiKeys: {
            name,
            key: apiKey,
            permissions,
            expiresAt: expiresAt ? new Date(expiresAt) : undefined
          }
        }
      },
      { new: true }
    );

    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          name,
          key: apiKey,
          permissions,
          expiresAt
        }
      }
    });

    await logActivity('create-api-key', 'user', user._id, user._id, 'User', req, { name, permissions });
  } catch (err) {
    console.error('Create API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating API key'
    });
  }
});

// Admin Authentication
app.get('/api/admin/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  res.status(200).json({
    status: 'success',
    csrfToken
  });
});

app.post('/api/admin/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email }).select('+password');
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    const token = generateJWT(admin._id, true);

    // Update last login
    admin.lastLogin = new Date();
    admin.loginHistory.push(getUserDeviceInfo(req));
    await admin.save();

    res.cookie('adminJwt', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          role: admin.role
        }
      }
    });

    await logActivity('admin-login', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during admin login'
    });
  }
});

app.post('/api/admin/auth/logout', adminProtect, (req, res) => {
  res.clearCookie('adminJwt');
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

// Admin Dashboard
app.get('/api/admin/dashboard', adminProtect, restrictTo('super', 'support', 'finance'), async (req, res) => {
  try {
    // Cache dashboard data for 5 minutes
    const cachedDashboard = await redis.get('admin-dashboard');
    if (cachedDashboard) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedDashboard)
      });
    }

    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ status: 'active' });
    const suspendedUsers = await User.countDocuments({ status: 'suspended' });
    const verifiedUsers = await User.countDocuments({
      'kycStatus.identity': 'verified',
      'kycStatus.address': 'verified',
      'kycStatus.facial': 'verified'
    });

    const pendingDeposits = await Transaction.countDocuments({ type: 'deposit', status: 'pending' });
    const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    const completedInvestments = await Investment.countDocuments({ status: 'completed' });
    const pendingLoans = await Loan.countDocuments({ status: 'pending' });
    const activeLoans = await Loan.countDocuments({ status: 'active' });

    const dashboardData = {
      totalUsers,
      activeUsers,
      suspendedUsers,
      verifiedUsers,
      pendingDeposits,
      pendingWithdrawals,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      activeInvestments,
      completedInvestments,
      pendingLoans,
      activeLoans
    };

    await redis.set('admin-dashboard', JSON.stringify(dashboardData), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: dashboardData
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching dashboard data'
    });
  }
});

app.get('/api/admin/users/growth', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const validDays = [7, 30, 90, 365];
    if (!validDays.includes(parseInt(days))) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid days parameter. Valid values are 7, 30, 90, or 365'
      });
    }

    const cacheKey = `user-growth-${days}`;
    const cachedData = await redis.get(cacheKey);
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }

    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id': 1 }
      }
    ]);

    const growthData = {
      days,
      total: userGrowth.reduce((sum, day) => sum + day.count, 0),
      data: userGrowth
    };

    await redis.set(cacheKey, JSON.stringify(growthData), 'EX', 3600);

    res.status(200).json({
      status: 'success',
      data: growthData
    });
  } catch (err) {
    console.error('User growth error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user growth data'
    });
  }
});

app.get('/api/admin/activity', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const activities = await SystemLog.find()
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .populate('performedBy', 'name email')
      .lean();

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    console.error('Activity log error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching activity logs'
    });
  }
});

// Admin User Management
app.get('/api/admin/users', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { page = 1, limit = 20, search, status, sort } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.status = status;

    const sortOptions = {};
    if (sort) {
      const [field, order] = sort.split(':');
      sortOptions[field] = order === 'desc' ? -1 : 1;
    } else {
      sortOptions.createdAt = -1;
    }

    const users = await User.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

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
    console.error('Get users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching users'
    });
  }
});

app.get('/api/admin/users/:id', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
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
    console.error('Get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user'
    });
  }
});

app.put('/api/admin/users/:id', adminProtect, restrictTo('super', 'support'), [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty'),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty'),
  body('email').optional().isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('phone').optional().trim(),
  body('country').optional().trim(),
  body('status').optional().isIn(['active', 'suspended', 'banned']).withMessage('Invalid status')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { id } = req.params;
    const updates = req.body;

    const user = await User.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-user', 'user', user._id, req.admin._id, 'Admin', req, updates);
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating user'
    });
  }
});

app.delete('/api/admin/users/:id', adminProtect, restrictTo('super'), async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(204).json({
      status: 'success',
      data: null
    });

    await logActivity('delete-user', 'user', user._id, req.admin._id, 'Admin', req);
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting user'
    });
  }
});

app.put('/api/admin/users/:id/status', adminProtect, restrictTo('super', 'support'), [
  body('status').isIn(['active', 'suspended', 'banned']).withMessage('Invalid status'),
  body('reason').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { id } = req.params;
    const { status, reason } = req.body;

    const user = await User.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Send notification to user
    user.notifications.push({
      title: 'Account Status Changed',
      message: `Your account status has been changed to ${status}. ${reason || ''}`,
      type: status === 'active' ? 'success' : 'warning'
    });
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('change-user-status', 'user', user._id, req.admin._id, 'Admin', req, { status, reason });
  } catch (err) {
    console.error('Change user status error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while changing user status'
    });
  }
});

// Admin KYC Management
app.get('/api/admin/kyc/pending', adminProtect, restrictTo('super', 'kyc'), async (req, res) => {
  try {
    const pendingKYCs = await KYC.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: 1 });

    res.status(200).json({
      status: 'success',
      data: pendingKYCs
    });
  } catch (err) {
    console.error('Pending KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching pending KYC submissions'
    });
  }
});

app.get('/api/admin/kyc/:id', adminProtect, restrictTo('super', 'kyc'), async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('reviewedBy', 'name');

    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: kyc
    });
  } catch (err) {
    console.error('Get KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching KYC submission'
    });
  }
});

app.post('/api/admin/kyc/:id/review', adminProtect, restrictTo('super', 'kyc'), [
  body('status').isIn(['approved', 'rejected']).withMessage('Invalid status'),
  body('rejectionReason').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { id } = req.params;
    const { status, rejectionReason } = req.body;

    const kyc = await KYC.findByIdAndUpdate(
      id,
      {
        status,
        rejectionReason: status === 'rejected' ? rejectionReason : undefined,
        reviewedBy: req.admin._id,
        reviewedAt: new Date()
      },
      { new: true }
    ).populate('user', 'firstName lastName email');

    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    // Update user's KYC status
    const user = await User.findById(kyc.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    user.kycStatus[kyc.type] = status === 'approved' ? 'verified' : 'rejected';
    await user.save();

    // Send notification to user
    user.notifications.push({
      title: 'KYC Status Update',
      message: `Your ${kyc.type} verification has been ${status}. ${status === 'rejected' ? rejectionReason : ''}`,
      type: status === 'approved' ? 'success' : 'error'
    });
    await user.save();

    res.status(200).json({
      status: 'success',
      data: kyc
    });

    await logActivity('review-kyc', 'kyc', kyc._id, req.admin._id, 'Admin', req, { status, rejectionReason });
  } catch (err) {
    console.error('Review KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while reviewing KYC submission'
    });
  }
});

// Admin Withdrawal Management
app.get('/api/admin/withdrawals/pending', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const pendingWithdrawals = await Transaction.find({ type: 'withdrawal', status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: 1 });

    res.status(200).json({
      status: 'success',
      data: pendingWithdrawals
    });
  } catch (err) {
    console.error('Pending withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching pending withdrawals'
    });
  }
});

app.get('/api/admin/withdrawals/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const withdrawal = await Transaction.findOne({
      _id: req.params.id,
      type: 'withdrawal'
    }).populate('user', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    console.error('Get withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching withdrawal'
    });
  }
});

app.post('/api/admin/withdrawals/:id/process', adminProtect, restrictTo('super', 'finance'), [
  body('status').isIn(['completed', 'cancelled']).withMessage('Invalid status'),
  body('notes').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    const withdrawal = await Transaction.findOneAndUpdate(
      { _id: id, type: 'withdrawal', status: 'pending' },
      {
        status,
        adminNotes: notes,
        processedBy: req.admin._id,
        processedAt: new Date()
      },
      { new: true }
    ).populate('user', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Pending withdrawal not found'
      });
    }

    if (status === 'cancelled') {
      // Refund the amount to user's balance
      const user = await User.findById(withdrawal.user._id);
      if (user) {
        user.balances.main += withdrawal.amount;
        await user.save();

        // Create a transaction record for the refund
        await Transaction.create({
          user: user._id,
          type: 'transfer',
          amount: withdrawal.amount,
          status: 'completed',
          method: 'internal',
          reference: `REFUND-${withdrawal.reference}`,
          details: `Refund for cancelled withdrawal ${withdrawal.reference}`,
          netAmount: withdrawal.amount
        });

        // Send notification to user
        user.notifications.push({
          title: 'Withdrawal Cancelled',
          message: `Your withdrawal of $${withdrawal.amount} has been cancelled and refunded to your account.`,
          type: 'warning'
        });
        await user.save();
      }
    }

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });

    await logActivity('process-withdrawal', 'transaction', withdrawal._id, req.admin._id, 'Admin', req, { status, notes });
  } catch (err) {
    console.error('Process withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing withdrawal'
    });
  }
});

app.post('/api/admin/withdrawals/process-batch', adminProtect, restrictTo('super', 'finance'), [
  body('ids').isArray().withMessage('IDs must be an array'),
  body('ids.*').isMongoId().withMessage('Invalid ID format'),
  body('status').isIn(['completed', 'cancelled']).withMessage('Invalid status')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { ids, status } = req.body;

    const withdrawals = await Transaction.updateMany(
      { _id: { $in: ids }, type: 'withdrawal', status: 'pending' },
      {
        status,
        processedBy: req.admin._id,
        processedAt: new Date()
      }
    );

    if (status === 'cancelled') {
      // Refund all cancelled withdrawals
      const cancelledWithdrawals = await Transaction.find({ _id: { $in: ids }, status: 'cancelled' });
      for (const withdrawal of cancelledWithdrawals) {
        const user = await User.findById(withdrawal.user);
        if (user) {
          user.balances.main += withdrawal.amount;
          await user.save();

          // Create a transaction record for the refund
          await Transaction.create({
            user: user._id,
            type: 'transfer',
            amount: withdrawal.amount,
            status: 'completed',
            method: 'internal',
            reference: `REFUND-${withdrawal.reference}`,
            details: `Refund for cancelled withdrawal ${withdrawal.reference}`,
            netAmount: withdrawal.amount
          });

          // Send notification to user
          user.notifications.push({
            title: 'Withdrawal Cancelled',
            message: `Your withdrawal of $${withdrawal.amount} has been cancelled and refunded to your account.`,
            type: 'warning'
          });
          await user.save();
        }
      }
    }

    res.status(200).json({
      status: 'success',
      data: {
        matched: withdrawals.n,
        modified: withdrawals.nModified
      }
    });

    await logActivity('batch-process-withdrawals', 'transaction', null, req.admin._id, 'Admin', req, { ids, status });
  } catch (err) {
    console.error('Batch process withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while batch processing withdrawals'
    });
  }
});

// Admin Loan Management
app.get('/api/admin/loans', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (status) query.status = status;

    const loans = await Loan.find(query)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Loan.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        loans,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get loans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching loans'
    });
  }
});

app.post('/api/admin/loans', adminProtect, restrictTo('super', 'finance'), [
  body('user').isMongoId().withMessage('Invalid user ID'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('interestRate').isFloat({ gt: 0 }).withMessage('Interest rate must be greater than 0'),
  body('duration').isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('collateralAmount').isFloat({ gt: 0 }).withMessage('Collateral amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { user, amount, interestRate, duration, collateralAmount, collateralCurrency = 'BTC' } = req.body;

    const userExists = await User.findById(user);
    if (!userExists) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    const loan = await Loan.create({
      user,
      amount,
      interestRate,
      duration,
      collateralAmount,
      collateralCurrency,
      status: 'approved',
      approvedBy: req.admin._id,
      approvedAt: new Date(),
      startDate: new Date(),
      endDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000),
      repaymentAmount: amount + (amount * interestRate / 100)
    });

    // Update user's loan balance
    userExists.balances.loan += amount;
    await userExists.save();

    // Create a transaction record
    await Transaction.create({
      user: userExists._id,
      type: 'loan',
      amount,
      status: 'completed',
      method: 'internal',
      reference: `LOAN-${loan._id.toString().slice(-6).toUpperCase()}`,
      details: `Loan approved for $${amount} at ${interestRate}% interest`,
      netAmount: amount
    });

    // Send notification to user
    userExists.notifications.push({
      title: 'Loan Approved',
      message: `Your loan of $${amount} has been approved. The repayment amount is $${loan.repaymentAmount} due on ${loan.endDate.toLocaleDateString()}.`,
      type: 'success'
    });
    await userExists.save();

    res.status(201).json({
      status: 'success',
      data: loan
    });

    await logActivity('create-loan', 'loan', loan._id, req.admin._id, 'Admin', req, req.body);
  } catch (err) {
    console.error('Create loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating loan'
    });
  }
});

app.get('/api/admin/loans/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'name');

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Loan not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    console.error('Get loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching loan'
    });
  }
});

app.put('/api/admin/loans/:id', adminProtect, restrictTo('super', 'finance'), [
  body('status').optional().isIn(['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted']).withMessage('Invalid status'),
  body('amount').optional().isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('interestRate').optional().isFloat({ gt: 0 }).withMessage('Interest rate must be greater than 0'),
  body('duration').optional().isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('collateralAmount').optional().isFloat({ gt: 0 }).withMessage('Collateral amount must be greater than 0'),
  body('adminNotes').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { id } = req.params;
    const updates = req.body;

    const loan = await Loan.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true
    }).populate('user', 'firstName lastName email');

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Loan not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: loan
    });

    await logActivity('update-loan', 'loan', loan._id, req.admin._id, 'Admin', req, updates);
  } catch (err) {
    console.error('Update loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating loan'
    });
  }
});

app.delete('/api/admin/loans/:id', adminProtect, restrictTo('super'), async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Loan not found'
      });
    }

    res.status(204).json({
      status: 'success',
      data: null
    });

    await logActivity('delete-loan', 'loan', loan._id, req.admin._id, 'Admin', req);
  } catch (err) {
    console.error('Delete loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting loan'
    });
  }
});

// Admin Profile
app.get('/api/admin/profile', adminProtect, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id)
      .select('-password -passwordChangedAt -__v');

    res.status(200).json({
      status: 'success',
      data: {
        admin
      }
    });
  } catch (err) {
    console.error('Get admin profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching admin profile'
    });
  }
});

// Dashboard Endpoints
app.get('/api/plans', protect, async (req, res) => {
  try {
    const cachedPlans = await redis.get('investment-plans');
    if (cachedPlans) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedPlans)
      });
    }

    const plans = await Plan.find({ isActive: true });
    await redis.set('investment-plans', JSON.stringify(plans), 'EX', 3600);

    res.status(200).json({
      status: 'success',
      data: plans
    });
  } catch (err) {
    console.error('Get plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investment plans'
    });
  }
});

app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
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

app.get('/api/mining/stats', protect, async (req, res) => {
  try {
    const stats = {
      hashrate: Math.floor(Math.random() * 100) + 50, // Simulated hashrate in TH/s
      activeWorkers: Math.floor(Math.random() * 5) + 1,
      shares: {
        accepted: Math.floor(Math.random() * 1000) + 500,
        rejected: Math.floor(Math.random() * 10),
        stale: Math.floor(Math.random() * 20)
      },
      estimatedDailyEarnings: (Math.random() * 0.01).toFixed(8)
    };

    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    console.error('Get mining stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching mining stats'
    });
  }
});

app.post('/api/transactions/deposit', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('method').isIn(['btc', 'bank', 'card']).withMessage('Invalid deposit method')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, method } = req.body;
    const reference = `DEP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    let transactionData = {
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'pending',
      method,
      reference,
      netAmount: amount,
      details: `Deposit of $${amount} via ${method}`
    };

    if (method === 'btc') {
      transactionData.btcAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
      transactionData.details += ` to address ${transactionData.btcAddress}`;
    }

    const transaction = await Transaction.create(transactionData);

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-deposit', 'transaction', transaction._id, req.user._id, 'User', req, { amount, method });
  } catch (err) {
    console.error('Create deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating deposit'
    });
  }
});

app.post('/api/transactions/withdraw', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('method').isIn(['btc', 'bank']).withMessage('Invalid withdrawal method'),
  body('btcAddress').if(body('method').equals('btc')).notEmpty().withMessage('BTC address is required for BTC withdrawals'),
  body('bankDetails').if(body('method').equals('bank')).isObject().withMessage('Bank details must be an object'),
  body('bankDetails.accountName').if(body('method').equals('bank')).notEmpty().withMessage('Account name is required'),
  body('bankDetails.accountNumber').if(body('method').equals('bank')).notEmpty().withMessage('Account number is required'),
  body('bankDetails.bankName').if(body('method').equals('bank')).notEmpty().withMessage('Bank name is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, method, btcAddress, bankDetails } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for withdrawal'
      });
    }

    const reference = `WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const fee = amount * 0.01; // 1% withdrawal fee
    const netAmount = amount - fee;

    let transactionData = {
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method,
      reference,
      fee,
      netAmount,
      details: `Withdrawal of $${amount} via ${method} (Fee: $${fee.toFixed(2)})`
    };

    if (method === 'btc') {
      transactionData.btcAddress = btcAddress;
      transactionData.details += ` to address ${btcAddress}`;
    } else {
      transactionData.bankDetails = bankDetails;
      transactionData.details += ` to ${bankDetails.accountName} (${bankDetails.bankName})`;
    }

    const transaction = await Transaction.create(transactionData);

    // Deduct from user's balance
    user.balances.main -= amount;
    await user.save();

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-withdrawal', 'transaction', transaction._id, req.user._id, 'User', req, { amount, method });
  } catch (err) {
    console.error('Create withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating withdrawal'
    });
  }
});

app.post('/api/transactions/transfer', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('from').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid source account'),
  body('to').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid destination account')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, from, to } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances[from] < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient balance in ${from} account`
      });
    }

    // Perform transfer
    user.balances[from] -= amount;
    user.balances[to] += amount;
    await user.save();

    // Create transaction record
    const reference = `TRF-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Transfer of $${amount} from ${from} to ${to} account`
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('transfer-funds', 'transaction', transaction._id, req.user._id, 'User', req, { amount, from, to });
  } catch (err) {
    console.error('Transfer funds error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while transferring funds'
    });
  }
});

app.post('/api/investments', protect, [
  body('plan').isMongoId().withMessage('Invalid plan ID'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { plan, amount } = req.body;
    const user = await User.findById(req.user.id);
    const investmentPlan = await Plan.findById(plan);

    if (!investmentPlan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    if (amount < investmentPlan.minAmount || amount > investmentPlan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${investmentPlan.minAmount} and $${investmentPlan.maxAmount} for this plan`
      });
    }

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for investment'
      });
    }

    // Deduct from main balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();

    // Calculate end date and expected return
    const endDate = new Date(Date.now() + investmentPlan.duration * 60 * 60 * 1000);
    const expectedReturn = amount + (amount * investmentPlan.percentage / 100);

    // Create investment
    const investment = await Investment.create({
      user: req.user.id,
      plan,
      amount,
      expectedReturn,
      endDate
    });

    // Create transaction record
    const reference = `INV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Investment of $${amount} in ${investmentPlan.name} (Expected return: $${expectedReturn.toFixed(2)})`
    });

    // Check for referral bonus
    if (user.referredBy && !investment.referralBonusPaid) {
      const referringUser = await User.findById(user.referredBy);
      if (referringUser) {
        const bonusAmount = amount * (investmentPlan.referralBonus / 100);
        
        referringUser.balances.main += bonusAmount;
        await referringUser.save();

        investment.referralBonusPaid = true;
        investment.referralBonusAmount = bonusAmount;
        await investment.save();

        // Create transaction record for referral bonus
        await Transaction.create({
          user: referringUser._id,
          type: 'referral',
          amount: bonusAmount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          reference: `REF-${reference}`,
          netAmount: bonusAmount,
          details: `Referral bonus for ${user.firstName} ${user.lastName}'s investment of $${amount}`
        });

        // Send notification to referring user
        referringUser.notifications.push({
          title: 'Referral Bonus',
          message: `You've earned $${bonusAmount.toFixed(2)} from ${user.firstName} ${user.lastName}'s investment.`,
          type: 'success'
        });
        await referringUser.save();
      }
    }

    res.status(201).json({
      status: 'success',
      data: investment
    });

    await logActivity('create-investment', 'investment', investment._id, req.user._id, 'User', req, { plan, amount });
  } catch (err) {
    console.error('Create investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating investment'
    });
  }
});

// Newsletter Subscription
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;

    const existingSubscriber = await NewsletterSubscriber.findOne({ email });
    if (existingSubscriber) {
      if (existingSubscriber.isActive) {
        return res.status(200).json({
          status: 'success',
          message: 'You are already subscribed to our newsletter'
        });
      } else {
        existingSubscriber.isActive = true;
        existingSubscriber.unsubscribedAt = undefined;
        await existingSubscriber.save();
        return res.status(200).json({
          status: 'success',
          message: 'You have been resubscribed to our newsletter'
        });
      }
    }

    await NewsletterSubscriber.create({ email });

    res.status(200).json({
      status: 'success',
      message: 'You have been subscribed to our newsletter'
    });
  } catch (err) {
    console.error('Newsletter subscription error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while subscribing to newsletter'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong on the server'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server`
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
