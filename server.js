require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Redis = require('ioredis');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const axios = require('axios');

// Initialize Express app
const app = express();

// Environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://bithhash.vercel.app';
const DEFAULT_BTC_ADDRESS = process.env.DEFAULT_BTC_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@bithash.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SecureAdminPassword123!';
const NODE_ENV = process.env.NODE_ENV || 'production';

// Redis configuration
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  enableOfflineQueue: false,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
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

// Security middleware
app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
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

// Database connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// MongoDB models
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, trim: true },
  country: { type: String, trim: true },
  password: { type: String, required: true, select: false },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  balances: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    btc: { type: Number, default: 0 }
  },
  kyc: {
    status: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    documents: [{
      type: { type: String, enum: ['id', 'passport', 'driver-license', 'proof-of-address', 'selfie'] },
      url: String,
      status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
      reviewedBy: mongoose.Schema.Types.ObjectId,
      reviewedAt: Date,
      rejectionReason: String
    }]
  },
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: true },
    push: { type: Boolean, default: true }
  },
  apiKeys: [{
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now }
  }],
  devices: [{
    deviceId: String,
    name: String,
    ip: String,
    lastActive: Date,
    os: String,
    browser: String
  }],
  activity: [{
    action: String,
    ip: String,
    device: String,
    timestamp: { type: Date, default: Date.now }
  }],
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  referralCode: String,
  referredBy: mongoose.Schema.Types.ObjectId,
  lastLogin: Date,
  btcDepositAddress: { type: String, default: DEFAULT_BTC_ADDRESS },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referralCode: 1 }, { unique: true, sparse: true });
userSchema.index({ 'kyc.status': 1 });
userSchema.index({ status: 1 });
userSchema.index({ createdAt: 1 });

const User = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  name: { type: String, required: true },
  role: { type: String, enum: ['super-admin', 'admin', 'support', 'financial'], default: 'admin' },
  permissions: [String],
  lastLogin: Date,
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  activity: [{
    action: String,
    ip: String,
    timestamp: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Admin = mongoose.model('Admin', adminSchema);

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'bonus', 'fee', 'loan'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  details: mongoose.Schema.Types.Mixed,
  reference: { type: String, unique: true },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: Date,
  notes: String
}, { timestamps: true });

transactionSchema.index({ userId: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ createdAt: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planId: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  returns: { type: Number, default: 0 },
  transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
  autoRenew: { type: Boolean, default: false }
}, { timestamps: true });

investmentSchema.index({ userId: 1 });
investmentSchema.index({ status: 1 });
investmentSchema.index({ endDate: 1 });

const Investment = mongoose.model('Investment', investmentSchema);

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number },
  duration: { type: Number, required: true }, // in days
  interestRate: { type: Number, required: true },
  compounding: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  features: [String]
}, { timestamps: true });

const Plan = mongoose.model('Plan', planSchema);

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, refPath: 'fromModel', required: true },
  fromModel: { type: String, required: true, enum: ['User', 'Admin'] },
  to: { type: mongoose.Schema.Types.ObjectId, refPath: 'toModel', required: true },
  toModel: { type: String, required: true, enum: ['User', 'Admin'] },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  attachments: [{
    url: String,
    type: String,
    name: String
  }]
}, { timestamps: true });

messageSchema.index({ from: 1, to: 1 });
messageSchema.index({ createdAt: -1 });

const Message = mongoose.model('Message', messageSchema);

const systemLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  entity: { type: String, required: true },
  entityId: mongoose.Schema.Types.ObjectId,
  performedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'performedByModel', required: true },
  performedByModel: { type: String, required: true, enum: ['User', 'Admin'] },
  ip: String,
  userAgent: String,
  details: mongoose.Schema.Types.Mixed
}, { timestamps: true });

systemLogSchema.index({ action: 1 });
systemLogSchema.index({ entity: 1 });
systemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', systemLogSchema);

// Initialize default admin
async function initializeDefaultAdmin() {
  const existingAdmin = await Admin.findOne({ email: ADMIN_EMAIL });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await Admin.create({
      email: ADMIN_EMAIL,
      password: hashedPassword,
      name: 'Super Admin',
      role: 'super-admin',
      permissions: ['all']
    });
    console.log('Default admin account created');
  }
}

// Utility functions
const createSendToken = (user, statusCode, res) => {
  const token = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

const generateApiKey = () => {
  return {
    key: `BH-${crypto.randomBytes(16).toString('hex').toUpperCase()}`,
    secret: `bh_sec_${crypto.randomBytes(32).toString('hex')}`
  };
};

// Error handling middleware
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  } else {
    // Operational, trusted error: send message to client
    if (err.isOperational) {
      res.status(err.statusCode).json({
        status: err.status,
        message: err.message
      });
    } else {
      // Programming or other unknown error: don't leak error details
      console.error('ERROR 💥', err);
      res.status(500).json({
        status: 'error',
        message: 'Something went very wrong!'
      });
    }
  }
};

// Authentication middleware
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    // Verify token
    const decoded = await jwt.verify(token, JWT_SECRET);

    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(new AppError('The user belonging to this token does no longer exist.', 401));
    }

    // Check if user changed password after the token was issued
    if (currentUser.passwordChangedAt) {
      const changedTimestamp = parseInt(currentUser.passwordChangedAt.getTime() / 1000, 10);
      if (decoded.iat < changedTimestamp) {
        return next(new AppError('User recently changed password! Please log in again.', 401));
      }
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (err) {
    next(err);
  }
};

const adminProtect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwtAdmin) {
      token = req.cookies.jwtAdmin;
    }

    if (!token) {
      return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    // Verify token
    const decoded = await jwt.verify(token, JWT_SECRET);

    // Check if admin still exists
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin) {
      return next(new AppError('The admin belonging to this token does no longer exist.', 401));
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.admin = currentAdmin;
    res.locals.admin = currentAdmin;
    next();
  } catch (err) {
    next(err);
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

// API Routes

// User routes
app.post('/api/users/signup', async (req, res, next) => {
  try {
    const { firstName, lastName, email, password, passwordConfirm, referralCode } = req.body;

    // Check if passwords match
    if (password !== passwordConfirm) {
      return next(new AppError('Passwords do not match', 400));
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new AppError('Email already in use', 400));
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create referral code
    const userReferralCode = crypto.randomBytes(4).toString('hex').toUpperCase();

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      referralCode: userReferralCode,
      referredBy: referralCode ? await User.findOne({ referralCode }).select('_id') : undefined
    });

    // Log activity
    await SystemLog.create({
      action: 'signup',
      entity: 'user',
      entityId: newUser._id,
      performedBy: newUser._id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { referralCode }
    });

    // Send welcome email
    const mailOptions = {
      from: 'BitHash <no-reply@bithash.com>',
      to: newUser.email,
      subject: 'Welcome to BitHash',
      html: `<p>Hello ${newUser.firstName},</p>
             <p>Welcome to BitHash! Your account has been successfully created.</p>
             <p>Your referral code is: <strong>${userReferralCode}</strong></p>
             <p>Start investing today and grow your Bitcoin holdings.</p>`
    };

    await transporter.sendMail(mailOptions);

    createSendToken(newUser, 201, res);
  } catch (err) {
    next(err);
  }
});

app.post('/api/users/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    // 3) Check if account is active
    if (user.status !== 'active') {
      return next(new AppError('Your account has been suspended. Please contact support.', 403));
    }

    // 4) Update last login
    user.lastLogin = new Date();
    await user.save();

    // 5) Log activity
    await SystemLog.create({
      action: 'login',
      entity: 'user',
      entityId: user._id,
      performedBy: user._id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // 6) If everything ok, send token to client
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
});

app.get('/api/users/me', protect, async (req, res, next) => {
  try {
    // Get user from database including balances
    const user = await User.findById(req.user.id).select('-password -twoFactorSecret -apiKeys.secret');

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    // Get BTC price from cache or API
    let btcPrice;
    const cachedPrice = await redis.get('btc_price');
    if (cachedPrice) {
      btcPrice = JSON.parse(cachedPrice);
    } else {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
      await redis.set('btc_price', JSON.stringify(btcPrice), 'EX', 60); // Cache for 60 seconds
    }

    // Calculate BTC equivalent of balances
    const btcBalances = {
      main: user.balances.main / btcPrice,
      active: user.balances.active / btcPrice,
      matured: user.balances.matured / btcPrice
    };

    res.status(200).json({
      status: 'success',
      data: {
        user,
        btcPrice,
        btcBalances
      }
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/users/profile', protect, async (req, res, next) => {
  try {
    // 1) Filter out unwanted fields that are not allowed to be updated
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'phone',
      'country'
    );

    // 2) Update user document
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret -apiKeys.secret');

    // 3) Log activity
    await SystemLog.create({
      action: 'update-profile',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: filteredBody
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/users/address', protect, async (req, res, next) => {
  try {
    const { street, city, state, postalCode, country } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { address: { street, city, state, postalCode, country } },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret -apiKeys.secret');

    // Log activity
    await SystemLog.create({
      action: 'update-address',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { street, city, state, postalCode, country }
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/users/password', protect, async (req, res, next) => {
  try {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;

    // 1) Get user from collection
    const user = await User.findById(req.user.id).select('+password');

    // 2) Check if POSTed current password is correct
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return next(new AppError('Your current password is wrong.', 401));
    }

    // 3) Check if new passwords match
    if (newPassword !== newPasswordConfirm) {
      return next(new AppError('New passwords do not match', 400));
    }

    // 4) Update password
    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordChangedAt = Date.now() - 1000;
    await user.save();

    // 5) Log activity
    await SystemLog.create({
      action: 'change-password',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // 6) Log user in, send JWT
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
});

app.post('/api/users/api-keys', protect, async (req, res, next) => {
  try {
    const { permissions, expiresInDays } = req.body;

    // Validate permissions
    const validPermissions = ['read', 'trade', 'withdraw', 'transfer'];
    if (!permissions.every(p => validPermissions.includes(p))) {
      return next(new AppError('Invalid permissions specified', 400));
    }

    // Generate API key
    const apiKey = generateApiKey();
    const expiresAt = expiresInDays ? 
      moment().add(expiresInDays, 'days').toDate() : 
      moment().add(30, 'days').toDate();

    // Add to user's API keys
    await User.findByIdAndUpdate(req.user.id, {
      $push: {
        apiKeys: {
          key: apiKey.key,
          secret: apiKey.secret,
          permissions,
          expiresAt
        }
      }
    });

    // Log activity
    await SystemLog.create({
      action: 'generate-api-key',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { permissions, expiresAt }
    });

    // Return the key and secret (only time secret is shown)
    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          key: apiKey.key,
          secret: apiKey.secret,
          permissions,
          expiresAt
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/users/api-keys/:keyId', protect, async (req, res, next) => {
  try {
    const { keyId } = req.params;

    // Remove the API key
    await User.findByIdAndUpdate(req.user.id, {
      $pull: { apiKeys: { key: keyId } }
    });

    // Log activity
    await SystemLog.create({
      action: 'revoke-api-key',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { keyId }
    });

    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/users/logout', protect, (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

// Admin routes
app.post('/api/admin/auth/login', async (req, res, next) => {
  try {
    const { email, password, twoFactorCode } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }

    // 2) Check if admin exists && password is correct
    const admin = await Admin.findOne({ email }).select('+password +twoFactorSecret');

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    // 3) If 2FA is enabled, verify the code
    if (admin.twoFactorEnabled) {
      if (!twoFactorCode) {
        return next(new AppError('Two-factor authentication code is required', 401));
      }
      // In a real implementation, you would verify the TOTP here
      // For now, we'll just check if any code was provided
    }

    // 4) Update last login
    admin.lastLogin = new Date();
    await admin.save();

    // 5) Log activity
    await SystemLog.create({
      action: 'admin-login',
      entity: 'admin',
      entityId: admin._id,
      performedBy: admin._id,
      performedByModel: 'Admin',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // 6) Create token
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });

    const cookieOptions = {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict'
    };

    res.cookie('jwtAdmin', token, cookieOptions);

    // Remove password from output
    admin.password = undefined;
    admin.twoFactorSecret = undefined;

    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/dashboard', adminProtect, async (req, res, next) => {
  try {
    // Get stats from cache if available
    const cachedStats = await redis.get('admin_dashboard_stats');
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedStats)
      });
    }

    // Get all stats in parallel
    const [
      totalUsers,
      activeUsers,
      newUsersToday,
      totalDeposits,
      totalWithdrawals,
      pendingWithdrawals,
      activeInvestments,
      kycPending
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ status: 'active' }),
      User.countDocuments({ createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } }),
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.countDocuments({ type: 'withdrawal', status: 'pending' }),
      Investment.countDocuments({ status: 'active' }),
      User.countDocuments({ 'kyc.status': 'pending' })
    ]);

    // Format the data
    const stats = {
      totalUsers,
      activeUsers,
      newUsersToday,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      pendingWithdrawals,
      activeInvestments,
      kycPending
    };

    // Cache the stats for 5 minutes
    await redis.set('admin_dashboard_stats', JSON.stringify(stats), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/users', adminProtect, restrictTo('super-admin', 'admin', 'support'), async (req, res, next) => {
  try {
    const { page = 1, limit = 20, search, status, sort } = req.query;

    // Build query
    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.status = status;

    // Build sort
    let sortOption = { createdAt: -1 };
    if (sort) {
      const [field, order] = sort.split(':');
      sortOption = { [field]: order === 'desc' ? -1 : 1 };
    }

    // Get users with pagination
    const users = await User.find(query)
      .sort(sortOption)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('-password -twoFactorSecret -apiKeys.secret');

    // Get total count
    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        users
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/users/:id', adminProtect, restrictTo('super-admin', 'admin', 'support'), async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -twoFactorSecret -apiKeys.secret')
      .populate('referredBy', 'firstName lastName email');

    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    // Get user transactions
    const transactions = await Transaction.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    // Get user investments
    const investments = await Investment.find({ userId: user._id })
      .populate('planId')
      .sort({ createdAt: -1 })
      .limit(5);

    res.status(200).json({
      status: 'success',
      data: {
        user,
        transactions,
        investments
      }
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/admin/users/:id', adminProtect, restrictTo('super-admin', 'admin'), async (req, res, next) => {
  try {
    const { status, balances, kycStatus } = req.body;

    // Prepare update object
    const updateObj = {};
    if (status) updateObj.status = status;
    if (kycStatus) updateObj['kyc.status'] = kycStatus;
    if (balances) {
      if (balances.main !== undefined) updateObj['balances.main'] = balances.main;
      if (balances.active !== undefined) updateObj['balances.active'] = balances.active;
      if (balances.matured !== undefined) updateObj['balances.matured'] = balances.matured;
      if (balances.btc !== undefined) updateObj['balances.btc'] = balances.btc;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      updateObj,
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret -apiKeys.secret');

    if (!updatedUser) {
      return next(new AppError('No user found with that ID', 404));
    }

    // Log activity
    await SystemLog.create({
      action: 'update-user',
      entity: 'user',
      entityId: updatedUser._id,
      performedBy: req.admin._id,
      performedByModel: 'Admin',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: updateObj
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/messages', adminProtect, restrictTo('super-admin', 'admin', 'support'), async (req, res, next) => {
  try {
    const { userId, message } = req.body;

    // Create message
    const newMessage = await Message.create({
      from: req.admin._id,
      fromModel: 'Admin',
      to: userId,
      toModel: 'User',
      message,
      read: false
    });

    // Log activity
    await SystemLog.create({
      action: 'send-message',
      entity: 'user',
      entityId: userId,
      performedBy: req.admin._id,
      performedByModel: 'Admin',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { messageId: newMessage._id }
    });

    // TODO: Send real-time notification via WebSocket

    res.status(201).json({
      status: 'success',
      data: {
        message: newMessage
      }
    });
  } catch (err) {
    next(err);
  }
});

// Transaction routes
app.get('/api/transactions', protect, async (req, res, next) => {
  try {
    const { page = 1, limit = 10, type, status } = req.query;

    // Build query
    const query = { userId: req.user.id };
    if (type) query.type = type;
    if (status) query.status = status;

    // Get transactions with pagination
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Get total count
    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/transactions/deposit', protect, async (req, res, next) => {
  try {
    const { amount, method } = req.body;

    // Validate amount
    if (amount <= 0) {
      return next(new AppError('Amount must be greater than zero', 400));
    }

    // Create transaction
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'deposit',
      amount,
      method,
      status: 'pending',
      reference: `DEP-${uuidv4().split('-')[0].toUpperCase()}`,
      details: {
        btcAddress: req.user.btcDepositAddress,
        ...(method === 'bank' && { bankDetails: 'Bank transfer details will be provided via email' }),
        ...(method === 'card' && { cardLast4: '1234' }) // In real app, use actual card details
      }
    });

    // Log activity
    await SystemLog.create({
      action: 'create-deposit',
      entity: 'transaction',
      entityId: transaction._id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { amount, method }
    });

    // Send email confirmation
    const mailOptions = {
      from: 'BitHash <no-reply@bithash.com>',
      to: req.user.email,
      subject: 'Deposit Request Received',
      html: `<p>Hello ${req.user.firstName},</p>
             <p>Your deposit request for $${amount} has been received and is being processed.</p>
             ${method === 'btc' ? `<p>Please send your Bitcoin to: <strong>${req.user.btcDepositAddress}</strong></p>` : ''}
             <p>Reference: ${transaction.reference}</p>
             <p>Thank you for choosing BitHash.</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/transactions/withdraw', protect, async (req, res, next) => {
  try {
    const { amount, method, destination } = req.body;

    // Validate amount
    if (amount <= 0) {
      return next(new AppError('Amount must be greater than zero', 400));
    }

    // Check user balance
    const user = await User.findById(req.user.id);
    if (user.balances.main < amount) {
      return next(new AppError('Insufficient balance for withdrawal', 400));
    }

    // Create transaction
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'withdrawal',
      amount,
      method,
      status: 'pending',
      reference: `WTH-${uuidv4().split('-')[0].toUpperCase()}`,
      details: {
        destination,
        ...(method === 'btc' && { btcAddress: destination })
      }
    });

    // Lock the amount (in real app, you might use a transaction here)
    user.balances.main -= amount;
    await user.save();

    // Log activity
    await SystemLog.create({
      action: 'create-withdrawal',
      entity: 'transaction',
      entityId: transaction._id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { amount, method, destination }
    });

    // Send email confirmation
    const mailOptions = {
      from: 'BitHash <no-reply@bithash.com>',
      to: req.user.email,
      subject: 'Withdrawal Request Received',
      html: `<p>Hello ${req.user.firstName},</p>
             <p>Your withdrawal request for $${amount} has been received and is being processed.</p>
             <p>Destination: ${destination}</p>
             <p>Reference: ${transaction.reference}</p>
             <p>Thank you for choosing BitHash.</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    next(err);
  }
});

// Investment routes
app.get('/api/plans', async (req, res, next) => {
  try {
    const plans = await Plan.find({ status: 'active' });

    res.status(200).json({
      status: 'success',
      results: plans.length,
      data: {
        plans
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/investments', protect, async (req, res, next) => {
  try {
    const { planId, amount, autoRenew } = req.body;

    // Validate amount
    if (amount <= 0) {
      return next(new AppError('Amount must be greater than zero', 400));
    }

    // Get plan
    const plan = await Plan.findById(planId);
    if (!plan || plan.status !== 'active') {
      return next(new AppError('Plan not found or inactive', 404));
    }

    // Check min amount
    if (amount < plan.minAmount) {
      return next(new AppError(`Minimum investment amount is $${plan.minAmount}`, 400));
    }

    // Check max amount if specified
    if (plan.maxAmount && amount > plan.maxAmount) {
      return next(new AppError(`Maximum investment amount is $${plan.maxAmount}`, 400));
    }

    // Check user balance
    const user = await User.findById(req.user.id);
    if (user.balances.main < amount) {
      return next(new AppError('Insufficient balance for investment', 400));
    }

    // Calculate end date
    const startDate = new Date();
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + plan.duration);

    // Create investment
    const investment = await Investment.create({
      userId: req.user.id,
      planId,
      amount,
      startDate,
      endDate,
      autoRenew: !!autoRenew
    });

    // Deduct from main balance and add to active balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();

    // Create transaction
    await Transaction.create({
      userId: req.user.id,
      type: 'investment',
      amount,
      status: 'completed',
      reference: `INV-${uuidv4().split('-')[0].toUpperCase()}`,
      details: {
        plan: plan.name,
        duration: plan.duration,
        interestRate: plan.interestRate
      }
    });

    // Log activity
    await SystemLog.create({
      action: 'create-investment',
      entity: 'investment',
      entityId: investment._id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { planId, amount, autoRenew }
    });

    // Send email confirmation
    const mailOptions = {
      from: 'BitHash <no-reply@bithash.com>',
      to: req.user.email,
      subject: 'New Investment Created',
      html: `<p>Hello ${req.user.firstName},</p>
             <p>Your investment in ${plan.name} has been successfully created.</p>
             <p>Amount: $${amount}</p>
             <p>Duration: ${plan.duration} days</p>
             <p>Interest Rate: ${plan.interestRate}%</p>
             <p>Maturity Date: ${endDate.toDateString()}</p>
             <p>Thank you for choosing BitHash.</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/investments', protect, async (req, res, next) => {
  try {
    const { status } = req.query;

    // Build query
    const query = { userId: req.user.id };
    if (status) query.status = status;

    const investments = await Investment.find(query)
      .populate('planId')
      .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: investments.length,
      data: {
        investments
      }
    });
  } catch (err) {
    next(err);
  }
});

// KYC routes
app.post('/api/kyc/submit', protect, async (req, res, next) => {
  try {
    const { documents } = req.body;

    // Validate documents
    if (!documents || !Array.isArray(documents) || documents.length === 0) {
      return next(new AppError('Please provide at least one document', 400));
    }

    // Update user KYC status and documents
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        'kyc.status': 'pending',
        $push: {
          'kyc.documents': {
            $each: documents.map(doc => ({
              type: doc.type,
              url: doc.url,
              status: 'pending'
            }))
          }
        }
      },
      { new: true }
    );

    // Log activity
    await SystemLog.create({
      action: 'submit-kyc',
      entity: 'user',
      entityId: req.user.id,
      performedBy: req.user.id,
      performedByModel: 'User',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { documentTypes: documents.map(d => d.type) }
    });

    // Send notification to admin
    const admins = await Admin.find({ role: { $in: ['super-admin', 'admin'] } });
    await Message.create({
      from: req.user.id,
      fromModel: 'User',
      to: admins[0]._id, // Send to first admin (in real app, might use round-robin)
      toModel: 'Admin',
      message: `New KYC submission from ${user.email} requires review`,
      read: false
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          kyc: user.kyc
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

// Error handling middleware (must be at the end)
app.use(globalErrorHandler);

// Initialize default admin and start server
initializeDefaultAdmin().then(() => {
  if (cluster.isMaster && NODE_ENV === 'production') {
    console.log(`Master ${process.pid} is running`);

    // Fork workers
    for (let i = 0; i < os.cpus().length; i++) {
      cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died`);
      cluster.fork(); // Create a new worker
    });
  } else {
    const server = app.listen(PORT, () => {
      console.log(`Server running on port ${PORT} in ${NODE_ENV} mode`);
    });

    // WebSocket server for real-time updates
    const wss = new WebSocket.Server({ server });

    wss.on('connection', (ws) => {
      console.log('New WebSocket connection');

      ws.on('message', (message) => {
        console.log('Received:', message);
        // Handle WebSocket messages
      });

      ws.on('close', () => {
        console.log('WebSocket connection closed');
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
  }
});
