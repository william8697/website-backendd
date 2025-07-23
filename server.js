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
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

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

redis.on('connect', () => console.log('Redis connected successfully'));
redis.on('error', err => console.error('Redis connection error:', err));

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// ================ MODELS ================ //

// User Schema
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please provide your first name'],
    trim: true,
    maxlength: [50, 'First name cannot be more than 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Please provide your last name'],
    trim: true,
    maxlength: [50, 'Last name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: {
    type: String,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  balance: {
    type: Number,
    default: 0,
    min: [0, 'Balance cannot be negative']
  },
  referralBonus: {
    type: Number,
    default: 0,
    min: [0, 'Referral bonus cannot be negative']
  },
  kycStatus: {
    type: String,
    enum: ['unverified', 'pending', 'approved', 'rejected'],
    default: 'unverified'
  },
  kycVerifiedAt: Date,
  status: {
    type: String,
    enum: ['active', 'suspended', 'banned'],
    default: 'active'
  },
  lastLogin: Date,
  devices: [{
    deviceId: String,
    ipAddress: String,
    userAgent: String,
    lastUsed: Date
  }],
  twoFactorAuth: {
    type: Boolean,
    default: false
  },
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  referralCode: {
    type: String,
    unique: true
  },
  referredBy: {
    type: mongoose.Schema.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referralCode: 1 }, { unique: true });
userSchema.index({ status: 1 });
userSchema.index({ kycStatus: 1 });

// Document middleware
userSchema.pre('save', async function(next) {
  // Generate referral code if new user
  if (this.isNew && !this.referralCode) {
    this.referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
  }

  // Hash password if modified
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
    if (!this.isNew) this.passwordChangedAt = Date.now() - 1000;
  }
  next();
});

// Instance methods
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model('User', userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false
  },
  role: {
    type: String,
    enum: ['admin', 'super-admin', 'support'],
    default: 'admin'
  },
  lastLogin: Date,
  active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

adminSchema.methods.correctPassword = async function(candidatePassword, adminPassword) {
  return await bcrypt.compare(candidatePassword, adminPassword);
};

const Admin = mongoose.model('Admin', adminSchema);

// Plan Schema
const planSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  minAmount: {
    type: Number,
    required: true
  },
  maxAmount: Number,
  duration: {
    type: Number, // in hours
    required: true
  },
  interestRate: {
    type: Number,
    required: true
  },
  referralBonus: {
    type: Number,
    required: true
  },
  contractType: {
    type: String,
    required: true
  },
  active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

const Plan = mongoose.model('Plan', planSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  plan: {
    type: mongoose.Schema.ObjectId,
    ref: 'Plan',
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: [0, 'Amount cannot be negative']
  },
  expectedEarnings: {
    type: Number,
    required: true
  },
  earnings: {
    type: Number,
    default: 0
  },
  startDate: {
    type: Date,
    default: Date.now
  },
  maturityDate: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'completed', 'cancelled'],
    default: 'active'
  }
}, {
  timestamps: true
});

investmentSchema.index({ user: 1 });
investmentSchema.index({ plan: 1 });
investmentSchema.index({ status: 1 });
investmentSchema.index({ maturityDate: 1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'investment', 'transfer', 'referral', 'interest'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  paymentMethod: {
    type: String,
    enum: ['btc', 'bank', 'card', 'internal']
  },
  walletAddress: String,
  description: String,
  reference: {
    type: String,
    unique: true
  }
}, {
  timestamps: true
});

transactionSchema.index({ user: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Document Schema
const kycDocumentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  documentType: {
    type: String,
    enum: ['passport', 'id-card', 'driver-license'],
    required: true
  },
  documentNumber: {
    type: String,
    required: true
  },
  frontImage: {
    type: String,
    required: true
  },
  backImage: String,
  selfieImage: String,
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  rejectionReason: String,
  reviewedBy: {
    type: mongoose.Schema.ObjectId,
    ref: 'Admin'
  },
  reviewedAt: Date
}, {
  timestamps: true
});

kycDocumentSchema.index({ user: 1 });
kycDocumentSchema.index({ status: 1 });

const KYCDocument = mongoose.model('KYCDocument', kycDocumentSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: [0, 'Amount cannot be negative']
  },
  walletAddress: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'rejected'],
    default: 'pending'
  },
  transaction: {
    type: mongoose.Schema.ObjectId,
    ref: 'Transaction'
  },
  processedBy: {
    type: mongoose.Schema.ObjectId,
    ref: 'Admin'
  },
  processedAt: Date,
  rejectionReason: String
}, {
  timestamps: true
});

withdrawalSchema.index({ user: 1 });
withdrawalSchema.index({ status: 1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Loan Schema
const loanSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: [0, 'Amount cannot be negative']
  },
  interestRate: {
    type: Number,
    required: true
  },
  duration: {
    type: Number, // in days
    required: true
  },
  purpose: String,
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'paid'],
    default: 'pending'
  },
  approvedBy: {
    type: mongoose.Schema.ObjectId,
    ref: 'Admin'
  },
  approvedAt: Date,
  dueDate: Date
}, {
  timestamps: true
});

loanSchema.index({ user: 1 });
loanSchema.index({ status: 1 });

const Loan = mongoose.model('Loan', loanSchema);

// Activity Log Schema
const activityLogSchema = new mongoose.Schema({
  admin: {
    type: mongoose.Schema.ObjectId,
    ref: 'Admin',
    required: true
  },
  action: {
    type: String,
    required: true
  },
  entityType: String,
  entityId: mongoose.Schema.Types.ObjectId,
  ipAddress: String,
  userAgent: String
}, {
  timestamps: true
});

activityLogSchema.index({ admin: 1 });
activityLogSchema.index({ createdAt: -1 });

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// API Key Schema
const apiKeySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true
  },
  key: {
    type: String,
    required: true,
    select: false
  },
  permissions: [String],
  expiresAt: Date,
  lastUsed: Date,
  active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

apiKeySchema.index({ user: 1 });
apiKeySchema.index({ key: 1 }, { unique: true });

const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// ================ UTILITY FUNCTIONS ================ //

const catchAsync = fn => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const createSendToken = (user, statusCode, res) => {
  const token = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

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

// ================ MIDDLEWARE ================ //

const protect = catchAsync(async (req, res, next) => {
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

  const decoded = await jwt.verify(token, JWT_SECRET);
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return res.status(401).json({
      status: 'fail',
      message: 'The user belonging to this token does no longer exist.'
    });
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return res.status(401).json({
      status: 'fail',
      message: 'User recently changed password! Please log in again.'
    });
  }

  req.user = currentUser;
  next();
});

const adminProtect = catchAsync(async (req, res, next) => {
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

  const decoded = await jwt.verify(token, JWT_SECRET);
  const currentAdmin = await Admin.findById(decoded.id);

  if (!currentAdmin) {
    return res.status(401).json({
      status: 'fail',
      message: 'The admin belonging to this token does no longer exist.'
    });
  }

  req.admin = currentAdmin;
  next();
});

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

// ================ INITIALIZATION ================ //

const initializeAdmin = async () => {
  const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
  if (!adminExists) {
    const admin = await Admin.create({
      email: 'admin@bithash.com',
      password: 'Admin@1234',
      firstName: 'System',
      lastName: 'Admin',
      role: 'super-admin'
    });
    console.log('Default admin created:', admin.email);
  }
};

const initializePlans = async () => {
  const plans = await Plan.countDocuments();
  if (plans === 0) {
    await Plan.create([
      {
        name: 'Starter Plan',
        minAmount: 30,
        maxAmount: 499,
        duration: 10,
        interestRate: 20,
        referralBonus: 5,
        contractType: '10 HOURS CONTRACT'
      },
      {
        name: 'Gold Plan',
        minAmount: 500,
        maxAmount: 1999,
        duration: 24,
        interestRate: 40,
        referralBonus: 5,
        contractType: '24 HOURS CONTRACT'
      },
      {
        name: 'Advance Plan',
        minAmount: 2000,
        maxAmount: 9999,
        duration: 48,
        interestRate: 60,
        referralBonus: 5,
        contractType: '48 HOURS CONTRACT'
      },
      {
        name: 'Exclusive Plan',
        minAmount: 10000,
        maxAmount: 30000,
        duration: 72,
        interestRate: 80,
        referralBonus: 5,
        contractType: '72 HOURS CONTRACT'
      },
      {
        name: 'Expert Plan',
        minAmount: 50000,
        maxAmount: null,
        duration: 96,
        interestRate: 100,
        referralBonus: 5,
        contractType: '96 HOURS CONTRACT'
      }
    ]);
    console.log('Investment plans initialized');
  }
};

// Initialize database
const initializeDB = async () => {
  await initializeAdmin();
  await initializePlans();
};

initializeDB();

// ================ ROUTES ================ //

// USER ENDPOINTS

// Get current user
app.get('/api/users/me', protect, catchAsync(async (req, res) => {
  const user = await User.findById(req.user._id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires')
    .populate('investments')
    .populate('transactions');

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// Update user profile
app.put('/api/users/profile', protect, catchAsync(async (req, res) => {
  const filteredBody = filterObj(
    req.body,
    'firstName',
    'lastName',
    'email',
    'phone',
    'country'
  );

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    filteredBody,
    {
      new: true,
      runValidators: true
    }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user address
app.put('/api/users/address', protect, catchAsync(async (req, res) => {
  const filteredBody = filterObj(
    req.body,
    'street',
    'city',
    'state',
    'postalCode',
    'country'
  );

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { address: filteredBody },
    {
      new: true,
      runValidators: true
    }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user password
app.put('/api/users/password', protect, catchAsync(async (req, res) => {
  const user = await User.findById(req.user._id).select('+password');

  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return res.status(401).json({
      status: 'fail',
      message: 'Your current password is wrong'
    });
  }

  user.password = req.body.newPassword;
  await user.save();

  createSendToken(user, 200, res);
}));

// Create API key
app.post('/api/users/api-keys', protect, catchAsync(async (req, res) => {
  const { name, permissions, expiresAt } = req.body;
  
  const apiKey = crypto.randomBytes(32).toString('hex');
  const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');

  const newApiKey = await ApiKey.create({
    user: req.user._id,
    name,
    key: hashedKey,
    permissions,
    expiresAt: expiresAt ? new Date(expiresAt) : null
  });

  res.status(201).json({
    status: 'success',
    data: {
      apiKey: {
        ...newApiKey.toObject(),
        key: apiKey // Only show the unhashed key once
      }
    }
  });
}));

// ADMIN ENDPOINTS

// Admin login
app.post('/api/admin/auth/login', catchAsync(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide email and password'
    });
  }

  const admin = await Admin.findOne({ email }).select('+password');

  if (!admin || !(await admin.correctPassword(password, admin.password))) {
    return res.status(401).json({
      status: 'fail',
      message: 'Incorrect email or password'
    });
  }

  const token = jwt.sign({ id: admin._id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

  admin.password = undefined;

  res.status(200).json({
    status: 'success',
    token,
    data: {
      admin
    }
  });
}));

// Admin logout
app.post('/api/admin/auth/logout', adminProtect, (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({
    status: 'success'
  });
});

// Get admin dashboard stats
app.get('/api/admin/dashboard', adminProtect, catchAsync(async (req, res) => {
  const stats = await redis.get('adminDashboardStats');
  
  if (stats) {
    return res.status(200).json({
      status: 'success',
      data: JSON.parse(stats)
    });
  }

  const totalUsers = await User.countDocuments();
  const activeUsers = await User.countDocuments({ status: 'active' });
  const totalDeposits = await Transaction.aggregate([
    { $match: { type: 'deposit', status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  const totalWithdrawals = await Transaction.aggregate([
    { $match: { type: 'withdrawal', status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
  const pendingKYC = await KYCDocument.countDocuments({ status: 'pending' });

  const dashboardStats = {
    totalUsers,
    activeUsers,
    totalDeposits: totalDeposits.length > 0 ? totalDeposits[0].total : 0,
    totalWithdrawals: totalWithdrawals.length > 0 ? totalWithdrawals[0].total : 0,
    pendingWithdrawals,
    pendingKYC
  };

  await redis.set('adminDashboardStats', JSON.stringify(dashboardStats), 'EX', 3600);

  res.status(200).json({
    status: 'success',
    data: dashboardStats
  });
}));

// Get user growth data
app.get('/api/admin/users/growth', adminProtect, catchAsync(async (req, res) => {
  const growthData = await redis.get('userGrowthData');
  
  if (growthData) {
    return res.status(200).json({
      status: 'success',
      data: JSON.parse(growthData)
    });
  }

  const now = new Date();
  const last30Days = new Date(now.setDate(now.getDate() - 30));

  const data = await User.aggregate([
    {
      $match: {
        createdAt: { $gte: last30Days }
      }
    },
    {
      $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
        count: { $sum: 1 }
      }
    },
    {
      $sort: { '_id': 1 }
    }
  ]);

  await redis.set('userGrowthData', JSON.stringify(data), 'EX', 3600);

  res.status(200).json({
    status: 'success',
    data
  });
}));

// Get admin activity logs
app.get('/api/admin/activity', adminProtect, catchAsync(async (req, res) => {
  const activities = await ActivityLog.find({ admin: req.admin._id })
    .sort('-createdAt')
    .limit(50);

  res.status(200).json({
    status: 'success',
    results: activities.length,
    data: {
      activities
    }
  });
}));

// Get all users (with pagination, filtering, sorting)
app.get('/api/admin/users', adminProtect, catchAsync(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const skip = (page - 1) * limit;

  let query = {};
  if (req.query.search) {
    query.$or = [
      { email: { $regex: req.query.search, $options: 'i' } },
      { firstName: { $regex: req.query.search, $options: 'i' } },
      { lastName: { $regex: req.query.search, $options: 'i' } }
    ];
  }
  if (req.query.status) {
    query.status = req.query.status;
  }

  const users = await User.find(query)
    .skip(skip)
    .limit(limit)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  const total = await User.countDocuments(query);

  res.status(200).json({
    status: 'success',
    results: users.length,
    total,
    data: {
      users
    }
  });
}));

// Get/Update/Delete specific user
app.route('/api/admin/users/:id')
  .get(adminProtect, catchAsync(async (req, res) => {
    const user = await User.findById(req.params.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires')
      .populate('investments')
      .populate('transactions');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  }))
  .put(adminProtect, catchAsync(async (req, res) => {
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'phone',
      'country',
      'balance',
      'referralBonus'
    );

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      filteredBody,
      {
        new: true,
        runValidators: true
      }
    ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

    if (!updatedUser) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  }))
  .delete(adminProtect, catchAsync(async (req, res) => {
    await User.findByIdAndDelete(req.params.id);

    res.status(204).json({
      status: 'success',
      data: null
    });
  }));

// Update user status
app.put('/api/admin/users/:id/status', adminProtect, catchAsync(async (req, res) => {
  const { status } = req.body;

  if (!['active', 'suspended', 'banned'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { status },
    {
      new: true,
      runValidators: true
    }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  if (!user) {
    return res.status(404).json({
      status: 'fail',
      message: 'No user found with that ID'
    });
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// Get pending KYC documents
app.get('/api/admin/kyc/pending', adminProtect, catchAsync(async (req, res) => {
  const pendingKYCs = await KYCDocument.find({ status: 'pending' })
    .populate('user', 'firstName lastName email');

  res.status(200).json({
    status: 'success',
    results: pendingKYCs.length,
    data: {
      kycDocuments: pendingKYCs
    }
  });
}));

// Get specific KYC document
app.get('/api/admin/kyc/:id', adminProtect, catchAsync(async (req, res) => {
  const kycDocument = await KYCDocument.findById(req.params.id)
    .populate('user', 'firstName lastName email');

  if (!kycDocument) {
    return res.status(404).json({
      status: 'fail',
      message: 'No KYC document found with that ID'
    });
  }

  res.status(200).json({
    status: 'success',
    data: {
      kycDocument
    }
  });
}));

// Review KYC document
app.post('/api/admin/kyc/:id/review', adminProtect, catchAsync(async (req, res) => {
  const { status, rejectionReason } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  if (status === 'rejected' && !rejectionReason) {
    return res.status(400).json({
      status: 'fail',
      message: 'Rejection reason is required when rejecting KYC'
    });
  }

  const kycDocument = await KYCDocument.findByIdAndUpdate(
    req.params.id,
    {
      status,
      rejectionReason: status === 'rejected' ? rejectionReason : undefined,
      reviewedBy: req.admin._id,
      reviewedAt: new Date()
    },
    { new: true }
  ).populate('user', 'firstName lastName email');

  if (!kycDocument) {
    return res.status(404).json({
      status: 'fail',
      message: 'No KYC document found with that ID'
    });
  }

  // Update user KYC status
  await User.findByIdAndUpdate(kycDocument.user._id, {
    kycStatus: status,
    kycVerifiedAt: status === 'approved' ? new Date() : null
  });

  res.status(200).json({
    status: 'success',
    data: {
      kycDocument
    }
  });
}));

// Get pending withdrawals
app.get('/api/admin/withdrawals/pending', adminProtect, catchAsync(async (req, res) => {
  const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
    .populate('user', 'firstName lastName email');

  res.status(200).json({
    status: 'success',
    results: pendingWithdrawals.length,
    data: {
      withdrawals: pendingWithdrawals
    }
  });
}));

// Get specific withdrawal
app.get('/api/admin/withdrawals/:id', adminProtect, catchAsync(async (req, res) => {
  const withdrawal = await Withdrawal.findById(req.params.id)
    .populate('user', 'firstName lastName email');

  if (!withdrawal) {
    return res.status(404).json({
      status: 'fail',
      message: 'No withdrawal found with that ID'
    });
  }

  res.status(200).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// Process withdrawal
app.post('/api/admin/withdrawals/:id/process', adminProtect, catchAsync(async (req, res) => {
  const { status, rejectionReason } = req.body;

  if (!['completed', 'rejected'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  if (status === 'rejected' && !rejectionReason) {
    return res.status(400).json({
      status: 'fail',
      message: 'Rejection reason is required when rejecting withdrawal'
    });
  }

  const withdrawal = await Withdrawal.findById(req.params.id)
    .populate('user', 'firstName lastName email balance');

  if (!withdrawal) {
    return res.status(404).json({
      status: 'fail',
      message: 'No withdrawal found with that ID'
    });
  }

  if (withdrawal.status !== 'pending') {
    return res.status(400).json({
      status: 'fail',
      message: 'Withdrawal has already been processed'
    });
  }

  if (status === 'completed') {
    // Create transaction record
    const transaction = await Transaction.create({
      user: withdrawal.user._id,
      amount: withdrawal.amount,
      type: 'withdrawal',
      status: 'completed',
      description: `Withdrawal to ${withdrawal.walletAddress}`,
      reference: `WDR-${Date.now()}`
    });

    withdrawal.transaction = transaction._id;
  } else if (status === 'rejected') {
    // Refund the amount to user's balance
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });
  }

  withdrawal.status = status;
  withdrawal.processedBy = req.admin._id;
  withdrawal.processedAt = new Date();
  withdrawal.rejectionReason = status === 'rejected' ? rejectionReason : undefined;
  await withdrawal.save();

  res.status(200).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', adminProtect, catchAsync(async (req, res) => {
  const { withdrawalIds, status } = req.body;

  if (!['completed', 'rejected'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide withdrawal IDs to process'
    });
  }

  const withdrawals = await Withdrawal.find({
    _id: { $in: withdrawalIds },
    status: 'pending'
  }).populate('user', 'firstName lastName email balance');

  if (withdrawals.length === 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'No pending withdrawals found with the provided IDs'
    });
  }

  const processedWithdrawals = [];
  const processedTransactions = [];

  for (const withdrawal of withdrawals) {
    if (status === 'completed') {
      const transaction = await Transaction.create({
        user: withdrawal.user._id,
        amount: withdrawal.amount,
        type: 'withdrawal',
        status: 'completed',
        description: `Withdrawal to ${withdrawal.walletAddress}`,
        reference: `WDR-${Date.now()}`
      });

      withdrawal.transaction = transaction._id;
      processedTransactions.push(transaction);
    } else if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.user._id, {
        $inc: { balance: withdrawal.amount }
      });
    }

    withdrawal.status = status;
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    await withdrawal.save();
    processedWithdrawals.push(withdrawal);
  }

  res.status(200).json({
    status: 'success',
    results: processedWithdrawals.length,
    data: {
      withdrawals: processedWithdrawals,
      transactions: status === 'completed' ? processedTransactions : undefined
    }
  });
}));

// Get all loans or create new loan
app.route('/api/admin/loans')
  .get(adminProtect, catchAsync(async (req, res) => {
    const loans = await Loan.find()
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName');

    res.status(200).json({
      status: 'success',
      results: loans.length,
      data: {
        loans
      }
    });
  }))
  .post(adminProtect, catchAsync(async (req, res) => {
    const { userId, amount, interestRate, duration, purpose } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    const loan = await Loan.create({
      user: userId,
      amount,
      interestRate,
      duration,
      purpose,
      status: 'approved',
      approvedBy: req.admin._id,
      approvedAt: new Date()
    });

    res.status(201).json({
      status: 'success',
      data: {
        loan
      }
    });
  }));

// Get/Update/Delete specific loan
app.route('/api/admin/loans/:id')
  .get(adminProtect, catchAsync(async (req, res) => {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName');

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        loan
      }
    });
  }))
  .put(adminProtect, catchAsync(async (req, res) => {
    const filteredBody = filterObj(
      req.body,
      'amount',
      'interestRate',
      'duration',
      'purpose',
      'status'
    );

    if (filteredBody.status === 'approved') {
      filteredBody.approvedBy = req.admin._id;
      filteredBody.approvedAt = new Date();
    }

    const loan = await Loan.findByIdAndUpdate(
      req.params.id,
      filteredBody,
      { new: true, runValidators: true }
    )
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName');

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        loan
      }
    });
  }))
  .delete(adminProtect, catchAsync(async (req, res) => {
    await Loan.findByIdAndDelete(req.params.id);

    res.status(204).json({
      status: 'success',
      data: null
    });
  }));

// Get admin profile
app.get('/api/admin/profile', adminProtect, catchAsync(async (req, res) => {
  const admin = await Admin.findById(req.admin._id)
    .select('-password -passwordChangedAt');

  res.status(200).json({
    status: 'success',
    data: {
      admin
    }
  });
}));

// DASHBOARD ENDPOINTS

// Get investment plans
app.get('/api/plans', protect, catchAsync(async (req, res) => {
  const plans = await Plan.find();

  res.status(200).json({
    status: 'success',
    results: plans.length,
    data: {
      plans
    }
  });
}));

// Get user transactions
app.get('/api/transactions', protect, catchAsync(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  let query = { user: req.user._id };
  if (req.query.type) {
    query.type = req.query.type;
  }
  if (req.query.status) {
    query.status = req.query.status;
  }

  const transactions = await Transaction.find(query)
    .sort('-createdAt')
    .skip(skip)
    .limit(limit);

  const total = await Transaction.countDocuments(query);

  res.status(200).json({
    status: 'success',
    results: transactions.length,
    total,
    data: {
      transactions
    }
  });
}));

// Get mining stats
app.get('/api/mining/stats', protect, catchAsync(async (req, res) => {
  const stats = await redis.get(`miningStats:${req.user._id}`);
  
  if (stats) {
    return res.status(200).json({
      status: 'success',
      data: JSON.parse(stats)
    });
  }

  const activeInvestments = await Investment.countDocuments({
    user: req.user._id,
    status: 'active'
  });
  const maturedInvestments = await Investment.countDocuments({
    user: req.user._id,
    status: 'completed'
  });
  const totalEarnings = await Investment.aggregate([
    { $match: { user: req.user._id, status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$earnings' } } }
  ]);
  const pendingEarnings = await Investment.aggregate([
    { $match: { user: req.user._id, status: 'active' } },
    { $group: { _id: null, total: { $sum: '$expectedEarnings' } } }
  ]);

  const miningStats = {
    activeInvestments,
    maturedInvestments,
    totalEarnings: totalEarnings.length > 0 ? totalEarnings[0].total : 0,
    pendingEarnings: pendingEarnings.length > 0 ? pendingEarnings[0].total : 0
  };

  await redis.set(`miningStats:${req.user._id}`, JSON.stringify(miningStats), 'EX', 600);

  res.status(200).json({
    status: 'success',
    data: miningStats
  });
}));

// Create deposit
app.post('/api/transactions/deposit', protect, catchAsync(async (req, res) => {
  const { amount, paymentMethod } = req.body;

  if (!amount || !paymentMethod) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide amount and payment method'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  let walletAddress;
  if (paymentMethod === 'btc') {
    walletAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
  }

  const transaction = await Transaction.create({
    user: req.user._id,
    amount,
    type: 'deposit',
    status: 'pending',
    paymentMethod,
    walletAddress,
    description: `Deposit via ${paymentMethod}`,
    reference: `DEP-${Date.now()}`
  });

  res.status(201).json({
    status: 'success',
    data: {
      transaction
    }
  });
}));

// Create withdrawal
app.post('/api/transactions/withdraw', protect, catchAsync(async (req, res) => {
  const { amount, walletAddress } = req.body;

  if (!amount || !walletAddress) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide amount and wallet address'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  const user = await User.findById(req.user._id);
  if (user.balance < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Deduct from user balance
  user.balance -= amount;
  await user.save();

  const withdrawal = await Withdrawal.create({
    user: req.user._id,
    amount,
    walletAddress,
    status: 'pending'
  });

  res.status(201).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// Create investment
app.post('/api/investments', protect, catchAsync(async (req, res) => {
  const { planId, amount } = req.body;

  if (!planId || !amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide plan ID and amount'
    });
  }

  const plan = await Plan.findById(planId);
  if (!plan) {
    return res.status(404).json({
      status: 'fail',
      message: 'No plan found with that ID'
    });
  }

  if (amount < plan.minAmount || (plan.maxAmount && amount > plan.maxAmount)) {
    return res.status(400).json({
      status: 'fail',
      message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount || 'unlimited'}`
    });
  }

  const user = await User.findById(req.user._id);
  if (user.balance < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Deduct from user balance
  user.balance -= amount;
  await user.save();

  // Calculate expected earnings
  const expectedEarnings = amount * (plan.interestRate / 100);
  const maturityDate = moment().add(plan.duration, 'hours').toDate();

  const investment = await Investment.create({
    user: req.user._id,
    plan: planId,
    amount,
    expectedEarnings,
    earnings: 0,
    startDate: new Date(),
    maturityDate,
    status: 'active'
  });

  // Create transaction record
  const transaction = await Transaction.create({
    user: req.user._id,
    amount,
    type: 'investment',
    status: 'completed',
    description: `Investment in ${plan.name}`,
    reference: `INV-${Date.now()}`
  });

  res.status(201).json({
    status: 'success',
    data: {
      investment,
      transaction
    }
  });
}));

// Transfer funds
app.post('/api/transactions/transfer', protect, catchAsync(async (req, res) => {
  const { recipientEmail, amount } = req.body;

  if (!recipientEmail || !amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide recipient email and amount'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  if (recipientEmail === req.user.email) {
    return res.status(400).json({
      status: 'fail',
      message: 'You cannot transfer to yourself'
    });
  }

  const recipient = await User.findOne({ email: recipientEmail });
  if (!recipient) {
    return res.status(404).json({
      status: 'fail',
      message: 'No user found with that email'
    });
  }

  const sender = await User.findById(req.user._id);
  if (sender.balance < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Perform transfer
  sender.balance -= amount;
  recipient.balance += amount;
  await Promise.all([sender.save(), recipient.save()]);

  // Create transaction records
  const senderTransaction = await Transaction.create({
    user: req.user._id,
    amount,
    type: 'transfer',
    status: 'completed',
    description: `Transfer to ${recipientEmail}`,
    reference: `TRF-${Date.now()}`
  });

  const recipientTransaction = await Transaction.create({
    user: recipient._id,
    amount,
    type: 'transfer',
    status: 'completed',
    description: `Transfer from ${req.user.email}`,
    reference: `TRF-${Date.now()}`
  });

  res.status(201).json({
    status: 'success',
    data: {
      transaction: senderTransaction
    }
  });
}));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  res.status(err.statusCode).json({
    status: err.status,
    message: err.message
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
