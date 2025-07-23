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
const validator = require('validator');

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

// Redis client
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// MongoDB connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

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

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'] },
  lastName: { type: String, required: [true, 'Last name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: { type: String, validate: [validator.isMobilePhone, 'Please provide a valid phone number'] },
  country: String,
  city: String,
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 8,
    select: false
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  apiKeys: [{
    name: String,
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now }
  }],
  balance: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 }
  },
  kyc: {
    status: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    documents: {
      identity: String,
      address: String,
      selfie: String
    },
    submittedAt: Date,
    reviewedAt: Date,
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
  },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  referralCode: String,
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

UserSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

UserSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

UserSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

UserSchema.methods.generateApiKey = function() {
  const key = uuidv4();
  const secret = crypto.randomBytes(32).toString('hex');
  return { key, secret };
};

const User = mongoose.model('User', UserSchema);

const AdminSchema = new mongoose.Schema({
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
  role: { type: String, enum: ['super-admin', 'admin', 'support'], default: 'admin' },
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  permissions: [String],
  status: { type: String, enum: ['active', 'suspended'], default: 'active' }
}, { timestamps: true });

AdminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

AdminSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const Admin = mongoose.model('Admin', AdminSchema);

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number, required: true },
  duration: { type: Number, required: true }, // in hours
  percentage: { type: Number, required: true },
  referralBonus: { type: Number, default: 5 },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
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
  referralBonusAmount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

InvestmentSchema.index({ user: 1, status: 1 });
InvestmentSchema.index({ endDate: 1 });

const Investment = mongoose.model('Investment', InvestmentSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  details: mongoose.Schema.Types.Mixed,
  reference: { type: String, unique: true },
  btcAddress: String,
  btcAmount: Number,
  btcTxId: String,
  adminNote: String,
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

TransactionSchema.index({ user: 1, type: 1, status: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const KYCSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['identity', 'address', 'selfie'], required: true },
  document: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewedAt: Date,
  rejectionReason: String,
  createdAt: { type: Date, default: Date.now }
});

const KYC = mongoose.model('KYC', KYCSchema);

const LoanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  collateral: { type: Number, required: true }, // BTC amount
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], default: 'pending' },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: Date,
  dueDate: Date,
  repaymentAmount: Number,
  createdAt: { type: Date, default: Date.now }
});

const Loan = mongoose.model('Loan', LoanSchema);

const ActivitySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  action: { type: String, required: true },
  details: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
});

const Activity = mongoose.model('Activity', ActivitySchema);

// Initialize default admin if not exists
async function initializeDefaultAdmin() {
  const defaultAdmin = {
    email: 'admin@bithash.com',
    password: 'Admin@1234',
    role: 'super-admin',
    permissions: ['all'],
    status: 'active'
  };

  const existingAdmin = await Admin.findOne({ email: defaultAdmin.email });
  if (!existingAdmin) {
    const admin = new Admin(defaultAdmin);
    await admin.save();
    console.log('Default admin created:', defaultAdmin.email);
  }
}

initializeDefaultAdmin();

// Initialize plans if not exists
async function initializePlans() {
  const plans = [
    {
      name: 'Starter Plan',
      description: '10 HOURS CONTRACT',
      minAmount: 30,
      maxAmount: 499,
      duration: 10,
      percentage: 20,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Gold Plan',
      description: '24 HOURS CONTRACT',
      minAmount: 500,
      maxAmount: 1999,
      duration: 24,
      percentage: 40,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Advance Plan',
      description: '48 HOURS CONTRACT',
      minAmount: 2000,
      maxAmount: 9999,
      duration: 48,
      percentage: 60,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Exclusive Plan',
      description: '72 HOURS CONTRACT',
      minAmount: 10000,
      maxAmount: 30000,
      duration: 72,
      percentage: 80,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Expert Plan',
      description: '96 HOURS CONTRACT',
      minAmount: 50000,
      maxAmount: 1000000,
      duration: 96,
      percentage: 100,
      referralBonus: 5,
      status: 'active'
    }
  ];

  for (const planData of plans) {
    const existingPlan = await Plan.findOne({ name: planData.name });
    if (!existingPlan) {
      const plan = new Plan(planData);
      await plan.save();
      console.log('Plan created:', planData.name);
    }
  }
}

initializePlans();

// Utility functions
const signToken = (id, role = 'user') => {
  return jwt.sign({ id, role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res, role = 'user') => {
  const token = signToken(user._id, role);
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none'
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

const catchAsync = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

const AppError = require('./utils/appError');

// Authentication middleware
const protect = catchAsync(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  const decoded = await promisify(jwt.verify)(token, JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please log in again.', 401));
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
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  const decoded = await promisify(jwt.verify)(token, JWT_SECRET);

  if (decoded.role !== 'admin' && decoded.role !== 'super-admin') {
    return next(new AppError('You do not have permission to perform this action', 403));
  }

  const currentAdmin = await Admin.findById(decoded.id);
  if (!currentAdmin) {
    return next(new AppError('The admin belonging to this token does no longer exist.', 401));
  }

  req.admin = currentAdmin;
  next();
});

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

// User Endpoints

// GET /api/users/me - Get current user
app.get('/api/users/me', protect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// PUT /api/users/profile - Update user profile
app.put('/api/users/profile', protect, catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, phone, country, city } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { firstName, lastName, email, phone, country, city },
    { new: true, runValidators: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// PUT /api/users/address - Update user address
app.put('/api/users/address', protect, catchAsync(async (req, res, next) => {
  const { street, city, state, postalCode, country } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { address: { street, city, state, postalCode, country } },
    { new: true, runValidators: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// PUT /api/users/password - Update user password
app.put('/api/users/password', protect, catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user._id).select('+password');

  if (!(await user.correctPassword(currentPassword, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  user.password = newPassword;
  await user.save();

  createSendToken(user, 200, res);
}));

// POST /api/users/api-keys - Create API key
app.post('/api/users/api-keys', protect, catchAsync(async (req, res, next) => {
  const { name, permissions, expiresInDays } = req.body;

  if (!name || !permissions || !Array.isArray(permissions)) {
    return next(new AppError('Please provide name and permissions for the API key', 400));
  }

  const { key, secret } = req.user.generateApiKey();
  const expiresAt = expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null;

  const newApiKey = {
    name,
    key,
    secret,
    permissions,
    expiresAt
  };

  await User.findByIdAndUpdate(req.user._id, {
    $push: { apiKeys: newApiKey }
  });

  res.status(201).json({
    status: 'success',
    data: {
      apiKey: {
        name,
        key,
        secret,
        permissions,
        expiresAt
      }
    }
  });
}));

// Admin Endpoints

// POST /api/admin/auth/login - Admin login
app.post('/api/admin/auth/login', catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  const admin = await Admin.findOne({ email }).select('+password');

  if (!admin || !(await admin.correctPassword(password, admin.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  if (admin.status === 'suspended') {
    return next(new AppError('Your account has been suspended. Please contact support.', 403));
  }

  admin.lastLogin = Date.now();
  admin.loginHistory.push({
    ip: req.ip,
    device: req.headers['user-agent'],
    location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
  });
  await admin.save();

  createSendToken(admin, 200, res, 'admin');
}));

// POST /api/admin/auth/logout - Admin logout
app.post('/api/admin/auth/logout', adminProtect, (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

// GET /api/admin/dashboard - Admin dashboard stats
app.get('/api/admin/dashboard', adminProtect, catchAsync(async (req, res, next) => {
  const stats = {};

  // Get total users
  stats.totalUsers = await User.countDocuments();
  stats.activeUsers = await User.countDocuments({ status: 'active' });
  stats.suspendedUsers = await User.countDocuments({ status: 'suspended' });

  // Get total deposits and withdrawals
  const depositStats = await Transaction.aggregate([
    { $match: { type: 'deposit', status: 'completed' } },
    { $group: { _id: null, totalAmount: { $sum: '$amount' }, count: { $sum: 1 } } }
  ]);

  const withdrawalStats = await Transaction.aggregate([
    { $match: { type: 'withdrawal', status: 'completed' } },
    { $group: { _id: null, totalAmount: { $sum: '$amount' }, count: { $sum: 1 } } }
  ]);

  stats.totalDeposits = depositStats.length > 0 ? depositStats[0].totalAmount : 0;
  stats.totalWithdrawals = withdrawalStats.length > 0 ? withdrawalStats[0].totalAmount : 0;
  stats.depositCount = depositStats.length > 0 ? depositStats[0].count : 0;
  stats.withdrawalCount = withdrawalStats.length > 0 ? withdrawalStats[0].count : 0;

  // Get pending KYC and withdrawals
  stats.pendingKYC = await KYC.countDocuments({ status: 'pending' });
  stats.pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });

  // Get recent activities
  stats.recentActivities = await Activity.find()
    .sort({ createdAt: -1 })
    .limit(10)
    .populate('user', 'firstName lastName email')
    .populate('admin', 'email');

  res.status(200).json({
    status: 'success',
    data: {
      stats
    }
  });
}));

// GET /api/admin/users/growth - User growth stats
app.get('/api/admin/users/growth', adminProtect, catchAsync(async (req, res, next) => {
  const { days = 30 } = req.query;
  const validDays = [7, 30, 90, 365];
  
  if (!validDays.includes(parseInt(days))) {
    return next(new AppError('Invalid days parameter. Valid values are 7, 30, 90, 365', 400));
  }

  const date = new Date();
  date.setDate(date.getDate() - days);

  const growthData = await User.aggregate([
    { $match: { createdAt: { $gte: date } } },
    { $group: {
      _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
      count: { $sum: 1 }
    }},
    { $sort: { _id: 1 } }
  ]);

  res.status(200).json({
    status: 'success',
    data: {
      growthData
    }
  });
}));

// GET /api/admin/activity - Recent activities
app.get('/api/admin/activity', adminProtect, catchAsync(async (req, res, next) => {
  const activities = await Activity.find()
    .sort({ createdAt: -1 })
    .limit(50)
    .populate('user', 'firstName lastName email')
    .populate('admin', 'email');

  res.status(200).json({
    status: 'success',
    data: {
      activities
    }
  });
}));

// GET /api/admin/users - List all users
app.get('/api/admin/users', adminProtect, catchAsync(async (req, res, next) => {
  const { page = 1, limit = 20, search, status } = req.query;
  const skip = (page - 1) * limit;

  let query = {};
  if (search) {
    query.$or = [
      { firstName: { $regex: search, $options: 'i' } },
      { lastName: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } }
    ];
  }
  if (status) {
    query.status = status;
  }

  const users = await User.find(query)
    .skip(skip)
    .limit(limit)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  const total = await User.countDocuments(query);

  res.status(200).json({
    status: 'success',
    results: total,
    data: {
      users
    }
  });
}));

// GET /api/admin/users/{id} - Get user by ID
app.get('/api/admin/users/:id', adminProtect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// PUT /api/admin/users/{id} - Update user
app.put('/api/admin/users/:id', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, phone, country, city, address, status, balance } = req.body;

  const updateFields = {
    firstName, lastName, email, phone, country, city, address, status
  };

  if (balance) {
    updateFields.balance = balance;
  }

  const user = await User.findByIdAndUpdate(req.params.id, updateFields, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'update_user',
    details: {
      userId: user._id,
      changes: updateFields
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// DELETE /api/admin/users/{id} - Delete user (soft delete)
app.delete('/api/admin/users/:id', adminProtect, restrictTo('super-admin'), catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.params.id, { status: 'banned' }, {
    new: true
  });

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'delete_user',
    details: {
      userId: user._id
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(204).json({
    status: 'success',
    data: null
  });
}));

// PUT /api/admin/users/{id}/status - Update user status
app.put('/api/admin/users/:id/status', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status } = req.body;

  if (!['active', 'suspended', 'banned'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const user = await User.findByIdAndUpdate(req.params.id, { status }, {
    new: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'update_user_status',
    details: {
      userId: user._id,
      status
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// GET /api/admin/kyc/pending - Get pending KYC submissions
app.get('/api/admin/kyc/pending', adminProtect, catchAsync(async (req, res, next) => {
  const pendingKYC = await KYC.find({ status: 'pending' })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: 1 });

  res.status(200).json({
    status: 'success',
    data: {
      pendingKYC
    }
  });
}));

// GET /api/admin/kyc/{id} - Get KYC submission details
app.get('/api/admin/kyc/:id', adminProtect, catchAsync(async (req, res, next) => {
  const kyc = await KYC.findById(req.params.id)
    .populate('user', 'firstName lastName email')
    .populate('reviewedBy', 'email');

  if (!kyc) {
    return next(new AppError('KYC submission not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      kyc
    }
  });
}));

// POST /api/admin/kyc/{id}/review - Review KYC submission
app.post('/api/admin/kyc/:id/review', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status, rejectionReason } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  if (status === 'rejected' && !rejectionReason) {
    return next(new AppError('Rejection reason is required', 400));
  }

  const kyc = await KYC.findByIdAndUpdate(req.params.id, {
    status,
    reviewedBy: req.admin._id,
    reviewedAt: Date.now(),
    rejectionReason: status === 'rejected' ? rejectionReason : undefined
  }, { new: true });

  if (!kyc) {
    return next(new AppError('KYC submission not found', 404));
  }

  // Update user KYC status if all documents are approved
  if (status === 'approved') {
    const userKYC = await KYC.find({ user: kyc.user });
    const allApproved = userKYC.every(doc => doc.status === 'approved');

    if (allApproved) {
      await User.findByIdAndUpdate(kyc.user, {
        'kyc.status': 'verified',
        'kyc.reviewedBy': req.admin._id,
        'kyc.reviewedAt': Date.now()
      });
    }
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'review_kyc',
    details: {
      kycId: kyc._id,
      userId: kyc.user,
      status,
      rejectionReason
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      kyc
    }
  });
}));

// GET /api/admin/withdrawals/pending - Get pending withdrawals
app.get('/api/admin/withdrawals/pending', adminProtect, catchAsync(async (req, res, next) => {
  const pendingWithdrawals = await Transaction.find({ type: 'withdrawal', status: 'pending' })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: 1 });

  res.status(200).json({
    status: 'success',
    data: {
      pendingWithdrawals
    }
  });
}));

// GET /api/admin/withdrawals/{id} - Get withdrawal details
app.get('/api/admin/withdrawals/:id', adminProtect, catchAsync(async (req, res, next) => {
  const withdrawal = await Transaction.findById(req.params.id)
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'email');

  if (!withdrawal || withdrawal.type !== 'withdrawal') {
    return next(new AppError('Withdrawal not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// POST /api/admin/withdrawals/{id}/process - Process withdrawal
app.post('/api/admin/withdrawals/:id/process', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status, adminNote } = req.body;

  if (!['completed', 'failed', 'cancelled'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const withdrawal = await Transaction.findOne({
    _id: req.params.id,
    type: 'withdrawal'
  }).populate('user', 'firstName lastName email');

  if (!withdrawal) {
    return next(new AppError('Withdrawal not found', 404));
  }

  if (withdrawal.status !== 'pending') {
    return next(new AppError('Withdrawal has already been processed', 400));
  }

  withdrawal.status = status;
  withdrawal.processedBy = req.admin._id;
  withdrawal.processedAt = Date.now();
  withdrawal.adminNote = adminNote;

  // If rejected, return funds to user's balance
  if (status === 'failed' || status === 'cancelled') {
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { 'balance.main': withdrawal.amount }
    });
  }

  await withdrawal.save();

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'process_withdrawal',
    details: {
      withdrawalId: withdrawal._id,
      userId: withdrawal.user._id,
      amount: withdrawal.amount,
      status
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// POST /api/admin/withdrawals/process-batch - Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { withdrawalIds, status, adminNote } = req.body;

  if (!['completed', 'failed', 'cancelled'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
    return next(new AppError('Please provide withdrawal IDs to process', 400));
  }

  const withdrawals = await Transaction.find({
    _id: { $in: withdrawalIds },
    type: 'withdrawal',
    status: 'pending'
  }).populate('user', 'firstName lastName email');

  if (withdrawals.length === 0) {
    return next(new AppError('No pending withdrawals found to process', 404));
  }

  const bulkOps = withdrawals.map(withdrawal => ({
    updateOne: {
      filter: { _id: withdrawal._id },
      update: {
        $set: {
          status,
          processedBy: req.admin._id,
          processedAt: Date.now(),
          adminNote
        }
      }
    }
  }));

  await Transaction.bulkWrite(bulkOps);

  // If rejected, return funds to users' balances
  if (status === 'failed' || status === 'cancelled') {
    const userUpdates = withdrawals.map(withdrawal => ({
      updateOne: {
        filter: { _id: withdrawal.user._id },
        update: { $inc: { 'balance.main': withdrawal.amount } }
      }
    }));

    await User.bulkWrite(userUpdates);
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'process_batch_withdrawals',
    details: {
      withdrawalIds,
      count: withdrawals.length,
      status
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      processedCount: withdrawals.length
    }
  });
}));

// GET /api/admin/loans - List all loans
app.get('/api/admin/loans', adminProtect, catchAsync(async (req, res, next) => {
  const { page = 1, limit = 20, status } = req.query;
  const skip = (page - 1) * limit;

  let query = {};
  if (status) {
    query.status = status;
  }

  const loans = await Loan.find(query)
    .skip(skip)
    .limit(limit)
    .populate('user', 'firstName lastName email')
    .populate('approvedBy', 'email');

  const total = await Loan.countDocuments(query);

  res.status(200).json({
    status: 'success',
    results: total,
    data: {
      loans
    }
  });
}));

// POST /api/admin/loans - Create new loan
app.post('/api/admin/loans', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { user, amount, interestRate, duration, collateral } = req.body;

  if (!user || !amount || !interestRate || !duration || !collateral) {
    return next(new AppError('Please provide all required fields', 400));
  }

  const repaymentAmount = amount + (amount * interestRate / 100);
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + duration);

  const loan = await Loan.create({
    user,
    amount,
    interestRate,
    duration,
    collateral,
    status: 'approved',
    approvedBy: req.admin._id,
    approvedAt: Date.now(),
    repaymentAmount,
    dueDate
  });

  // Update user balance
  await User.findByIdAndUpdate(user, {
    $inc: { 'balance.main': amount }
  });

  // Create transaction
  await Transaction.create({
    user,
    type: 'loan',
    amount,
    status: 'completed',
    method: 'internal',
    details: {
      loanId: loan._id,
      interestRate,
      duration,
      repaymentAmount
    }
  });

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'create_loan',
    details: {
      loanId: loan._id,
      userId: user,
      amount,
      interestRate,
      duration
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(201).json({
    status: 'success',
    data: {
      loan
    }
  });
}));

// GET /api/admin/loans/{id} - Get loan details
app.get('/api/admin/loans/:id', adminProtect, catchAsync(async (req, res, next) => {
  const loan = await Loan.findById(req.params.id)
    .populate('user', 'firstName lastName email')
    .populate('approvedBy', 'email');

  if (!loan) {
    return next(new AppError('Loan not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      loan
    }
  });
}));

// PUT /api/admin/loans/{id} - Update loan
app.put('/api/admin/loans/:id', adminProtect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { amount, interestRate, duration, collateral, status } = req.body;

  const loan = await Loan.findById(req.params.id);
  if (!loan) {
    return next(new AppError('Loan not found', 404));
  }

  if (loan.status !== 'pending' && req.admin.role !== 'super-admin') {
    return next(new AppError('Only super-admin can modify approved loans', 403));
  }

  const updateFields = {};
  if (amount) updateFields.amount = amount;
  if (interestRate) updateFields.interestRate = interestRate;
  if (duration) {
    updateFields.duration = duration;
    const dueDate = new Date(loan.approvedAt || Date.now());
    dueDate.setDate(dueDate.getDate() + duration);
    updateFields.dueDate = dueDate;
  }
  if (collateral) updateFields.collateral = collateral;
  if (status) updateFields.status = status;

  if (interestRate || amount) {
    updateFields.repaymentAmount = (amount || loan.amount) + 
      ((amount || loan.amount) * (interestRate || loan.interestRate) / 100);
  }

  const updatedLoan = await Loan.findByIdAndUpdate(req.params.id, updateFields, {
    new: true,
    runValidators: true
  });

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'update_loan',
    details: {
      loanId: loan._id,
      changes: updateFields
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(200).json({
    status: 'success',
    data: {
      loan: updatedLoan
    }
  });
}));

// DELETE /api/admin/loans/{id} - Delete loan
app.delete('/api/admin/loans/:id', adminProtect, restrictTo('super-admin'), catchAsync(async (req, res, next) => {
  const loan = await Loan.findByIdAndDelete(req.params.id);

  if (!loan) {
    return next(new AppError('Loan not found', 404));
  }

  // Log activity
  await Activity.create({
    admin: req.admin._id,
    action: 'delete_loan',
    details: {
      loanId: loan._id,
      userId: loan.user
    },
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  res.status(204).json({
    status: 'success',
    data: null
  });
}));

// GET /api/admin/profile - Get admin profile
app.get('/api/admin/profile', adminProtect, catchAsync(async (req, res, next) => {
  const admin = await Admin.findById(req.admin._id)
    .select('-password -twoFactorSecret');

  res.status(200).json({
    status: 'success',
    data: {
      admin
    }
  });
}));

// Dashboard Endpoints

// GET /api/plans - Get investment plans
app.get('/api/plans', protect, catchAsync(async (req, res, next) => {
  const plans = await Plan.find({ status: 'active' }).sort({ minAmount: 1 });

  res.status(200).json({
    status: 'success',
    data: {
      plans
    }
  });
}));

// GET /api/transactions - Get user transactions
app.get('/api/transactions', protect, catchAsync(async (req, res, next) => {
  const { page = 1, limit = 10, type } = req.query;
  const skip = (page - 1) * limit;

  let query = { user: req.user._id };
  if (type) {
    query.type = type;
  }

  const transactions = await Transaction.find(query)
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 });

  const total = await Transaction.countDocuments(query);

  res.status(200).json({
    status: 'success',
    results: total,
    data: {
      transactions
    }
  });
}));

// GET /api/mining/stats - Get mining statistics
app.get('/api/mining/stats', protect, catchAsync(async (req, res, next) => {
  const stats = {};

  // Get active investments
  stats.activeInvestments = await Investment.countDocuments({
    user: req.user._id,
    status: 'active'
  });

  // Get total invested amount
  const investmentStats = await Investment.aggregate([
    { $match: { user: req.user._id } },
    { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
  ]);

  stats.totalInvested = investmentStats.length > 0 ? investmentStats[0].totalAmount : 0;

  // Get expected returns
  const expectedReturns = await Investment.aggregate([
    { $match: { user: req.user._id, status: 'active' } },
    { $group: { _id: null, totalReturns: { $sum: '$expectedReturn' } } }
  ]);

  stats.expectedReturns = expectedReturns.length > 0 ? expectedReturns[0].totalReturns : 0;

  // Get completed investments
  stats.completedInvestments = await Investment.countDocuments({
    user: req.user._id,
    status: 'completed'
  });

  res.status(200).json({
    status: 'success',
    data: {
      stats
    }
  });
}));

// POST /api/transactions/deposit - Create deposit
app.post('/api/transactions/deposit', protect, catchAsync(async (req, res, next) => {
  const { amount, method } = req.body;

  if (!amount || !method) {
    return next(new AppError('Please provide amount and method', 400));
  }

  if (!['btc', 'bank', 'card'].includes(method)) {
    return next(new AppError('Invalid deposit method', 400));
  }

  const reference = `DEP-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  let btcAddress = '';

  if (method === 'btc') {
    btcAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
  }

  const deposit = await Transaction.create({
    user: req.user._id,
    type: 'deposit',
    amount,
    method,
    status: 'pending',
    reference,
    btcAddress: method === 'btc' ? btcAddress : undefined
  });

  res.status(201).json({
    status: 'success',
    data: {
      deposit
    }
  });
}));

// POST /api/transactions/withdraw - Create withdrawal
app.post('/api/transactions/withdraw', protect, catchAsync(async (req, res, next) => {
  const { amount, method, btcAddress } = req.body;

  if (!amount || !method) {
    return next(new AppError('Please provide amount and method', 400));
  }

  if (!['btc', 'bank'].includes(method)) {
    return next(new AppError('Invalid withdrawal method', 400));
  }

  if (method === 'btc' && !btcAddress) {
    return next(new AppError('BTC address is required for BTC withdrawals', 400));
  }

  // Check user balance
  const user = await User.findById(req.user._id);
  if (user.balance.main < amount) {
    return next(new AppError('Insufficient balance', 400));
  }

  // Check if user has pending withdrawals
  const pendingWithdrawals = await Transaction.countDocuments({
    user: req.user._id,
    type: 'withdrawal',
    status: 'pending'
  });

  if (pendingWithdrawals > 0) {
    return next(new AppError('You already have a pending withdrawal', 400));
  }

  // Deduct amount from user balance
  user.balance.main -= amount;
  await user.save();

  const reference = `WTH-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  const withdrawal = await Transaction.create({
    user: req.user._id,
    type: 'withdrawal',
    amount,
    method,
    status: 'pending',
    reference,
    btcAddress: method === 'btc' ? btcAddress : undefined
  });

  res.status(201).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// POST /api/transactions/transfer - Transfer between accounts
app.post('/api/transactions/transfer', protect, catchAsync(async (req, res, next) => {
  const { amount, from, to } = req.body;

  if (!amount || !from || !to) {
    return next(new AppError('Please provide amount, from and to accounts', 400));
  }

  if (from === to) {
    return next(new AppError('Cannot transfer to the same account', 400));
  }

  const validAccounts = ['main', 'active', 'matured'];
  if (!validAccounts.includes(from) || !validAccounts.includes(to)) {
    return next(new AppError('Invalid account type', 400));
  }

  const user = await User.findById(req.user._id);
  if (user.balance[from] < amount) {
    return next(new AppError(`Insufficient balance in ${from} account`, 400));
  }

  // Update balances
  user.balance[from] -= amount;
  user.balance[to] += amount;
  await user.save();

  const reference = `TRF-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  const transfer = await Transaction.create({
    user: req.user._id,
    type: 'transfer',
    amount,
    method: 'internal',
    status: 'completed',
    reference,
    details: {
      from,
      to
    }
  });

  res.status(201).json({
    status: 'success',
    data: {
      transfer
    }
  });
}));

// POST /api/investments - Create investment
app.post('/api/investments', protect, catchAsync(async (req, res, next) => {
  const { planId, amount } = req.body;

  if (!planId || !amount) {
    return next(new AppError('Please provide plan ID and amount', 400));
  }

  const plan = await Plan.findById(planId);
  if (!plan || plan.status !== 'active') {
    return next(new AppError('Plan not found or inactive', 404));
  }

  if (amount < plan.minAmount || amount > plan.maxAmount) {
    return next(new AppError(`Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`, 400));
  }

  const user = await User.findById(req.user._id);
  if (user.balance.main < amount) {
    return next(new AppError('Insufficient balance', 400));
  }

  // Deduct amount from main balance
  user.balance.main -= amount;
  user.balance.active += amount;
  await user.save();

  const endDate = new Date();
  endDate.setHours(endDate.getHours() + plan.duration);

  const expectedReturn = amount + (amount * plan.percentage / 100);

  const investment = await Investment.create({
    user: req.user._id,
    plan: plan._id,
    amount,
    expectedReturn,
    endDate
  });

  // Create transaction
  await Transaction.create({
    user: req.user._id,
    type: 'investment',
    amount,
    status: 'completed',
    method: 'internal',
    details: {
      planId: plan._id,
      planName: plan.name,
      expectedReturn,
      endDate
    }
  });

  // Check for referral bonus
  if (user.referredBy && !investment.referralBonusPaid) {
    const referralBonus = amount * (plan.referralBonus / 100);
    
    // Update referrer's balance
    await User.findByIdAndUpdate(user.referredBy, {
      $inc: { 'balance.main': referralBonus }
    });

    // Create referral transaction for referrer
    await Transaction.create({
      user: user.referredBy,
      type: 'referral',
      amount: referralBonus,
      status: 'completed',
      method: 'internal',
      details: {
        referredUserId: user._id,
        investmentId: investment._id
      }
    });

    // Update investment with referral info
    investment.referralBonusPaid = true;
    investment.referralBonusAmount = referralBonus;
    await investment.save();

    // Create referral transaction for user (optional)
    await Transaction.create({
      user: user._id,
      type: 'referral',
      amount: referralBonus,
      status: 'completed',
      method: 'internal',
      details: {
        referrerId: user.referredBy,
        investmentId: investment._id
      }
    });
  }

  res.status(201).json({
    status: 'success',
    data: {
      investment
    }
  });
}));

// Error handling middleware
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  console.error(err);

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

// Process completed investments
async function processCompletedInvestments() {
  const now = new Date();
  const completedInvestments = await Investment.find({
    status: 'active',
    endDate: { $lte: now }
  }).populate('user plan');

  for (const investment of completedInvestments) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Update investment status
      investment.status = 'completed';
      await investment.save({ session });

      // Update user balance
      await User.findByIdAndUpdate(investment.user._id, {
        $inc: { 
          'balance.active': -investment.amount,
          'balance.matured': investment.expectedReturn 
        }
      }, { session });

      // Create transaction
      await Transaction.create([{
        user: investment.user._id,
        type: 'interest',
        amount: investment.expectedReturn - investment.amount,
        status: 'completed',
        method: 'internal',
        details: {
          investmentId: investment._id,
          planName: investment.plan.name
        }
      }], { session });

      await session.commitTransaction();
    } catch (err) {
      await session.abortTransaction();
      console.error('Error processing investment:', err);
    } finally {
      session.endSession();
    }
  }
}

// Run investment processing every hour
setInterval(processCompletedInvestments, 60 * 60 * 1000);

// Initial processing on startup
processCompletedInvestments();
