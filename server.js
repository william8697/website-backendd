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
const validator = require('validator');
const moment = require('moment');

// Initialize Express app
const app = express();

// Environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://bithhash.vercel.app';
const DEFAULT_BTC_ADDRESS = process.env.DEFAULT_BTC_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
  maxPoolSize: 50,
  minPoolSize: 10
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Redis connection
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  connectTimeout: 10000,
  maxRetriesPerRequest: 3
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use('/api', limiter);

// MongoDB Schemas
const userSchema = new mongoose.Schema({
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
  address: String,
  postalCode: String,
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
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now },
    lastUsed: Date
  }],
  balances: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    bonus: { type: Number, default: 0 }
  },
  kycStatus: {
    identity: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    address: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    facial: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' }
  },
  kycDocuments: {
    identityFront: String,
    identityBack: String,
    selfie: String,
    proofOfAddress: String
  },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  referralCode: String,
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

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

const adminSchema = new mongoose.Schema({
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
  permissions: [String],
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

adminSchema.methods.correctPassword = async function(candidatePassword, adminPassword) {
  return await bcrypt.compare(candidatePassword, adminPassword);
};

const Admin = mongoose.model('Admin', adminSchema);

const planSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Plan name is required'] },
  description: String,
  minAmount: { type: Number, required: [true, 'Minimum amount is required'] },
  maxAmount: { type: Number, required: [true, 'Maximum amount is required'] },
  duration: { type: Number, required: [true, 'Duration in hours is required'] },
  percentage: { type: Number, required: [true, 'Percentage return is required'] },
  referralBonus: { type: Number, default: 5 },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

const Plan = mongoose.model('Plan', planSchema);

const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'bonus', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  details: {
    btcAddress: String,
    transactionId: String,
    bankName: String,
    accountNumber: String,
    accountName: String,
    cardLast4: String,
    cardBrand: String
  },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  adminNote: String,
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
});

const Transaction = mongoose.model('Transaction', transactionSchema);

const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  expectedReturn: { type: Number, required: true },
  actualReturn: { type: Number, default: 0 },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
  referralBonusPaid: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Investment = mongoose.model('Investment', investmentSchema);

const kycSubmissionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['identity', 'address', 'facial'], required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewNote: String,
  reviewedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const KycSubmission = mongoose.model('KycSubmission', kycSubmissionSchema);

const activityLogSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  action: { type: String, required: true },
  details: String,
  ipAddress: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
});

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

const loanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  collateralAmount: { type: Number, required: true },
  collateralCurrency: { type: String, default: 'BTC' },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], default: 'pending' },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: Date,
  dueDate: Date,
  repayments: [{
    amount: Number,
    date: { type: Date, default: Date.now },
    transaction: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Loan = mongoose.model('Loan', loanSchema);

// Initialize default admin if not exists
const createDefaultAdmin = async () => {
  const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
  if (!adminExists) {
    await Admin.create({
      email: 'admin@bithash.com',
      password: 'Admin@1234',
      role: 'super-admin',
      permissions: ['all']
    });
    console.log('Default admin created');
  }
};

// Initialize investment plans if not exists
const initializePlans = async () => {
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
    const planExists = await Plan.findOne({ name: planData.name });
    if (!planExists) {
      await Plan.create(planData);
    }
  }
};

// Helper functions
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

  const decoded = await jwt.verify(token, JWT_SECRET);

  let currentUser;
  if (decoded.role === 'admin') {
    currentUser = await Admin.findById(decoded.id).select('+password');
  } else {
    currentUser = await User.findById(decoded.id).select('+password');
  }

  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please log in again.', 401));
  }

  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

// API Routes

// User Endpoints
app.get('/api/users/me', protect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret -loginHistory');
  
  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

app.put('/api/users/profile', protect, catchAsync(async (req, res, next) => {
  const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'phone', 'country', 'city');
  
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret -loginHistory');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

app.put('/api/users/address', protect, catchAsync(async (req, res, next) => {
  const filteredBody = filterObj(req.body, 'address', 'city', 'country', 'postalCode');
  
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret -loginHistory');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

app.put('/api/users/password', protect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('+password');
  
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }
  
  user.password = req.body.newPassword;
  await user.save();
  
  createSendToken(user, 200, res);
}));

app.post('/api/users/api-keys', protect, catchAsync(async (req, res, next) => {
  const { name, permissions } = req.body;
  
  if (!name || !permissions || !Array.isArray(permissions)) {
    return next(new AppError('Please provide name and permissions for the API key.', 400));
  }
  
  const apiKey = crypto.randomBytes(32).toString('hex');
  const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
  
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 1); // 1 year expiration
  
  const newApiKey = {
    name,
    key: hashedKey,
    permissions,
    expiresAt
  };
  
  await User.findByIdAndUpdate(req.user.id, {
    $push: { apiKeys: newApiKey }
  });
  
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
}));

// Admin Endpoints
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
  await admin.save();
  
  createSendToken(admin, 200, res, 'admin');
}));

app.post('/api/admin/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

app.get('/api/admin/dashboard', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const stats = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
    Transaction.countDocuments({ status: 'completed', createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
    Transaction.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
    ]),
    Investment.countDocuments({ status: 'active' }),
    KycSubmission.countDocuments({ status: 'pending' }),
    Withdrawal.countDocuments({ status: 'pending' })
  ]);
  
  res.status(200).json({
    status: 'success',
    data: {
      totalUsers: stats[0],
      newUsersToday: stats[1],
      transactionsToday: stats[2],
      revenueToday: stats[3][0]?.totalAmount || 0,
      activeInvestments: stats[4],
      pendingKyc: stats[5],
      pendingWithdrawals: stats[6]
    }
  });
}));

app.get('/api/admin/users/growth', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const days = parseInt(req.query.days) || 30;
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
      $sort: { _id: 1 }
    }
  ]);
  
  res.status(200).json({
    status: 'success',
    data: userGrowth
  });
}));

app.get('/api/admin/activity', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const activities = await ActivityLog.find()
    .sort('-createdAt')
    .limit(50)
    .populate('user', 'firstName lastName email')
    .populate('admin', 'email');
  
  res.status(200).json({
    status: 'success',
    results: activities.length,
    data: activities
  });
}));

app.get('/api/admin/users', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status, search, page = 1, limit = 20 } = req.query;
  
  const query = {};
  if (status) query.status = status;
  if (search) {
    query.$or = [
      { firstName: { $regex: search, $options: 'i' } },
      { lastName: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } }
    ];
  }
  
  const skip = (page - 1) * limit;
  
  const users = await User.find(query)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret -loginHistory')
    .skip(skip)
    .limit(limit)
    .sort('-createdAt');
  
  const total = await User.countDocuments(query);
  
  res.status(200).json({
    status: 'success',
    results: users.length,
    total,
    data: users
  });
}));

app.route('/api/admin/users/:id')
  .get(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
    
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  }))
  .put(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'phone',
      'country',
      'city',
      'address',
      'postalCode',
      'kycStatus',
      'status',
      'balances'
    );
    
    const user = await User.findByIdAndUpdate(req.params.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
    
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }
    
    await ActivityLog.create({
      admin: req.user.id,
      action: 'Updated user',
      details: `Updated user ${user.email} (${user._id})`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  }))
  .delete(protect, restrictTo('super-admin'), catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }
    
    await ActivityLog.create({
      admin: req.user.id,
      action: 'Deleted user',
      details: `Deleted user ${user.email} (${user._id})`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  }));

app.put('/api/admin/users/:id/status', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status } = req.body;
  
  if (!status || !['active', 'suspended', 'banned'].includes(status)) {
    return next(new AppError('Please provide a valid status', 400));
  }
  
  const user = await User.findByIdAndUpdate(req.params.id, { status }, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }
  
  await ActivityLog.create({
    admin: req.user.id,
    action: 'Changed user status',
    details: `Changed status of user ${user.email} (${user._id}) to ${status}`,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(200).json({
    status: 'success',
    data: user
  });
}));

app.get('/api/admin/kyc/pending', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const pendingKyc = await KycSubmission.find({ status: 'pending' })
    .populate('user', 'firstName lastName email')
    .sort('-createdAt');
  
  res.status(200).json({
    status: 'success',
    results: pendingKyc.length,
    data: pendingKyc
  });
}));

app.get('/api/admin/kyc/:id', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const kyc = await KycSubmission.findById(req.params.id)
    .populate('user', 'firstName lastName email')
    .populate('reviewedBy', 'email');
  
  if (!kyc) {
    return next(new AppError('No KYC submission found with that ID', 404));
  }
  
  res.status(200).json({
    status: 'success',
    data: kyc
  });
}));

app.post('/api/admin/kyc/:id/review', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status, note } = req.body;
  
  if (!status || !['approved', 'rejected'].includes(status)) {
    return next(new AppError('Please provide a valid status (approved or rejected)', 400));
  }
  
  const kyc = await KycSubmission.findById(req.params.id);
  if (!kyc) {
    return next(new AppError('No KYC submission found with that ID', 404));
  }
  
  kyc.status = status;
  kyc.reviewedBy = req.user.id;
  kyc.reviewNote = note;
  kyc.reviewedAt = new Date();
  await kyc.save();
  
  // Update user's KYC status
  const user = await User.findById(kyc.user);
  if (user) {
    user.kycStatus[kyc.type] = status;
    await user.save();
  }
  
  await ActivityLog.create({
    admin: req.user.id,
    action: 'Reviewed KYC',
    details: `Reviewed KYC submission ${kyc._id} for user ${user?.email || kyc.user} as ${status}`,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(200).json({
    status: 'success',
    data: kyc
  });
}));

app.get('/api/admin/withdrawals/pending', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const pendingWithdrawals = await Transaction.find({ 
    type: 'withdrawal',
    status: 'pending'
  })
    .populate('user', 'firstName lastName email')
    .sort('-createdAt');
  
  res.status(200).json({
    status: 'success',
    results: pendingWithdrawals.length,
    data: pendingWithdrawals
  });
}));

app.get('/api/admin/withdrawals/:id', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const withdrawal = await Transaction.findOne({
    _id: req.params.id,
    type: 'withdrawal'
  }).populate('user', 'firstName lastName email');
  
  if (!withdrawal) {
    return next(new AppError('No withdrawal found with that ID', 404));
  }
  
  res.status(200).json({
    status: 'success',
    data: withdrawal
  });
}));

app.post('/api/admin/withdrawals/:id/process', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { status, adminNote } = req.body;
  
  if (!status || !['completed', 'failed', 'cancelled'].includes(status)) {
    return next(new AppError('Please provide a valid status (completed, failed or cancelled)', 400));
  }
  
  const withdrawal = await Transaction.findOne({
    _id: req.params.id,
    type: 'withdrawal',
    status: 'pending'
  }).populate('user', 'firstName lastName email');
  
  if (!withdrawal) {
    return next(new AppError('No pending withdrawal found with that ID', 404));
  }
  
  // If rejecting, refund the amount to user's balance
  if (status === 'failed' || status === 'cancelled') {
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { 'balances.main': withdrawal.amount }
    });
  }
  
  withdrawal.status = status;
  withdrawal.adminNote = adminNote;
  withdrawal.completedAt = new Date();
  await withdrawal.save();
  
  await ActivityLog.create({
    admin: req.user.id,
    action: 'Processed withdrawal',
    details: `Processed withdrawal ${withdrawal._id} for user ${withdrawal.user.email} as ${status}`,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(200).json({
    status: 'success',
    data: withdrawal
  });
}));

app.post('/api/admin/withdrawals/process-batch', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const { withdrawalIds, status, adminNote } = req.body;
  
  if (!withdrawalIds || !Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
    return next(new AppError('Please provide an array of withdrawal IDs', 400));
  }
  
  if (!status || !['completed', 'failed', 'cancelled'].includes(status)) {
    return next(new AppError('Please provide a valid status (completed, failed or cancelled)', 400));
  }
  
  const withdrawals = await Transaction.find({
    _id: { $in: withdrawalIds },
    type: 'withdrawal',
    status: 'pending'
  }).populate('user', 'firstName lastName email');
  
  if (withdrawals.length === 0) {
    return next(new AppError('No pending withdrawals found with the provided IDs', 404));
  }
  
  const bulkOps = withdrawals.map(withdrawal => {
    const update = {
      updateOne: {
        filter: { _id: withdrawal._id },
        update: {
          $set: {
            status,
            adminNote,
            completedAt: new Date()
          }
        }
      }
    };
    
    // If rejecting, add operation to refund user's balance
    if (status === 'failed' || status === 'cancelled') {
      bulkOps.push({
        updateOne: {
          filter: { _id: withdrawal.user._id },
          update: {
            $inc: { 'balances.main': withdrawal.amount }
          }
        }
      });
    }
    
    return update;
  });
  
  await Transaction.bulkWrite(bulkOps);
  
  await ActivityLog.create({
    admin: req.user.id,
    action: 'Bulk processed withdrawals',
    details: `Processed ${withdrawals.length} withdrawals as ${status}`,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(200).json({
    status: 'success',
    results: withdrawals.length,
    data: withdrawals
  });
}));

app.route('/api/admin/loans')
  .get(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const loans = await Loan.find(query)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'email')
      .skip(skip)
      .limit(limit)
      .sort('-createdAt');
    
    const total = await Loan.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: loans.length,
      total,
      data: loans
    });
  }))
  .post(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const { userId, amount, interestRate, duration, collateralAmount } = req.body;
    
    if (!userId || !amount || !interestRate || !duration || !collateralAmount) {
      return next(new AppError('Please provide all required loan fields', 400));
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }
    
    if (user.balances.main < collateralAmount) {
      return next(new AppError('User does not have sufficient balance for collateral', 400));
    }
    
    const loan = await Loan.create({
      user: userId,
      amount,
      interestRate,
      duration,
      collateralAmount,
      approvedBy: req.user.id,
      approvedAt: new Date(),
      status: 'approved',
      dueDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000)
    });
    
    // Deduct collateral from user's balance
    user.balances.main -= collateralAmount;
    await user.save();
    
    await ActivityLog.create({
      admin: req.user.id,
      action: 'Created loan',
      details: `Created loan ${loan._id} for user ${user.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(201).json({
      status: 'success',
      data: loan
    });
  }));

app.route('/api/admin/loans/:id')
  .get(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'email');
    
    if (!loan) {
      return next(new AppError('No loan found with that ID', 404));
    }
    
    res.status(200).json({
      status: 'success',
      data: loan
    });
  }))
  .put(protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
    const { amount, interestRate, duration, collateralAmount, status } = req.body;
    
    const loan = await Loan.findById(req.params.id).populate('user', 'firstName lastName email');
    if (!loan) {
      return next(new AppError('No loan found with that ID', 404));
    }
    
    // Update loan details
    if (amount) loan.amount = amount;
    if (interestRate) loan.interestRate = interestRate;
    if (duration) {
      loan.duration = duration;
      loan.dueDate = new Date(Date.now() + duration * 24 * 60 * 60 * 1000);
    }
    if (collateralAmount) {
      // Return previous collateral to user
      loan.user.balances.main += loan.collateralAmount;
      // Deduct new collateral
      loan.user.balances.main -= collateralAmount;
      loan.collateralAmount = collateralAmount;
      await loan.user.save();
    }
    if (status) loan.status = status;
    
    await loan.save();
    
    await ActivityLog.create({
      admin: req.user.id,
      action: 'Updated loan',
      details: `Updated loan ${loan._id} for user ${loan.user.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(200).json({
      status: 'success',
      data: loan
    });
  }))
  .delete(protect, restrictTo('super-admin'), catchAsync(async (req, res, next) => {
    const loan = await Loan.findByIdAndDelete(req.params.id).populate('user', 'firstName lastName email');
    
    if (!loan) {
      return next(new AppError('No loan found with that ID', 404));
    }
    
    // Return collateral to user
    loan.user.balances.main += loan.collateralAmount;
    await loan.user.save();
    
    await ActivityLog.create({
      admin: req.user.id,
      action: 'Deleted loan',
      details: `Deleted loan ${loan._id} for user ${loan.user.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  }));

app.get('/api/admin/profile', protect, restrictTo('super-admin', 'admin'), catchAsync(async (req, res, next) => {
  const admin = await Admin.findById(req.user.id)
    .select('-password -loginHistory');
  
  res.status(200).json({
    status: 'success',
    data: admin
  });
}));

// Dashboard Endpoints
app.get('/api/plans', protect, catchAsync(async (req, res, next) => {
  const plans = await Plan.find({ status: 'active' }).sort('minAmount');
  
  res.status(200).json({
    status: 'success',
    results: plans.length,
    data: plans
  });
}));

app.get('/api/transactions', protect, catchAsync(async (req, res, next) => {
  const { type, status, page = 1, limit = 20 } = req.query;
  
  const query = { user: req.user.id };
  if (type) query.type = type;
  if (status) query.status = status;
  
  const skip = (page - 1) * limit;
  
  const transactions = await Transaction.find(query)
    .sort('-createdAt')
    .skip(skip)
    .limit(limit);
  
  const total = await Transaction.countDocuments(query);
  
  res.status(200).json({
    status: 'success',
    results: transactions.length,
    total,
    data: transactions
  });
}));

app.get('/api/mining/stats', protect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  
  const activeInvestments = await Investment.countDocuments({ 
    user: req.user.id,
    status: 'active'
  });
  
  const completedInvestments = await Investment.countDocuments({ 
    user: req.user.id,
    status: 'completed'
  });
  
  const totalInvested = await Investment.aggregate([
    { $match: { user: req.user._id } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  
  const totalEarned = await Investment.aggregate([
    { $match: { user: req.user._id, status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$actualReturn' } } }
  ]);
  
  res.status(200).json({
    status: 'success',
    data: {
      hashrate: 0, // Placeholder for actual mining stats
      activeWorkers: activeInvestments,
      shares: completedInvestments,
      totalInvested: totalInvested[0]?.total || 0,
      totalEarned: totalEarned[0]?.total || 0,
      estimatedDailyEarnings: user.balances.active * 0.002 // Example calculation
    }
  });
}));

app.post('/api/transactions/deposit', protect, catchAsync(async (req, res, next) => {
  const { amount, method } = req.body;
  
  if (!amount || !method || !['btc', 'bank', 'card'].includes(method)) {
    return next(new AppError('Please provide amount and valid method (btc, bank or card)', 400));
  }
  
  if (amount <= 0) {
    return next(new AppError('Amount must be greater than 0', 400));
  }
  
  let details = {};
  if (method === 'btc') {
    details.btcAddress = DEFAULT_BTC_ADDRESS;
  } else if (method === 'bank') {
    details.bankName = 'BitHash Bank';
    details.accountNumber = '1234567890';
    details.accountName = 'BitHash LLC';
  } else if (method === 'card') {
    details.cardBrand = 'Visa/Mastercard';
    details.cardLast4 = '4242';
  }
  
  const transaction = await Transaction.create({
    user: req.user.id,
    type: 'deposit',
    amount,
    currency: 'USD',
    status: 'pending',
    method,
    details,
    netAmount: amount
  });
  
  res.status(201).json({
    status: 'success',
    data: transaction
  });
}));

app.post('/api/transactions/withdraw', protect, catchAsync(async (req, res, next) => {
  const { amount, method, btcAddress, bankDetails } = req.body;
  
  if (!amount || !method || !['btc', 'bank'].includes(method)) {
    return next(new AppError('Please provide amount and valid method (btc or bank)', 400));
  }
  
  if (amount <= 0) {
    return next(new AppError('Amount must be greater than 0', 400));
  }
  
  const user = await User.findById(req.user.id);
  if (user.balances.main < amount) {
    return next(new AppError('Insufficient balance for withdrawal', 400));
  }
  
  let details = {};
  if (method === 'btc') {
    if (!btcAddress || !validator.isBtcAddress(btcAddress)) {
      return next(new AppError('Please provide a valid BTC address', 400));
    }
    details.btcAddress = btcAddress;
  } else if (method === 'bank') {
    if (!bankDetails || !bankDetails.accountNumber || !bankDetails.accountName || !bankDetails.bankName) {
      return next(new AppError('Please provide complete bank details', 400));
    }
    details = bankDetails;
  }
  
  // Deduct amount from user's balance immediately
  user.balances.main -= amount;
  await user.save();
  
  const transaction = await Transaction.create({
    user: req.user.id,
    type: 'withdrawal',
    amount,
    currency: 'USD',
    status: 'pending',
    method,
    details,
    netAmount: amount,
    fee: method === 'btc' ? Math.max(amount * 0.01, 10) : 0 // 1% fee for BTC, min $10
  });
  
  res.status(201).json({
    status: 'success',
    data: transaction
  });
}));

app.post('/api/transactions/transfer', protect, catchAsync(async (req, res, next) => {
  const { amount, toEmail } = req.body;
  
  if (!amount || !toEmail) {
    return next(new AppError('Please provide amount and recipient email', 400));
  }
  
  if (amount <= 0) {
    return next(new AppError('Amount must be greater than 0', 400));
  }
  
  const user = await User.findById(req.user.id);
  if (user.balances.main < amount) {
    return next(new AppError('Insufficient balance for transfer', 400));
  }
  
  const recipient = await User.findOne({ email: toEmail.toLowerCase() });
  if (!recipient) {
    return next(new AppError('No user found with that email', 404));
  }
  
  if (recipient.id === user.id) {
    return next(new AppError('Cannot transfer to yourself', 400));
  }
  
  // Deduct from sender
  user.balances.main -= amount;
  await user.save();
  
  // Add to recipient
  recipient.balances.main += amount;
  await recipient.save();
  
  // Create transactions for both users
  const senderTransaction = await Transaction.create({
    user: user.id,
    type: 'transfer',
    amount,
    currency: 'USD',
    status: 'completed',
    method: 'internal',
    details: {
      to: recipient.email,
      direction: 'out'
    },
    netAmount: -amount
  });
  
  const recipientTransaction = await Transaction.create({
    user: recipient.id,
    type: 'transfer',
    amount,
    currency: 'USD',
    status: 'completed',
    method: 'internal',
    details: {
      from: user.email,
      direction: 'in'
    },
    netAmount: amount
  });
  
  res.status(201).json({
    status: 'success',
    data: senderTransaction
  });
}));

app.post('/api/investments', protect, catchAsync(async (req, res, next) => {
  const { planId, amount } = req.body;
  
  if (!planId || !amount) {
    return next(new AppError('Please provide plan ID and amount', 400));
  }
  
  const plan = await Plan.findById(planId);
  if (!plan || plan.status !== 'active') {
    return next(new AppError('Plan not available', 404));
  }
  
  if (amount < plan.minAmount || amount > plan.maxAmount) {
    return next(new AppError(`Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`, 400));
  }
  
  const user = await User.findById(req.user.id);
  if (user.balances.main < amount) {
    return next(new AppError('Insufficient balance for investment', 400));
  }
  
  // Deduct investment amount from main balance
  user.balances.main -= amount;
  // Add to active balance
  user.balances.active += amount;
  await user.save();
  
  const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);
  const expectedReturn = amount * (plan.percentage / 100);
  
  const investment = await Investment.create({
    user: user.id,
    plan: plan.id,
    amount,
    expectedReturn,
    endDate,
    status: 'active'
  });
  
  // Create transaction record
  await Transaction.create({
    user: user.id,
    type: 'investment',
    amount,
    currency: 'USD',
    status: 'completed',
    method: 'internal',
    netAmount: -amount
  });
  
  res.status(201).json({
    status: 'success',
    data: investment
  });
}));

// Process completed investments (cron job)
const processCompletedInvestments = catchAsync(async () => {
  const now = new Date();
  const completedInvestments = await Investment.find({
    status: 'active',
    endDate: { $lte: now }
  }).populate('user', 'balances').populate('plan');
  
  for (const investment of completedInvestments) {
    // Calculate actual return (could add some variability here)
    const actualReturn = investment.expectedReturn;
    
    // Update user balances
    investment.user.balances.active -= investment.amount;
    investment.user.balances.matured += investment.amount + actualReturn;
    await investment.user.save();
    
    // Update investment record
    investment.actualReturn = actualReturn;
    investment.status = 'completed';
    await investment.save();
    
    // Create transaction for the return
    await Transaction.create({
      user: investment.user._id,
      type: 'investment',
      amount: actualReturn,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      netAmount: actualReturn
    });
    
    // Check if referral bonus needs to be paid
    if (investment.user.referredBy && !investment.referralBonusPaid) {
      const referrer = await User.findById(investment.user.referredBy);
      if (referrer) {
        const bonusAmount = actualReturn * (investment.plan.referralBonus / 100);
        referrer.balances.bonus += bonusAmount;
        await referrer.save();
        
        await Transaction.create({
          user: referrer._id,
          type: 'referral',
          amount: bonusAmount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          netAmount: bonusAmount
        });
        
        investment.referralBonusPaid = true;
        await investment.save();
      }
    }
  }
  
  console.log(`Processed ${completedInvestments.length} completed investments`);
});

// Error handling middleware
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  
  if (NODE_ENV === 'development') {
    console.error(err.stack);
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
});

// Start server
const server = app.listen(PORT, async () => {
  await createDefaultAdmin();
  await initializePlans();
  console.log(`Server running on port ${PORT} in ${NODE_ENV} mode`);
  
  // Schedule investment processing every hour
  setInterval(processCompletedInvestments, 60 * 60 * 1000);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', err => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', err => {
  console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
