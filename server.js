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
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced security middleware
app.use(helmet());
app.use(cors({
  origin: 'https://bithhash.vercel.app',
  credentials: true
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
  max: 200, // limit each IP to 200 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// Redis client setup
const redisClient = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// MongoDB connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000
})
.then(() => console.log('MongoDB connected successfully'))
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

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Default BTC deposit address
const DEFAULT_BTC_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  country: { type: String },
  password: { type: String, required: true, select: false },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String
  },
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
  apiKeys: [{
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now }
  }],
  kycStatus: {
    verified: { type: Boolean, default: false },
    documents: {
      identity: { type: String, enum: ['pending', 'approved', 'rejected', 'none'], default: 'none' },
      address: { type: String, enum: ['pending', 'approved', 'rejected', 'none'], default: 'none' },
      facial: { type: String, enum: ['pending', 'approved', 'rejected', 'none'], default: 'none' }
    }
  },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
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
  referralCode: String,
  referredBy: String,
  createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  name: { type: String, required: true },
  role: { type: String, enum: ['super', 'support', 'finance'], default: 'support' },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String
  },
  createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'bonus'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  reference: String,
  metadata: Object,
  createdAt: { type: Date, default: Date.now }
});

const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planId: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  interestRate: { type: Number, required: true },
  maturityDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'matured', 'cancelled'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number },
  duration: { type: Number, required: true }, // in days
  interestRate: { type: Number, required: true },
  description: String,
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const kycSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['identity', 'address', 'facial'], required: true },
  documentFront: String,
  documentBack: String,
  selfie: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewNotes: String,
  reviewedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  method: { type: String, enum: ['btc', 'bank'], required: true },
  address: String, // BTC address or bank details
  status: { type: String, enum: ['pending', 'processing', 'completed', 'rejected'], default: 'pending' },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: Date,
  notes: String,
  createdAt: { type: Date, default: Date.now }
});

const loanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  collateralAmount: { type: Number, required: true }, // in BTC
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], default: 'pending' },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: Date,
  dueDate: Date,
  createdAt: { type: Date, default: Date.now }
});

const activitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  action: { type: String, required: true },
  details: Object,
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, required: true }, // can be user or admin
  to: { type: mongoose.Schema.Types.ObjectId, required: true }, // can be user or admin
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Investment = mongoose.model('Investment', investmentSchema);
const Plan = mongoose.model('Plan', planSchema);
const Kyc = mongoose.model('Kyc', kycSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Loan = mongoose.model('Loan', loanSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Message = mongoose.model('Message', messageSchema);

// Utility functions
const createSendToken = (user, statusCode, res, isAdmin = false) => {
  const token = jwt.sign({ id: user._id, isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
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

const catchAsync = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

const AppError = require('./utils/appError');

// Initialize WebSocket server
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', ws => {
  console.log('New WebSocket connection');
  
  ws.on('message', message => {
    console.log(`Received: ${message}`);
    ws.send(`Echo: ${message}`);
  });
});

// Attach WebSocket to HTTP server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, ws => {
    wss.emit('connection', ws, request);
  });
});

// Create default admin if not exists
const createDefaultAdmin = async () => {
  const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
  if (!adminExists) {
    const admin = new Admin({
      email: 'admin@bithash.com',
      password: bcrypt.hashSync('Admin@1234', 12),
      name: 'Super Admin',
      role: 'super'
    });
    await admin.save();
    console.log('Default admin created');
  }
};

createDefaultAdmin();

// Create default investment plans if not exists
const createDefaultPlans = async () => {
  const plans = [
    {
      name: 'Starter Plan',
      minAmount: 100,
      maxAmount: 999,
      duration: 30,
      interestRate: 5,
      description: 'Perfect for beginners',
      active: true
    },
    {
      name: 'Premium Plan',
      minAmount: 1000,
      maxAmount: 4999,
      duration: 60,
      interestRate: 7.5,
      description: 'For serious investors',
      active: true
    },
    {
      name: 'VIP Plan',
      minAmount: 5000,
      maxAmount: 50000,
      duration: 90,
      interestRate: 10,
      description: 'Maximum returns for VIP members',
      active: true
    }
  ];

  for (const plan of plans) {
    const planExists = await Plan.findOne({ name: plan.name });
    if (!planExists) {
      await Plan.create(plan);
    }
  }
  console.log('Default investment plans checked/created');
};

createDefaultPlans();

// Middleware to protect routes
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

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token no longer exists.', 401));
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

  const decoded = await jwt.verify(token, JWT_SECRET);

  if (!decoded.isAdmin) {
    return next(new AppError('You are not authorized to access this route.', 403));
  }

  const currentAdmin = await Admin.findById(decoded.id);
  if (!currentAdmin) {
    return next(new AppError('The admin belonging to this token no longer exists.', 401));
  }

  req.admin = currentAdmin;
  next();
});

// USER ENDPOINTS

// Get current user profile
app.get('/api/users/me', protect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
}));

// Update user profile
app.put('/api/users/profile', protect, catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, phone, country } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    { firstName, lastName, email, phone, country },
    { new: true, runValidators: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user address
app.put('/api/users/address', protect, catchAsync(async (req, res, next) => {
  const { street, city, state, postalCode, country } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    { address: { street, city, state, postalCode, country } },
    { new: true, runValidators: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user password
app.put('/api/users/password', protect, catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(currentPassword, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  user.password = newPassword;
  user.passwordChangedAt = Date.now() - 1000;
  await user.save();

  createSendToken(user, 200, res);
}));

// Create API key
app.post('/api/users/api-keys', protect, catchAsync(async (req, res, next) => {
  const { permissions, expiresInDays } = req.body;

  const apiKey = crypto.randomBytes(32).toString('hex');
  const apiSecret = crypto.randomBytes(64).toString('hex');
  const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);

  await User.findByIdAndUpdate(
    req.user.id,
    { $push: { apiKeys: { key: apiKey, secret: apiSecret, permissions, expiresAt } } },
    { new: true }
  );

  res.status(201).json({
    status: 'success',
    data: {
      apiKey,
      apiSecret,
      expiresAt,
      permissions
    }
  });
}));

// ADMIN ENDPOINTS

// Admin login
app.post('/api/admin/auth/login', catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  const admin = await Admin.findOne({ email }).select('+password');

  if (!admin || !(await admin.correctPassword(password, admin.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  admin.lastLogin = Date.now();
  await admin.save();

  createSendToken(admin, 200, res, true);
}));

// Admin logout
app.post('/api/admin/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

// Get admin dashboard stats
app.get('/api/admin/dashboard', adminProtect, catchAsync(async (req, res, next) => {
  const [usersCount, activeInvestments, pendingWithdrawals, pendingKyc] = await Promise.all([
    User.countDocuments(),
    Investment.countDocuments({ status: 'active' }),
    Withdrawal.countDocuments({ status: 'pending' }),
    Kyc.countDocuments({ status: 'pending' })
  ]);

  const recentTransactions = await Transaction.find()
    .sort('-createdAt')
    .limit(10)
    .populate('userId', 'firstName lastName email');

  res.status(200).json({
    status: 'success',
    data: {
      stats: {
        totalUsers: usersCount,
        activeInvestments,
        pendingWithdrawals,
        pendingKyc
      },
      recentTransactions
    }
  });
}));

// Get user growth data
app.get('/api/admin/users/growth', adminProtect, catchAsync(async (req, res, next) => {
  const growthData = await User.aggregate([
    {
      $group: {
        _id: {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } },
    { $limit: 30 }
  ]);

  res.status(200).json({
    status: 'success',
    data: growthData
  });
}));

// Get admin activity log
app.get('/api/admin/activity', adminProtect, catchAsync(async (req, res, next) => {
  const activities = await Activity.find({ adminId: req.admin._id })
    .sort('-createdAt')
    .limit(50);

  res.status(200).json({
    status: 'success',
    data: activities
  });
}));

// Get all users
app.get('/api/admin/users', adminProtect, catchAsync(async (req, res, next) => {
  const users = await User.find()
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret')
    .sort('-createdAt');

  res.status(200).json({
    status: 'success',
    results: users.length,
    data: users
  });
}));

// Get single user
app.get('/api/admin/users/:id', adminProtect, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: user
  });
}));

// Update user
app.put('/api/admin/users/:id', adminProtect, catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: user
  });
}));

// Delete user
app.delete('/api/admin/users/:id', adminProtect, catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null
  });
}));

// Update user status
app.put('/api/admin/users/:id/status', adminProtect, catchAsync(async (req, res, next) => {
  const { status } = req.body;

  if (!['active', 'suspended', 'banned'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { status },
    { new: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorAuth.secret');

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: user
  });
}));

// Get pending KYC
app.get('/api/admin/kyc/pending', adminProtect, catchAsync(async (req, res, next) => {
  const pendingKyc = await Kyc.find({ status: 'pending' })
    .populate('userId', 'firstName lastName email')
    .sort('-createdAt');

  res.status(200).json({
    status: 'success',
    results: pendingKyc.length,
    data: pendingKyc
  });
}));

// Get single KYC
app.get('/api/admin/kyc/:id', adminProtect, catchAsync(async (req, res, next) => {
  const kyc = await Kyc.findById(req.params.id)
    .populate('userId', 'firstName lastName email')
    .populate('reviewedBy', 'name');

  if (!kyc) {
    return next(new AppError('No KYC found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: kyc
  });
}));

// Review KYC
app.post('/api/admin/kyc/:id/review', adminProtect, catchAsync(async (req, res, next) => {
  const { status, notes } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const kyc = await Kyc.findByIdAndUpdate(
    req.params.id,
    {
      status,
      reviewedBy: req.admin._id,
      reviewNotes: notes,
      reviewedAt: Date.now()
    },
    { new: true }
  ).populate('userId', 'firstName lastName email');

  if (!kyc) {
    return next(new AppError('No KYC found with that ID', 404));
  }

  // Update user KYC status
  const user = await User.findById(kyc.userId._id);
  if (status === 'approved') {
    user.kycStatus.documents[kyc.type] = 'approved';
    await user.save();
  } else {
    user.kycStatus.documents[kyc.type] = 'rejected';
    await user.save();
  }

  res.status(200).json({
    status: 'success',
    data: kyc
  });
}));

// Get pending withdrawals
app.get('/api/admin/withdrawals/pending', adminProtect, catchAsync(async (req, res, next) => {
  const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
    .populate('userId', 'firstName lastName email')
    .sort('-createdAt');

  res.status(200).json({
    status: 'success',
    results: pendingWithdrawals.length,
    data: pendingWithdrawals
  });
}));

// Get single withdrawal
app.get('/api/admin/withdrawals/:id', adminProtect, catchAsync(async (req, res, next) => {
  const withdrawal = await Withdrawal.findById(req.params.id)
    .populate('userId', 'firstName lastName email')
    .populate('processedBy', 'name');

  if (!withdrawal) {
    return next(new AppError('No withdrawal found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: withdrawal
  });
}));

// Process withdrawal
app.post('/api/admin/withdrawals/:id/process', adminProtect, catchAsync(async (req, res, next) => {
  const { status, notes } = req.body;

  if (!['processing', 'completed', 'rejected'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const withdrawal = await Withdrawal.findByIdAndUpdate(
    req.params.id,
    {
      status,
      processedBy: req.admin._id,
      notes,
      processedAt: status === 'processing' ? Date.now() : undefined
    },
    { new: true }
  ).populate('userId', 'firstName lastName email');

  if (!withdrawal) {
    return next(new AppError('No withdrawal found with that ID', 404));
  }

  // If completed, deduct from user's balance
  if (status === 'completed') {
    const user = await User.findById(withdrawal.userId._id);
    user.balances.main -= withdrawal.amount;
    await user.save();
  }

  res.status(200).json({
    status: 'success',
    data: withdrawal
  });
}));

// Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', adminProtect, catchAsync(async (req, res, next) => {
  const { withdrawalIds, status } = req.body;

  if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
    return next(new AppError('Please provide withdrawal IDs', 400));
  }

  if (!['processing', 'completed', 'rejected'].includes(status)) {
    return next(new AppError('Invalid status value', 400));
  }

  const withdrawals = await Withdrawal.updateMany(
    { _id: { $in: withdrawalIds } },
    {
      status,
      processedBy: req.admin._id,
      processedAt: status === 'processing' ? Date.now() : undefined
    }
  );

  // If completed, deduct from users' balances
  if (status === 'completed') {
    const completedWithdrawals = await Withdrawal.find({ _id: { $in: withdrawalIds } });
    for (const withdrawal of completedWithdrawals) {
      const user = await User.findById(withdrawal.userId);
      user.balances.main -= withdrawal.amount;
      await user.save();
    }
  }

  res.status(200).json({
    status: 'success',
    data: {
      matchedCount: withdrawals.n,
      modifiedCount: withdrawals.nModified
    }
  });
}));

// Get all loans
app.get('/api/admin/loans', adminProtect, catchAsync(async (req, res, next) => {
  const loans = await Loan.find()
    .populate('userId', 'firstName lastName email')
    .populate('approvedBy', 'name')
    .sort('-createdAt');

  res.status(200).json({
    status: 'success',
    results: loans.length,
    data: loans
  });
}));

// Create loan
app.post('/api/admin/loans', adminProtect, catchAsync(async (req, res, next) => {
  const loan = await Loan.create(req.body);

  res.status(201).json({
    status: 'success',
    data: loan
  });
}));

// Get single loan
app.get('/api/admin/loans/:id', adminProtect, catchAsync(async (req, res, next) => {
  const loan = await Loan.findById(req.params.id)
    .populate('userId', 'firstName lastName email')
    .populate('approvedBy', 'name');

  if (!loan) {
    return next(new AppError('No loan found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: loan
  });
}));

// Update loan
app.put('/api/admin/loans/:id', adminProtect, catchAsync(async (req, res, next) => {
  const loan = await Loan.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true
  })
    .populate('userId', 'firstName lastName email')
    .populate('approvedBy', 'name');

  if (!loan) {
    return next(new AppError('No loan found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: loan
  });
}));

// Delete loan
app.delete('/api/admin/loans/:id', adminProtect, catchAsync(async (req, res, next) => {
  const loan = await Loan.findByIdAndDelete(req.params.id);

  if (!loan) {
    return next(new AppError('No loan found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null
  });
}));

// Get admin profile
app.get('/api/admin/profile', adminProtect, catchAsync(async (req, res, next) => {
  const admin = await Admin.findById(req.admin._id)
    .select('-password -passwordChangedAt -twoFactorAuth.secret');

  res.status(200).json({
    status: 'success',
    data: admin
  });
}));

// DASHBOARD ENDPOINTS

// Get investment plans
app.get('/api/plans', protect, catchAsync(async (req, res, next) => {
  const plans = await Plan.find({ active: true });

  res.status(200).json({
    status: 'success',
    results: plans.length,
    data: plans
  });
}));

// Get user transactions
app.get('/api/transactions', protect, catchAsync(async (req, res, next) => {
  const transactions = await Transaction.find({ userId: req.user._id })
    .sort('-createdAt')
    .limit(50);

  res.status(200).json({
    status: 'success',
    results: transactions.length,
    data: transactions
  });
}));

// Get mining stats
app.get('/api/mining/stats', protect, catchAsync(async (req, res, next) => {
  const stats = {
    hashrate: Math.random() * 100,
    activeWorkers: Math.floor(Math.random() * 10) + 1,
    shares: {
      accepted: Math.floor(Math.random() * 1000) + 500,
      rejected: Math.floor(Math.random() * 10),
      stale: Math.floor(Math.random() * 5)
    },
    estimatedEarnings: (Math.random() * 0.01).toFixed(8)
  };

  res.status(200).json({
    status: 'success',
    data: stats
  });
}));

// Create deposit
app.post('/api/transactions/deposit', protect, catchAsync(async (req, res, next) => {
  const { amount, method } = req.body;

  if (!amount || !method) {
    return next(new AppError('Please provide amount and method', 400));
  }

  const transaction = await Transaction.create({
    userId: req.user._id,
    type: 'deposit',
    amount,
    method,
    status: 'pending',
    reference: `DEP-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    metadata: {
      btcAddress: method === 'btc' ? DEFAULT_BTC_DEPOSIT_ADDRESS : null
    }
  });

  res.status(201).json({
    status: 'success',
    data: transaction
  });
}));

// Create withdrawal
app.post('/api/transactions/withdraw', protect, catchAsync(async (req, res, next) => {
  const { amount, method, address } = req.body;

  if (!amount || !method || (method === 'btc' && !address)) {
    return next(new AppError('Please provide all required fields', 400));
  }

  // Check if user has sufficient balance
  const user = await User.findById(req.user._id);
  if (user.balances.main < amount) {
    return next(new AppError('Insufficient balance', 400));
  }

  // Create withdrawal
  const withdrawal = await Withdrawal.create({
    userId: req.user._id,
    amount,
    method,
    address,
    status: 'pending'
  });

  // Deduct from user's balance immediately (will be refunded if rejected)
  user.balances.main -= amount;
  await user.save();

  res.status(201).json({
    status: 'success',
    data: withdrawal
  });
}));

// Create investment
app.post('/api/investments', protect, catchAsync(async (req, res, next) => {
  const { planId, amount } = req.body;

  if (!planId || !amount) {
    return next(new AppError('Please provide plan ID and amount', 400));
  }

  // Get plan
  const plan = await Plan.findById(planId);
  if (!plan) {
    return next(new AppError('No plan found with that ID', 404));
  }

  // Check amount against plan limits
  if (amount < plan.minAmount || (plan.maxAmount && amount > plan.maxAmount)) {
    return next(new AppError(`Amount must be between ${plan.minAmount} and ${plan.maxAmount || 'unlimited'}`, 400));
  }

  // Check user balance
  const user = await User.findById(req.user._id);
  if (user.balances.main < amount) {
    return next(new AppError('Insufficient balance', 400));
  }

  // Deduct from main balance and add to active balance
  user.balances.main -= amount;
  user.balances.active += amount;
  await user.save();

  // Calculate maturity date
  const maturityDate = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000);

  // Create investment
  const investment = await Investment.create({
    userId: req.user._id,
    planId,
    amount,
    duration: plan.duration,
    interestRate: plan.interestRate,
    maturityDate,
    status: 'active'
  });

  res.status(201).json({
    status: 'success',
    data: investment
  });
}));

// Transfer between balances
app.post('/api/transactions/transfer', protect, catchAsync(async (req, res, next) => {
  const { from, to, amount } = req.body;

  if (!from || !to || !amount) {
    return next(new AppError('Please provide source, destination and amount', 400));
  }

  if (from === to) {
    return next(new AppError('Cannot transfer between same accounts', 400));
  }

  const validAccounts = ['main', 'active', 'matured', 'btc'];
  if (!validAccounts.includes(from) || !validAccounts.includes(to)) {
    return next(new AppError('Invalid account type', 400));
  }

  const user = await User.findById(req.user._id);
  if (user.balances[from] < amount) {
    return next(new AppError(`Insufficient balance in ${from} account`, 400));
  }

  // Perform transfer
  user.balances[from] -= amount;
  user.balances[to] += amount;
  await user.save();

  // Record transaction
  const transaction = await Transaction.create({
    userId: req.user._id,
    type: 'transfer',
    amount,
    method: 'internal',
    status: 'completed',
    reference: `TRF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    metadata: { from, to }
  });

  res.status(201).json({
    status: 'success',
    data: transaction
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

// 404 handler
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Start server
process.on('unhandledRejection', err => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});
