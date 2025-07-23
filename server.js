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
const axios = require('axios');

// Initialize Express app
const app = express();

// Environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://bithhash.vercel.app';
const DEFAULT_BTC_ADDRESS = process.env.DEFAULT_BTC_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

redis.on('connect', () => console.log('Redis connected successfully'));
redis.on('error', err => console.error('Redis connection error:', err));

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
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
if (NODE_ENV === 'production') {
  app.use('/api', limiter);
}

// Models
const User = require('./models/User');
const Admin = require('./models/Admin');
const Transaction = require('./models/Transaction');
const Investment = require('./models/Investment');
const Plan = require('./models/Plan');
const KYCDocument = require('./models/KYCDocument');
const Withdrawal = require('./models/Withdrawal');
const Loan = require('./models/Loan');
const ApiKey = require('./models/ApiKey');
const ActivityLog = require('./models/ActivityLog');
const Device = require('./models/Device');
const Notification = require('./models/Notification');

// Utility functions
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

const logActivity = async (userId, action, details) => {
  try {
    await ActivityLog.create({ user: userId, action, details });
  } catch (err) {
    console.error('Failed to log activity:', err);
  }
};

// Middleware
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
  } else if (req.cookies.jwtAdmin) {
    token = req.cookies.jwtAdmin;
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

// Initialize default admin if not exists
const initializeAdmin = async () => {
  const adminEmail = 'admin@bithash.com';
  const adminExists = await Admin.findOne({ email: adminEmail });
  
  if (!adminExists) {
    const admin = await Admin.create({
      name: 'Super Admin',
      email: adminEmail,
      password: 'Admin@1234',
      role: 'super-admin',
      active: true
    });
    console.log('Default admin created:', admin.email);
  }
};

initializeAdmin();

// USER ENDPOINTS

// Get current user
app.get('/api/users/me', protect, catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id)
    .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires')
    .populate('activeInvestments')
    .populate('transactions');

  // Get BTC price from cache or API
  let btcPrice = await redis.get('btcPrice');
  if (!btcPrice) {
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
      await redis.set('btcPrice', btcPrice, 'EX', 60); // Cache for 60 seconds
    } catch (err) {
      btcPrice = 50000; // Fallback value
    }
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
      btcPrice
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
    'country',
    'dateOfBirth',
    'gender'
  );

  if (req.body.email) {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser && existingUser._id.toString() !== req.user.id) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use by another account'
      });
    }
  }

  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  await logActivity(req.user.id, 'profile_update', 'Updated profile information');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user address
app.put('/api/users/address', protect, catchAsync(async (req, res) => {
  const { street, city, state, postalCode, country } = req.body;

  if (!street || !city || !state || !postalCode || !country) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide all address fields'
    });
  }

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      address: {
        street,
        city,
        state,
        postalCode,
        country
      }
    },
    {
      new: true,
      runValidators: true
    }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  await logActivity(req.user.id, 'address_update', 'Updated address information');

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
}));

// Update user password
app.put('/api/users/password', protect, catchAsync(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide both current and new password'
    });
  }

  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(currentPassword, user.password))) {
    return res.status(401).json({
      status: 'fail',
      message: 'Your current password is wrong'
    });
  }

  if (currentPassword === newPassword) {
    return res.status(400).json({
      status: 'fail',
      message: 'New password must be different from current password'
    });
  }

  user.password = newPassword;
  await user.save();

  // Logout all devices by changing JWT secret
  const newJwtSecret = crypto.randomBytes(32).toString('hex');
  await redis.set(`user:${user._id}:jwtSecret`, newJwtSecret);

  await logActivity(user._id, 'password_change', 'Changed account password');

  res.status(200).json({
    status: 'success',
    message: 'Password updated successfully!'
  });
}));

// Create API key
app.post('/api/users/api-keys', protect, catchAsync(async (req, res) => {
  const { name, permissions, expiresAt } = req.body;

  if (!name || !permissions || !Array.isArray(permissions)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide API key name and permissions array'
    });
  }

  const apiKey = crypto.randomBytes(32).toString('hex');
  const apiKeySecret = crypto.randomBytes(32).toString('hex');

  const newApiKey = await ApiKey.create({
    user: req.user.id,
    name,
    key: apiKey,
    secret: apiKeySecret,
    permissions,
    expiresAt: expiresAt ? new Date(expiresAt) : null
  });

  await logActivity(req.user.id, 'api_key_create', `Created API key: ${name}`);

  res.status(201).json({
    status: 'success',
    data: {
      apiKey: {
        id: newApiKey._id,
        name: newApiKey.name,
        key: newApiKey.key,
        permissions: newApiKey.permissions,
        expiresAt: newApiKey.expiresAt,
        createdAt: newApiKey.createdAt
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

  if (!admin.active) {
    return res.status(403).json({
      status: 'fail',
      message: 'Your account has been deactivated'
    });
  }

  const token = jwt.sign({ id: admin._id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwtAdmin', token, cookieOptions);

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
app.post('/api/admin/auth/logout', (req, res) => {
  res.cookie('jwtAdmin', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

// Admin dashboard stats
app.get('/api/admin/dashboard', adminProtect, catchAsync(async (req, res) => {
  const stats = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
    Transaction.countDocuments(),
    Transaction.aggregate([
      {
        $match: { status: 'completed' }
      },
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$amount' }
        }
      }
    ]),
    Investment.countDocuments(),
    Withdrawal.countDocuments({ status: 'pending' }),
    KYCDocument.countDocuments({ status: 'pending' })
  ]);

  const [
    totalUsers,
    newUsersThisWeek,
    totalTransactions,
    totalTransactionVolume,
    totalInvestments,
    pendingWithdrawals,
    pendingKYCs
  ] = stats;

  res.status(200).json({
    status: 'success',
    data: {
      totalUsers,
      newUsersThisWeek,
      totalTransactions,
      totalTransactionVolume: totalTransactionVolume[0]?.totalAmount || 0,
      totalInvestments,
      pendingWithdrawals,
      pendingKYCs
    }
  });
}));

// User growth stats
app.get('/api/admin/users/growth', adminProtect, catchAsync(async (req, res) => {
  const { period = '30d' } = req.query;
  let days;

  if (period === '7d') days = 7;
  else if (period === '30d') days = 30;
  else if (period === '90d') days = 90;
  else if (period === '1y') days = 365;
  else days = 30;

  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const endDate = new Date();

  const userGrowth = await User.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate, $lte: endDate }
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
    data: {
      userGrowth
    }
  });
}));

// Recent activity
app.get('/api/admin/activity', adminProtect, catchAsync(async (req, res) => {
  const activities = await ActivityLog.find()
    .sort('-createdAt')
    .limit(50)
    .populate('user', 'firstName lastName email');

  res.status(200).json({
    status: 'success',
    results: activities.length,
    data: {
      activities
    }
  });
}));

// Get all users
app.get('/api/admin/users', adminProtect, catchAsync(async (req, res) => {
  const { page = 1, limit = 20, search, status, sort } = req.query;
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

  let sortOption = { createdAt: -1 };
  if (sort === 'name_asc') sortOption = { firstName: 1 };
  if (sort === 'name_desc') sortOption = { firstName: -1 };
  if (sort === 'date_asc') sortOption = { createdAt: 1 };
  if (sort === 'date_desc') sortOption = { createdAt: -1 };

  const users = await User.find(query)
    .sort(sortOption)
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
      .populate('transactions')
      .populate('investments')
      .populate('kycDocuments');

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
      'dateOfBirth',
      'gender',
      'address',
      'balances'
    );

    const updatedUser = await User.findByIdAndUpdate(req.params.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

    await logActivity(req.admin._id, 'user_update', `Updated user ${updatedUser.email}`);

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  }))
  .delete(adminProtect, catchAsync(async (req, res) => {
    await User.findByIdAndUpdate(req.params.id, { active: false });

    await logActivity(req.admin._id, 'user_deactivate', `Deactivated user ${req.params.id}`);

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
    { new: true }
  ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');

  await logActivity(req.admin._id, 'user_status_change', `Changed status of ${user.email} to ${status}`);

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
      message: 'Please provide rejection reason'
    });
  }

  const kycDocument = await KYCDocument.findByIdAndUpdate(
    req.params.id,
    {
      status,
      reviewedBy: req.admin._id,
      reviewedAt: new Date(),
      rejectionReason: status === 'rejected' ? rejectionReason : undefined
    },
    { new: true }
  ).populate('user', 'firstName lastName email');

  if (status === 'approved') {
    await User.findByIdAndUpdate(kycDocument.user._id, {
      kycVerified: true,
      kycVerifiedAt: new Date()
    });
  }

  await logActivity(
    req.admin._id,
    'kyc_review',
    `Reviewed KYC for ${kycDocument.user.email} as ${status}`
  );

  // Send notification to user
  await Notification.create({
    user: kycDocument.user._id,
    title: 'KYC Verification Update',
    message: `Your KYC verification has been ${status}. ${
      status === 'rejected' ? `Reason: ${rejectionReason}` : ''
    }`,
    type: 'kyc'
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
  const { status, transactionHash, rejectionReason } = req.body;

  if (!['completed', 'rejected'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  if (status === 'rejected' && !rejectionReason) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide rejection reason'
    });
  }

  if (status === 'completed' && !transactionHash) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide transaction hash'
    });
  }

  const withdrawal = await Withdrawal.findById(req.params.id);
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

  withdrawal.status = status;
  withdrawal.processedBy = req.admin._id;
  withdrawal.processedAt = new Date();

  if (status === 'completed') {
    withdrawal.transactionHash = transactionHash;
  } else {
    withdrawal.rejectionReason = rejectionReason;
    
    // Refund the amount if rejected
    await User.findByIdAndUpdate(withdrawal.user, {
      $inc: { 'balances.main': withdrawal.amount }
    });
  }

  await withdrawal.save();

  await logActivity(
    req.admin._id,
    'withdrawal_process',
    `Processed withdrawal ${withdrawal._id} as ${status}`
  );

  // Send notification to user
  await Notification.create({
    user: withdrawal.user,
    title: 'Withdrawal Update',
    message: `Your withdrawal request has been ${status}. ${
      status === 'rejected' ? `Reason: ${rejectionReason}` : ''
    }`,
    type: 'withdrawal'
  });

  res.status(200).json({
    status: 'success',
    data: {
      withdrawal
    }
  });
}));

// Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', adminProtect, catchAsync(async (req, res) => {
  const { withdrawalIds, status, transactionHashes, rejectionReason } = req.body;

  if (!withdrawalIds || !Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide withdrawal IDs'
    });
  }

  if (!['completed', 'rejected'].includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status value'
    });
  }

  if (status === 'completed' && (!transactionHashes || transactionHashes.length !== withdrawalIds.length)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide transaction hash for each withdrawal'
    });
  }

  if (status === 'rejected' && !rejectionReason) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide rejection reason'
    });
  }

  const withdrawals = await Withdrawal.find({
    _id: { $in: withdrawalIds },
    status: 'pending'
  });

  if (withdrawals.length === 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'No pending withdrawals found with provided IDs'
    });
  }

  const processedWithdrawals = [];
  const bulkUserUpdates = [];

  for (let i = 0; i < withdrawals.length; i++) {
    const withdrawal = withdrawals[i];
    withdrawal.status = status;
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();

    if (status === 'completed') {
      withdrawal.transactionHash = transactionHashes[i];
    } else {
      withdrawal.rejectionReason = rejectionReason;
      bulkUserUpdates.push({
        updateOne: {
          filter: { _id: withdrawal.user },
          update: { $inc: { 'balances.main': withdrawal.amount } }
        }
      });
    }

    processedWithdrawals.push(withdrawal.save());

    // Create notification
    processedWithdrawals.push(
      Notification.create({
        user: withdrawal.user,
        title: 'Withdrawal Update',
        message: `Your withdrawal request has been ${status}. ${
          status === 'rejected' ? `Reason: ${rejectionReason}` : ''
        }`,
        type: 'withdrawal'
      })
    );
  }

  if (bulkUserUpdates.length > 0) {
    processedWithdrawals.push(User.bulkWrite(bulkUserUpdates));
  }

  await Promise.all(processedWithdrawals);

  await logActivity(
    req.admin._id,
    'withdrawal_batch_process',
    `Processed ${withdrawals.length} withdrawals as ${status}`
  );

  res.status(200).json({
    status: 'success',
    results: withdrawals.length,
    data: {
      withdrawals
    }
  });
}));

// Get/Create loans
app.route('/api/admin/loans')
  .get(adminProtect, catchAsync(async (req, res) => {
    const loans = await Loan.find()
      .populate('user', 'firstName lastName email')
      .sort('-createdAt');

    res.status(200).json({
      status: 'success',
      results: loans.length,
      data: {
        loans
      }
    });
  }))
  .post(adminProtect, catchAsync(async (req, res) => {
    const { userId, amount, interestRate, term, collateralAmount, collateralType } = req.body;

    if (!userId || !amount || !interestRate || !term || !collateralAmount || !collateralType) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields'
      });
    }

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
      term,
      collateralAmount,
      collateralType,
      createdBy: req.admin._id
    });

    await logActivity(
      req.admin._id,
      'loan_create',
      `Created loan for ${user.email} of ${amount} BTC`
    );

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
      .populate('user', 'firstName lastName email');

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
      'term',
      'status',
      'collateralAmount',
      'collateralType'
    );

    const loan = await Loan.findByIdAndUpdate(req.params.id, filteredBody, {
      new: true,
      runValidators: true
    }).populate('user', 'firstName lastName email');

    await logActivity(
      req.admin._id,
      'loan_update',
      `Updated loan ${loan._id} for ${loan.user.email}`
    );

    res.status(200).json({
      status: 'success',
      data: {
        loan
      }
    });
  }))
  .delete(adminProtect, catchAsync(async (req, res) => {
    await Loan.findByIdAndDelete(req.params.id);

    await logActivity(
      req.admin._id,
      'loan_delete',
      `Deleted loan ${req.params.id}`
    );

    res.status(204).json({
      status: 'success',
      data: null
    });
  }));

// Get admin profile
app.get('/api/admin/profile', adminProtect, catchAsync(async (req, res) => {
  const admin = await Admin.findById(req.admin._id).select('-password');

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
  const plans = await Plan.find({ active: true });

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
  const { type, limit = 10, page = 1 } = req.query;
  const skip = (page - 1) * limit;

  let query = { user: req.user._id };
  if (type) {
    query.type = type;
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
  const stats = await Investment.aggregate([
    {
      $match: {
        user: mongoose.Types.ObjectId(req.user._id),
        status: 'active'
      }
    },
    {
      $group: {
        _id: null,
        totalHashrate: { $sum: '$hashrate' },
        totalPower: { $sum: '$powerConsumption' },
        activePlans: { $sum: 1 }
      }
    }
  ]);

  const miningStats = stats[0] || {
    totalHashrate: 0,
    totalPower: 0,
    activePlans: 0
  };

  res.status(200).json({
    status: 'success',
    data: {
      stats: miningStats
    }
  });
}));

// Create deposit
app.post('/api/transactions/deposit', protect, catchAsync(async (req, res) => {
  const { amount, currency, method } = req.body;

  if (!amount || !currency || !method) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide amount, currency and method'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  const txId = uuidv4();
  let btcAddress = DEFAULT_BTC_ADDRESS;

  if (method === 'bank') {
    btcAddress = null;
  }

  const transaction = await Transaction.create({
    user: req.user._id,
    type: 'deposit',
    amount,
    currency,
    method,
    status: 'pending',
    txId,
    btcAddress
  });

  await logActivity(
    req.user._id,
    'deposit_create',
    `Created deposit request of ${amount} ${currency}`
  );

  res.status(201).json({
    status: 'success',
    data: {
      transaction
    }
  });
}));

// Create withdrawal
app.post('/api/transactions/withdraw', protect, catchAsync(async (req, res) => {
  const { amount, currency, walletAddress } = req.body;

  if (!amount || !currency || !walletAddress) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide amount, currency and wallet address'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  const user = await User.findById(req.user._id);
  if (user.balances.main < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Check if user has completed KYC if withdrawal is above threshold
  if (amount > 1 && !user.kycVerified) { // 1 BTC threshold for example
    return res.status(400).json({
      status: 'fail',
      message: 'KYC verification required for withdrawals above 1 BTC'
    });
  }

  // Deduct from user balance
  user.balances.main -= amount;
  await user.save();

  const withdrawal = await Withdrawal.create({
    user: req.user._id,
    amount,
    currency,
    walletAddress,
    status: 'pending'
  });

  await logActivity(
    req.user._id,
    'withdrawal_create',
    `Created withdrawal request of ${amount} ${currency}`
  );

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

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  const plan = await Plan.findById(planId);
  if (!plan || !plan.active) {
    return res.status(404).json({
      status: 'fail',
      message: 'Plan not found or inactive'
    });
  }

  const user = await User.findById(req.user._id);
  if (user.balances.main < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Deduct from user balance
  user.balances.main -= amount;
  user.balances.active += amount;
  await user.save();

  const investment = await Investment.create({
    user: req.user._id,
    plan: planId,
    amount,
    hashrate: (amount / plan.price) * plan.hashrate,
    powerConsumption: (amount / plan.price) * plan.power,
    startDate: new Date(),
    endDate: moment().add(plan.duration, 'days').toDate(),
    status: 'active'
  });

  await Transaction.create({
    user: req.user._id,
    type: 'investment',
    amount,
    currency: 'BTC',
    status: 'completed',
    reference: `Investment in ${plan.name}`
  });

  await logActivity(
    req.user._id,
    'investment_create',
    `Created investment in ${plan.name} with ${amount} BTC`
  );

  res.status(201).json({
    status: 'success',
    data: {
      investment
    }
  });
}));

// Transfer between balances
app.post('/api/transactions/transfer', protect, catchAsync(async (req, res) => {
  const { from, to, amount } = req.body;

  if (!from || !to || !amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide from, to and amount'
    });
  }

  if (amount <= 0) {
    return res.status(400).json({
      status: 'fail',
      message: 'Amount must be greater than 0'
    });
  }

  const validBalances = ['main', 'active', 'savings'];
  if (!validBalances.includes(from) || !validBalances.includes(to)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid balance type'
    });
  }

  if (from === to) {
    return res.status(400).json({
      status: 'fail',
      message: 'Cannot transfer to the same balance'
    });
  }

  const user = await User.findById(req.user._id);
  if (user.balances[from] < amount) {
    return res.status(400).json({
      status: 'fail',
      message: 'Insufficient balance'
    });
  }

  // Perform transfer
  user.balances[from] -= amount;
  user.balances[to] += amount;
  await user.save();

  await Transaction.create({
    user: req.user._id,
    type: 'transfer',
    amount,
    currency: 'BTC',
    status: 'completed',
    reference: `Transfer from ${from} to ${to}`
  });

  await logActivity(
    req.user._id,
    'balance_transfer',
    `Transferred ${amount} BTC from ${from} to ${to}`
  );

  res.status(200).json({
    status: 'success',
    data: {
      balances: user.balances
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

// 404 handler
app.all('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${NODE_ENV} mode`);
});

// Process investments daily
const processInvestments = async () => {
  try {
    const now = new Date();
    const investments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    });

    if (investments.length === 0) return;

    const bulkUserUpdates = [];
    const bulkInvestmentUpdates = [];

    for (const investment of investments) {
      const plan = await Plan.findById(investment.plan);
      if (!plan) continue;

      // Calculate profit
      const profit = investment.amount * (plan.profitPercentage / 100);

      bulkUserUpdates.push({
        updateOne: {
          filter: { _id: investment.user },
          update: {
            $inc: {
              'balances.main': investment.amount + profit,
              'balances.active': -investment.amount
            }
          }
        }
      });

      bulkInvestmentUpdates.push({
        updateOne: {
          filter: { _id: investment._id },
          update: {
            status: 'completed',
            profit,
            completedAt: now
          }
        }
      });

      // Create transaction for profit
      await Transaction.create({
        user: investment.user,
        type: 'profit',
        amount: profit,
        currency: 'BTC',
        status: 'completed',
        reference: `Profit from investment ${investment._id}`
      });
    }

    await Promise.all([
      User.bulkWrite(bulkUserUpdates),
      Investment.bulkWrite(bulkInvestmentUpdates)
    ]);

    console.log(`Processed ${investments.length} investments`);
  } catch (err) {
    console.error('Error processing investments:', err);
  }
};

// Run investment processing daily at midnight
setInterval(processInvestments, 24 * 60 * 60 * 1000);
