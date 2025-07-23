require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['https://bithhash.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());


// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Default BTC deposit address
const DEFAULT_BTC_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';


// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', limiter);

// Body parser
app.use(express.json({ limit: '10kb' }));

// Add these lines for CSRF protection
const session = require('express-session');
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(csrfProtection);

// Redis client
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// MongoDB connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', { 
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
  phone: { type: String, default: '' },
  country: { type: String, default: '' },
  city: { type: String, default: '' },
  address: { type: String, default: '' },
  postalCode: { type: String, default: '' },
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
  status: { type: String, enum: ['active', 'suspended', 'deleted'], default: 'active' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
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
  balances: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    bonus: { type: Number, default: 0 }
  },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  apiKeys: [{
    name: String,
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now },
    status: { type: String, enum: ['active', 'revoked'], default: 'active' }
  }],
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

// Indexes
UserSchema.index({ email: 1 });
UserSchema.index({ referralCode: 1 });
UserSchema.index({ 'kycStatus.identity': 1 });
UserSchema.index({ 'kycStatus.address': 1 });
UserSchema.index({ status: 1 });

// Middleware
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

// Methods
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

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number, required: true },
  duration: { type: Number, required: true }, // in hours
  percentage: { type: Number, required: true }, // profit percentage
  referralBonus: { type: Number, default: 5 }, // percentage
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

const Plan = mongoose.model('Plan', PlanSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'bonus', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  details: {
    btcAddress: String,
    txHash: String,
    bankName: String,
    accountNumber: String,
    routingNumber: String,
    cardLast4: String,
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  adminNote: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', TransactionSchema);

const InvestmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  expectedProfit: { type: Number, required: true },
  actualProfit: { type: Number, default: 0 },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  referralBonusPaid: { type: Boolean, default: false },
  referralUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referralBonusAmount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Investment = mongoose.model('Investment', InvestmentSchema);

const AdminActivitySchema = new mongoose.Schema({
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: { type: String, required: true },
  targetId: mongoose.Schema.Types.ObjectId,
  details: Object,
  ip: String,
  createdAt: { type: Date, default: Date.now }
});

const AdminActivity = mongoose.model('AdminActivity', AdminActivitySchema);

const KYCSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['identity', 'address', 'facial'], required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  documents: {
    front: String,
    back: String,
    selfie: String
  },
  adminReviewer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNote: String,
  reviewedAt: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const KYC = mongoose.model('KYC', KYCSchema);

const LoanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  collateralAmount: { type: Number, required: true },
  collateralCurrency: { type: String, default: 'BTC' },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'completed', 'defaulted'], default: 'pending' },
  startDate: Date,
  endDate: Date,
  adminApprover: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  adminNote: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Loan = mongoose.model('Loan', LoanSchema);

// Initialize default admin if not exists
const createDefaultAdmin = async () => {
  const adminEmail = 'admin@bithash.com';
  const adminPassword = 'Admin@1234';
  
  const existingAdmin = await User.findOne({ email: adminEmail });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    const admin = await User.create({
      firstName: 'Admin',
      lastName: 'System',
      email: adminEmail,
      password: hashedPassword,
      role: 'admin',
      referralCode: 'ADMIN' + Math.random().toString(36).substr(2, 6).toUpperCase(),
      notificationPreferences: {
        email: true,
        sms: false,
        push: true
      }
    });
    console.log('Default admin created:', admin.email);
  }
};

createDefaultAdmin();

// Initialize plans if not exists
const initializePlans = async () => {
  const plans = [
    {
      name: 'Starter Plan',
      description: '20% After 10 hours',
      minAmount: 30,
      maxAmount: 499,
      duration: 10,
      percentage: 20,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Gold Plan',
      description: '40% After 24 hours',
      minAmount: 500,
      maxAmount: 1999,
      duration: 24,
      percentage: 40,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Advance Plan',
      description: '60% After 48 hours',
      minAmount: 2000,
      maxAmount: 9999,
      duration: 48,
      percentage: 60,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Exclusive Plan',
      description: '80% After 72 hours',
      minAmount: 10000,
      maxAmount: 30000,
      duration: 72,
      percentage: 80,
      referralBonus: 5,
      status: 'active'
    },
    {
      name: 'Expert Plan',
      description: '100% After 96 hours',
      minAmount: 50000,
      maxAmount: 1000000,
      duration: 96,
      percentage: 100,
      referralBonus: 5,
      status: 'active'
    }
  ];

  for (const plan of plans) {
    const existingPlan = await Plan.findOne({ name: plan.name });
    if (!existingPlan) {
      await Plan.create(plan);
      console.log(`Plan created: ${plan.name}`);
    }
  }
};

initializePlans();

// Utility functions
const signToken = (id, role) => {
  return jwt.sign({ id, role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.role);
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

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

const logAdminActivity = async (adminId, action, target, targetId = null, details = {}) => {
  try {
    const ip = '127.0.0.1'; // In production, get from request
    await AdminActivity.create({
      admin: adminId,
      action,
      target,
      targetId,
      details,
      ip
    });
  } catch (err) {
    console.error('Error logging admin activity:', err);
  }
};

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

    if (currentUser.status !== 'active') {
      return res.status(403).json({
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

// Routes

app.get('/api/csrf-token', (req, res) => {
  res.json({ 
    csrfToken: req.csrfToken(),
    status: 'success'
  });
});

// User Endpoints
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching user data'
    });
  }
});

app.put('/api/users/profile', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'phone', 'country', 'city', 'notificationPreferences');
    
    if (req.body.email && req.body.email !== req.user.email) {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Email already in use'
        });
      }
    }
    
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error updating profile'
    });
  }
});

app.put('/api/users/address', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'address', 'city', 'country', 'postalCode');
    
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error updating address'
    });
  }
});

app.put('/api/users/password', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    user.password = req.body.newPassword;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error updating password'
    });
  }
});

app.post('/api/users/api-keys', protect, async (req, res) => {
  try {
    const { name, permissions } = req.body;
    
    if (!name || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide name and permissions for the API key'
      });
    }
    
    const { key, secret } = req.user.generateApiKey();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    
    const newApiKey = {
      name,
      key,
      secret,
      permissions,
      expiresAt,
      status: 'active'
    };
    
    await User.findByIdAndUpdate(req.user.id, {
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
          expiresAt: expiresAt.toISOString()
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error generating API key'
    });
  }
});

// Admin Endpoints
app.post('/api/admin/auth/login', csrfProtection, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    if (user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to access this resource'
      });
    }
    
    await logAdminActivity(user._id, 'login', 'system');
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error during login'
    });
  }
});

app.post('/api/admin/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

app.get('/api/admin/dashboard', protect, restrictTo('admin'), async (req, res) => {
  try {
    // Cache dashboard data for 5 minutes
    const cachedData = await redis.get('adminDashboard');
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }
    
    const totalUsers = await User.countDocuments({ role: 'user' });
    const activeUsers = await User.countDocuments({ role: 'user', status: 'active' });
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
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
    
    const dashboardData = {
      totalUsers,
      activeUsers,
      pendingKYC,
      pendingWithdrawals,
      totalDeposits: totalDeposits.length > 0 ? totalDeposits[0].total : 0,
      totalWithdrawals: totalWithdrawals.length > 0 ? totalWithdrawals[0].total : 0,
      activeInvestments,
      updatedAt: new Date()
    };
    
    await redis.set('adminDashboard', JSON.stringify(dashboardData), 'EX', 300); // 5 minutes
    
    res.status(200).json({
      status: 'success',
      data: dashboardData
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching dashboard data'
    });
  }
});

app.get('/api/admin/users/growth', protect, restrictTo('admin'), async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const cacheKey = `userGrowth:${days}`;
    
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
          createdAt: { $gte: startDate },
          role: 'user'
        }
      },
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
      {
        $sort: {
          '_id.year': 1,
          '_id.month': 1,
          '_id.day': 1
        }
      },
      {
        $project: {
          date: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: {
                $dateFromParts: {
                  year: '$_id.year',
                  month: '$_id.month',
                  day: '$_id.day'
                }
              }
            }
          },
          count: 1,
          _id: 0
        }
      }
    ]);
    
    await redis.set(cacheKey, JSON.stringify(userGrowth), 'EX', 3600); // 1 hour
    
    res.status(200).json({
      status: 'success',
      data: userGrowth
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching user growth data'
    });
  }
});

app.get('/api/admin/activity', protect, restrictTo('admin'), async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const activities = await AdminActivity.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('admin', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching admin activities'
    });
  }
});

app.get('/api/admin/users', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const query = { role: 'user' };
    
    if (req.query.search) {
      query.$or = [
        { firstName: { $regex: req.query.search, $options: 'i' } },
        { lastName: { $regex: req.query.search, $options: 'i' } },
        { email: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    
    if (req.query.status) {
      query.status = req.query.status;
    }
    
    const users = await User.find(query)
      .skip(skip)
      .limit(limit)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
    
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: users
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching users'
    });
  }
});

app.route('/api/admin/users/:id')
  .get(protect, restrictTo('admin'), async (req, res) => {
    try {
      const user = await User.findById(req.params.id)
        .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
      
      if (!user) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found'
        });
      }
      
      res.status(200).json({
        status: 'success',
        data: user
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error fetching user'
      });
    }
  })
  .put(protect, restrictTo('admin'), async (req, res) => {
    try {
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
        'balances',
        'notificationPreferences'
      );
      
      const updatedUser = await User.findByIdAndUpdate(req.params.id, filteredBody, {
        new: true,
        runValidators: true
      }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
      
      if (!updatedUser) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found'
        });
      }
      
      await logAdminActivity(req.user.id, 'update', 'user', updatedUser._id, {
        fieldsUpdated: Object.keys(filteredBody)
      });
      
      res.status(200).json({
        status: 'success',
        data: updatedUser
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error updating user'
      });
    }
  })
  .delete(protect, restrictTo('admin'), async (req, res) => {
    try {
      const user = await User.findByIdAndUpdate(req.params.id, { status: 'deleted' }, {
        new: true
      });
      
      if (!user) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found'
        });
      }
      
      await logAdminActivity(req.user.id, 'delete', 'user', user._id);
      
      res.status(204).json({
        status: 'success',
        data: null
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error deleting user'
      });
    }
  });

app.put('/api/admin/users/:id/status', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['active', 'suspended'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }
    
    const user = await User.findByIdAndUpdate(req.params.id, { status }, {
      new: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    await logAdminActivity(req.user.id, 'update', 'user status', user._id, { status });
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error updating user status'
    });
  }
});

app.get('/api/admin/kyc/pending', protect, restrictTo('admin'), async (req, res) => {
  try {
    const pendingKYC = await KYC.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: 1 });
    
    res.status(200).json({
      status: 'success',
      data: pendingKYC
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching pending KYC'
    });
  }
});

app.get('/api/admin/kyc/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('adminReviewer', 'firstName lastName');
    
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
    res.status(500).json({
      status: 'error',
      message: 'Error fetching KYC details'
    });
  }
});

app.post('/api/admin/kyc/:id/review', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { status, note } = req.body;
    
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }
    
    const kyc = await KYC.findByIdAndUpdate(req.params.id, {
      status,
      adminReviewer: req.user.id,
      reviewNote: note,
      reviewedAt: new Date()
    }, {
      new: true
    });
    
    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }
    
    // Update user's KYC status
    const kycField = `${kyc.type}Status`;
    await User.findByIdAndUpdate(kyc.user, {
      [`kycStatus.${kyc.type}`]: status === 'approved' ? 'verified' : 'rejected'
    });
    
    await logAdminActivity(req.user.id, 'review', 'kyc', kyc._id, { status, note });
    
    res.status(200).json({
      status: 'success',
      data: kyc
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error processing KYC review'
    });
  }
});

app.get('/api/admin/withdrawals/pending', protect, restrictTo('admin'), async (req, res) => {
  try {
    const pendingWithdrawals = await Transaction.find({ type: 'withdrawal', status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: 1 });
    
    res.status(200).json({
      status: 'success',
      data: pendingWithdrawals
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching pending withdrawals'
    });
  }
});

app.get('/api/admin/withdrawals/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const withdrawal = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email');
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
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
    res.status(500).json({
      status: 'error',
      message: 'Error fetching withdrawal details'
    });
  }
});

app.post('/api/admin/withdrawals/:id/process', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    
    if (!['completed', 'cancelled'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }
    
    const withdrawal = await Transaction.findById(req.params.id);
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Withdrawal has already been processed'
      });
    }
    
    // If cancelling, return funds to user's balance
    if (status === 'cancelled') {
      await User.findByIdAndUpdate(withdrawal.user, {
        $inc: { 'balances.main': withdrawal.amount }
      });
    }
    
    withdrawal.status = status;
    withdrawal.adminNote = adminNote;
    withdrawal.updatedAt = new Date();
    await withdrawal.save();
    
    await logAdminActivity(req.user.id, 'process', 'withdrawal', withdrawal._id, { status });
    
    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error processing withdrawal'
    });
  }
});

app.post('/api/admin/withdrawals/process-batch', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { withdrawalIds, status } = req.body;
    
    if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide withdrawal IDs to process'
      });
    }
    
    if (!['completed', 'cancelled'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }
    
    const withdrawals = await Transaction.find({
      _id: { $in: withdrawalIds },
      type: 'withdrawal',
      status: 'pending'
    });
    
    if (withdrawals.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'No pending withdrawals found with the provided IDs'
      });
    }
    
    // Process each withdrawal
    const processedWithdrawals = [];
    
    for (const withdrawal of withdrawals) {
      if (status === 'cancelled') {
        await User.findByIdAndUpdate(withdrawal.user, {
          $inc: { 'balances.main': withdrawal.amount }
        });
      }
      
      withdrawal.status = status;
      withdrawal.updatedAt = new Date();
      await withdrawal.save();
      processedWithdrawals.push(withdrawal);
      
      await logAdminActivity(req.user.id, 'batch-process', 'withdrawal', withdrawal._id, { status });
    }
    
    res.status(200).json({
      status: 'success',
      data: processedWithdrawals
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error processing batch withdrawals'
    });
  }
});

app.route('/api/admin/loans')
  .get(protect, restrictTo('admin'), async (req, res) => {
    try {
      const loans = await Loan.find()
        .populate('user', 'firstName lastName email')
        .populate('adminApprover', 'firstName lastName')
        .sort({ createdAt: -1 });
      
      res.status(200).json({
        status: 'success',
        data: loans
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error fetching loans'
      });
    }
  })
  .post(protect, restrictTo('admin'), async (req, res) => {
    try {
      const { userId, amount, collateralAmount, interestRate, duration } = req.body;
      
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found'
        });
      }
      
      if (user.balances.main < collateralAmount) {
        return res.status(400).json({
          status: 'fail',
          message: 'User does not have sufficient collateral'
        });
      }
      
      const loan = await Loan.create({
        user: userId,
        amount,
        collateralAmount,
        collateralCurrency: 'BTC',
        interestRate,
        duration,
        status: 'approved',
        adminApprover: req.user.id,
        startDate: new Date(),
        endDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000)
      });
      
      // Deduct collateral from user's balance
      user.balances.main -= collateralAmount;
      await user.save();
      
      await logAdminActivity(req.user.id, 'create', 'loan', loan._id, {
        amount,
        collateralAmount,
        interestRate,
        duration
      });
      
      res.status(201).json({
        status: 'success',
        data: loan
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error creating loan'
      });
    }
  });

app.route('/api/admin/loans/:id')
  .get(protect, restrictTo('admin'), async (req, res) => {
    try {
      const loan = await Loan.findById(req.params.id)
        .populate('user', 'firstName lastName email')
        .populate('adminApprover', 'firstName lastName');
      
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
      res.status(500).json({
        status: 'error',
        message: 'Error fetching loan'
      });
    }
  })
  .put(protect, restrictTo('admin'), async (req, res) => {
    try {
      const { status, adminNote } = req.body;
      
      const loan = await Loan.findById(req.params.id);
      
      if (!loan) {
        return res.status(404).json({
          status: 'fail',
          message: 'Loan not found'
        });
      }
      
      if (loan.status !== 'pending') {
        return res.status(400).json({
          status: 'fail',
          message: 'Loan has already been processed'
        });
      }
      
      if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({
          status: 'fail',
          message: 'Invalid status value'
        });
      }
      
      if (status === 'approved') {
        loan.status = 'active';
        loan.adminApprover = req.user.id;
        loan.startDate = new Date();
        loan.endDate = new Date(Date.now() + loan.duration * 24 * 60 * 60 * 1000);
        
        // Deduct collateral from user's balance
        await User.findByIdAndUpdate(loan.user, {
          $inc: { 'balances.main': -loan.collateralAmount }
        });
      } else {
        loan.status = 'rejected';
        loan.adminApprover = req.user.id;
        loan.adminNote = adminNote;
      }
      
      await loan.save();
      
      await logAdminActivity(req.user.id, 'update', 'loan', loan._id, { status });
      
      res.status(200).json({
        status: 'success',
        data: loan
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error updating loan'
      });
    }
  })
  .delete(protect, restrictTo('admin'), async (req, res) => {
    try {
      const loan = await Loan.findByIdAndDelete(req.params.id);
      
      if (!loan) {
        return res.status(404).json({
          status: 'fail',
          message: 'Loan not found'
        });
      }
      
      // Return collateral if loan was active
      if (loan.status === 'active') {
        await User.findByIdAndUpdate(loan.user, {
          $inc: { 'balances.main': loan.collateralAmount }
        });
      }
      
      await logAdminActivity(req.user.id, 'delete', 'loan', loan._id);
      
      res.status(204).json({
        status: 'success',
        data: null
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Error deleting loan'
      });
    }
  });

app.get('/api/admin/profile', protect, restrictTo('admin'), async (req, res) => {
  try {
    const admin = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -twoFactorSecret');
    
    res.status(200).json({
      status: 'success',
      data: admin
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching admin profile'
    });
  }
});

// Dashboard Endpoints
app.get('/api/plans', protect, async (req, res) => {
  try {
    const cachedPlans = await redis.get('investmentPlans');
    if (cachedPlans) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedPlans)
      });
    }
    
    const plans = await Plan.find({ status: 'active' }).sort({ minAmount: 1 });
    await redis.set('investmentPlans', JSON.stringify(plans), 'EX', 3600); // Cache for 1 hour
    
    res.status(200).json({
      status: 'success',
      data: plans
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching investment plans'
    });
  }
});

app.get('/api/transactions', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Transaction.countDocuments({ user: req.user.id });
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: transactions
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching transactions'
    });
  }
});

app.get('/api/mining/stats', protect, async (req, res) => {
  try {
    const cacheKey = `miningStats:${req.user.id}`;
    const cachedStats = await redis.get(cacheKey);
    
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedStats)
      });
    }
    
    const activeInvestments = await Investment.find({
      user: req.user.id,
      status: 'active'
    }).populate('plan');
    
    const completedInvestments = await Investment.find({
      user: req.user.id,
      status: 'completed'
    }).countDocuments();
    
    const totalInvested = await Investment.aggregate([
      { $match: { user: req.user._id } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalProfit = await Investment.aggregate([
      { $match: { user: req.user._id, status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$actualProfit' } } }
    ]);
    
    const stats = {
      activeInvestments: activeInvestments.length,
      completedInvestments,
      totalInvested: totalInvested.length > 0 ? totalInvested[0].total : 0,
      totalProfit: totalProfit.length > 0 ? totalProfit[0].total : 0,
      activePlans: activeInvestments.map(inv => ({
        planName: inv.plan.name,
        amount: inv.amount,
        expectedProfit: inv.expectedProfit,
        endDate: inv.endDate
      })),
      updatedAt: new Date()
    };
    
    await redis.set(cacheKey, JSON.stringify(stats), 'EX', 300); // Cache for 5 minutes
    
    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error fetching mining stats'
    });
  }
});

app.post('/api/transactions/deposit', protect, async (req, res) => {
  try {
    const { amount, method } = req.body;
    
    if (!amount || !method) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and method'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    let details = {};
    if (method === 'btc') {
      details.btcAddress = DEFAULT_BTC_DEPOSIT_ADDRESS;
    } else if (method === 'bank') {
      details.bankName = req.body.bankName;
      details.accountNumber = req.body.accountNumber;
      details.routingNumber = req.body.routingNumber;
    } else if (method === 'card') {
      details.cardLast4 = req.body.cardLast4;
    }
    
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'pending',
      method,
      details,
      netAmount: amount,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    res.status(201).json({
      status: 'success',
      data: transaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error creating deposit transaction'
    });
  }
});

app.post('/api/transactions/withdraw', protect, async (req, res) => {
  try {
    const { amount, method } = req.body;
    
    if (!amount || !method) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and method'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user.id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    let details = {};
    if (method === 'btc') {
      details.btcAddress = req.body.btcAddress;
      if (!details.btcAddress) {
        return res.status(400).json({
          status: 'fail',
          message: 'BTC address is required'
        });
      }
    } else if (method === 'bank') {
      details.bankName = req.body.bankName;
      details.accountNumber = req.body.accountNumber;
      details.routingNumber = req.body.routingNumber;
      
      if (!details.bankName || !details.accountNumber || !details.routingNumber) {
        return res.status(400).json({
          status: 'fail',
          message: 'Bank details are incomplete'
        });
      }
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
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    res.status(201).json({
      status: 'success',
      data: transaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error creating withdrawal transaction'
    });
  }
});

app.post('/api/transactions/transfer', protect, async (req, res) => {
  try {
    const { amount, recipientEmail } = req.body;
    
    if (!amount || !recipientEmail) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and recipient email'
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
        message: 'Recipient not found'
      });
    }
    
    const user = await User.findById(req.user.id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct from sender and add to recipient
    user.balances.main -= amount;
    recipient.balances.main += amount;
    
    await Promise.all([user.save(), recipient.save()]);
    
    // Create transactions for both parties
    const senderTransaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      details: {
        recipient: recipient._id,
        direction: 'out'
      },
      netAmount: amount,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    const recipientTransaction = await Transaction.create({
      user: recipient._id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      details: {
        recipient: req.user.id,
        direction: 'in'
      },
      netAmount: amount,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    res.status(201).json({
      status: 'success',
      data: senderTransaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error processing transfer'
    });
  }
});

app.post('/api/investments', protect, async (req, res) => {
  try {
    const { planId, amount, referralCode } = req.body;
    
    if (!planId || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide plan ID and amount'
      });
    }
    
    const plan = await Plan.findById(planId);
    if (!plan || plan.status !== 'active') {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found or inactive'
      });
    }
    
    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }
    
    const user = await User.findById(req.user.id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Check referral code if provided
    let referralUser = null;
    if (referralCode) {
      referralUser = await User.findOne({ referralCode });
      if (!referralUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Invalid referral code'
        });
      }
    }
    
    // Deduct amount from user's balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();
    
    // Calculate expected profit
    const expectedProfit = amount * (plan.percentage / 100);
    const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);
    
    const investment = await Investment.create({
      user: req.user.id,
      plan: planId,
      amount,
      expectedProfit,
      actualProfit: 0,
      startDate: new Date(),
      endDate,
      status: 'active',
      referralUser: referralUser ? referralUser._id : undefined,
      referralBonusPaid: false,
      referralBonusAmount: referralUser ? amount * (plan.referralBonus / 100) : 0
    });
    
    // Create transaction record
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      details: {
        plan: planId,
        investment: investment._id
      },
      netAmount: amount,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    res.status(201).json({
      status: 'success',
      data: investment
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error creating investment'
    });
  }
});

// Process completed investments (cron job endpoint)
app.post('/api/investments/process-completed', async (req, res) => {
  try {
    if (req.headers['x-cron-secret'] !== process.env.CRON_SECRET) {
      return res.status(403).json({
        status: 'fail',
        message: 'Unauthorized'
      });
    }
    
    const now = new Date();
    const completedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan referralUser');
    
    for (const investment of completedInvestments) {
      // Update user balances
      const user = investment.user;
      user.balances.active -= investment.amount;
      user.balances.matured += investment.amount + investment.expectedProfit;
      await user.save();
      
      // Update investment status
      investment.actualProfit = investment.expectedProfit;
      investment.status = 'completed';
      await investment.save();
      
      // Create transaction for profit
      await Transaction.create({
        user: user._id,
        type: 'investment',
        amount: investment.expectedProfit,
        currency: 'USD',
        status: 'completed',
        method: 'internal',
        details: {
          plan: investment.plan._id,
          investment: investment._id,
          type: 'profit'
        },
        netAmount: investment.expectedProfit,
        createdAt: now,
        updatedAt: now
      });
      
      // Process referral bonus if applicable
      if (investment.referralUser && !investment.referralBonusPaid) {
        const referralUser = investment.referralUser;
        referralUser.balances.bonus += investment.referralBonusAmount;
        await referralUser.save();
        
        investment.referralBonusPaid = true;
        await investment.save();
        
        await Transaction.create({
          user: referralUser._id,
          type: 'referral',
          amount: investment.referralBonusAmount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          details: {
            referredUser: user._id,
            investment: investment._id
          },
          netAmount: investment.referralBonusAmount,
          createdAt: now,
          updatedAt: now
        });
      }
    }
    
    res.status(200).json({
      status: 'success',
      message: `Processed ${completedInvestments.length} investments`
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Error processing completed investments'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
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
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
