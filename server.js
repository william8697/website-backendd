require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { Server } = require('socket.io');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const morgan = require('morgan');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

// Constants
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';
const BTC_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const DEFAULT_ADMIN_EMAIL = 'admin@bithash.com';
const DEFAULT_ADMIN_PASSWORD = 'Admin@1234!';

// Initialize Express
const app = express();
const httpServer = createServer(app);

// Configure Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: 'https://bithhash.vercel.app',
    methods: ['GET', 'POST']
  }
});

// Initialize Redis
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// Configure email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// MongoDB connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => logger.info('MongoDB connected successfully'))
.catch(err => logger.error('MongoDB connection error:', err));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: { type: String },
  country: { type: String },
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  balance: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 }
  },
  kyc: {
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'not_submitted'], default: 'not_submitted' },
    documents: {
      identity: String,
      address: String,
      selfie: String
    },
    submittedAt: Date,
    reviewedAt: Date,
    reviewedBy: mongoose.Schema.Types.ObjectId
  },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    method: { type: String, enum: ['none', 'sms', 'authenticator'], default: 'none' },
    secret: String
  },
  apiKeys: [{
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now }
  }],
  devices: [{
    ip: String,
    userAgent: String,
    lastAccessed: Date
  }],
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  referralCode: { type: String, unique: true },
  referredBy: mongoose.Schema.Types.ObjectId,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['superadmin', 'admin', 'support'], default: 'admin' },
  lastLogin: Date,
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String
  }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'BTC' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  address: String,
  txHash: String,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
});

const InvestmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  planId: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  startDate: { type: Date, default: Date.now },
  endDate: Date,
  expectedProfit: Number,
  actualProfit: { type: Number, default: 0 },
  transactions: [mongoose.Schema.Types.ObjectId]
});

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  duration: { type: Number, required: true }, // in hours
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number, required: true },
  profitPercentage: { type: Number, required: true },
  referralBonus: { type: Number, default: 5 },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' }
});

const SystemActivitySchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  adminId: mongoose.Schema.Types.ObjectId,
  action: { type: String, required: true },
  entityType: String,
  entityId: mongoose.Schema.Types.ObjectId,
  ipAddress: String,
  userAgent: String,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
});

const LoanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  amount: { type: Number, required: true },
  collateralAmount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'defaulted', 'completed'], default: 'pending' },
  startDate: Date,
  endDate: Date,
  payments: [{
    amount: Number,
    date: Date,
    txId: mongoose.Schema.Types.ObjectId
  }],
  approvedBy: mongoose.Schema.Types.ObjectId,
  approvedAt: Date
});

const ChatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  adminId: { type: mongoose.Schema.Types.ObjectId, required: true },
  message: { type: String, required: true },
  sender: { type: String, enum: ['user', 'admin'], required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// MongoDB Models
const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Investment = mongoose.model('Investment', InvestmentSchema);
const Plan = mongoose.model('Plan', PlanSchema);
const SystemActivity = mongoose.model('SystemActivity', SystemActivitySchema);
const Loan = mongoose.model('Loan', LoanSchema);
const Chat = mongoose.model('Chat', ChatSchema);

// Initialize default admin
async function initializeDefaultAdmin() {
  try {
    const existingAdmin = await Admin.findOne({ email: DEFAULT_ADMIN_EMAIL });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 12);
      await Admin.create({
        email: DEFAULT_ADMIN_EMAIL,
        password: hashedPassword,
        firstName: 'System',
        lastName: 'Administrator',
        role: 'superadmin'
      });
      logger.info('Default admin account created');
    }
  } catch (err) {
    logger.error('Error creating default admin:', err);
  }
}

// Initialize investment plans
async function initializePlans() {
  try {
    const existingPlans = await Plan.countDocuments();
    if (existingPlans === 0) {
      await Plan.insertMany([
        {
          name: 'Starter Plan',
          duration: 10,
          minAmount: 30,
          maxAmount: 499,
          profitPercentage: 20,
          referralBonus: 5,
          status: 'active'
        },
        {
          name: 'Gold Plan',
          duration: 24,
          minAmount: 500,
          maxAmount: 1999,
          profitPercentage: 40,
          referralBonus: 5,
          status: 'active'
        },
        {
          name: 'Advance Plan',
          duration: 48,
          minAmount: 2000,
          maxAmount: 9999,
          profitPercentage: 60,
          referralBonus: 5,
          status: 'active'
        },
        {
          name: 'Exclusive Plan',
          duration: 72,
          minAmount: 10000,
          maxAmount: 30000,
          profitPercentage: 80,
          referralBonus: 5,
          status: 'active'
        },
        {
          name: 'Expert Plan',
          duration: 96,
          minAmount: 50000,
          maxAmount: 1000000,
          profitPercentage: 100,
          referralBonus: 5,
          status: 'active'
        }
      ]);
      logger.info('Investment plans initialized');
    }
  } catch (err) {
    logger.error('Error initializing investment plans:', err);
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: 'https://bithhash.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({ status: 'error', message: 'You are not logged in! Please log in to get access.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id).select('+devices');
    if (!currentUser) {
      return res.status(401).json({ status: 'error', message: 'The user belonging to this token no longer exists.' });
    }

    if (currentUser.status !== 'active') {
      return res.status(401).json({ status: 'error', message: 'Your account has been suspended or banned.' });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    logger.error('Authentication error:', err);
    res.status(401).json({ status: 'error', message: 'Invalid or expired token. Please log in again.' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.jwtAdmin) {
      token = req.cookies.jwtAdmin;
    }

    if (!token) {
      return res.status(401).json({ status: 'error', message: 'You are not logged in! Please log in to get access.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin) {
      return res.status(401).json({ status: 'error', message: 'The admin belonging to this token no longer exists.' });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    logger.error('Admin authentication error:', err);
    res.status(401).json({ status: 'error', message: 'Invalid or expired token. Please log in again.' });
  }
};

// Utility functions
const createAndSendToken = (user, statusCode, res, isAdmin = false) => {
  const token = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  if (isAdmin) {
    res.cookie('jwtAdmin', token, cookieOptions);
  } else {
    res.cookie('jwt', token, cookieOptions);
  }

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

const logActivity = async (userId, adminId, action, entityType, entityId, metadata = {}) => {
  try {
    await SystemActivity.create({
      userId,
      adminId,
      action,
      entityType,
      entityId,
      ipAddress: metadata.ip || 'unknown',
      userAgent: metadata.userAgent || 'unknown',
      metadata
    });
  } catch (err) {
    logger.error('Error logging activity:', err);
  }
};

// Socket.IO events
io.on('connection', (socket) => {
  logger.info('New WebSocket connection');

  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (user) {
        socket.join(`user_${user._id}`);
        socket.emit('authenticated', { status: 'success' });
      }
    } catch (err) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });

  socket.on('admin-authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const admin = await Admin.findById(decoded.id);
      if (admin) {
        socket.join('admins');
        socket.emit('admin-authenticated', { status: 'success' });
      }
    } catch (err) {
      socket.emit('error', { message: 'Admin authentication failed' });
    }
  });

  socket.on('disconnect', () => {
    logger.info('Client disconnected');
  });
});

// User Endpoints
app.get('/api/users/me', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -twoFactorAuth.secret -apiKeys -devices');
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    logger.error('Error fetching user profile:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.put('/api/users/profile', authenticateUser, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, country } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { firstName, lastName, email, phone, country },
      { new: true, runValidators: true }
    ).select('-password -twoFactorAuth.secret -apiKeys -devices');

    await logActivity(req.user._id, null, 'update_profile', 'user', req.user._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    logger.error('Error updating user profile:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.put('/api/users/address', authenticateUser, async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { address: { street, city, state, postalCode, country } },
      { new: true, runValidators: true }
    ).select('-password -twoFactorAuth.secret -apiKeys -devices');

    await logActivity(req.user._id, null, 'update_address', 'user', req.user._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    logger.error('Error updating user address:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.put('/api/users/password', authenticateUser, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user._id).select('+password');
    if (!await bcrypt.compare(currentPassword, user.password)) {
      return res.status(401).json({ status: 'error', message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    await logActivity(req.user._id, null, 'change_password', 'user', req.user._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      message: 'Password updated successfully'
    });
  } catch (err) {
    logger.error('Error changing password:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/users/api-keys', authenticateUser, async (req, res) => {
  try {
    const { permissions, expiresInDays } = req.body;
    
    const apiKey = crypto.randomBytes(16).toString('hex');
    const apiSecret = crypto.randomBytes(32).toString('hex');
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        $push: {
          apiKeys: {
            key: apiKey,
            secret: apiSecret,
            permissions,
            expiresAt
          }
        }
      },
      { new: true }
    );

    await logActivity(req.user._id, null, 'create_api_key', 'user', req.user._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({
      status: 'success',
      data: {
        apiKey,
        apiSecret,
        expiresAt
      }
    });
  } catch (err) {
    logger.error('Error creating API key:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Admin Endpoints
app.post('/api/admin/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Please provide email and password' });
    }

    const admin = await Admin.findOne({ email }).select('+password');
    if (!admin || !await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ status: 'error', message: 'Incorrect email or password' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    await logActivity(null, admin._id, 'admin_login', 'admin', admin._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    createAndSendToken(admin, 200, res, true);
  } catch (err) {
    logger.error('Admin login error:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/admin/auth/logout', authenticateAdmin, async (req, res) => {
  try {
    res.cookie('jwtAdmin', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    await logActivity(null, req.admin._id, 'admin_logout', 'admin', req.admin._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({ status: 'success', message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Admin logout error:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      newUsersToday,
      totalDeposits,
      totalWithdrawals,
      pendingWithdrawals,
      pendingKyc,
      activeInvestments
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
      User.countDocuments({ 'kyc.status': 'pending' }),
      Investment.countDocuments({ status: 'active' })
    ]);

    const dashboardStats = {
      totalUsers,
      activeUsers,
      newUsersToday,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      pendingWithdrawals,
      pendingKyc,
      activeInvestments
    };

    await logActivity(null, req.admin._id, 'view_dashboard', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: dashboardStats
    });
  } catch (err) {
    logger.error('Error fetching admin dashboard:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/users/growth', authenticateAdmin, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
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

    await logActivity(null, req.admin._id, 'view_user_growth', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: userGrowth
    });
  } catch (err) {
    logger.error('Error fetching user growth data:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/activity', authenticateAdmin, async (req, res) => {
  try {
    const activities = await SystemActivity.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('userId', 'email firstName lastName')
      .populate('adminId', 'email firstName lastName');

    await logActivity(null, req.admin._id, 'view_activity_log', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    logger.error('Error fetching system activity:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, status } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) {
      query.status = status;
    }

    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -twoFactorAuth.secret -apiKeys -devices')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 }),
      User.countDocuments(query)
    ]);

    await logActivity(null, req.admin._id, 'view_users', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      search,
      status
    });

    res.status(200).json({
      status: 'success',
      data: {
        users,
        total,
        page: Number(page),
        limit: Number(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    logger.error('Error fetching users:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.route('/api/admin/users/:id')
  .get(authenticateAdmin, async (req, res) => {
    try {
      const user = await User.findById(req.params.id)
        .select('-password -twoFactorAuth.secret -apiKeys -devices');
      
      if (!user) {
        return res.status(404).json({ status: 'error', message: 'User not found' });
      }

      await logActivity(null, req.admin._id, 'view_user', 'user', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(200).json({
        status: 'success',
        data: {
          user
        }
      });
    } catch (err) {
      logger.error('Error fetching user:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  })
  .put(authenticateAdmin, async (req, res) => {
    try {
      const { firstName, lastName, email, phone, country, status, balance } = req.body;
      
      const updateData = { firstName, lastName, email, phone, country };
      if (status) updateData.status = status;
      if (balance) updateData.balance = balance;

      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true, runValidators: true }
      ).select('-password -twoFactorAuth.secret -apiKeys -devices');

      if (!updatedUser) {
        return res.status(404).json({ status: 'error', message: 'User not found' });
      }

      await logActivity(null, req.admin._id, 'update_user', 'user', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        changes: req.body
      });

      res.status(200).json({
        status: 'success',
        data: {
          user: updatedUser
        }
      });
    } catch (err) {
      logger.error('Error updating user:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  })
  .delete(authenticateAdmin, async (req, res) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      
      if (!user) {
        return res.status(404).json({ status: 'error', message: 'User not found' });
      }

      await logActivity(null, req.admin._id, 'delete_user', 'user', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(204).json({
        status: 'success',
        data: null
      });
    } catch (err) {
      logger.error('Error deleting user:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  });

app.put('/api/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({ status: 'error', message: 'Invalid status value' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select('-password -twoFactorAuth.secret -apiKeys -devices');

    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    await logActivity(null, req.admin._id, 'update_user_status', 'user', req.params.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      status
    });

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    logger.error('Error updating user status:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/kyc/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingKyc = await User.find({ 'kyc.status': 'pending' })
      .select('firstName lastName email kyc.submittedAt')
      .sort({ 'kyc.submittedAt': 1 });

    await logActivity(null, req.admin._id, 'view_pending_kyc', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: pendingKyc
    });
  } catch (err) {
    logger.error('Error fetching pending KYC:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('firstName lastName email kyc');
    
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    if (user.kyc.status !== 'pending') {
      return res.status(400).json({ status: 'error', message: 'No pending KYC for this user' });
    }

    await logActivity(null, req.admin._id, 'view_kyc_details', 'user', req.params.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          kyc: user.kyc
        }
      }
    });
  } catch (err) {
    logger.error('Error fetching KYC details:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/admin/kyc/:id/review', authenticateAdmin, async (req, res) => {
  try {
    const { status, reason } = req.body;
    
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ status: 'error', message: 'Invalid status value' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      {
        'kyc.status': status,
        'kyc.reviewedAt': new Date(),
        'kyc.reviewedBy': req.admin._id,
        ...(status === 'rejected' && { 'kyc.rejectionReason': reason })
      },
      { new: true }
    ).select('firstName lastName email kyc');

    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Send email notification to user
    try {
      await transporter.sendMail({
        from: 'noreply@bithash.com',
        to: user.email,
        subject: `Your KYC verification has been ${status}`,
        text: `Dear ${user.firstName},\n\nYour KYC verification has been ${status}${status === 'rejected' ? ` for the following reason: ${reason}` : ''}.\n\nThank you,\nBitHash Team`
      });
    } catch (emailErr) {
      logger.error('Error sending KYC status email:', emailErr);
    }

    await logActivity(null, req.admin._id, 'review_kyc', 'user', req.params.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      status,
      reason
    });

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    logger.error('Error reviewing KYC:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/withdrawals/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingWithdrawals = await Transaction.find({ type: 'withdrawal', status: 'pending' })
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: 1 });

    await logActivity(null, req.admin._id, 'view_pending_withdrawals', 'admin', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: pendingWithdrawals
    });
  } catch (err) {
    logger.error('Error fetching pending withdrawals:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/admin/withdrawals/:id', authenticateAdmin, async (req, res) => {
  try {
    const withdrawal = await Transaction.findOne({
      _id: req.params.id,
      type: 'withdrawal'
    }).populate('userId', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({ status: 'error', message: 'Withdrawal not found' });
    }

    await logActivity(null, req.admin._id, 'view_withdrawal', 'transaction', req.params.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    logger.error('Error fetching withdrawal:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/admin/withdrawals/:id/process', authenticateAdmin, async (req, res) => {
  try {
    const { status, txHash, adminNote } = req.body;
    
    if (!['completed', 'failed', 'cancelled'].includes(status)) {
      return res.status(400).json({ status: 'error', message: 'Invalid status value' });
    }

    const withdrawal = await Transaction.findOneAndUpdate(
      {
        _id: req.params.id,
        type: 'withdrawal',
        status: 'pending'
      },
      {
        status,
        txHash,
        metadata: { ...req.body.metadata, adminNote, processedBy: req.admin._id }
      },
      { new: true }
    ).populate('userId', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({ status: 'error', message: 'Pending withdrawal not found' });
    }

    // If rejected, return funds to user's balance
    if (status !== 'completed') {
      await User.findByIdAndUpdate(
        withdrawal.userId,
        { $inc: { 'balance.main': withdrawal.amount } }
      );
    }

    // Send email notification to user
    try {
      const user = await User.findById(withdrawal.userId);
      if (user) {
        await transporter.sendMail({
          from: 'noreply@bithash.com',
          to: user.email,
          subject: `Your withdrawal has been ${status}`,
          text: `Dear ${user.firstName},\n\nYour withdrawal of ${withdrawal.amount} BTC has been ${status}${adminNote ? ` with the following note: ${adminNote}` : ''}.\n\nThank you,\nBitHash Team`
        });
      }
    } catch (emailErr) {
      logger.error('Error sending withdrawal status email:', emailErr);
    }

    await logActivity(null, req.admin._id, 'process_withdrawal', 'transaction', req.params.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      status,
      txHash
    });

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    logger.error('Error processing withdrawal:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/admin/withdrawals/process-batch', authenticateAdmin, async (req, res) => {
  try {
    const { withdrawalIds, status, txHash, adminNote } = req.body;
    
    if (!['completed', 'failed', 'cancelled'].includes(status)) {
      return res.status(400).json({ status: 'error', message: 'Invalid status value' });
    }

    const withdrawals = await Transaction.updateMany(
      {
        _id: { $in: withdrawalIds },
        type: 'withdrawal',
        status: 'pending'
      },
      {
        status,
        txHash,
        metadata: { ...req.body.metadata, adminNote, processedBy: req.admin._id }
      }
    );

    if (withdrawals.nModified === 0) {
      return res.status(404).json({ status: 'error', message: 'No pending withdrawals found' });
    }

    // If rejected, return funds to users' balances
    if (status !== 'completed') {
      const withdrawalDocs = await Transaction.find({ _id: { $in: withdrawalIds } });
      const bulkOps = withdrawalDocs.map(wd => ({
        updateOne: {
          filter: { _id: wd.userId },
          update: { $inc: { 'balance.main': wd.amount } }
        }
      }));
      
      await User.bulkWrite(bulkOps);
    }

    await logActivity(null, req.admin._id, 'process_batch_withdrawals', 'transaction', null, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      count: withdrawals.nModified,
      status,
      txHash
    });

    res.status(200).json({
      status: 'success',
      data: {
        processedCount: withdrawals.nModified
      }
    });
  } catch (err) {
    logger.error('Error processing batch withdrawals:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.route('/api/admin/loans')
  .get(authenticateAdmin, async (req, res) => {
    try {
      const { status } = req.query;
      let query = {};
      if (status) query.status = status;

      const loans = await Loan.find(query)
        .populate('userId', 'firstName lastName email')
        .populate('approvedBy', 'firstName lastName')
        .sort({ createdAt: -1 });

      await logActivity(null, req.admin._id, 'view_loans', 'admin', null, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        status
      });

      res.status(200).json({
        status: 'success',
        data: loans
      });
    } catch (err) {
      logger.error('Error fetching loans:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  })
  .post(authenticateAdmin, async (req, res) => {
    try {
      const { userId, amount, collateralAmount, interestRate, duration } = req.body;
      
      const loan = await Loan.create({
        userId,
        amount,
        collateralAmount,
        interestRate,
        duration,
        status: 'approved',
        approvedBy: req.admin._id,
        approvedAt: new Date(),
        startDate: new Date(),
        endDate: new Date(new Date().setDate(new Date().getDate() + duration))
      });

      await logActivity(null, req.admin._id, 'create_loan', 'loan', loan._id, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: req.body
      });

      res.status(201).json({
        status: 'success',
        data: loan
      });
    } catch (err) {
      logger.error('Error creating loan:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  });

app.route('/api/admin/loans/:id')
  .get(authenticateAdmin, async (req, res) => {
    try {
      const loan = await Loan.findById(req.params.id)
        .populate('userId', 'firstName lastName email')
        .populate('approvedBy', 'firstName lastName')
        .populate('payments.txId', 'amount createdAt');

      if (!loan) {
        return res.status(404).json({ status: 'error', message: 'Loan not found' });
      }

      await logActivity(null, req.admin._id, 'view_loan', 'loan', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(200).json({
        status: 'success',
        data: loan
      });
    } catch (err) {
      logger.error('Error fetching loan:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  })
  .put(authenticateAdmin, async (req, res) => {
    try {
      const { status } = req.body;
      
      if (!['approved', 'rejected', 'active', 'defaulted', 'completed'].includes(status)) {
        return res.status(400).json({ status: 'error', message: 'Invalid status value' });
      }

      const updateData = { status };
      if (status === 'approved') {
        updateData.approvedBy = req.admin._id;
        updateData.approvedAt = new Date();
        updateData.startDate = new Date();
        updateData.endDate = new Date(new Date().setDate(new Date().getDate() + req.body.duration));
      }

      const loan = await Loan.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true }
      );

      if (!loan) {
        return res.status(404).json({ status: 'error', message: 'Loan not found' });
      }

      await logActivity(null, req.admin._id, 'update_loan', 'loan', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        status
      });

      res.status(200).json({
        status: 'success',
        data: loan
      });
    } catch (err) {
      logger.error('Error updating loan:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  })
  .delete(authenticateAdmin, async (req, res) => {
    try {
      const loan = await Loan.findByIdAndDelete(req.params.id);
      
      if (!loan) {
        return res.status(404).json({ status: 'error', message: 'Loan not found' });
      }

      await logActivity(null, req.admin._id, 'delete_loan', 'loan', req.params.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(204).json({
        status: 'success',
        data: null
      });
    } catch (err) {
      logger.error('Error deleting loan:', err);
      res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
  });

app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin._id).select('-password -twoFactorAuth.secret');
    
    res.status(200).json({
      status: 'success',
      data: admin
    });
  } catch (err) {
    logger.error('Error fetching admin profile:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Dashboard Endpoints
app.get('/api/plans', authenticateUser, async (req, res) => {
  try {
    const plans = await Plan.find({ status: 'active' }).sort({ minAmount: 1 });

    res.status(200).json({
      status: 'success',
      data: plans
    });
  } catch (err) {
    logger.error('Error fetching investment plans:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/transactions', authenticateUser, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    const skip = (page - 1) * limit;

    let query = { userId: req.user._id };
    if (type) query.type = type;

    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Transaction.countDocuments(query)
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        total,
        page: Number(page),
        limit: Number(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    logger.error('Error fetching transactions:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/api/mining/stats', authenticateUser, async (req, res) => {
  try {
    const [activeInvestments, completedInvestments, totalInvested, totalEarned] = await Promise.all([
      Investment.countDocuments({ userId: req.user._id, status: 'active' }),
      Investment.countDocuments({ userId: req.user._id, status: 'completed' }),
      Investment.aggregate([
        { $match: { userId: req.user._id } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Investment.aggregate([
        { $match: { userId: req.user._id } },
        { $group: { _id: null, total: { $sum: '$actualProfit' } } }
      ])
    ]);

    const miningStats = {
      activeInvestments: activeInvestments,
      completedInvestments: completedInvestments,
      totalInvested: totalInvested[0]?.total || 0,
      totalEarned: totalEarned[0]?.total || 0
    };

    res.status(200).json({
      status: 'success',
      data: miningStats
    });
  } catch (err) {
    logger.error('Error fetching mining stats:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/transactions/deposit', authenticateUser, async (req, res) => {
  try {
    const { amount, currency = 'BTC', method } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Invalid amount' });
    }

    const deposit = await Transaction.create({
      userId: req.user._id,
      type: 'deposit',
      amount,
      currency,
      status: 'pending',
      address: BTC_DEPOSIT_ADDRESS,
      metadata: { method }
    });

    await logActivity(req.user._id, null, 'create_deposit', 'transaction', deposit._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      amount,
      currency,
      method
    });

    res.status(201).json({
      status: 'success',
      data: deposit
    });
  } catch (err) {
    logger.error('Error creating deposit:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/transactions/withdraw', authenticateUser, async (req, res) => {
  try {
    const { amount, address, currency = 'BTC', method } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Invalid amount' });
    }

    if (!address) {
      return res.status(400).json({ status: 'error', message: 'Address is required' });
    }

    if (req.user.balance.main < amount) {
      return res.status(400).json({ status: 'error', message: 'Insufficient balance' });
    }

    // Deduct from user balance immediately
    await User.findByIdAndUpdate(
      req.user._id,
      { $inc: { 'balance.main': -amount } }
    );

    const withdrawal = await Transaction.create({
      userId: req.user._id,
      type: 'withdrawal',
      amount,
      currency,
      status: 'pending',
      address,
      metadata: { method }
    });

    await logActivity(req.user._id, null, 'create_withdrawal', 'transaction', withdrawal._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      amount,
      currency,
      method,
      address
    });

    res.status(201).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    logger.error('Error creating withdrawal:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/investments', authenticateUser, async (req, res) => {
  try {
    const { planId, amount } = req.body;
    
    if (!planId || !amount) {
      return res.status(400).json({ status: 'error', message: 'Plan ID and amount are required' });
    }

    const plan = await Plan.findById(planId);
    if (!plan || plan.status !== 'active') {
      return res.status(400).json({ status: 'error', message: 'Invalid investment plan' });
    }

    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({ 
        status: 'error', 
        message: `Amount must be between ${plan.minAmount} and ${plan.maxAmount}` 
      });
    }

    if (req.user.balance.main < amount) {
      return res.status(400).json({ status: 'error', message: 'Insufficient balance' });
    }

    // Deduct from main balance and add to active balance
    await User.findByIdAndUpdate(
      req.user._id,
      { 
        $inc: { 
          'balance.main': -amount,
          'balance.active': amount
        }
      }
    );

    const endDate = new Date();
    endDate.setHours(endDate.getHours() + plan.duration);

    const investment = await Investment.create({
      userId: req.user._id,
      planId,
      amount,
      status: 'active',
      startDate: new Date(),
      endDate,
      expectedProfit: amount * (plan.profitPercentage / 100)
    });

    await logActivity(req.user._id, null, 'create_investment', 'investment', investment._id, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      planId,
      amount
    });

    res.status(201).json({
      status: 'success',
      data: investment
    });
  } catch (err) {
    logger.error('Error creating investment:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/transactions/transfer', authenticateUser, async (req, res) => {
  try {
    const { amount, recipientEmail } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Invalid amount' });
    }

    if (!recipientEmail) {
      return res.status(400).json({ status: 'error', message: 'Recipient email is required' });
    }

    if (req.user.balance.main < amount) {
      return res.status(400).json({ status: 'error', message: 'Insufficient balance' });
    }

    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({ status: 'error', message: 'Recipient not found' });
    }

    if (recipient._id.equals(req.user._id)) {
      return res.status(400).json({ status: 'error', message: 'Cannot transfer to yourself' });
    }

    // Perform transfer as a transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from sender
      await User.findByIdAndUpdate(
        req.user._id,
        { $inc: { 'balance.main': -amount } },
        { session }
      );

      // Add to recipient
      await User.findByIdAndUpdate(
        recipient._id,
        { $inc: { 'balance.main': amount } },
        { session }
      );

      // Create transfer records
      const transferOut = await Transaction.create([{
        userId: req.user._id,
        type: 'transfer',
        amount,
        status: 'completed',
        metadata: {
          direction: 'out',
          recipient: recipient._id,
          recipientEmail
        }
      }], { session });

      const transferIn = await Transaction.create([{
        userId: recipient._id,
        type: 'transfer',
        amount,
        status: 'completed',
        metadata: {
          direction: 'in',
          sender: req.user._id,
          senderEmail: req.user.email
        }
      }], { session });

      await session.commitTransaction();
      session.endSession();

      await logActivity(req.user._id, null, 'transfer_out', 'transaction', transferOut[0]._id, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        amount,
        recipient: recipient._id,
        recipientEmail
      });

      await logActivity(recipient._id, null, 'transfer_in', 'transaction', transferIn[0]._id, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        amount,
        sender: req.user._id,
        senderEmail: req.user.email
      });

      res.status(201).json({
        status: 'success',
        data: transferOut[0]
      });
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      throw err;
    }
  } catch (err) {
    logger.error('Error processing transfer:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ status: 'error', message: 'Internal server error' });
});

// 404 handler
app.all('*', (req, res) => {
  res.status(404).json({ status: 'error', message: `${req.originalUrl} not found` });
});

// Process investment completions
async function processInvestmentCompletions() {
  try {
    const now = new Date();
    const completedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    });

    if (completedInvestments.length > 0) {
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const bulkOps = [];
        const transactionInserts = [];

        for (const investment of completedInvestments) {
          const plan = await Plan.findById(investment.planId);
          const profit = investment.amount * (plan.profitPercentage / 100);

          bulkOps.push({
            updateOne: {
              filter: { _id: investment.userId },
              update: {
                $inc: {
                  'balance.active': -investment.amount,
                  'balance.matured': investment.amount + profit
                }
              }
            }
          });

          transactionInserts.push({
            userId: investment.userId,
            type: 'interest',
            amount: profit,
            status: 'completed',
            metadata: {
              investmentId: investment._id,
              planId: plan._id,
              planName: plan.name
            }
          });
        }

        await User.bulkWrite(bulkOps, { session });
        await Transaction.insertMany(transactionInserts, { session });
        await Investment.updateMany(
          { _id: { $in: completedInvestments.map(i => i._id) } },
          { status: 'completed', actualProfit: { $multiply: ['$amount', { $divide: ['$expectedProfit', '$amount'] }] } },
          { session }
        );

        await session.commitTransaction();
        session.endSession();

        logger.info(`Processed ${completedInvestments.length} investment completions`);
      } catch (err) {
        await session.abortTransaction();
        session.endSession();
        throw err;
      }
    }
  } catch (err) {
    logger.error('Error processing investment completions:', err);
  }
}

// Initialize the system
async function initializeSystem() {
  await initializeDefaultAdmin();
  await initializePlans();
  
  // Start investment processing job (runs every hour)
  setInterval(processInvestmentCompletions, 60 * 60 * 1000);
  
  const PORT = process.env.PORT || 3000;
  httpServer.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
}

initializeSystem();
