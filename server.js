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
const WebSocket = require('ws');
const moment = require('moment');
const axios = require('axios');

// Initialize Express app
const app = express();

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  serverSelectionTimeoutMS: 50000,
  maxPoolSize: 100
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  connectTimeout: 10000,
  maxRetriesPerRequest: 5
});

redis.on('connect', () => {
  console.log('Connected to Redis');
});

redis.on('error', (err) => {
  console.error('Redis connection error:', err);
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://bithhash.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(limiter);

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';

// Models
const User = require('./models/User');
const Admin = require('./models/Admin');
const Transaction = require('./models/Transaction');
const Investment = require('./models/Investment');
const Plan = require('./models/Plan');
const KYCDocument = require('./models/KYCDocument');
const Withdrawal = require('./models/Withdrawal');
const Loan = require('./models/Loan');
const ActivityLog = require('./models/ActivityLog');
const ApiKey = require('./models/ApiKey');
const Device = require('./models/Device');
const Notification = require('./models/Notification');

// Utility functions
const generateApiKey = () => crypto.randomBytes(32).toString('hex');
const generateSecurePassword = () => crypto.randomBytes(16).toString('hex');
const calculateInvestmentReturns = (amount, plan) => {
  // Implementation based on plan details
  return amount * (1 + plan.dailyInterest / 100) ** plan.duration;
};

// WebSocket server
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  
  ws.on('message', (message) => {
    console.log('Received:', message);
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

// Attach WebSocket to Express server
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error'
  });
});

// Authentication middleware
const authenticateUser = async (req, res, next) => {
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
    const currentUser = await User.findById(decoded.id).select('+active +lastPasswordChange');

    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
      });
    }

    if (!currentUser.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated. Please contact support.'
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

const authenticateAdmin = async (req, res, next) => {
  try {
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
    const currentAdmin = await Admin.findById(decoded.id).select('+active +lastPasswordChange');

    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    if (currentAdmin.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'Admin recently changed password! Please log in again.'
      });
    }

    if (!currentAdmin.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your admin account has been deactivated.'
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
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

// Log activity middleware
const logActivity = async (userId, action, details) => {
  await ActivityLog.create({
    user: userId,
    action,
    details,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
};

// Initialize default admin
const initializeDefaultAdmin = async () => {
  const adminCount = await Admin.countDocuments();
  if (adminCount === 0) {
    const defaultAdmin = new Admin({
      name: 'Super Admin',
      email: 'admin@bithash.com',
      password: 'Admin@1234',
      role: 'super-admin',
      active: true
    });
    await defaultAdmin.save();
    console.log('Default admin created:', defaultAdmin.email);
  }
};

initializeDefaultAdmin();

// USER ENDPOINTS

// Get current user
app.get('/api/users/me', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -__v')
      .populate('investments')
      .populate('devices')
      .populate('notifications');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Update user profile
app.put('/api/users/profile', authenticateUser, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, country } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { firstName, lastName, email, phone, country },
      { new: true, runValidators: true }
    ).select('-password -__v');

    await logActivity(req.user.id, 'PROFILE_UPDATE', 'Updated profile information');

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Update user address
app.put('/api/users/address', authenticateUser, async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { address: { street, city, state, postalCode, country } },
      { new: true, runValidators: true }
    ).select('-password -__v');

    await logActivity(req.user.id, 'ADDRESS_UPDATE', 'Updated address information');

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Update user password
app.put('/api/users/password', authenticateUser, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    user.password = newPassword;
    await user.save();
    
    await logActivity(req.user.id, 'PASSWORD_CHANGE', 'Changed account password');

    res.status(200).json({
      status: 'success',
      message: 'Password updated successfully'
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Create API key
app.post('/api/users/api-keys', authenticateUser, async (req, res) => {
  try {
    const { name, permissions, expiresAt } = req.body;
    
    const apiKey = new ApiKey({
      user: req.user.id,
      name,
      key: generateApiKey(),
      permissions,
      expiresAt: expiresAt ? new Date(expiresAt) : null
    });
    
    await apiKey.save();
    
    await logActivity(req.user.id, 'API_KEY_CREATE', `Created API key: ${name}`);

    res.status(201).json({
      status: 'success',
      data: {
        apiKey
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// ADMIN ENDPOINTS

// Admin login
app.post('/api/admin/auth/login', async (req, res) => {
  try {
    const { email, password, twoFACode } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
    const admin = await Admin.findOne({ email }).select('+password +twoFASecret');
    
    if (!admin || !(await admin.correctPassword(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    if (admin.twoFAEnabled && !twoFACode) {
      return res.status(401).json({
        status: 'fail',
        message: '2FA code required'
      });
    }
    
    if (admin.twoFAEnabled && twoFACode) {
      // Verify 2FA code here
      // Implementation depends on your 2FA method (TOTP, SMS, etc.)
    }
    
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });
    
    res.cookie('jwtAdmin', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    admin.lastLogin = new Date();
    await admin.save();
    
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
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Admin logout
app.post('/api/admin/auth/logout', authenticateAdmin, (req, res) => {
  res.cookie('jwtAdmin', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

// Get admin dashboard stats
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const newUsersCount = await User.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    const transactionsCount = await Transaction.countDocuments();
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          usersCount,
          activeUsersCount,
          newUsersCount,
          transactionsCount,
          totalDeposits: totalDeposits[0]?.total || 0,
          totalWithdrawals: totalWithdrawals[0]?.total || 0
        }
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get user growth data
app.get('/api/admin/users/growth', authenticateAdmin, async (req, res) => {
  try {
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
      data: {
        growthData
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get recent activity
app.get('/api/admin/activity', authenticateAdmin, async (req, res) => {
  try {
    const activities = await ActivityLog.find()
      .sort('-createdAt')
      .limit(50)
      .populate('user', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: {
        activities
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get all users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const users = await User.find()
      .select('-password -__v')
      .skip(skip)
      .limit(limit)
      .sort('-createdAt');
    
    const total = await User.countDocuments();
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get single user
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -__v')
      .populate('investments')
      .populate('transactions')
      .populate('devices');
    
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
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Update user
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    }).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    await logActivity(req.admin._id, 'USER_UPDATE', `Updated user ${user.email}`);
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    await logActivity(req.admin._id, 'USER_DELETE', `Deleted user ${user.email}`);
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Update user status
app.put('/api/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active: status === 'active' },
      { new: true }
    ).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    await logActivity(
      req.admin._id,
      'USER_STATUS_CHANGE',
      `Changed status of user ${user.email} to ${status}`
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get pending KYC documents
app.get('/api/admin/kyc/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingKYCs = await KYCDocument.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort('-submittedAt');
    
    res.status(200).json({
      status: 'success',
      data: {
        documents: pendingKYCs
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get KYC document by ID
app.get('/api/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const kycDoc = await KYCDocument.findById(req.params.id)
      .populate('user', 'firstName lastName email');
    
    if (!kycDoc) {
      return res.status(404).json({
        status: 'fail',
        message: 'No KYC document found with that ID'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        document: kycDoc
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Review KYC document
app.post('/api/admin/kyc/:id/review', authenticateAdmin, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    const kycDoc = await KYCDocument.findByIdAndUpdate(
      req.params.id,
      { 
        status,
        reviewedBy: req.admin._id,
        reviewedAt: new Date(),
        rejectionReason: status === 'rejected' ? rejectionReason : undefined
      },
      { new: true }
    ).populate('user', 'firstName lastName email');
    
    if (!kycDoc) {
      return res.status(404).json({
        status: 'fail',
        message: 'No KYC document found with that ID'
      });
    }
    
    // Update user verification status if approved
    if (status === 'approved') {
      await User.findByIdAndUpdate(kycDoc.user._id, {
        isVerified: true,
        verificationLevel: 'full'
      });
      
      // Send verification email
      const mailOptions = {
        from: 'support@bithash.com',
        to: kycDoc.user.email,
        subject: 'KYC Verification Approved',
        text: `Dear ${kycDoc.user.firstName},\n\nYour KYC verification has been approved. You now have full access to all platform features.\n\nThank you,\nBitHash Team`
      };
      
      await transporter.sendMail(mailOptions);
    }
    
    await logActivity(
      req.admin._id,
      'KYC_REVIEW',
      `Reviewed KYC for ${kycDoc.user.email} with status ${status}`
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        document: kycDoc
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get pending withdrawals
app.get('/api/admin/withdrawals/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: pendingWithdrawals
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get withdrawal by ID
app.get('/api/admin/withdrawals/:id', authenticateAdmin, async (req, res) => {
  try {
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
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Process withdrawal
app.post('/api/admin/withdrawals/:id/process', authenticateAdmin, async (req, res) => {
  try {
    const { status, transactionHash, adminNote } = req.body;
    
    const withdrawal = await Withdrawal.findByIdAndUpdate(
      req.params.id,
      { 
        status,
        processedBy: req.admin._id,
        processedAt: new Date(),
        transactionHash,
        adminNote
      },
      { new: true }
    ).populate('user', 'firstName lastName email');
    
    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'No withdrawal found with that ID'
      });
    }
    
    // Update user balance if rejected
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.user._id, {
        $inc: { balance: withdrawal.amount }
      });
    }
    
    // Send notification email
    const mailOptions = {
      from: 'support@bithash.com',
      to: withdrawal.user.email,
      subject: `Withdrawal ${status}`,
      text: `Dear ${withdrawal.user.firstName},\n\nYour withdrawal request of ${withdrawal.amount} ${withdrawal.currency} has been ${status}.\n\n${status === 'completed' ? `Transaction hash: ${transactionHash}` : adminNote ? `Reason: ${adminNote}` : ''}\n\nThank you,\nBitHash Team`
    };
    
    await transporter.sendMail(mailOptions);
    
    await logActivity(
      req.admin._id,
      'WITHDRAWAL_PROCESS',
      `Processed withdrawal for ${withdrawal.user.email} with status ${status}`
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawal
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', authenticateAdmin, async (req, res) => {
  try {
    const { withdrawalIds, status, transactionHashes } = req.body;
    
    if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide withdrawal IDs to process'
      });
    }
    
    const processedWithdrawals = [];
    
    for (let i = 0; i < withdrawalIds.length; i++) {
      const withdrawal = await Withdrawal.findByIdAndUpdate(
        withdrawalIds[i],
        { 
          status,
          processedBy: req.admin._id,
          processedAt: new Date(),
          transactionHash: transactionHashes?.[i] || undefined
        },
        { new: true }
      ).populate('user', 'firstName lastName email');
      
      if (withdrawal) {
        processedWithdrawals.push(withdrawal);
        
        // Update user balance if rejected
        if (status === 'rejected') {
          await User.findByIdAndUpdate(withdrawal.user._id, {
            $inc: { balance: withdrawal.amount }
          });
        }
        
        // Send notification email
        const mailOptions = {
          from: 'support@bithash.com',
          to: withdrawal.user.email,
          subject: `Withdrawal ${status}`,
          text: `Dear ${withdrawal.user.firstName},\n\nYour withdrawal request of ${withdrawal.amount} ${withdrawal.currency} has been ${status}.\n\n${status === 'completed' && transactionHashes?.[i] ? `Transaction hash: ${transactionHashes[i]}` : ''}\n\nThank you,\nBitHash Team`
        };
        
        await transporter.sendMail(mailOptions);
      }
    }
    
    await logActivity(
      req.admin._id,
      'WITHDRAWAL_BATCH_PROCESS',
      `Processed ${processedWithdrawals.length} withdrawals with status ${status}`
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: processedWithdrawals
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get all loans
app.get('/api/admin/loans', authenticateAdmin, async (req, res) => {
  try {
    const loans = await Loan.find()
      .populate('user', 'firstName lastName email')
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      data: {
        loans
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Create loan
app.post('/api/admin/loans', authenticateAdmin, async (req, res) => {
  try {
    const { userId, amount, collateralAmount, interestRate, duration, currency } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    const loan = new Loan({
      user: userId,
      amount,
      collateralAmount,
      interestRate,
      duration,
      currency,
      status: 'active',
      approvedBy: req.admin._id
    });
    
    await loan.save();
    
    // Update user balance
    await User.findByIdAndUpdate(userId, {
      $inc: { balance: amount }
    });
    
    await logActivity(
      req.admin._id,
      'LOAN_CREATE',
      `Created loan for ${user.email} of ${amount} ${currency}`
    );
    
    res.status(201).json({
      status: 'success',
      data: {
        loan
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get loan by ID
app.get('/api/admin/loans/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'name email');
    
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
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Update loan
app.put('/api/admin/loans/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await Loan.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    }).populate('user', 'firstName lastName email');
    
    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }
    
    await logActivity(
      req.admin._id,
      'LOAN_UPDATE',
      `Updated loan ${loan._id} for ${loan.user.email}`
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        loan
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Delete loan
app.delete('/api/admin/loans/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);
    
    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }
    
    await logActivity(
      req.admin._id,
      'LOAN_DELETE',
      `Deleted loan ${loan._id}`
    );
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get admin profile
app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin._id).select('-password -__v');
    
    res.status(200).json({
      status: 'success',
      data: {
        admin
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// DASHBOARD ENDPOINTS

// Get investment plans
app.get('/api/plans', authenticateUser, async (req, res) => {
  try {
    const plans = await Plan.find({ active: true }).sort('minAmount');
    
    res.status(200).json({
      status: 'success',
      data: {
        plans
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get user transactions
app.get('/api/transactions', authenticateUser, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ user: req.user.id })
      .skip(skip)
      .limit(limit)
      .sort('-createdAt');
    
    const total = await Transaction.countDocuments({ user: req.user.id });
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Get mining stats
app.get('/api/mining/stats', authenticateUser, async (req, res) => {
  try {
    const miningStats = {
      hashrate: 125.4,
      shares: 2456,
      lastShareTime: new Date(),
      activeWorkers: 3,
      estimatedDailyEarnings: 0.0054
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        stats: miningStats
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Create deposit
app.post('/api/transactions/deposit', authenticateUser, async (req, res) => {
  try {
    const { amount, currency, method } = req.body;
    
    const transaction = new Transaction({
      user: req.user.id,
      type: 'deposit',
      amount,
      currency,
      method,
      status: method === 'crypto' ? 'pending' : 'processing',
      address: method === 'crypto' ? 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k' : null
    });
    
    await transaction.save();
    
    await logActivity(
      req.user.id,
      'DEPOSIT_CREATE',
      `Created deposit of ${amount} ${currency} via ${method}`
    );
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Create withdrawal
app.post('/api/transactions/withdraw', authenticateUser, async (req, res) => {
  try {
    const { amount, currency, address, method } = req.body;
    
    // Check user balance
    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Check if user is verified for large withdrawals
    if (amount > 1000 && !user.isVerified) {
      return res.status(400).json({
        status: 'fail',
        message: 'KYC verification required for withdrawals over 1000 USD'
      });
    }
    
    // Deduct from user balance
    user.balance -= amount;
    await user.save();
    
    const withdrawal = new Withdrawal({
      user: req.user.id,
      amount,
      currency,
      address,
      method,
      status: 'pending'
    });
    
    await withdrawal.save();
    
    await logActivity(
      req.user.id,
      'WITHDRAWAL_CREATE',
      `Created withdrawal of ${amount} ${currency} to ${address}`
    );
    
    res.status(201).json({
      status: 'success',
      data: {
        withdrawal
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Create investment
app.post('/api/investments', authenticateUser, async (req, res) => {
  try {
    const { planId, amount } = req.body;
    
    // Check user balance
    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Get plan
    const plan = await Plan.findById(planId);
    if (!plan || !plan.active) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found or inactive'
      });
    }
    
    // Check minimum amount
    if (amount < plan.minAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Minimum investment amount is ${plan.minAmount}`
      });
    }
    
    // Deduct from user balance
    user.balance -= amount;
    await user.save();
    
    // Create investment
    const investment = new Investment({
      user: req.user.id,
      plan: planId,
      amount,
      expectedReturn: calculateInvestmentReturns(amount, plan),
      status: 'active'
    });
    
    await investment.save();
    
    // Create transaction record
    const transaction = new Transaction({
      user: req.user.id,
      type: 'investment',
      amount,
      currency: 'USD',
      status: 'completed',
      reference: `Investment in ${plan.name}`
    });
    
    await transaction.save();
    
    await logActivity(
      req.user.id,
      'INVESTMENT_CREATE',
      `Created investment in ${plan.name} with ${amount} USD`
    );
    
    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Transfer funds
app.post('/api/transactions/transfer', authenticateUser, async (req, res) => {
  try {
    const { recipientEmail, amount, currency } = req.body;
    
    // Check user balance
    const sender = await User.findById(req.user.id);
    if (sender.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Find recipient
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({
        status: 'fail',
        message: 'Recipient not found'
      });
    }
    
    // Deduct from sender and add to recipient
    sender.balance -= amount;
    recipient.balance += amount;
    
    await sender.save();
    await recipient.save();
    
    // Create transactions for both parties
    const senderTransaction = new Transaction({
      user: req.user.id,
      type: 'transfer',
      amount: -amount,
      currency,
      status: 'completed',
      reference: `Transfer to ${recipientEmail}`
    });
    
    const recipientTransaction = new Transaction({
      user: recipient._id,
      type: 'transfer',
      amount,
      currency,
      status: 'completed',
      reference: `Transfer from ${sender.email}`
    });
    
    await senderTransaction.save();
    await recipientTransaction.save();
    
    await logActivity(
      req.user.id,
      'TRANSFER_CREATE',
      `Transferred ${amount} ${currency} to ${recipientEmail}`
    );
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction: senderTransaction
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Handle 404
app.all('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Export the app for testing
module.exports = app;
