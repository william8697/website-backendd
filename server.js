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
const https = require('https');
const fs = require('fs');
const path = require('path');

// Initialize Express app
const app = express();

// Enable trust proxy for rate limiting behind reverse proxy
app.set('trust proxy', 1);

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
app.use('/api/', limiter);

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
  useCreateIndex: true,
  useFindAndModify: false
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

// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

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
const logActivity = async (userId, action, details) => {
  await ActivityLog.create({ user: userId, action, details });
};

// Default BTC deposit address
const DEFAULT_BTC_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// WebSocket server for real-time updates
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    // Handle WebSocket messages
    console.log('Received WebSocket message:', message);
  });
});

// Create HTTPS server
const server = https.createServer({
  key: fs.readFileSync(path.join(__dirname, 'ssl', 'private.key')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.crt'))
}, app);

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Middleware to protect routes
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      status: 'error',
      message: 'You are not logged in! Please log in to get access.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id).select('+active +lastActivity');

    if (!currentUser) {
      return res.status(401).json({
        status: 'error',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (!currentUser.active) {
      return res.status(401).json({
        status: 'error',
        message: 'Your account has been deactivated. Please contact support.'
      });
    }

    // Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'error',
        message: 'User recently changed password! Please log in again.'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const adminProtect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwtAdmin) {
    token = req.cookies.jwtAdmin;
  }

  if (!token) {
    return res.status(401).json({
      status: 'error',
      message: 'You are not logged in! Please log in to get access.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentAdmin = await Admin.findById(decoded.id).select('+active +lastActivity +role');

    if (!currentAdmin) {
      return res.status(401).json({
        status: 'error',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    if (!currentAdmin.active) {
      return res.status(401).json({
        status: 'error',
        message: 'Your account has been deactivated. Please contact administrator.'
      });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({
        status: 'error',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
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

// Initialize investment plans
const initializePlans = async () => {
  const plansCount = await Plan.countDocuments();
  if (plansCount === 0) {
    const defaultPlans = [
      {
        name: 'Starter Plan',
        minAmount: 100,
        maxAmount: 999,
        duration: 30,
        dailyProfit: 1.5,
        description: 'Perfect for beginners'
      },
      {
        name: 'Advanced Plan',
        minAmount: 1000,
        maxAmount: 4999,
        duration: 60,
        dailyProfit: 2.0,
        description: 'For experienced investors'
      },
      {
        name: 'Professional Plan',
        minAmount: 5000,
        maxAmount: 20000,
        duration: 90,
        dailyProfit: 2.5,
        description: 'Maximum returns for professionals'
      }
    ];
    await Plan.insertMany(defaultPlans);
    console.log('Default investment plans created');
  }
};

// Initialize the system
const initializeSystem = async () => {
  await initializeDefaultAdmin();
  await initializePlans();
};

initializeSystem().catch(err => console.error('Initialization error:', err));

// Routes

// User Endpoints
// GET /api/users/me - Get current user profile
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -__v -twoFactorSecret')
      .populate('activeInvestments')
      .populate('transactions');

    if (!user) {
      return res.status(404).json({
        status: 'error',
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
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// PUT /api/users/profile - Update user profile
app.put('/api/users/profile', protect, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, country } = req.body;

    // Validate input
    if (!firstName || !lastName || !email || !country) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide all required fields'
      });
    }

    // Check if email is already taken by another user
    const existingUser = await User.findOne({ email, _id: { $ne: req.user.id } });
    if (existingUser) {
      return res.status(400).json({
        status: 'error',
        message: 'Email is already in use'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { firstName, lastName, email, phone, country },
      { new: true, runValidators: true }
    ).select('-password -__v -twoFactorSecret');

    await logActivity(req.user.id, 'PROFILE_UPDATE', 'Updated profile information');

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// PUT /api/users/address - Update user address
app.put('/api/users/address', protect, async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;

    // Validate input
    if (!street || !city || !state || !postalCode || !country) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide all address fields'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { 
        address: { street, city, state, postalCode, country },
        addressVerified: false // Reset verification status when address changes
      },
      { new: true, runValidators: true }
    ).select('-password -__v -twoFactorSecret');

    await logActivity(req.user.id, 'ADDRESS_UPDATE', 'Updated address information');

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// PUT /api/users/password - Change user password
app.put('/api/users/password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide both current and new password'
      });
    }

    // Get user from collection
    const user = await User.findById(req.user.id).select('+password');

    // Check if current password is correct
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'error',
        message: 'Your current password is wrong'
      });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Log user out of all devices by changing the passwordChangedAt field
    user.passwordChangedAt = Date.now();
    await user.save({ validateBeforeSave: false });

    // Invalidate all existing sessions in Redis
    const sessionKey = `user:${user.id}:sessions`;
    await redis.del(sessionKey);

    await logActivity(user.id, 'PASSWORD_CHANGE', 'Changed account password');

    res.status(200).json({
      status: 'success',
      message: 'Password changed successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/users/api-keys - Generate new API key
app.post('/api/users/api-keys', protect, async (req, res) => {
  try {
    const { name, permissions, expiresAt } = req.body;

    if (!name || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide API key name and permissions'
      });
    }

    const key = generateApiKey();
    const hashedKey = crypto.createHash('sha256').update(key).digest('hex');

    const apiKey = await ApiKey.create({
      user: req.user.id,
      name,
      key: hashedKey,
      permissions,
      expiresAt: expiresAt ? new Date(expiresAt) : null
    });

    await logActivity(req.user.id, 'API_KEY_GENERATE', `Generated new API key: ${apiKey.name}`);

    // Send the unhashed key only once
    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          ...apiKey.toObject(),
          key // Send the unhashed key only in the response
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Admin Endpoints
// POST /api/admin/auth/login - Admin login
app.post('/api/admin/auth/login', async (req, res) => {
  try {
    const { email, password, twoFactorCode } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide email and password'
      });
    }

    const admin = await Admin.findOne({ email }).select('+password +twoFactorSecret');

    if (!admin || !(await admin.correctPassword(password, admin.password))) {
      return res.status(401).json({
        status: 'error',
        message: 'Incorrect email or password'
      });
    }

    // Check if 2FA is enabled and verify code if provided
    if (admin.twoFactorEnabled) {
      if (!twoFactorCode) {
        return res.status(400).json({
          status: 'error',
          message: 'Two-factor authentication code is required'
        });
      }

      const verified = admin.verifyTwoFactorCode(twoFactorCode);
      if (!verified) {
        return res.status(401).json({
          status: 'error',
          message: 'Invalid two-factor authentication code'
        });
      }
    }

    // Create token
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });

    // Remove sensitive data from output
    admin.password = undefined;
    admin.twoFactorSecret = undefined;

    // Set cookie
    res.cookie('jwtAdmin', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    await logActivity(admin._id, 'ADMIN_LOGIN', 'Logged into admin panel', true);

    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/admin/auth/logout - Admin logout
app.post('/api/admin/auth/logout', adminProtect, async (req, res) => {
  try {
    await logActivity(req.admin._id, 'ADMIN_LOGOUT', 'Logged out from admin panel', true);

    res.cookie('jwtAdmin', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/dashboard - Get admin dashboard stats
app.get('/api/admin/dashboard', adminProtect, async (req, res) => {
  try {
    // Get stats from cache if available
    const cachedStats = await redis.get('admin:dashboard:stats');
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedStats)
      });
    }

    // Calculate stats
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ active: true });
    const newUsersToday = await User.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
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
    const activeInvestments = await Investment.countDocuments({ status: 'active' });

    const stats = {
      totalUsers,
      activeUsers,
      newUsersToday,
      totalDeposits: totalDeposits.length > 0 ? totalDeposits[0].total : 0,
      totalWithdrawals: totalWithdrawals.length > 0 ? totalWithdrawals[0].total : 0,
      pendingWithdrawals,
      pendingKYC,
      activeInvestments
    };

    // Cache stats for 5 minutes
    await redis.set('admin:dashboard:stats', JSON.stringify(stats), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/users/growth - Get user growth data
app.get('/api/admin/users/growth', adminProtect, async (req, res) => {
  try {
    const cachedData = await redis.get('admin:users:growth');
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }

    const today = new Date();
    const last30Days = new Date(today.setDate(today.getDate() - 30));

    const growthData = await User.aggregate([
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

    // Cache for 1 hour
    await redis.set('admin:users:growth', JSON.stringify(growthData), 'EX', 3600);

    res.status(200).json({
      status: 'success',
      data: growthData
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/activity - Get recent system activity
app.get('/api/admin/activity', adminProtect, async (req, res) => {
  try {
    const activities = await ActivityLog.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('user', 'firstName lastName email')
      .populate('admin', 'name email');

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/users - Get all users
app.get('/api/admin/users', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
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
      query.active = status === 'active';
    }

    let sortOption = { createdAt: -1 };
    if (sort) {
      const [field, order] = sort.split(':');
      sortOption = { [field]: order === 'desc' ? -1 : 1 };
    }

    const users = await User.find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -twoFactorSecret -__v');

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
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/users/{id} - Get user by ID
app.get('/api/admin/users/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -twoFactorSecret -__v')
      .populate('transactions')
      .populate('investments')
      .populate('kycDocuments')
      .populate('withdrawals');

    if (!user) {
      return res.status(404).json({
        status: 'error',
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
      message: 'Internal server error'
    });
  }
});

// PUT /api/admin/users/{id} - Update user by ID
app.put('/api/admin/users/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { firstName, lastName, email, phone, country, balance, walletAddress } = req.body;

    const updates = {};
    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (email) updates.email = email;
    if (phone) updates.phone = phone;
    if (country) updates.country = country;
    if (balance !== undefined) updates.balance = parseFloat(balance);
    if (walletAddress) updates.walletAddress = walletAddress;

    const user = await User.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret -__v');

    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    await logActivity(req.admin._id, 'USER_UPDATE', `Updated user ${user.email}`, true);

    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// DELETE /api/admin/users/{id} - Delete user by ID
app.delete('/api/admin/users/:id', adminProtect, restrictTo('super-admin'), async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Log the deletion
    await logActivity(req.admin._id, 'USER_DELETE', `Deleted user ${user.email}`, true);

    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// PUT /api/admin/users/{id}/status - Update user status
app.put('/api/admin/users/:id/status', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { active } = req.body;

    if (typeof active !== 'boolean') {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a valid status'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret -__v');

    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    const action = active ? 'USER_ACTIVATE' : 'USER_DEACTIVATE';
    await logActivity(req.admin._id, action, `${active ? 'Activated' : 'Deactivated'} user ${user.email}`, true);

    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/kyc/pending - Get pending KYC documents
app.get('/api/admin/kyc/pending', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const pendingKYCs = await KYCDocument.find({ status: 'pending' })
      .populate('user', 'firstName lastName email');

    res.status(200).json({
      status: 'success',
      data: pendingKYCs
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/kyc/{id} - Get KYC document by ID
app.get('/api/admin/kyc/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const kycDoc = await KYCDocument.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!kycDoc) {
      return res.status(404).json({
        status: 'error',
        message: 'KYC document not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: kycDoc
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/admin/kyc/{id}/review - Review KYC document
app.post('/api/admin/kyc/:id/review', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { status, reason } = req.body;

    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid status. Must be "approved" or "rejected"'
      });
    }

    if (status === 'rejected' && !reason) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a reason for rejection'
      });
    }

    const kycDoc = await KYCDocument.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!kycDoc) {
      return res.status(404).json({
        status: 'error',
        message: 'KYC document not found'
      });
    }

    if (kycDoc.status !== 'pending') {
      return res.status(400).json({
        status: 'error',
        message: 'KYC document has already been processed'
      });
    }

    kycDoc.status = status;
    kycDoc.reviewedBy = req.admin._id;
    kycDoc.reviewedAt = new Date();
    if (status === 'rejected') {
      kycDoc.rejectionReason = reason;
    }

    await kycDoc.save();

    // Update user verification status if approved
    if (status === 'approved') {
      await User.findByIdAndUpdate(kycDoc.user._id, {
        kycVerified: true,
        kycVerifiedAt: new Date()
      });
    }

    // Send notification to user
    const notification = new Notification({
      user: kycDoc.user._id,
      title: 'KYC Verification Update',
      message: `Your KYC verification has been ${status}. ${status === 'rejected' ? 'Reason: ' + reason : ''}`,
      type: 'kyc'
    });
    await notification.save();

    await logActivity(
      req.admin._id,
      'KYC_REVIEW',
      `${status} KYC for user ${kycDoc.user.email}`,
      true
    );

    res.status(200).json({
      status: 'success',
      data: kycDoc
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/withdrawals/pending - Get pending withdrawals
app.get('/api/admin/withdrawals/pending', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: 1 });

    res.status(200).json({
      status: 'success',
      data: pendingWithdrawals
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/withdrawals/{id} - Get withdrawal by ID
app.get('/api/admin/withdrawals/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const withdrawal = await Withdrawal.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'error',
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
      message: 'Internal server error'
    });
  }
});

// POST /api/admin/withdrawals/{id}/process - Process withdrawal
app.post('/api/admin/withdrawals/:id/process', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { status, txHash, adminNote } = req.body;

    if (!['completed', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid status. Must be "completed" or "rejected"'
      });
    }

    if (status === 'completed' && !txHash) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide transaction hash for completed withdrawals'
      });
    }

    const withdrawal = await Withdrawal.findById(req.params.id)
      .populate('user', 'firstName lastName email balance');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'error',
        message: 'Withdrawal not found'
      });
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'error',
        message: 'Withdrawal has already been processed'
      });
    }

    // If rejecting, return funds to user's balance
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.user._id, {
        $inc: { balance: withdrawal.amount }
      });
    }

    withdrawal.status = status;
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    if (txHash) withdrawal.txHash = txHash;
    if (adminNote) withdrawal.adminNote = adminNote;

    await withdrawal.save();

    // Create transaction record
    const transaction = new Transaction({
      user: withdrawal.user._id,
      type: 'withdrawal',
      amount: withdrawal.amount,
      status: withdrawal.status,
      currency: withdrawal.currency,
      txHash: withdrawal.txHash,
      adminNote: withdrawal.adminNote
    });
    await transaction.save();

    // Send notification to user
    const notification = new Notification({
      user: withdrawal.user._id,
      title: 'Withdrawal Processed',
      message: `Your withdrawal of ${withdrawal.amount} ${withdrawal.currency} has been ${status}.`,
      type: 'withdrawal'
    });
    await notification.save();

    await logActivity(
      req.admin._id,
      'WITHDRAWAL_PROCESS',
      `${status} withdrawal for user ${withdrawal.user.email}`,
      true
    );

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/admin/withdrawals/process-batch - Process batch withdrawals
app.post('/api/admin/withdrawals/process-batch', adminProtect, restrictTo('super-admin'), async (req, res) => {
  try {
    const { withdrawalIds, txHash } = req.body;

    if (!withdrawalIds || !Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide valid withdrawal IDs'
      });
    }

    if (!txHash) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide transaction hash'
      });
    }

    const withdrawals = await Withdrawal.find({
      _id: { $in: withdrawalIds },
      status: 'pending'
    }).populate('user', 'firstName lastName email');

    if (withdrawals.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No pending withdrawals found with the provided IDs'
      });
    }

    // Process all withdrawals in the batch
    const processedWithdrawals = [];
    for (const withdrawal of withdrawals) {
      withdrawal.status = 'completed';
      withdrawal.txHash = txHash;
      withdrawal.processedBy = req.admin._id;
      withdrawal.processedAt = new Date();
      await withdrawal.save();

      // Create transaction record
      const transaction = new Transaction({
        user: withdrawal.user._id,
        type: 'withdrawal',
        amount: withdrawal.amount,
        status: 'completed',
        currency: withdrawal.currency,
        txHash: withdrawal.txHash
      });
      await transaction.save();

      // Send notification to user
      const notification = new Notification({
        user: withdrawal.user._id,
        title: 'Withdrawal Processed',
        message: `Your withdrawal of ${withdrawal.amount} ${withdrawal.currency} has been processed.`,
        type: 'withdrawal'
      });
      await notification.save();

      processedWithdrawals.push(withdrawal);
    }

    await logActivity(
      req.admin._id,
      'WITHDRAWAL_BATCH',
      `Processed batch of ${processedWithdrawals.length} withdrawals`,
      true
    );

    res.status(200).json({
      status: 'success',
      data: processedWithdrawals
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/loans - Get all loans
app.get('/api/admin/loans', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { status } = req.query;
    let query = {};
    if (status) query.status = status;

    const loans = await Loan.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      data: loans
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/admin/loans - Create new loan
app.post('/api/admin/loans', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { userId, amount, interestRate, duration, collateralAmount, collateralType } = req.body;

    if (!userId || !amount || !interestRate || !duration || !collateralAmount || !collateralType) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide all required fields'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    const loan = await Loan.create({
      user: userId,
      amount: parseFloat(amount),
      interestRate: parseFloat(interestRate),
      duration: parseInt(duration),
      collateralAmount: parseFloat(collateralAmount),
      collateralType,
      status: 'active',
      createdBy: req.admin._id
    });

    // Add loan amount to user's balance
    user.balance += parseFloat(amount);
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      user: userId,
      type: 'loan',
      amount: parseFloat(amount),
      status: 'completed',
      currency: 'USD',
      reference: `Loan #${loan._id}`
    });
    await transaction.save();

    // Send notification to user
    const notification = new Notification({
      user: userId,
      title: 'Loan Approved',
      message: `Your loan of $${amount} has been approved and credited to your account.`,
      type: 'loan'
    });
    await notification.save();

    await logActivity(
      req.admin._id,
      'LOAN_CREATE',
      `Created loan for user ${user.email}`,
      true
    );

    res.status(201).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/loans/{id} - Get loan by ID
app.get('/api/admin/loans/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('createdBy', 'name email');

    if (!loan) {
      return res.status(404).json({
        status: 'error',
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
      message: 'Internal server error'
    });
  }
});

// PUT /api/admin/loans/{id} - Update loan by ID
app.put('/api/admin/loans/:id', adminProtect, restrictTo('admin', 'super-admin'), async (req, res) => {
  try {
    const { status, interestRate, adminNote } = req.body;

    const loan = await Loan.findById(req.params.id);
    if (!loan) {
      return res.status(404).json({
        status: 'error',
        message: 'Loan not found'
      });
    }

    if (status) loan.status = status;
    if (interestRate) loan.interestRate = interestRate;
    if (adminNote) loan.adminNote = adminNote;

    await loan.save();

    if (status === 'defaulted') {
      // Handle defaulted loan (e.g., liquidate collateral)
      const user = await User.findById(loan.user);
      if (user) {
        user.balance -= loan.collateralAmount;
        await user.save();
      }
    }

    await logActivity(
      req.admin._id,
      'LOAN_UPDATE',
      `Updated loan #${loan._id}`,
      true
    );

    res.status(200).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// DELETE /api/admin/loans/{id} - Delete loan by ID
app.delete('/api/admin/loans/:id', adminProtect, restrictTo('super-admin'), async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);

    if (!loan) {
      return res.status(404).json({
        status: 'error',
        message: 'Loan not found'
      });
    }

    await logActivity(
      req.admin._id,
      'LOAN_DELETE',
      `Deleted loan #${loan._id}`,
      true
    );

    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/admin/profile - Get admin profile
app.get('/api/admin/profile', adminProtect, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin._id).select('-password -twoFactorSecret -__v');

    res.status(200).json({
      status: 'success',
      data: admin
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Dashboard Endpoints
// GET /api/plans - Get investment plans
app.get('/api/plans', protect, async (req, res) => {
  try {
    const cachedPlans = await redis.get('investment:plans');
    if (cachedPlans) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedPlans)
      });
    }

    const plans = await Plan.find({ active: true }).sort({ minAmount: 1 });

    // Cache plans for 1 day
    await redis.set('investment:plans', JSON.stringify(plans), 'EX', 86400);

    res.status(200).json({
      status: 'success',
      data: plans
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/transactions - Get user transactions
app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, status, limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    let query = { user: req.user._id };
    if (type) query.type = type;
    if (status) query.status = status;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: transactions
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// GET /api/mining/stats - Get mining statistics
app.get('/api/mining/stats', protect, async (req, res) => {
  try {
    const cachedStats = await redis.get(`user:${req.user.id}:mining:stats`);
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedStats)
      });
    }

    const activeInvestments = await Investment.find({
      user: req.user._id,
      status: 'active'
    }).populate('plan');

    const totalInvested = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const dailyProfit = activeInvestments.reduce((sum, inv) => {
      return sum + (inv.amount * inv.plan.dailyProfit / 100);
    }, 0);

    const stats = {
      activeInvestments: activeInvestments.length,
      totalInvested,
      dailyProfit,
      estimatedMonthlyProfit: dailyProfit * 30,
      estimatedYearlyProfit: dailyProfit * 365
    };

    // Cache for 1 hour
    await redis.set(`user:${req.user.id}:mining:stats`, JSON.stringify(stats), 'EX', 3600);

    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/transactions/deposit - Create deposit transaction
app.post('/api/transactions/deposit', protect, async (req, res) => {
  try {
    const { amount, currency, method } = req.body;

    if (!amount || !currency || !method) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide amount, currency and method'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be greater than 0'
      });
    }

    // For BTC deposits, provide the deposit address
    let depositAddress;
    if (currency === 'BTC' && method === 'crypto') {
      depositAddress = DEFAULT_BTC_DEPOSIT_ADDRESS;
    }

    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'deposit',
      amount,
      currency,
      method,
      status: 'pending',
      depositAddress
    });

    await logActivity(req.user._id, 'DEPOSIT_REQUEST', `Requested deposit of ${amount} ${currency}`);

    res.status(201).json({
      status: 'success',
      data: transaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/transactions/withdraw - Create withdrawal request
app.post('/api/transactions/withdraw', protect, async (req, res) => {
  try {
    const { amount, currency, walletAddress } = req.body;

    if (!amount || !currency || !walletAddress) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide amount, currency and wallet address'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be greater than 0'
      });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient balance'
      });
    }

    // Check withdrawal limits
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const withdrawalsToday = await Withdrawal.countDocuments({
      user: req.user._id,
      createdAt: { $gte: today }
    });

    if (withdrawalsToday >= 3) {
      return res.status(400).json({
        status: 'error',
        message: 'You have reached your daily withdrawal limit (3 withdrawals per day)'
      });
    }

    // Deduct amount from user balance
    user.balance -= amount;
    await user.save();

    // Create withdrawal record
    const withdrawal = await Withdrawal.create({
      user: req.user._id,
      amount,
      currency,
      walletAddress,
      status: 'pending'
    });

    // Create transaction record
    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'withdrawal',
      amount,
      currency,
      status: 'pending',
      reference: `Withdrawal #${withdrawal._id}`
    });

    await logActivity(req.user._id, 'WITHDRAWAL_REQUEST', `Requested withdrawal of ${amount} ${currency}`);

    res.status(201).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/investments - Create new investment
app.post('/api/investments', protect, async (req, res) => {
  try {
    const { planId, amount } = req.body;

    if (!planId || !amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide plan ID and amount'
      });
    }

    const plan = await Plan.findById(planId);
    if (!plan || !plan.active) {
      return res.status(404).json({
        status: 'error',
        message: 'Plan not found or inactive'
      });
    }

    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'error',
        message: `Amount must be between ${plan.minAmount} and ${plan.maxAmount}`
      });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient balance'
      });
    }

    // Deduct amount from user balance
    user.balance -= amount;
    await user.save();

    // Create investment
    const investment = await Investment.create({
      user: req.user._id,
      plan: planId,
      amount,
      startDate: new Date(),
      endDate: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
      dailyProfit: plan.dailyProfit,
      status: 'active'
    });

    // Add to user's active investments
    user.activeInvestments.push(investment._id);
    await user.save();

    // Create transaction record
    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'investment',
      amount,
      status: 'completed',
      currency: 'USD',
      reference: `Investment in ${plan.name}`
    });

    await logActivity(req.user._id, 'INVESTMENT_CREATE', `Invested $${amount} in ${plan.name}`);

    res.status(201).json({
      status: 'success',
      data: investment
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// POST /api/transactions/transfer - Transfer funds between accounts
app.post('/api/transactions/transfer', protect, async (req, res) => {
  try {
    const { recipientEmail, amount, note } = req.body;

    if (!recipientEmail || !amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide recipient email and amount'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be greater than 0'
      });
    }

    // Check if recipient exists
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({
        status: 'error',
        message: 'Recipient not found'
      });
    }

    // Check sender balance
    const sender = await User.findById(req.user._id);
    if (sender.balance < amount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient balance'
      });
    }

    // Perform transfer
    sender.balance -= amount;
    recipient.balance += amount;

    await sender.save();
    await recipient.save();

    // Create transaction records for both parties
    const senderTransaction = await Transaction.create({
      user: req.user._id,
      type: 'transfer-out',
      amount,
      status: 'completed',
      currency: 'USD',
      reference: `Transfer to ${recipient.email}`,
      note
    });

    const recipientTransaction = await Transaction.create({
      user: recipient._id,
      type: 'transfer-in',
      amount,
      status: 'completed',
      currency: 'USD',
      reference: `Transfer from ${sender.email}`,
      note
    });

    // Send notification to recipient
    const notification = new Notification({
      user: recipient._id,
      title: 'Funds Received',
      message: `You have received $${amount} from ${sender.firstName} ${sender.lastName}.`,
      type: 'transfer'
    });
    await notification.save();

    await logActivity(req.user._id, 'FUNDS_TRANSFER', `Transferred $${amount} to ${recipient.email}`);

    res.status(201).json({
      status: 'success',
      data: senderTransaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
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
    status: 'error',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});
