require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: 'https://bithhash.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

// Database connections
const mongoURI = 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
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

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Models
const User = require('./models/User');
const Admin = require('./models/Admin');
const Transaction = require('./models/Transaction');
const Investment = require('./models/Investment');
const KYCDoc = require('./models/KYCDoc');
const Loan = require('./models/Loan');
const APIKey = require('./models/APIKey');
const ActivityLog = require('./models/ActivityLog');

// Default admin credentials (should be changed after first login)
const DEFAULT_ADMIN = {
  email: 'admin@bithash.com',
  password: 'SecureAdminPassword123!',
  role: 'superadmin'
};

// Initialize WebSocket server
const wss = new WebSocket.Server({ noServer: true });

// Utility functions
const generateAPIKey = () => crypto.randomBytes(32).toString('hex');
const logActivity = async (userId, action, details) => {
  await ActivityLog.create({ userId, action, details });
};

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('+active');
    if (!user || !user.active) {
      return res.status(401).json({ error: 'User account is inactive' });
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(decoded.id);
    if (!admin) return res.status(401).json({ error: 'Admin not found' });

    req.admin = admin;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Initialize default admin (run once)
const initializeAdmin = async () => {
  const existingAdmin = await Admin.findOne({ email: DEFAULT_ADMIN.email });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, 12);
    await Admin.create({
      email: DEFAULT_ADMIN.email,
      password: hashedPassword,
      role: DEFAULT_ADMIN.role
    });
    console.log('Default admin account created');
  }
};

// User Endpoints
app.get('/api/users/me', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -__v -twoFactorSecret')
      .populate('kyc', 'status reason');
    
    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      country: user.country,
      address: user.address,
      balances: user.balances,
      kyc: user.kyc,
      twoFactorEnabled: user.twoFactorEnabled,
      createdAt: user.createdAt
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.put('/api/users/profile', authenticateUser, [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('phone').trim().notEmpty().withMessage('Phone is required'),
  body('country').trim().notEmpty().withMessage('Country is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { firstName, lastName, email, phone, country } = req.body;
    
    // Check if email is already taken by another user
    if (email !== req.user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email is already in use' });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(req.user.id, {
      firstName,
      lastName,
      email,
      phone,
      country
    }, { new: true }).select('-password -__v');

    await logActivity(req.user.id, 'PROFILE_UPDATE', 'Updated profile information');
    
    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.put('/api/users/address', authenticateUser, [
  body('street').trim().notEmpty().withMessage('Street address is required'),
  body('city').trim().notEmpty().withMessage('City is required'),
  body('state').trim().notEmpty().withMessage('State is required'),
  body('postalCode').trim().notEmpty().withMessage('Postal code is required'),
  body('country').trim().notEmpty().withMessage('Country is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { street, city, state, postalCode, country } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(req.user.id, {
      address: { street, city, state, postalCode, country }
    }, { new: true }).select('-password -__v');

    await logActivity(req.user.id, 'ADDRESS_UPDATE', 'Updated address information');
    
    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update address' });
  }
});

app.put('/api/users/password', authenticateUser, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id).select('+password');
    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();

    await logActivity(req.user.id, 'PASSWORD_CHANGE', 'Changed account password');
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update password' });
  }
});

app.post('/api/users/api-keys', authenticateUser, [
  body('name').trim().notEmpty().withMessage('API key name is required'),
  body('permissions').isArray().withMessage('Permissions must be an array'),
  body('expiresAt').optional().isISO8601().withMessage('Invalid expiration date')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, permissions, expiresAt } = req.body;
    const apiKey = generateAPIKey();
    const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
    
    const newAPIKey = await APIKey.create({
      userId: req.user.id,
      name,
      key: hashedKey,
      permissions,
      expiresAt: expiresAt || null
    });

    await logActivity(req.user.id, 'API_KEY_CREATE', `Created API key: ${name}`);
    
    // Return the plaintext key only once
    res.json({
      id: newAPIKey.id,
      name: newAPIKey.name,
      key: apiKey,
      permissions: newAPIKey.permissions,
      expiresAt: newAPIKey.expiresAt,
      createdAt: newAPIKey.createdAt
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

// Admin Endpoints
app.post('/api/admin/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password, twoFactorCode } = req.body;
    const admin = await Admin.findOne({ email }).select('+password +twoFactorSecret');
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // If 2FA is enabled, verify the code
    if (admin.twoFactorEnabled && twoFactorCode) {
      const verified = verifyTwoFactorCode(admin.twoFactorSecret, twoFactorCode);
      if (!verified) {
        return res.status(401).json({ error: 'Invalid two-factor code' });
      }
    }

    const token = jwt.sign({ id: admin.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.json({
      id: admin.id,
      email: admin.email,
      role: admin.role,
      token
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/admin/auth/logout', authenticateAdmin, async (req, res) => {
  try {
    // In a real implementation, you might want to invalidate the token
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    // Cache dashboard data for 5 minutes
    const cachedData = await redis.get('admin:dashboard');
    if (cachedData) {
      return res.json(JSON.parse(cachedData));
    }

    const [totalUsers, activeUsers, pendingKYC, pendingWithdrawals, totalDeposits, totalWithdrawals] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ active: true }),
      KYCDoc.countDocuments({ status: 'pending' }),
      Transaction.countDocuments({ type: 'withdrawal', status: 'pending' }),
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);

    const dashboardData = {
      totalUsers,
      activeUsers,
      pendingKYC,
      pendingWithdrawals,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      updatedAt: new Date()
    };

    await redis.setex('admin:dashboard', 300, JSON.stringify(dashboardData));
    
    res.json(dashboardData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

app.get('/api/admin/users/growth', authenticateAdmin, async (req, res) => {
  try {
    const cachedData = await redis.get('admin:users:growth');
    if (cachedData) {
      return res.json(JSON.parse(cachedData));
    }

    const now = new Date();
    const last30Days = new Date(now.setDate(now.getDate() - 30));
    
    const growthData = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: last30Days }
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

    await redis.setex('admin:users:growth', 3600, JSON.stringify(growthData));
    
    res.json(growthData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user growth data' });
  }
});

app.get('/api/admin/activity', authenticateAdmin, async (req, res) => {
  try {
    const activities = await ActivityLog.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('userId', 'email firstName lastName');
    
    res.json(activities);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch activity logs' });
  }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, status } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.active = status === 'active';
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -twoFactorSecret -__v')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 }),
      User.countDocuments(query)
    ]);
    
    res.json({
      users,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -twoFactorSecret -__v')
      .populate('kyc', 'status reason documents')
      .populate('transactions', 'type amount status createdAt')
      .populate('investments', 'plan amount status createdAt');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

app.put('/api/admin/users/:id', authenticateAdmin, [
  body('email').optional().isEmail().normalizeEmail(),
  body('firstName').optional().trim().notEmpty(),
  body('lastName').optional().trim().notEmpty(),
  body('phone').optional().trim().notEmpty(),
  body('country').optional().trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { id } = req.params;
    const updates = req.body;
    
    // Prevent changing certain fields directly
    delete updates.password;
    delete updates.balances;
    delete updates.kyc;
    
    const user = await User.findByIdAndUpdate(id, updates, { new: true })
      .select('-password -twoFactorSecret -__v');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await logActivity(req.admin.id, 'USER_UPDATE', `Updated user ${user.email}`);
    
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Clean up related data
    await Promise.all([
      Transaction.deleteMany({ userId: user.id }),
      Investment.deleteMany({ userId: user.id }),
      KYCDoc.deleteMany({ userId: user.id }),
      APIKey.deleteMany({ userId: user.id })
    ]);
    
    await logActivity(req.admin.id, 'USER_DELETE', `Deleted user ${user.email}`);
    
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.put('/api/admin/users/:id/status', authenticateAdmin, [
  body('active').isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { id } = req.params;
    const { active } = req.body;
    
    const user = await User.findByIdAndUpdate(id, { active }, { new: true })
      .select('-password -twoFactorSecret -__v');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await logActivity(req.admin.id, 'USER_STATUS', `Set user ${user.email} status to ${active}`);
    
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

app.get('/api/admin/kyc/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingKYC = await KYCDoc.find({ status: 'pending' })
      .populate('userId', 'email firstName lastName');
    
    res.json(pendingKYC);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch pending KYC' });
  }
});

app.get('/api/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const kyc = await KYCDoc.findById(req.params.id)
      .populate('userId', 'email firstName lastName');
    
    if (!kyc) {
      return res.status(404).json({ error: 'KYC document not found' });
    }
    
    res.json(kyc);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch KYC details' });
  }
});

app.post('/api/admin/kyc/:id/review', authenticateAdmin, [
  body('status').isIn(['approved', 'rejected']),
  body('reason').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { id } = req.params;
    const { status, reason } = req.body;
    
    const kyc = await KYCDoc.findByIdAndUpdate(id, { status, reason }, { new: true })
      .populate('userId', 'email firstName lastName');
    
    if (!kyc) {
      return res.status(404).json({ error: 'KYC document not found' });
    }
    
    // Update user verification status
    await User.findByIdAndUpdate(kyc.userId, { verified: status === 'approved' });
    
    // Send email notification
    await transporter.sendMail({
      from: '"BitHash Support" <support@bithash.com>',
      to: kyc.userId.email,
      subject: `Your KYC Verification has been ${status}`,
      text: `Dear ${kyc.userId.firstName},\n\nYour KYC verification has been ${status}. ${reason ? `Reason: ${reason}` : ''}\n\nThank you,\nBitHash Team`
    });
    
    await logActivity(req.admin.id, 'KYC_REVIEW', `Reviewed KYC for ${kyc.userId.email} as ${status}`);
    
    res.json(kyc);
  } catch (err) {
    res.status(500).json({ error: 'Failed to process KYC review' });
  }
});

app.get('/api/admin/withdrawals/pending', authenticateAdmin, async (req, res) => {
  try {
    const pendingWithdrawals = await Transaction.find({ 
      type: 'withdrawal',
      status: 'pending'
    }).populate('userId', 'email firstName lastName');
    
    res.json(pendingWithdrawals);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
  }
});

app.get('/api/admin/withdrawals/:id', authenticateAdmin, async (req, res) => {
  try {
    const withdrawal = await Transaction.findOne({
      _id: req.params.id,
      type: 'withdrawal'
    }).populate('userId', 'email firstName lastName');
    
    if (!withdrawal) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }
    
    res.json(withdrawal);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch withdrawal details' });
  }
});

app.post('/api/admin/withdrawals/:id/process', authenticateAdmin, [
  body('status').isIn(['completed', 'rejected']),
  body('reason').optional().trim(),
  body('txHash').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { id } = req.params;
    const { status, reason, txHash } = req.body;
    
    const withdrawal = await Transaction.findOneAndUpdate(
      { _id: id, type: 'withdrawal', status: 'pending' },
      { status, reason, txHash, processedBy: req.admin.id, processedAt: new Date() },
      { new: true }
    ).populate('userId', 'email firstName lastName');
    
    if (!withdrawal) {
      return res.status(404).json({ error: 'Pending withdrawal not found' });
    }
    
    // If rejected, return funds to user's balance
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.userId, {
        $inc: { 'balances.main': withdrawal.amount }
      });
    }
    
    // Send email notification
    await transporter.sendMail({
      from: '"BitHash Support" <support@bithash.com>',
      to: withdrawal.userId.email,
      subject: `Your Withdrawal has been ${status}`,
      text: `Dear ${withdrawal.userId.firstName},\n\nYour withdrawal request for ${withdrawal.amount} BTC has been ${status}. ${reason ? `Reason: ${reason}` : ''}\n\nThank you,\nBitHash Team`
    });
    
    await logActivity(req.admin.id, 'WITHDRAWAL_PROCESS', `Processed withdrawal for ${withdrawal.userId.email} as ${status}`);
    
    res.json(withdrawal);
  } catch (err) {
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

app.post('/api/admin/withdrawals/process-batch', authenticateAdmin, [
  body('ids').isArray(),
  body('status').isIn(['completed', 'rejected']),
  body('reason').optional().trim(),
  body('txHash').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { ids, status, reason, txHash } = req.body;
    
    const result = await Transaction.updateMany(
      { _id: { $in: ids }, type: 'withdrawal', status: 'pending' },
      { status, reason, txHash, processedBy: req.admin.id, processedAt: new Date() }
    );
    
    if (result.nModified === 0) {
      return res.status(404).json({ error: 'No pending withdrawals found' });
    }
    
    // If rejected, return funds to users' balances
    if (status === 'rejected') {
      const withdrawals = await Transaction.find({ _id: { $in: ids } });
      const bulkOps = withdrawals.map(wd => ({
        updateOne: {
          filter: { _id: wd.userId },
          update: { $inc: { 'balances.main': wd.amount } }
        }
      }));
      
      await User.bulkWrite(bulkOps);
    }
    
    await logActivity(req.admin.id, 'WITHDRAWAL_BATCH', `Processed ${result.nModified} withdrawals as ${status}`);
    
    res.json({ message: `${result.nModified} withdrawals processed successfully` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process batch withdrawals' });
  }
});

app.get('/api/admin/loans', authenticateAdmin, async (req, res) => {
  try {
    const loans = await Loan.find()
      .populate('userId', 'email firstName lastName')
      .sort({ createdAt: -1 });
    
    res.json(loans);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch loans' });
  }
});

app.post('/api/admin/loans', authenticateAdmin, [
  body('userId').isMongoId(),
  body('amount').isFloat({ gt: 0 }),
  body('interestRate').isFloat({ min: 0, max: 100 }),
  body('term').isInt({ min: 1 }),
  body('collateralAmount').optional().isFloat({ gt: 0 }),
  body('collateralType').optional().trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { userId, amount, interestRate, term, collateralAmount, collateralType } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const loan = await Loan.create({
      userId,
      amount,
      interestRate,
      term,
      status: 'active',
      collateralAmount,
      collateralType,
      createdBy: req.admin.id
    });
    
    await logActivity(req.admin.id, 'LOAN_CREATE', `Created loan for ${user.email}`);
    
    res.status(201).json(loan);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create loan' });
  }
});

app.get('/api/admin/loans/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await Loan.findById(req.params.id)
      .populate('userId', 'email firstName lastName')
      .populate('createdBy', 'email');
    
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    res.json(loan);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch loan details' });
  }
});

app.put('/api/admin/loans/:id', authenticateAdmin, [
  body('status').optional().isIn(['active', 'paid', 'defaulted', 'cancelled']),
  body('interestRate').optional().isFloat({ min: 0, max: 100 }),
  body('term').optional().isInt({ min: 1 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { id } = req.params;
    const updates = req.body;
    
    const loan = await Loan.findByIdAndUpdate(id, updates, { new: true })
      .populate('userId', 'email firstName lastName');
    
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    await logActivity(req.admin.id, 'LOAN_UPDATE', `Updated loan ${loan._id}`);
    
    res.json(loan);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update loan' });
  }
});

app.delete('/api/admin/loans/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    await logActivity(req.admin.id, 'LOAN_DELETE', `Deleted loan ${loan._id}`);
    
    res.json({ message: 'Loan deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete loan' });
  }
});

app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id)
      .select('-password -twoFactorSecret -__v');
    
    res.json(admin);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin profile' });
  }
});

// Dashboard Endpoints
app.get('/api/plans', authenticateUser, async (req, res) => {
  try {
    const cachedPlans = await redis.get('investment:plans');
    if (cachedPlans) {
      return res.json(JSON.parse(cachedPlans));
    }

    const plans = [
      {
        id: 'starter',
        name: 'Starter Plan',
        minAmount: 0.01,
        maxAmount: 0.5,
        duration: 30,
        dailyProfit: 0.8,
        features: ['24/7 Support', 'Instant Withdrawal']
      },
      {
        id: 'premium',
        name: 'Premium Plan',
        minAmount: 0.5,
        maxAmount: 5,
        duration: 60,
        dailyProfit: 1.2,
        features: ['Priority Support', 'Dedicated Account Manager']
      },
      {
        id: 'vip',
        name: 'VIP Plan',
        minAmount: 5,
        maxAmount: null,
        duration: 90,
        dailyProfit: 1.8,
        features: ['24/7 Personal Support', 'Exclusive Investment Opportunities']
      }
    ];

    await redis.setex('investment:plans', 86400, JSON.stringify(plans));
    
    res.json(plans);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch investment plans' });
  }
});

app.get('/api/transactions', authenticateUser, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { userId: req.user.id };
    if (type) query.type = type;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Transaction.countDocuments(query)
    ]);
    
    res.json({
      transactions,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/mining/stats', authenticateUser, async (req, res) => {
  try {
    const stats = {
      hashrate: 125.4,
      activeWorkers: 8,
      shares: {
        accepted: 12500,
        rejected: 42
      },
      estimatedDailyEarnings: 0.0025,
      lastPayout: '2023-05-15T08:30:00Z',
      nextPayout: '2023-05-16T08:30:00Z'
    };
    
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch mining stats' });
  }
});

app.post('/api/transactions/deposit', authenticateUser, [
  body('amount').isFloat({ gt: 0 }),
  body('method').isIn(['btc', 'bank', 'card']),
  body('currency').optional().isIn(['USD', 'EUR', 'GBP'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { amount, method, currency } = req.body;
    
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'deposit',
      amount,
      method,
      currency,
      status: method === 'btc' ? 'pending' : 'processing',
      address: method === 'btc' ? 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k' : null
    });
    
    await logActivity(req.user.id, 'DEPOSIT_INIT', `Initiated ${method} deposit of ${amount}`);
    
    res.status(201).json(transaction);
  } catch (err) {
    res.status(500).json({ error: 'Failed to initiate deposit' });
  }
});

app.post('/api/transactions/withdraw', authenticateUser, [
  body('amount').isFloat({ gt: 0 }),
  body('method').isIn(['btc', 'bank']),
  body('address').if(body('method').equals('btc')).notEmpty(),
  body('accountDetails').if(body('method').equals('bank')).notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { amount, method, address, accountDetails } = req.body;
    const user = await User.findById(req.user.id);
    
    // Check if user has sufficient balance
    if (user.balances.main < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Check if user is verified for withdrawals
    if (!user.verified) {
      return res.status(403).json({ error: 'Account must be verified to withdraw' });
    }
    
    // Create withdrawal transaction
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'withdrawal',
      amount,
      method,
      address: method === 'btc' ? address : null,
      accountDetails: method === 'bank' ? accountDetails : null,
      status: 'pending'
    });
    
    // Deduct from user's balance immediately
    user.balances.main -= amount;
    await user.save();
    
    await logActivity(req.user.id, 'WITHDRAWAL_REQUEST', `Requested ${method} withdrawal of ${amount}`);
    
    res.status(201).json(transaction);
  } catch (err) {
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

app.post('/api/investments', authenticateUser, [
  body('planId').isIn(['starter', 'premium', 'vip']),
  body('amount').isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { planId, amount } = req.body;
    const user = await User.findById(req.user.id);
    
    // Check if user has sufficient balance
    if (user.balances.main < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Get plan details (in a real app, this would come from the database)
    const plans = {
      starter: { min: 0.01, max: 0.5, duration: 30, dailyProfit: 0.8 },
      premium: { min: 0.5, max: 5, duration: 60, dailyProfit: 1.2 },
      vip: { min: 5, max: null, duration: 90, dailyProfit: 1.8 }
    };
    
    const plan = plans[planId];
    if (!plan) {
      return res.status(400).json({ error: 'Invalid investment plan' });
    }
    
    // Validate amount against plan limits
    if (amount < plan.min || (plan.max && amount > plan.max)) {
      return res.status(400).json({ 
        error: `Amount must be between ${plan.min} and ${plan.max || 'unlimited'} for this plan`
      });
    }
    
    // Deduct from main balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();
    
    // Create investment
    const investment = await Investment.create({
      userId: req.user.id,
      planId,
      amount,
      dailyProfit: plan.dailyProfit,
      duration: plan.duration,
      status: 'active',
      startDate: new Date(),
      endDate: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000)
    });
    
    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'investment',
      amount,
      status: 'completed',
      reference: `Investment in ${planId} plan`
    });
    
    await logActivity(req.user.id, 'INVESTMENT_CREATE', `Created ${planId} investment of ${amount}`);
    
    res.status(201).json(investment);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create investment' });
  }
});

app.post('/api/transactions/transfer', authenticateUser, [
  body('recipientEmail').isEmail().normalizeEmail(),
  body('amount').isFloat({ gt: 0 }),
  body('note').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { recipientEmail, amount, note } = req.body;
    const sender = await User.findById(req.user.id);
    const recipient = await User.findOne({ email: recipientEmail });
    
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    if (sender.balances.main < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Perform transfer within a transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct from sender
      sender.balances.main -= amount;
      await sender.save({ session });
      
      // Add to recipient
      recipient.balances.main += amount;
      await recipient.save({ session });
      
      // Create transaction records
      const senderTx = await Transaction.create([{
        userId: sender.id,
        type: 'transfer_out',
        amount,
        status: 'completed',
        recipient: recipient.id,
        note
      }], { session });
      
      const recipientTx = await Transaction.create([{
        userId: recipient.id,
        type: 'transfer_in',
        amount,
        status: 'completed',
        sender: sender.id,
        note
      }], { session });
      
      await session.commitTransaction();
      
      await logActivity(sender.id, 'TRANSFER_SEND', `Sent ${amount} to ${recipient.email}`);
      await logActivity(recipient.id, 'TRANSFER_RECEIVE', `Received ${amount} from ${sender.email}`);
      
      res.status(201).json({
        message: 'Transfer completed successfully',
        transaction: senderTx[0]
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to process transfer' });
  }
});

// WebSocket upgrade handler
const server = app.listen(PORT, async () => {
  await initializeAdmin();
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// WebSocket connections
wss.on('connection', (ws, request) => {
  // Authenticate WebSocket connection
  const token = request.url.split('token=')[1];
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    ws.userId = decoded.id;
    
    ws.on('message', (message) => {
      // Handle real-time messages
      try {
        const data = JSON.parse(message);
        // Process different message types (chat, notifications, etc.)
      } catch (err) {
        console.error('Invalid WebSocket message:', err);
      }
    });
    
    ws.on('close', () => {
      // Clean up
    });
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
