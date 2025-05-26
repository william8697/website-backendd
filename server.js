require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const WebSocket = require('ws');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect('mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  walletAddress: { type: String, unique: true, sparse: true },
  nonce: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  portfolio: {
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 },
    SOL: { type: Number, default: 0 },
    XRP: { type: Number, default: 0 },
    ADA: { type: Number, default: 0 },
    DOGE: { type: Number, default: 0 },
    DOT: { type: Number, default: 0 },
    SHIB: { type: Number, default: 0 },
    AVAX: { type: Number, default: 0 }
  },
  isAdmin: { type: Boolean, default: false },
  apiKey: { type: String },
  kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  kycDocs: [{
    docType: String,
    docUrl: String,
    uploadedAt: Date
  }],
  settings: {
    theme: { type: String, default: 'light' },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false }
  },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'transfer'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true },
  order: { type: Number, default: 0 }
});

const AdminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: { type: String },
  details: { type: Object },
  ip: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);
const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// Email Configuration
const transporter = nodemailer.createTransport({
  host: 'sandbox.sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Helper Functions
const generateNonce = () => crypto.randomBytes(16).toString('hex');
const generateApiKey = () => crypto.randomBytes(32).toString('hex');

// Coin Price Data (simulated)
const coinPrices = {
  BTC: 50000,
  ETH: 3000,
  BNB: 400,
  SOL: 100,
  XRP: 0.5,
  ADA: 0.4,
  DOGE: 0.1,
  DOT: 7,
  SHIB: 0.00001,
  AVAX: 30
};

// Auth Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || !user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// Routes

// Core Authentication & Session
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency: currency || 'USD'
    });

    await user.save();
    const token = generateToken(user);

    return res.status(201).json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ success: false, message: 'Wallet address and signature required' });
    }

    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Wallet already registered' });
    }

    // In a real app, you would verify the signature here
    const user = new User({
      firstName,
      lastName,
      walletAddress,
      country,
      currency: currency || 'USD',
      nonce: generateNonce()
    });

    await user.save();
    const token = generateToken(user);

    return res.status(201).json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();
    const token = generateToken(user);

    return res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', authenticate, (req, res) => {
  return res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/v1/auth/me', authenticate, (req, res) => {
  const user = req.user;
  return res.json({ 
    success: true, 
    user: {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      walletAddress: user.walletAddress,
      balance: user.balance,
      portfolio: user.portfolio,
      settings: user.settings,
      kycStatus: user.kycStatus
    }
  });
});

app.get('/auth/verify', authenticate, (req, res) => {
  return res.json({ success: true, message: 'Token is valid' });
});

app.get('/api/v1/auth/status', authenticate, (req, res) => {
  return res.json({ success: true, isAuthenticated: true, isAdmin: req.user.isAdmin });
});

app.get('/api/v1/auth/check', authenticate, (req, res) => {
  return res.json({ success: true, message: 'Session is valid' });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `You requested a password reset. Click <a href="${resetUrl}">here</a> to reset your password.`
    });

    return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Wallet not registered' });
    }

    const nonce = generateNonce();
    user.nonce = nonce;
    await user.save();

    return res.json({ success: true, nonce });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    const user = await User.findOne({ walletAddress });
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Wallet not registered' });
    }

    // In a real app, you would verify the signature against the nonce here
    user.lastLogin = new Date();
    await user.save();
    const token = generateToken(user);

    return res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// User Management
app.get('/api/v1/users/me', authenticate, (req, res) => {
  const user = req.user;
  return res.json({ 
    success: true, 
    user: {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      walletAddress: user.walletAddress,
      balance: user.balance,
      portfolio: user.portfolio,
      settings: user.settings,
      kycStatus: user.kycStatus,
      kycDocs: user.kycDocs
    }
  });
});

app.get('/api/v1/users/settings', authenticate, (req, res) => {
  return res.json({ success: true, settings: req.user.settings });
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { settings } = req.body;
    const user = req.user;
    
    user.settings = { ...user.settings, ...settings };
    await user.save();

    return res.json({ success: true, settings: user.settings });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/auth/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;
    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.array('documents'), async (req, res) => {
  try {
    const user = req.user;
    const { docType } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ success: false, message: 'No documents uploaded' });
    }

    const docUrls = files.map(file => `/uploads/${file.filename}`);
    
    user.kycDocs.push({
      docType,
      docUrl: docUrls[0],
      uploadedAt: new Date()
    });
    user.kycStatus = 'pending';
    await user.save();

    return res.json({ success: true, message: 'KYC documents submitted for review' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = req.user;
    user.apiKey = generateApiKey();
    await user.save();

    return res.json({ success: true, apiKey: user.apiKey });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = req.user;
    // In a real app, you would generate a comprehensive data export here
    return res.json({ 
      success: true, 
      data: {
        user: {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          walletAddress: user.walletAddress,
          balance: user.balance,
          portfolio: user.portfolio,
          settings: user.settings
        },
        message: 'Data export generated successfully'
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    return res.json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isAdmin: true });
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();
    const token = generateToken(user);

    return res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
  return res.json({ success: true, isAdmin: true });
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    return res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        totalTrades,
        totalVolume: totalVolume[0]?.total || 0,
        kycPending: await User.countDocuments({ kycStatus: 'pending' }),
        openTickets: await Ticket.countDocuments({ status: 'open' })
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = search 
      ? {
          $or: [
            { firstName: { $regex: search, $options: 'i' } },
            { lastName: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
            { walletAddress: { $regex: search, $options: 'i' } }
          ]
        }
      : {};
    
    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -nonce -resetPasswordToken -resetPasswordExpires');
    
    const total = await User.countDocuments(query);
    
    return res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -nonce -resetPasswordToken -resetPasswordExpires');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    
    return res.json({
      success: true,
      user,
      trades,
      transactions
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { balance, kycStatus, isAdmin } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (balance !== undefined) user.balance = balance;
    if (kycStatus !== undefined) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    
    await user.save();
    
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_user',
      target: user.email,
      details: req.body,
      ip: req.ip
    });
    
    return res.json({ success: true, message: 'User updated successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    const query = status ? { status } : {};
    
    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Trade.countDocuments(query);
    
    return res.json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = type ? { type } : {};
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    return res.json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    return res.json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = req.body;
    const ticket = await Ticket.findById(req.params.id);
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    if (status) ticket.status = status;
    if (response) {
      ticket.responses.push({
        message: response,
        isAdmin: true
      });
    }
    
    await ticket.save();
    
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_ticket',
      target: ticket.subject,
      details: req.body,
      ip: req.ip
    });
    
    return res.json({ success: true, message: 'Ticket updated successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('kycStatus kycDocs firstName lastName email');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    return res.json({ success: true, kyc: user });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const { kycStatus } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.kycStatus = kycStatus;
    await user.save();
    
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_kyc',
      target: user.email,
      details: req.body,
      ip: req.ip
    });
    
    return res.json({ success: true, message: 'KYC status updated successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    
    const logs = await AdminLog.find()
      .populate('adminId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await AdminLog.countDocuments();
    
    return res.json({
      success: true,
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    // In a real app, you would send this to all connected WebSocket clients
    await AdminLog.create({
      adminId: req.user._id,
      action: 'broadcast',
      details: { message },
      ip: req.ip
    });
    
    return res.json({ success: true, message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would fetch these from a dedicated settings collection
    return res.json({
      success: true,
      settings: {
        maintenanceMode: false,
        depositEnabled: true,
        withdrawalEnabled: true,
        tradingEnabled: true,
        signupEnabled: true,
        maxWithdrawal: 10000,
        minDeposit: 10
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const settings = req.body;
    
    // In a real app, you would save these to a dedicated settings collection
    await AdminLog.create({
      adminId: req.user._id,
      action: 'update_settings',
      details: settings,
      ip: req.ip
    });
    
    return res.json({ success: true, message: 'Settings updated successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Exchange & Market
app.get('/exchange/coins', (req, res) => {
  return res.json({
    success: true,
    coins: Object.keys(coinPrices).map(symbol => ({
      symbol,
      name: {
        BTC: 'Bitcoin',
        ETH: 'Ethereum',
        BNB: 'Binance Coin',
        SOL: 'Solana',
        XRP: 'Ripple',
        ADA: 'Cardano',
        DOGE: 'Dogecoin',
        DOT: 'Polkadot',
        SHIB: 'Shiba Inu',
        AVAX: 'Avalanche'
      }[symbol],
      price: coinPrices[symbol],
      change24h: (Math.random() * 20 - 10).toFixed(2)
    }))
  });
});

app.get('/exchange/rates', (req, res) => {
  const rates = {};
  const coins = Object.keys(coinPrices);
  
  for (const from of coins) {
    rates[from] = {};
    for (const to of coins) {
      if (from === to) {
        rates[from][to] = 1;
      } else {
        rates[from][to] = (coinPrices[from] / coinPrices[to]).toFixed(8);
      }
    }
  }
  
  return res.json({ success: true, rates });
});

app.get('/exchange/rate', (req, res) => {
  const { from, to } = req.query;
  
  if (!from || !to || !coinPrices[from] || !coinPrices[to]) {
    return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
  }
  
  const rate = (coinPrices[from] / coinPrices[to]).toFixed(8);
  return res.json({ success: true, from, to, rate });
});

app.post('/exchange/convert', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid parameters' });
    }
    
    if (!coinPrices[from] || !coinPrices[to]) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
    }
    
    const user = req.user;
    const fromBalance = user.portfolio[from] || 0;
    
    if (fromBalance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const rate = coinPrices[from] / coinPrices[to];
    const convertedAmount = amount * rate;
    
    // Update user portfolio
    user.portfolio[from] = (user.portfolio[from] || 0) - amount;
    user.portfolio[to] = (user.portfolio[to] || 0) + convertedAmount;
    await user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    await trade.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount,
      currency: from,
      status: 'completed'
    });
    await transaction.save();
    
    return res.json({
      success: true,
      from,
      to,
      amount,
      convertedAmount,
      rate,
      newFromBalance: user.portfolio[from],
      newToBalance: user.portfolio[to]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/exchange/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    return res.json({ success: true, trades });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/market/data', (req, res) => {
  const coins = Object.keys(coinPrices).map(symbol => ({
    symbol,
    name: {
      BTC: 'Bitcoin',
      ETH: 'Ethereum',
      BNB: 'Binance Coin',
      SOL: 'Solana',
      XRP: 'Ripple',
      ADA: 'Cardano',
      DOGE: 'Dogecoin',
      DOT: 'Polkadot',
      SHIB: 'Shiba Inu',
      AVAX: 'Avalanche'
    }[symbol],
    price: coinPrices[symbol],
    change24h: (Math.random() * 20 - 10).toFixed(2),
    volume: (Math.random() * 1000000).toFixed(2),
    marketCap: (coinPrices[symbol] * (Math.random() * 10000000)).toFixed(2)
  }));
  
  return res.json({ success: true, marketData: coins });
});

app.get('/market/detailed', (req, res) => {
  const coins = Object.keys(coinPrices).map(symbol => ({
    symbol,
    name: {
      BTC: 'Bitcoin',
      ETH: 'Ethereum',
      BNB: 'Binance Coin',
      SOL: 'Solana',
      XRP: 'Ripple',
      ADA: 'Cardano',
      DOGE: 'Dogecoin',
      DOT: 'Polkadot',
      SHIB: 'Shiba Inu',
      AVAX: 'Avalanche'
    }[symbol],
    price: coinPrices[symbol],
    change24h: (Math.random() * 20 - 10).toFixed(2),
    change7d: (Math.random() * 30 - 15).toFixed(2),
    high24h: (coinPrices[symbol] * 1.1).toFixed(2),
    low24h: (coinPrices[symbol] * 0.9).toFixed(2),
    volume: (Math.random() * 1000000).toFixed(2),
    marketCap: (coinPrices[symbol] * (Math.random() * 10000000)).toFixed(2),
    circulatingSupply: (Math.random() * 1000000).toFixed(2),
    allTimeHigh: (coinPrices[symbol] * 1.5).toFixed(2),
    allTimeLow: (coinPrices[symbol] * 0.5).toFixed(2)
  }));
  
  return res.json({ success: true, detailedMarketData: coins });
});

// Wallet & Portfolio
app.get('/wallet/deposit-address', authenticate, (req, res) => {
  return res.json({
    success: true,
    address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
    memo: `User ID: ${req.user._id}`
  });
});

app.post('/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { amount, address } = req.body;
    const user = req.user;
    
    if (!amount || amount <= 0 || !address) {
      return res.status(400).json({ success: false, message: 'Invalid parameters' });
    }
    
    if (user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    user.balance -= amount;
    await user.save();
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      address
    });
    await transaction.save();
    
    return res.json({
      success: true,
      message: 'Withdrawal request submitted',
      newBalance: user.balance,
      transactionId: transaction._id
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/portfolio', authenticate, (req, res) => {
  const user = req.user;
  const portfolio = Object.entries(user.portfolio)
    .filter(([_, balance]) => balance > 0)
    .map(([symbol, balance]) => ({
      symbol,
      name: {
        BTC: 'Bitcoin',
        ETH: 'Ethereum',
        BNB: 'Binance Coin',
        SOL: 'Solana',
        XRP: 'Ripple',
        ADA: 'Cardano',
        DOGE: 'Dogecoin',
        DOT: 'Polkadot',
        SHIB: 'Shiba Inu',
        AVAX: 'Avalanche'
      }[symbol],
      balance,
      value: (balance * coinPrices[symbol]).toFixed(2),
      change24h: (Math.random() * 20 - 10).toFixed(2)
    }));
  
  return res.json({
    success: true,
    portfolio,
    totalValue: portfolio.reduce((sum, item) => sum + parseFloat(item.value), 0).toFixed(2),
    balance: user.balance
  });
});

// Trading
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid parameters' });
    }
    
    if (!coinPrices[from] || !coinPrices[to]) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
    }
    
    const user = req.user;
    const fromBalance = user.portfolio[from] || 0;
    
    if (fromBalance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const rate = coinPrices[from] / coinPrices[to];
    const convertedAmount = amount * rate;
    
    // Update user portfolio
    user.portfolio[from] = (user.portfolio[from] || 0) - amount;
    user.portfolio[to] = (user.portfolio[to] || 0) + convertedAmount;
    await user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    await trade.save();
    
    return res.json({
      success: true,
      from,
      to,
      amount,
      convertedAmount,
      rate,
      newFromBalance: user.portfolio[from],
      newToBalance: user.portfolio[to]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid parameters' });
    }
    
    if (!coinPrices[from] || !coinPrices[to]) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
    }
    
    const user = req.user;
    const fromBalance = user.portfolio[from] || 0;
    
    if (fromBalance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const rate = coinPrices[from] / coinPrices[to];
    const convertedAmount = amount * rate;
    
    // Update user portfolio
    user.portfolio[from] = (user.portfolio[from] || 0) - amount;
    user.portfolio[to] = (user.portfolio[to] || 0) + convertedAmount;
    await user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      type: 'sell',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    await trade.save();
    
    return res.json({
      success: true,
      from,
      to,
      amount,
      convertedAmount,
      rate,
      newFromBalance: user.portfolio[from],
      newToBalance: user.portfolio[to]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'pending' })
      .sort({ createdAt: -1 })
      .limit(10);
    
    return res.json({ success: true, trades });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    return res.json({ success: true, transactions });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Support & Contact
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ order: 1 });
    return res.json({ success: true, faqs });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support/contact', async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    
    if (!email || !subject || !message) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const ticket = new Ticket({
      email,
      subject,
      message,
      status: 'open'
    });
    await ticket.save();
    
    return res.json({ success: true, message: 'Support ticket submitted successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const ticket = new Ticket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      status: 'open'
    });
    await ticket.save();
    
    return res.json({ success: true, message: 'Support ticket submitted successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    return res.json({ success: true, tickets });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support', authenticate, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const files = req.files;
    
    if (!subject || !message) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const attachments = files?.map(file => `/uploads/${file.filename}`) || [];
    
    const ticket = new Ticket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    await ticket.save();
    
    return res.json({ success: true, message: 'Support ticket submitted successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Team & Stats
app.get('/api/v1/team', (req, res) => {
  return res.json({
    success: true,
    team: [
      {
        name: 'John Doe',
        role: 'CEO & Founder',
        bio: 'Blockchain expert with 10+ years of experience in cryptocurrency trading and platform development.',
        image: '/images/team/john.jpg'
      },
      {
        name: 'Jane Smith',
        role: 'CTO',
        bio: 'Software architect specializing in secure trading systems and high-performance backend infrastructure.',
        image: '/images/team/jane.jpg'
      },
      {
        name: 'Mike Johnson',
        role: 'Lead Developer',
        bio: 'Full-stack developer with expertise in blockchain integration and real-time trading systems.',
        image: '/images/team/mike.jpg'
      },
      {
        name: 'Sarah Williams',
        role: 'Customer Support',
        bio: 'Dedicated support specialist ensuring our users have the best experience with our platform.',
        image: '/images/team/sarah.jpg'
      }
    ]
  });
});

app.get('/api/v1/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    return res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers: Math.floor(totalUsers * 0.7),
        totalTrades,
        totalVolume: totalVolume[0]?.total || 0,
        dailyVolume: (totalVolume[0]?.total || 0) / 30,
        supportedCoins: Object.keys(coinPrices).length
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Serve static files (for uploads)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection');
  
  // Authenticate via token from query params
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }
  
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      ws.close(1008, 'Invalid token');
      return;
    }
    
    const user = await User.findById(decoded.id);
    if (!user) {
      ws.close(1008, 'User not found');
      return;
    }
    
    // Store user info on the WebSocket connection
    ws.user = {
      id: user._id,
      isAdmin: user.isAdmin
    };
    
    // Send initial balance update
    ws.send(JSON.stringify({
      type: 'balance_update',
      data: {
        balance: user.balance,
        portfolio: user.portfolio
      }
    }));
    
    // Handle messages
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        
        if (data.type === 'subscribe') {
          // Handle subscription requests
          ws.subscriptions = data.channels;
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
      }
    });
    
    // Simulate real-time updates
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        // Send market data updates
        const marketUpdate = {};
        for (const symbol in coinPrices) {
          const change = (Math.random() * 0.2 - 0.1);
          coinPrices[symbol] *= (1 + change);
          marketUpdate[symbol] = {
            price: coinPrices[symbol],
            change24h: (change * 100).toFixed(2)
          };
        }
        
        ws.send(JSON.stringify({
          type: 'market_update',
          data: marketUpdate
        }));
        
        // Send portfolio updates if subscribed
        if (ws.subscriptions?.includes('portfolio')) {
          ws.send(JSON.stringify({
            type: 'portfolio_update',
            data: {
              balance: user.balance,
              portfolio: user.portfolio
            }
          }));
        }
      } else {
        clearInterval(interval);
      }
    }, 5000);
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

// Admin WebSocket
const adminWss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  if (request.url === '/api/v1/admin/ws') {
    adminWss.handleUpgrade(request, socket, head, (ws) => {
      adminWss.emit('connection', ws, request);
    });
  } else {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  }
});

adminWss.on('connection', (ws, req) => {
  console.log('New Admin WebSocket connection');
  
  const token = req.headers['sec-websocket-protocol'];
  
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }
  
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err || !decoded.isAdmin) {
      ws.close(1008, 'Admin access required');
      return;
    }
    
    const user = await User.findById(decoded.id);
    if (!user || !user.isAdmin) {
      ws.close(1008, 'Admin not found');
      return;
    }
    
    ws.user = {
      id: user._id,
      isAdmin: true
    };
    
    // Send initial admin stats
    const stats = {
      totalUsers: await User.countDocuments(),
      activeUsers: await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
      totalTrades: await Trade.countDocuments(),
      openTickets: await Ticket.countDocuments({ status: 'open' }),
      pendingKyc: await User.countDocuments({ kycStatus: 'pending' })
    };
    
    ws.send(JSON.stringify({
      type: 'admin_stats',
      data: stats
    }));
    
    // Handle admin messages
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        
        if (data.type === 'broadcast' && data.message) {
          // Broadcast to all connected clients
          wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({
                type: 'admin_broadcast',
                message: data.message
              }));
            }
          });
        }
      } catch (err) {
        console.error('Admin WebSocket message error:', err);
      }
    });
    
    // Simulate real-time admin updates
    const interval = setInterval(async () => {
      if (ws.readyState === WebSocket.OPEN) {
        const stats = {
          totalUsers: await User.countDocuments(),
          activeUsers: await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
          totalTrades: await Trade.countDocuments(),
          openTickets: await Ticket.countDocuments({ status: 'open' }),
          pendingKyc: await User.countDocuments({ kycStatus: 'pending' })
        };
        
        ws.send(JSON.stringify({
          type: 'admin_stats',
          data: stats
        }));
      } else {
        clearInterval(interval);
      }
    }, 10000);
  });
  
  ws.on('close', () => {
    console.log('Admin WebSocket connection closed');
  });
});
