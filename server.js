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
const WebSocket = require('ws');
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection - Updated for MongoDB Driver v4.0.0+
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto-arbitrage?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));
mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected successfully');
    
    // Check if any admin exists
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const adminEmail = 'admin@yourdomain.com';
      const adminPassword = 'yourSecurePassword123!';
      const salt = bcrypt.genSaltSync(12);
      const hashedPassword = bcrypt.hashSync(adminPassword, salt);
      
      await Admin.create({
        email: adminEmail,
        password: hashedPassword,
        permissions: ['superadmin']
      });
      
      console.log('Initial admin created:', adminEmail);
    }
  })

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api', limiter);

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true },
  walletProvider: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: {
    USD: { type: Number, default: 0 },
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 }
  },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDetails: {
    legalName: String,
    address: String,
    idFront: String,
    idBack: String,
    selfie: String
  },
  settings: {
    theme: { type: String, default: 'dark' },
    language: { type: String, default: 'en' },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    }
  },
  apiKey: { type: String },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pair: { type: String, required: true },
  type: { type: String, enum: ['buy', 'sell', 'arbitrage'], required: true },
  amount: { type: Number, required: true },
  price: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'canceled'], default: 'pending' },
  profit: { type: Number },
  exchangeFrom: { type: String },
  exchangeTo: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'fee'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  fee: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const ArbitrageOpportunitySchema = new mongoose.Schema({
  pair: { type: String, required: true },
  exchangeFrom: { type: String, required: true },
  exchangeTo: { type: String, required: true },
  buyPrice: { type: Number, required: true },
  sellPrice: { type: Number, required: true },
  profit: { type: Number, required: true },
  expiry: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  attachments: [String],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security'], required: true },
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  permissions: [String],
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const ArbitrageOpportunity = mongoose.model('ArbitrageOpportunity', ArbitrageOpportunitySchema);
const Ticket = mongoose.model('Ticket', TicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// JWT Config
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Utility functions
const createToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

const filterUserData = (user) => {
  const userObj = user.toObject();
  delete userObj.password;
  delete userObj.__v;
  return userObj;
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const ext = file.originalname.split('.').pop();
    cb(null, `${uuidv4()}.${ext}`);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPG, PNG, and PDF are allowed.'), false);
    }
  }
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Auth Middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({ status: 'fail', message: 'You are not logged in! Please log in to get access.' });
  }

  try {
    const decoded = verifyToken(token);
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({ status: 'fail', message: 'The user belonging to this token does no longer exist.' });
    }
    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'fail', message: 'Invalid token. Please log in again.' });
  }
};

const adminProtect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ status: 'fail', message: 'You are not logged in! Please log in to get access.' });
  }

  try {
    const decoded = verifyToken(token);
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin) {
      return res.status(401).json({ status: 'fail', message: 'The admin belonging to this token does no longer exist.' });
    }
    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'fail', message: 'Invalid token. Please log in again.' });
  }
};

// API Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ status: 'fail', message: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      apiKey: crypto.randomBytes(16).toString('hex')
    });

    // Generate token
    const token = createToken(newUser._id);

    // Send welcome email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to Crypto Arbitrage Platform',
      html: `<h1>Welcome ${firstName}!</h1><p>Your account has been successfully created.</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(newUser)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, walletProvider, signature, message } = req.body;
    
    // Verify signature (simplified for example)
    // In production, you would verify the signature against the message and wallet address
    
    // Check if wallet already exists
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ status: 'fail', message: 'Wallet already registered' });
    }

    // Create user
    const newUser = await User.create({
      walletAddress,
      walletProvider,
      apiKey: crypto.randomBytes(16).toString('hex')
    });

    // Generate token
    const token = createToken(newUser._id);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(newUser)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password!' });
    }

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    // 3) If everything ok, send token to client
    const token = createToken(user._id);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature, message } = req.body;
    
    // Verify signature (simplified for example)
    // In production, you would verify the signature against the message and wallet address
    
    // Check if wallet exists
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ status: 'fail', message: 'Wallet not registered' });
    }

    // Generate token
    const token = createToken(user._id);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/auth/verify', protect, async (req, res) => {
  try {
    res.status(200).json({
      status: 'success',
      data: {
        user: filterUserData(req.user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      // For security reasons, we don't reveal if email exists
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    // Create reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // Send email
    const resetURL = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      html: `<p>Click <a href="${resetURL}">here</a> to reset your password</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/auth/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ status: 'fail', message: 'Token is invalid or has expired' });
    }

    user.password = await bcrypt.hash(req.body.password, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const token = createToken(user._id);

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// User Routes
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    res.status(200).json({
      status: 'success',
      data: {
        user: filterUserData(req.user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/users/update-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Your current password is wrong' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    const token = createToken(user._id);

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const { theme, language, notifications } = req.body;
    const user = await User.findById(req.user._id);

    if (theme) user.settings.theme = theme;
    if (language) user.settings.language = language;
    if (notifications) {
      if (notifications.email !== undefined) user.settings.notifications.email = notifications.email;
      if (notifications.push !== undefined) user.settings.notifications.push = notifications.push;
    }

    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/users/kyc', protect, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { legalName, address } = req.body;
    const user = await User.findById(req.user._id);

    if (user.kycStatus === 'verified') {
      return res.status(400).json({ status: 'fail', message: 'KYC already verified' });
    }

    if (!req.files || !req.files.idFront || !req.files.idBack || !req.files.selfie) {
      return res.status(400).json({ status: 'fail', message: 'Please upload all required documents' });
    }

    user.kycDetails = {
      legalName,
      address,
      idFront: req.files.idFront[0].path,
      idBack: req.files.idBack[0].path,
      selfie: req.files.selfie[0].path
    };
    user.kycStatus = 'pending';
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        user: filterUserData(user)
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/users/generate-api-key', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.apiKey = crypto.randomBytes(16).toString('hex');
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        apiKey: user.apiKey
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/users/export-data', protect, async (req, res) => {
  try {
    const user = req.user;
    
    // In a real application, you would queue a job to export all user data
    // and email it to the user when ready
    
    res.status(200).json({
      status: 'success',
      message: 'Data export request received. You will receive an email when your data is ready.'
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.delete('/api/v1/users/delete-account', protect, async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect password' });
    }

    await User.findByIdAndDelete(req.user._id);

    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/balance', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/wallet/deposit-address', protect, async (req, res) => {
  try {
    // In a real application, this would generate a unique deposit address
    // for the user based on the selected cryptocurrency
    const { currency } = req.query;
    const currencies = ['BTC', 'ETH', 'BNB', 'USDT'];
    
    if (!currency || !currencies.includes(currency.toUpperCase())) {
      return res.status(400).json({ status: 'fail', message: 'Invalid currency' });
    }

    // Generate a mock deposit address
    const depositAddress = crypto.randomBytes(10).toString('hex');

    res.status(200).json({
      status: 'success',
      data: {
        currency: currency.toUpperCase(),
        address: depositAddress,
        memo: currency.toUpperCase() === 'BNB' ? req.user._id.toString() : null
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/wallet/deposit', protect, async (req, res) => {
  try {
    const { currency, amount, txHash } = req.body;
    const user = await User.findById(req.user._id);

    if (!currency || !amount || !txHash) {
      return res.status(400).json({ status: 'fail', message: 'Please provide currency, amount, and transaction hash' });
    }

    if (amount <= 0) {
      return res.status(400).json({ status: 'fail', message: 'Amount must be greater than 0' });
    }

    // Create transaction record
    const transaction = await Transaction.create({
      userId: user._id,
      type: 'deposit',
      amount,
      currency,
      txHash,
      status: 'pending'
    });

    // In a real application, you would verify the transaction on the blockchain
    // before updating the user's balance

    res.status(200).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { currency, amount, address } = req.body;
    const user = await User.findById(req.user._id);

    if (!currency || !amount || !address) {
      return res.status(400).json({ status: 'fail', message: 'Please provide currency, amount, and address' });
    }

    if (amount <= 0) {
      return res.status(400).json({ status: 'fail', message: 'Amount must be greater than 0' });
    }

    if (amount < 350) {
      return res.status(400).json({ status: 'fail', message: 'Minimum withdrawal amount is $350' });
    }

    if (user.balance[currency] < amount) {
      return res.status(400).json({ status: 'fail', message: 'Insufficient balance' });
    }

    // In a real application, you would validate the address format
    // based on the cryptocurrency

    // Create transaction record
    const transaction = await Transaction.create({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending'
    });

    // Deduct from user balance (in a real app, this would happen after blockchain confirmation)
    user.balance[currency] -= amount;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', protect, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['pending'] }
    }).sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/trades/history', protect, async (req, res) => {
  try {
    const { limit = 10, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['completed', 'failed', 'canceled'] }
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Trade.countDocuments({
      userId: req.user._id,
      status: { $in: ['completed', 'failed', 'canceled'] }
    });

    res.status(200).json({
      status: 'success',
      results: trades.length,
      total,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/trades/execute', protect, async (req, res) => {
  try {
    const { pair, amount, type } = req.body;
    const user = await User.findById(req.user._id);

    if (!pair || !amount || !type) {
      return res.status(400).json({ status: 'fail', message: 'Please provide pair, amount, and type' });
    }

    if (amount <= 0) {
      return res.status(400).json({ status: 'fail', message: 'Amount must be greater than 0' });
    }

    if (user.balance.USD < 100) {
      return res.status(400).json({ status: 'fail', message: 'Minimum balance of $100 required to trade' });
    }

    // Get current price (in a real app, this would come from an exchange API)
    const price = Math.random() * 10000;

    // Create trade
    const trade = await Trade.create({
      userId: user._id,
      pair,
      type,
      amount,
      price,
      status: 'pending'
    });

    // Create transaction
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount,
      currency: 'USD',
      status: 'pending'
    });

    // Deduct from user balance (in a real app, this would happen after trade execution)
    user.balance.USD -= amount;
    await user.save();

    // Simulate trade completion after 5 seconds
    setTimeout(async () => {
      const profit = amount * 0.05; // 5% profit for demo
      trade.status = 'completed';
      trade.profit = profit;
      trade.completedAt = new Date();
      await trade.save();

      // Update user balance with profit
      user.balance.USD += amount + profit;
      await user.save();

      // Update transaction
      await Transaction.updateOne(
        { userId: user._id, tradeId: trade._id },
        { status: 'completed' }
      );
    }, 5000);

    res.status(200).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Arbitrage Routes
app.get('/api/v1/arbitrage/opportunities', protect, async (req, res) => {
  try {
    // In a real application, these would come from your arbitrage detection system
    const mockOpportunities = [
      {
        pair: 'BTC/USDT',
        exchangeFrom: 'Binance',
        exchangeTo: 'Kraken',
        buyPrice: 50000,
        sellPrice: 50250,
        profit: 250,
        expiry: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes from now
      },
      {
        pair: 'ETH/USDT',
        exchangeFrom: 'Coinbase',
        exchangeTo: 'Binance',
        buyPrice: 3500,
        sellPrice: 3525,
        profit: 25,
        expiry: new Date(Date.now() + 3 * 60 * 1000) // 3 minutes from now
      }
    ];

    res.status(200).json({
      status: 'success',
      results: mockOpportunities.length,
      data: {
        opportunities: mockOpportunities
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/arbitrage/execute', protect, async (req, res) => {
  try {
    const { opportunityId } = req.body;
    const user = await User.findById(req.user._id);

    if (!opportunityId) {
      return res.status(400).json({ status: 'fail', message: 'Please provide opportunityId' });
    }

    if (user.balance.USD < 100) {
      return res.status(400).json({ status: 'fail', message: 'Minimum balance of $100 required to trade' });
    }

    // In a real application, you would fetch the opportunity details
    // and execute the arbitrage trade on the exchanges

    // For demo purposes, we'll use a mock opportunity
    const mockOpportunity = {
      pair: 'BTC/USDT',
      exchangeFrom: 'Binance',
      exchangeTo: 'Kraken',
      buyPrice: 50000,
      sellPrice: 50250,
      profit: 250
    };

    // Create trade
    const trade = await Trade.create({
      userId: user._id,
      pair: mockOpportunity.pair,
      type: 'arbitrage',
      amount: 100, // Fixed $100 for demo
      price: mockOpportunity.buyPrice,
      profit: mockOpportunity.profit,
      exchangeFrom: mockOpportunity.exchangeFrom,
      exchangeTo: mockOpportunity.exchangeTo,
      status: 'pending'
    });

    // Create transaction
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount: 100,
      currency: 'USD',
      status: 'pending'
    });

    // Deduct from user balance (in a real app, this would happen after trade execution)
    user.balance.USD -= 100;
    await user.save();

    // Simulate trade completion after 5 seconds
    setTimeout(async () => {
      trade.status = 'completed';
      trade.completedAt = new Date();
      await trade.save();

      // Update user balance with profit
      user.balance.USD += 100 + mockOpportunity.profit;
      await user.save();

      // Update transaction
      await Transaction.updateOne(
        { userId: user._id, tradeId: trade._id },
        { status: 'completed' }
      );
    }, 5000);

    res.status(200).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Transaction Routes
app.get('/api/v1/transactions/recent', protect, async (req, res) => {
  try {
    const { limit = 5 } = req.query;
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/transactions/history', protect, async (req, res) => {
  try {
    const { limit = 10, page = 1, type } = req.query;
    const skip = (page - 1) * limit;

    const query = { userId: req.user._id };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const { category } = req.query;
    const query = category ? { category } : {};

    const faqs = await FAQ.find(query).sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: faqs.length,
      data: {
        faqs
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/support/tickets', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files ? req.files.map(file => file.path) : [];

    if (!subject || !message) {
      return res.status(400).json({ status: 'fail', message: 'Please provide subject and message' });
    }

    const ticket = await Ticket.create({
      userId: req.user._id,
      subject,
      message,
      attachments
    });

    res.status(201).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user._id }).sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/support/tickets/:id', protect, async (req, res) => {
  try {
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/support/tickets/:id/response', protect, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ status: 'fail', message: 'Please provide a message' });
    }

    const ticket = await Ticket.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user._id
      },
      {
        $push: {
          responses: {
            userId: req.user._id,
            message
          }
        },
        $set: { updatedAt: new Date() }
      },
      { new: true }
    );

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password!' });
    }

    const admin = await Admin.findOne({ email }).select('+password');

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    const token = createToken(admin._id);

    admin.lastLogin = new Date();
    await admin.save();

    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin: {
          _id: admin._id,
          email: admin.email,
          permissions: admin.permissions,
          lastLogin: admin.lastLogin,
          createdAt: admin.createdAt
        }
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ kycStatus: 'verified' });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          totalUsers,
          verifiedUsers,
          totalTrades,
          totalVolume: totalVolume.length ? totalVolume[0].total : 0
        }
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/users', adminProtect, async (req, res) => {
  try {
    const { limit = 10, page = 1, search, status } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.kycStatus = status;

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -__v');

    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -__v');
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/admin/users/:id/verify', adminProtect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'verified' },
      { new: true }
    ).select('-password -__v');

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/admin/users/:id/suspend', adminProtect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isSuspended: true },
      { new: true }
    ).select('-password -__v');

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/trades', adminProtect, async (req, res) => {
  try {
    const { limit = 10, page = 1, status, type } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (status) query.status = status;
    if (type) query.type = type;

    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Trade.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: trades.length,
      total,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/transactions', adminProtect, async (req, res) => {
  try {
    const { limit = 10, page = 1, type, status } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;

    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/tickets', adminProtect, async (req, res) => {
  try {
    const { limit = 10, page = 1, status } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (status) query.status = status;

    const tickets = await Ticket.find(query)
      .populate('userId', 'firstName lastName email')
      .populate('responses.userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Ticket.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: tickets.length,
      total,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.patch('/api/v1/admin/tickets/:id', adminProtect, async (req, res) => {
  try {
    const { status, priority } = req.body;

    const update = {};
    if (status) update.status = status;
    if (priority) update.priority = priority;

    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true }
    )
      .populate('userId', 'firstName lastName email')
      .populate('responses.userId', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/admin/tickets/:id/response', adminProtect, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ status: 'fail', message: 'Please provide a message' });
    }

    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      {
        $push: {
          responses: {
            userId: req.admin._id,
            message
          }
        },
        $set: { updatedAt: new Date(), status: 'pending' }
      },
      { new: true }
    )
      .populate('userId', 'firstName lastName email')
      .populate('responses.userId', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/admin/broadcast', adminProtect, async (req, res) => {
  try {
    const { message, target } = req.body;

    if (!message) {
      return res.status(400).json({ status: 'fail', message: 'Please provide a message' });
    }

    // In a real application, you would send this message to all targeted users
    // via email, push notification, or WebSocket

    res.status(200).json({
      status: 'success',
      message: 'Broadcast message queued for delivery'
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  try {
    const decoded = verifyToken(token);
    ws.userId = decoded.id;
  } catch (err) {
    ws.close(1008, 'Invalid token');
    return;
  }

  ws.on('message', (message) => {
    // Handle incoming WebSocket messages
    console.log(`Received message from user ${ws.userId}: ${message}`);
  });

  // Send initial connection confirmation
  ws.send(JSON.stringify({ type: 'connection', status: 'success' }));
});

// Upgrade HTTP server to WebSocket
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Utility function to broadcast to all connected clients
const broadcast = (data) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

// Utility function to send to specific user
const sendToUser = (userId, data) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.userId === userId) {
      client.send(JSON.stringify(data));
    }
  });
};

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  server.close(() => {
    process.exit(1);
  });
});
