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
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();

// MongoDB connection
const DB = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(DB, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
}).then(() => console.log('DB connection successful!'));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter);

// Models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  walletAddress: String,
  walletProvider: String,
  country: String,
  currency: { type: String, default: 'USD' },
  balance: {
    USD: { type: Number, default: 0 },
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 }
  },
  kycStatus: { type: String, enum: ['unverified', 'pending', 'verified', 'rejected'], default: 'unverified' },
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
  apiKey: String,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now },
  active: { type: Boolean, default: true }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pair: { type: String, required: true },
  type: { type: String, enum: ['buy', 'sell', 'arbitrage'], required: true },
  amount: { type: Number, required: true },
  price: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'canceled'], default: 'pending' },
  profit: Number,
  exchangeFrom: String,
  exchangeTo: String,
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'fee', 'bonus'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  address: String,
  txHash: String,
  fee: Number,
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
}));

const ArbitrageOpportunity = mongoose.model('ArbitrageOpportunity', new mongoose.Schema({
  pair: { type: String, required: true },
  exchangeFrom: { type: String, required: true },
  exchangeTo: { type: String, required: true },
  buyPrice: { type: Number, required: true },
  sellPrice: { type: Number, required: true },
  profit: { type: Number, required: true },
  expiry: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved', 'closed'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  attachments: [String],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security'], required: true },
  createdAt: { type: Date, default: Date.now }
}));

const Admin = mongoose.model('Admin', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  role: { type: String, enum: ['support', 'moderator', 'admin', 'superadmin'], default: 'support' },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
}));

const ActivityLog = mongoose.model('ActivityLog', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
}));

// JWT Config
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '90d';
const COOKIE_EXPIRES = 90 * 24 * 60 * 60 * 1000;

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});

// File upload
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, `${file.fieldname}-${Date.now()}${ext}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed!'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Utility functions
const signToken = id => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(Date.now() + COOKIE_EXPIRES),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none'
  };
  
  res.cookie('jwt', token, cookieOptions);
  
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

// Authentication middleware
const protect = async (req, res, next) => {
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
  
  try {
    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id);
    
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token does no longer exist.'
      });
    }
    
    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token! Please log in again.'
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
      status: 'fail',
      message: 'You are not logged in! Please log in to get access.'
    });
  }
  
  try {
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
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token! Please log in again.'
    });
  }
};

// Routes

// Authentication Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, passwordConfirm, country, currency } = req.body;
    
    if (password !== passwordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match!'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use!'
      });
    }
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, walletProvider, signature, country, currency } = req.body;
    
    // Verify signature here (implementation depends on your wallet provider)
    
    const newUser = await User.create({
      walletAddress,
      walletProvider,
      country,
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet already registered!'
      });
    }
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password!'
      });
    }
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password!'
      });
    }
    
    user.lastLogin = Date.now();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature here
    
    const user = await User.findOne({ walletAddress });
    
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'No user found with this wallet address!'
      });
    }
    
    user.lastLogin = Date.now();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/auth/verify', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user
    }
  });
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
    const user = await User.findOne({ email: req.body.email });
    
    if (!user) {
      // Always return success to prevent email enumeration
      return res.status(200).json({
        status: 'success',
        message: 'Password reset link sent to email!'
      });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    const passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    await User.findByIdAndUpdate(user._id, {
      passwordResetToken,
      passwordResetExpires
    });
    
    const resetURL = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
    
    try {
      await transporter.sendMail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message
      });
      
      res.status(200).json({
        status: 'success',
        message: 'Password reset link sent to email!'
      });
    } catch (err) {
      await User.findByIdAndUpdate(user._id, {
        passwordResetToken: undefined,
        passwordResetExpires: undefined
      });
      
      res.status(500).json({
        status: 'error',
        message: 'There was an error sending the email. Try again later!'
      });
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
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
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }
    
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/auth/update-password', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+password');
    
    if (!(await bcrypt.compare(req.body.currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong!'
      });
    }
    
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// User Routes
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
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

app.patch('/api/v1/users/update-me', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'country',
      'currency'
    );
    
    const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(
      req.body,
      'settings.theme',
      'settings.language',
      'settings.notifications.email',
      'settings.notifications.push'
    );
    
    const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/users/kyc', protect, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { legalName, address } = req.body;
    
    const kycDetails = {
      legalName,
      address,
      idFront: req.files.idFront ? req.files.idFront[0].path : undefined,
      idBack: req.files.idBack ? req.files.idBack[0].path : undefined,
      selfie: req.files.selfie ? req.files.selfie[0].path : undefined
    };
    
    const updatedUser = await User.findByIdAndUpdate(req.user._id, {
      kycDetails,
      kycStatus: 'pending'
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/users/generate-api-key', protect, async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(32).toString('hex');
    
    const updatedUser = await User.findByIdAndUpdate(req.user._id, {
      apiKey
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        apiKey
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/users/export-data', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id });
    
    const data = {
      user,
      trades,
      transactions
    };
    
    // In a real app, you would save this to a file and email it
    res.status(200).json({
      status: 'success',
      data
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.delete('/api/v1/users/delete-account', protect, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { active: false });
    
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
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
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/wallet/deposit-address', protect, async (req, res) => {
  try {
    // In a real app, this would generate a unique deposit address for the user
    const depositAddress = crypto.randomBytes(20).toString('hex');
    
    res.status(200).json({
      status: 'success',
      data: {
        address: depositAddress
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/wallet/deposit', protect, async (req, res) => {
  try {
    const { amount, currency, txHash } = req.body;
    
    if (!['USD', 'BTC', 'ETH', 'BNB'].includes(currency)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid currency!'
      });
    }
    
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'deposit',
      amount,
      currency,
      txHash,
      status: 'pending'
    });
    
    // In a real app, you would verify the transaction on the blockchain
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { amount, currency, address } = req.body;
    
    if (!['USD', 'BTC', 'ETH', 'BNB'].includes(currency)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid currency!'
      });
    }
    
    const user = await User.findById(req.user._id);
    
    if (user.balance[currency] < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance!'
      });
    }
    
    // Minimum withdrawal amount check
    if (amount < (currency === 'USD' ? 350 : 0.01)) {
      return res.status(400).json({
        status: 'fail',
        message: `Minimum withdrawal amount is ${currency === 'USD' ? '$350' : '0.01'}!`
      });
    }
    
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending'
    });
    
    // In a real app, you would process the withdrawal
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', protect, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['pending'] }
    }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/trades/history', protect, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['completed', 'failed', 'canceled'] }
    }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/trades/execute', protect, async (req, res) => {
  try {
    const { pair, type, amount } = req.body;
    
    const user = await User.findById(req.user._id);
    
    if (user.balance.USD < 100) {
      return res.status(400).json({
        status: 'fail',
        message: 'Minimum $100 balance required for trading!'
      });
    }
    
    // Get current price from exchange API (simulated here)
    const price = Math.random() * 10000;
    
    const trade = await Trade.create({
      userId: req.user._id,
      pair,
      type,
      amount,
      price,
      status: 'pending'
    });
    
    // In a real app, you would execute the trade on the exchange
    
    res.status(201).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Arbitrage Routes
app.get('/api/v1/arbitrage/opportunities', protect, async (req, res) => {
  try {
    const opportunities = await ArbitrageOpportunity.find({
      expiry: { $gt: Date.now() }
    }).sort('-profit');
    
    res.status(200).json({
      status: 'success',
      results: opportunities.length,
      data: {
        opportunities
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/arbitrage/execute', protect, async (req, res) => {
  try {
    const { opportunityId } = req.body;
    
    const opportunity = await ArbitrageOpportunity.findById(opportunityId);
    
    if (!opportunity || opportunity.expiry < Date.now()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Opportunity no longer available!'
      });
    }
    
    const user = await User.findById(req.user._id);
    
    if (user.balance.USD < 100) {
      return res.status(400).json({
        status: 'fail',
        message: 'Minimum $100 balance required for arbitrage!'
      });
    }
    
    const trade = await Trade.create({
      userId: req.user._id,
      pair: opportunity.pair,
      type: 'arbitrage',
      amount: opportunity.buyPrice * 0.95, // Example calculation
      price: opportunity.buyPrice,
      profit: opportunity.profit,
      exchangeFrom: opportunity.exchangeFrom,
      exchangeTo: opportunity.exchangeTo,
      status: 'pending'
    });
    
    // In a real app, you would execute the arbitrage trade
    
    res.status(201).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Transaction Routes
app.get('/api/v1/transactions/recent', protect, async (req, res) => {
  try {
    const transactions = await Transaction.find({
      userId: req.user._id
    }).sort('-createdAt').limit(10);
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/transactions/history', protect, async (req, res) => {
  try {
    const transactions = await Transaction.find({
      userId: req.user._id
    }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find();
    
    res.status(200).json({
      status: 'success',
      results: faqs.length,
      data: {
        faqs
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/support/tickets', protect, upload.array('attachments', 5), async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments: req.files ? req.files.map(file => file.path) : []
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({
      userId: req.user._id
    }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/support/tickets/:id', protect, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID!'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/support/tickets/:id/respond', protect, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findOneAndUpdate({
      _id: req.params.id,
      userId: req.user._id
    }, {
      $push: {
        responses: {
          userId: req.user._id,
          message,
          isAdmin: false
        }
      },
      status: 'pending',
      updatedAt: Date.now()
    }, {
      new: true
    });
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID!'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password!'
      });
    }
    
    const admin = await Admin.findOne({ email }).select('+password');
    
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password!'
      });
    }
    
    admin.lastLogin = Date.now();
    await admin.save();
    
    const token = signToken(admin._id);
    const cookieOptions = {
      expires: new Date(Date.now() + COOKIE_EXPIRES),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none'
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
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const verifiedUsersCount = await User.countDocuments({ kycStatus: 'verified' });
    const tradesCount = await Trade.countDocuments();
    const transactionsVolume = await Transaction.aggregate([
      { $match: { type: 'trade', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.status(200).json({
      status: 'success',
      data: {
        users: usersCount,
        verifiedUsers: verifiedUsersCount,
        trades: tradesCount,
        volume: transactionsVolume[0] ? transactionsVolume[0].total : 0
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users', adminProtect, async (req, res) => {
  try {
    const query = {};
    
    if (req.query.search) {
      query.$or = [
        { email: { $regex: req.query.search, $options: 'i' } },
        { firstName: { $regex: req.query.search, $options: 'i' } },
        { lastName: { $regex: req.query.search, $options: 'i' } },
        { walletAddress: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    
    if (req.query.status) {
      query.active = req.query.status === 'active';
    }
    
    if (req.query.kycStatus) {
      query.kycStatus = req.query.kycStatus;
    }
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const users = await User.find(query).skip(skip).limit(limit);
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID!'
      });
    }
    
    const trades = await Trade.find({ userId: user._id }).sort('-createdAt').limit(5);
    const transactions = await Transaction.find({ userId: user._id }).sort('-createdAt').limit(5);
    
    res.status(200).json({
      status: 'success',
      data: {
        user,
        trades,
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const { active, kycStatus } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(req.params.id, {
      active,
      kycStatus
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/users/:id/reset-password', adminProtect, async (req, res) => {
  try {
    const newPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    await User.findByIdAndUpdate(req.params.id, {
      password: hashedPassword
    });
    
    // In a real app, you would email the new password to the user
    
    res.status(200).json({
      status: 'success',
      data: {
        password: newPassword
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/trades', adminProtect, async (req, res) => {
  try {
    const query = {};
    
    if (req.query.userId) {
      query.userId = req.query.userId;
    }
    
    if (req.query.status) {
      query.status = req.query.status;
    }
    
    if (req.query.type) {
      query.type = req.query.type;
    }
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find(query).skip(skip).limit(limit).populate('userId');
    const total = await Trade.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/transactions', adminProtect, async (req, res) => {
  try {
    const query = {};
    
    if (req.query.userId) {
      query.userId = req.query.userId;
    }
    
    if (req.query.type) {
      query.type = req.query.type;
    }
    
    if (req.query.status) {
      query.status = req.query.status;
    }
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find(query).skip(skip).limit(limit).populate('userId');
    const total = await Transaction.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets', adminProtect, async (req, res) => {
  try {
    const query = {};
    
    if (req.query.status) {
      query.status = req.query.status;
    }
    
    if (req.query.priority) {
      query.priority = req.query.priority;
    }
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const tickets = await SupportTicket.find(query).skip(skip).limit(limit).populate('userId');
    const total = await SupportTicket.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets/:id', adminProtect, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id).populate('userId');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID!'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/tickets/:id', adminProtect, async (req, res) => {
  try {
    const { status, priority } = req.body;
    
    const updatedTicket = await SupportTicket.findByIdAndUpdate(req.params.id, {
      status,
      priority,
      updatedAt: Date.now()
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket: updatedTicket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/tickets/:id/respond', adminProtect, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findByIdAndUpdate(req.params.id, {
      $push: {
        responses: {
          userId: req.admin._id,
          message,
          isAdmin: true
        }
      },
      status: 'pending',
      updatedAt: Date.now()
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/kyc', adminProtect, async (req, res) => {
  try {
    const query = { kycStatus: 'pending' };
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const users = await User.find(query).skip(skip).limit(limit);
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/approve', adminProtect, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(req.params.id, {
      kycStatus: 'verified'
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/reject', adminProtect, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(req.params.id, {
      kycStatus: 'rejected'
    }, {
      new: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/broadcast', adminProtect, async (req, res) => {
  try {
    const { message, target } = req.body;
    
    // In a real app, you would send this to all targeted users
    // via email, push notification, or WebSocket
    
    res.status(200).json({
      status: 'success',
      message: 'Broadcast sent successfully!'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/logs', adminProtect, async (req, res) => {
  try {
    const query = {};
    
    if (req.query.userId) {
      query.userId = req.query.userId;
    }
    
    if (req.query.action) {
      query.action = { $regex: req.query.action, $options: 'i' };
    }
    
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 10;
    const skip = (page - 1) * limit;
    
    const logs = await ActivityLog.find(query).skip(skip).limit(limit).populate('userId');
    const total = await ActivityLog.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: total,
      data: {
        logs
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/settings', adminProtect, async (req, res) => {
  try {
    // In a real app, you would get these from a settings collection
    const settings = {
      maintenance: false,
      kycRequired: true,
      minDeposit: 10,
      minWithdrawal: 350,
      minTrade: 100
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/settings', adminProtect, async (req, res) => {
  try {
    // In a real app, you would update these in a settings collection
    res.status(200).json({
      status: 'success',
      message: 'Settings updated successfully!'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// WebSocket Server
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`App running on port ${process.env.PORT || 3000}...`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  // Authenticate via token in URL query
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    ws.userId = decoded.id;
    
    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message);
        
        if (data.type === 'subscribe') {
          // Handle subscription to different channels
          ws.subscriptions = data.channels;
        }
      } catch (err) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format'
        }));
      }
    });
    
    ws.on('close', () => {
      // Clean up
    });
    
    // Send initial connection confirmation
    ws.send(JSON.stringify({
      type: 'connection',
      status: 'success',
      message: 'WebSocket connection established'
    }));
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Broadcast function to send messages to specific users
function broadcastToUser(userId, message) {
  wss.clients.forEach(client => {
    if (client.userId === userId && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Global error handling
process.on('unhandledRejection', err => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err);
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