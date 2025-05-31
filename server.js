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
const morgan = require('morgan');
const crypto = require('crypto');
const WebSocket = require('ws');
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { ethers } = require('ethers');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT Configuration
const JWT_SECRET = '17581758Na.##';
const JWT_EXPIRES_IN = '30d';

// Mailtrap Configuration
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
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true },
  country: { type: String, required: true },
  currency: { type: String, default: 'USD' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'none'], default: 'none' },
  kycDocuments: [{
    documentType: String,
    documentNumber: String,
    frontImage: String,
    backImage: String,
    selfie: String,
    submittedAt: Date
  }],
  apiKey: { type: String, unique: true, sparse: true },
  settings: {
    twoFactorEnabled: { type: Boolean, default: false },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: false }
    },
    theme: { type: String, enum: ['light', 'dark', 'system'], default: 'system' }
  },
  balance: {
    btc: { type: Number, default: 0 },
    eth: { type: Number, default: 0 },
    usdt: { type: Number, default: 0 },
    bnb: { type: Number, default: 0 },
    sol: { type: Number, default: 0 },
    xrp: { type: Number, default: 0 },
    ada: { type: Number, default: 0 },
    doge: { type: Number, default: 0 },
    dot: { type: Number, default: 0 },
    shib: { type: Number, default: 0 }
  },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: Date
  }],
  passwordResetToken: String,
  passwordResetExpires: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  this.updatedAt = Date.now();
  next();
});

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell', 'convert'], required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  timestamp: { type: Date, default: Date.now }
});

const Trade = mongoose.model('Trade', TradeSchema);

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'bonus'], required: true },
  coin: { type: String, required: true },
  amount: { type: Number, required: true },
  address: String,
  txHash: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  timestamp: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', TransactionSchema);

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    isAdmin: Boolean,
    timestamp: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

TicketSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Ticket = mongoose.model('Ticket', TicketSchema);

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true },
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const FAQ = mongoose.model('FAQ', FAQSchema);

const AdminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: String,
  details: Object,
  ip: String,
  timestamp: { type: Date, default: Date.now }
});

const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

// Create default admin user if not exists
async function createDefaultAdmin() {
  const adminEmail = 'Admin@youngblood.com';
  const adminPassword = '17581758..';
  
  const existingAdmin = await User.findOne({ email: adminEmail });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    await User.create({
      firstName: 'Admin',
      lastName: 'User',
      email: adminEmail,
      password: hashedPassword,
      role: 'admin',
      isVerified: true,
      country: 'US',
      currency: 'USD'
    });
    console.log('Default admin user created');
  }
}

createDefaultAdmin().catch(err => console.error('Error creating admin:', err));

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-production-domain.com'],
  credentials: true
}));
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(morgan('dev'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// File upload configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'), false);
    }
  }
});

// Authentication middleware
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({ status: 'fail', message: 'You are not logged in! Please log in to get access.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id).select('+passwordChangedAt');

    if (!currentUser) {
      return res.status(401).json({ status: 'fail', message: 'The user belonging to this token no longer exists.' });
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({ status: 'fail', message: 'User recently changed password! Please log in again.' });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'fail', message: 'Invalid token. Please log in again.' });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ status: 'fail', message: 'You do not have permission to perform this action' });
    }
    next();
  };
};

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Authentication token missing');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    clients.set(decoded.id, ws);
    
    ws.on('message', (message) => {
      // Handle incoming messages
      const data = JSON.parse(message);
      console.log('Received message:', data);
      
      // Broadcast to other clients if needed
      wss.clients.forEach(client => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(data));
        }
      });
    });

    ws.on('close', () => {
      clients.delete(decoded.id);
    });
  } catch (err) {
    ws.close(1008, 'Invalid authentication token');
  }
});

// Helper functions
const signToken = id => {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
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

// Coin price simulation
const COINS = ['btc', 'eth', 'usdt', 'bnb', 'sol', 'xrp', 'ada', 'doge', 'dot', 'shib'];
const PRICE_RANGES = {
  btc: { min: 50000, max: 70000 },
  eth: { min: 2500, max: 4000 },
  usdt: { min: 0.99, max: 1.01 },
  bnb: { min: 300, max: 500 },
  sol: { min: 100, max: 200 },
  xrp: { min: 0.4, max: 0.8 },
  ada: { min: 0.4, max: 0.7 },
  doge: { min: 0.1, max: 0.2 },
  dot: { min: 5, max: 10 },
  shib: { min: 0.00001, max: 0.00003 }
};

const getSimulatedPrices = () => {
  const prices = {};
  COINS.forEach(coin => {
    const range = PRICE_RANGES[coin];
    prices[coin] = (Math.random() * (range.max - range.min) + range.min).toFixed(coin === 'usdt' ? 4 : 2);
  });
  return prices;
};

const getConversionRate = (fromCoin, toCoin) => {
  const prices = getSimulatedPrices();
  return (prices[fromCoin] / prices[toCoin]).toFixed(8);
};

// Routes

// 1. Authentication Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({ status: 'fail', message: 'Passwords do not match' });
    }

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency,
      isVerified: true // In production, you'd send verification email
    });

    // Send welcome email
    const mailOptions = {
      from: 'support@youngblood.com',
      to: newUser.email,
      subject: 'Welcome to Youngblood Trading Platform',
      html: `<h1>Welcome ${newUser.firstName}!</h1><p>Your account has been successfully created.</p>`
    };

    await transporter.sendMail(mailOptions);

    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ status: 'fail', message: 'Email already in use' });
    }
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password' });
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    user.lastLogin = Date.now();
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ status: 'fail', message: 'Invalid wallet address' });
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    res.status(200).json({ status: 'success', data: { nonce } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature, nonce } = req.body;
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ status: 'fail', message: 'Invalid wallet address' });
    }

    // Verify the signature
    const recoveredAddress = ethers.utils.verifyMessage(nonce, signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ status: 'fail', message: 'Signature verification failed' });
    }

    let user = await User.findOne({ walletAddress: walletAddress.toLowerCase() });
    
    if (!user) {
      // Create new user if not exists
      user = await User.create({
        walletAddress: walletAddress.toLowerCase(),
        isVerified: true,
        country: 'US',
        currency: 'USD'
      });
    }

    user.lastLogin = Date.now();
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, nonce, firstName, lastName, email, country, currency } = req.body;
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({ status: 'fail', message: 'Invalid wallet address' });
    }

    // Verify the signature
    const recoveredAddress = ethers.utils.verifyMessage(nonce, signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ status: 'fail', message: 'Signature verification failed' });
    }

    // Check if wallet or email already exists
    const existingUser = await User.findOne({ 
      $or: [
        { walletAddress: walletAddress.toLowerCase() },
        { email: email.toLowerCase() }
      ] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        status: 'fail', 
        message: existingUser.walletAddress ? 'Wallet already registered' : 'Email already in use' 
      });
    }

    const user = await User.create({
      firstName,
      lastName,
      email,
      walletAddress: walletAddress.toLowerCase(),
      isVerified: true,
      country,
      currency
    });

    // Send welcome email
    const mailOptions = {
      from: 'support@youngblood.com',
      to: user.email,
      subject: 'Welcome to Youngblood Trading Platform',
      html: `<h1>Welcome ${user.firstName}!</h1><p>Your wallet has been successfully connected.</p>`
    };

    await transporter.sendMail(mailOptions);

    createSendToken(user, 201, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({ status: 'success', message: 'If the email exists, a reset link has been sent' });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `https://yourdomain.com/reset-password/${resetToken}`;

    const mailOptions = {
      from: 'support@youngblood.com',
      to: user.email,
      subject: 'Your password reset token (valid for 10 minutes)',
      html: `<p>Forgot your password? Submit a PATCH request with your new password to: ${resetURL}</p>`
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ status: 'success', message: 'Token sent to email' });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.patch('/api/v1/auth/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ 
      passwordResetToken: hashedToken, 
      passwordResetExpires: { $gt: Date.now() } 
    });

    if (!user) {
      return res.status(400).json({ status: 'fail', message: 'Token is invalid or has expired' });
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.patch('/api/v1/auth/update-password', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await bcrypt.compare(req.body.currentPassword, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Your current password is wrong' });
    }

    user.password = req.body.newPassword;
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

app.get('/api/v1/auth/status', protect, (req, res) => {
  res.status(200).json({ status: 'success', data: { user: req.user } });
});

app.get('/api/v1/auth/check', protect, (req, res) => {
  res.status(200).json({ status: 'success', data: { user: req.user } });
});

// 2. User Routes
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({ status: 'success', data: { settings: user.settings } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.patch('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'twoFactorEnabled', 'notifications', 'theme');
    const user = await User.findByIdAndUpdate(req.user.id, { settings: filteredBody }, { new: true });
    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/users/kyc', protect, upload.fields([
  { name: 'frontImage', maxCount: 1 },
  { name: 'backImage', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    const files = req.files;

    if (!documentType || !documentNumber || !files.frontImage || !files.selfie) {
      return res.status(400).json({ status: 'fail', message: 'Missing required fields' });
    }

    // In a real app, you'd upload these files to cloud storage
    const kycDoc = {
      documentType,
      documentNumber,
      frontImage: 'path/to/uploaded/frontImage.jpg',
      backImage: files.backImage ? 'path/to/uploaded/backImage.jpg' : undefined,
      selfie: 'path/to/uploaded/selfie.jpg',
      submittedAt: Date.now()
    };

    const user = await User.findByIdAndUpdate(req.user.id, { 
      kycStatus: 'pending',
      $push: { kycDocuments: kycDoc }
    }, { new: true });

    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/users/generate-api-key', protect, async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(32).toString('hex');
    const user = await User.findByIdAndUpdate(req.user.id, { apiKey }, { new: true });
    res.status(200).json({ status: 'success', data: { apiKey: user.apiKey } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/users/export-data', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const trades = await Trade.find({ userId: req.user.id });
    const transactions = await Transaction.find({ userId: req.user.id });

    const data = {
      user,
      trades,
      transactions
    };

    // In a real app, you'd generate a file and email it
    res.status(200).json({ status: 'success', data });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.delete('/api/v1/users/delete-account', protect, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);
    res.status(204).json({ status: 'success', data: null });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 3. Wallet Routes
app.get('/api/v1/wallet/deposit-address', protect, (req, res) => {
  try {
    const depositAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
    res.status(200).json({ status: 'success', data: { depositAddress } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { coin, amount, address } = req.body;
    
    if (!COINS.includes(coin.toLowerCase())) {
      return res.status(400).json({ status: 'fail', message: 'Invalid coin' });
    }

    if (amount <= 0) {
      return res.status(400).json({ status: 'fail', message: 'Amount must be positive' });
    }

    const user = await User.findById(req.user.id);
    
    if (user.balance[coin] < amount) {
      return res.status(400).json({ status: 'fail', message: 'Insufficient balance' });
    }

    // Create transaction
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'withdrawal',
      coin,
      amount,
      address,
      status: 'pending'
    });

    // Update user balance (in real app, you'd wait for blockchain confirmation)
    user.balance[coin] -= amount;
    await user.save();

    // Notify via WebSocket
    const ws = clients.get(req.user.id);
    if (ws) {
      ws.send(JSON.stringify({
        type: 'balance_update',
        data: { balance: user.balance }
      }));
    }

    res.status(200).json({ status: 'success', data: { transaction } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 4. Exchange Routes
app.get('/api/v1/exchange/coins', (req, res) => {
  try {
    res.status(200).json({ status: 'success', data: { coins: COINS } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/exchange/rates', (req, res) => {
  try {
    const prices = getSimulatedPrices();
    res.status(200).json({ status: 'success', data: { prices } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/exchange/rate', (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!COINS.includes(from.toLowerCase()) || !COINS.includes(to.toLowerCase())) {
      return res.status(400).json({ status: 'fail', message: 'Invalid coin pair' });
    }

    const rate = getConversionRate(from, to);
    res.status(200).json({ status: 'success', data: { from, to, rate } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/exchange/convert', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!COINS.includes(fromCoin.toLowerCase()) || !COINS.includes(toCoin.toLowerCase())) {
      return res.status(400).json({ status: 'fail', message: 'Invalid coin pair' });
    }

    if (amount <= 0) {
      return res.status(400).json({ status: 'fail', message: 'Amount must be positive' });
    }

    const user = await User.findById(req.user.id);
    
    if (user.balance[fromCoin] < amount) {
      return res.status(400).json({ status: 'fail', message: 'Insufficient balance' });
    }

    const rate = parseFloat(getConversionRate(fromCoin, toCoin));
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.01; // 1% fee

    // Create trade record
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed'
    });

    // Create transaction records
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      coin: fromCoin,
      amount: -amount,
      status: 'completed'
    });

    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      coin: toCoin,
      amount: convertedAmount - fee,
      status: 'completed'
    });

    // Update user balance
    user.balance[fromCoin] -= amount;
    user.balance[toCoin] += (convertedAmount - fee);
    await user.save();

    // Notify via WebSocket
    const ws = clients.get(req.user.id);
    if (ws) {
      ws.send(JSON.stringify({
        type: 'balance_update',
        data: { balance: user.balance }
      }));
      
      ws.send(JSON.stringify({
        type: 'trade_update',
        data: { trade }
      }));
    }

    res.status(200).json({ status: 'success', data: { trade } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/exchange/history', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user.id }).sort('-timestamp');
    res.status(200).json({ status: 'success', data: { trades } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 5. Market Routes
app.get('/api/v1/market/data', (req, res) => {
  try {
    const prices = getSimulatedPrices();
    const marketData = COINS.map(coin => ({
      coin,
      price: prices[coin],
      change24h: (Math.random() * 20 - 10).toFixed(2) + '%',
      volume: (Math.random() * 1000000).toFixed(0)
    }));
    
    res.status(200).json({ status: 'success', data: { marketData } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/market/detailed', (req, res) => {
  try {
    const prices = getSimulatedPrices();
    const detailedData = COINS.map(coin => ({
      coin,
      price: prices[coin],
      high24h: (prices[coin] * 1.1).toFixed(2),
      low24h: (prices[coin] * 0.9).toFixed(2),
      volume: (Math.random() * 1000000).toFixed(0),
      marketCap: (Math.random() * 1000000000).toFixed(0)
    }));
    
    res.status(200).json({ status: 'success', data: { detailedData } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 6. Portfolio Routes
app.get('/api/v1/portfolio', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const trades = await Trade.find({ userId: req.user.id }).sort('-timestamp').limit(5);
    const transactions = await Transaction.find({ userId: req.user.id }).sort('-timestamp').limit(5);
    
    const portfolioValue = Object.entries(user.balance).reduce((total, [coin, amount]) => {
      if (coin === 'usdt') return total + amount;
      const price = parseFloat(getSimulatedPrices()[coin]);
      return total + (amount * price);
    }, 0);
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        balance: user.balance, 
        portfolioValue: portfolioValue.toFixed(2),
        trades,
        transactions 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 7. Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort('order');
    res.status(200).json({ status: 'success', data: { faqs } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/support/my-tickets', protect, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user.id }).sort('-createdAt');
    res.status(200).json({ status: 'success', data: { tickets } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/support/tickets', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files?.map(file => file.path) || [];
    
    const ticket = await Ticket.create({
      userId: req.user.id,
      email: req.user.email,
      subject,
      message,
      attachments
    });

    // Notify admin via WebSocket
    const adminUsers = await User.find({ role: 'admin' });
    adminUsers.forEach(admin => {
      const ws = clients.get(admin._id);
      if (ws) {
        ws.send(JSON.stringify({
          type: 'new_ticket',
          data: { ticket }
        }));
      }
    });

    res.status(201).json({ status: 'success', data: { ticket } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/support/contact', upload.array('attachments', 3), async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    const attachments = req.files?.map(file => file.path) || [];
    
    const ticket = await Ticket.create({
      email,
      subject,
      message,
      attachments
    });

    // Notify admin via WebSocket
    const adminUsers = await User.find({ role: 'admin' });
    adminUsers.forEach(admin => {
      const ws = clients.get(admin._id);
      if (ws) {
        ws.send(JSON.stringify({
          type: 'new_ticket',
          data: { ticket }
        }));
      }
    });

    res.status(201).json({ status: 'success', data: { ticket } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 8. Stats Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastLogin: { $gt: Date.now() - 30 * 24 * 60 * 60 * 1000 } });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = (await Trade.aggregate([
      { $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } }
    ]))[0]?.total || 0;
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        totalUsers, 
        activeUsers, 
        totalTrades, 
        totalVolume: totalVolume.toFixed(2) 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 9. Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password' });
    }

    const user = await User.findOne({ email, role: 'admin' }).select('+password');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    user.lastLogin = Date.now();
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/verify', protect, restrictTo('admin'), (req, res) => {
  res.status(200).json({ status: 'success', data: { user: req.user } });
});

app.get('/api/v1/admin/dashboard-stats', protect, restrictTo('admin'), async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const stats = {
      totalUsers: await User.countDocuments(),
      newUsersToday: await User.countDocuments({ createdAt: { $gte: today } }),
      totalTrades: await Trade.countDocuments(),
      tradesToday: await Trade.countDocuments({ timestamp: { $gte: today } }),
      totalVolume: (await Trade.aggregate([
        { $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } } }
      ]))[0]?.total || 0,
      volumeToday: (await Trade.aggregate([
        { $match: { timestamp: { $gte: today } } },
        { $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } }
      ]))[0]?.total || 0,
      pendingTickets: await Ticket.countDocuments({ status: 'open' }),
      pendingKYC: await User.countDocuments({ kycStatus: 'pending' })
    };
    
    res.status(200).json({ status: 'success', data: { stats } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/users', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const users = await User.find().skip(skip).limit(limit);
    const total = await User.countDocuments();
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        users, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/users/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: req.params.id }).sort('-timestamp');
    const transactions = await Transaction.find({ userId: req.params.id }).sort('-timestamp');
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        user, 
        trades, 
        transactions 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.put('/api/v1/admin/users/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'role', 'isVerified', 'kycStatus', 'balance');
    const user = await User.findByIdAndUpdate(req.params.id, filteredBody, { new: true });
    
    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/trades', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find().populate('userId', 'firstName lastName email').skip(skip).limit(limit).sort('-timestamp');
    const total = await Trade.countDocuments();
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        trades, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/transactions', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find().populate('userId', 'firstName lastName email').skip(skip).limit(limit).sort('-timestamp');
    const total = await Transaction.countDocuments();
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        transactions, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/tickets', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const status = req.query.status || 'open';
    
    const tickets = await Ticket.find({ status }).populate('userId', 'firstName lastName email').skip(skip).limit(limit).sort('-createdAt');
    const total = await Ticket.countDocuments({ status });
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        tickets, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/tickets/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id).populate('userId', 'firstName lastName email');
    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }
    
    res.status(200).json({ status: 'success', data: { ticket } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.put('/api/v1/admin/tickets/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { status, response } = req.body;
    
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }
    
    if (status) ticket.status = status;
    if (response) {
      ticket.responses.push({
        message: response,
        isAdmin: true
      });
    }
    
    await ticket.save();
    
    // Notify user via WebSocket if online
    if (ticket.userId) {
      const ws = clients.get(ticket.userId.toString());
      if (ws) {
        ws.send(JSON.stringify({
          type: 'ticket_update',
          data: { ticket }
        }));
      }
    }
    
    res.status(200).json({ status: 'success', data: { ticket } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/kyc', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const status = req.query.status || 'pending';
    
    const users = await User.find({ kycStatus: status }).skip(skip).limit(limit).sort('-updatedAt');
    const total = await User.countDocuments({ kycStatus: status });
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        users, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/kyc/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }
    
    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.put('/api/v1/admin/kyc/:id', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { status, reason } = req.body;
    
    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ status: 'fail', message: 'Invalid status' });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      { kycStatus: status }, 
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }
    
    // Send email notification
    const mailOptions = {
      from: 'support@youngblood.com',
      to: user.email,
      subject: `Your KYC verification is ${status}`,
      html: `<p>Your KYC verification has been ${status}. ${reason ? `Reason: ${reason}` : ''}</p>`
    };
    
    await transporter.sendMail(mailOptions);
    
    // Notify user via WebSocket if online
    const ws = clients.get(user._id.toString());
    if (ws) {
      ws.send(JSON.stringify({
        type: 'kyc_update',
        data: { user }
      }));
    }
    
    res.status(200).json({ status: 'success', data: { user } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/logs', protect, restrictTo('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const logs = await AdminLog.find().populate('adminId', 'firstName lastName email').skip(skip).limit(limit).sort('-timestamp');
    const total = await AdminLog.countDocuments();
    
    res.status(200).json({ 
      status: 'success', 
      data: { 
        logs, 
        pagination: { 
          page, 
          limit, 
          total, 
          pages: Math.ceil(total / limit) 
        } 
      } 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/admin/broadcast', protect, restrictTo('admin'), async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ status: 'fail', message: 'Message is required' });
    }
    
    // Broadcast to all connected clients
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'broadcast',
          data: { message }
        }));
      }
    });
    
    // Log the broadcast
    await AdminLog.create({
      adminId: req.user.id,
      action: 'broadcast',
      details: { message },
      ip: req.ip
    });
    
    res.status(200).json({ status: 'success', message: 'Broadcast sent' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/v1/admin/settings', protect, restrictTo('admin'), async (req, res) => {
  try {
    // In a real app, you'd have a Settings model
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.01,
      withdrawalFee: 0.001,
      depositEnabled: true,
      withdrawalEnabled: true,
      signupEnabled: true
    };
    
    res.status(200).json({ status: 'success', data: { settings } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/v1/admin/settings', protect, restrictTo('admin'), async (req, res) => {
  try {
    // In a real app, you'd update settings in database
    const settings = req.body;
    
    await AdminLog.create({
      adminId: req.user.id,
      action: 'update_settings',
      details: settings,
      ip: req.ip
    });
    
    res.status(200).json({ status: 'success', data: { settings } });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Serve static files (HTML pages)
app.use(express.static(path.join(__dirname, 'public')));

// Route handlers for HTML pages
const htmlPages = [
  'about', 'account', 'admin', 'dashboard', 'faqs', 
  'forgot-password', 'index', 'login', 'logout', 'signup', 'support'
];

htmlPages.forEach(page => {
  app.get(`/${page}.html`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', `${page}.html`));
  });
});

// 404 handler
app.all('*', (req, res) => {
  res.status(404).json({ status: 'fail', message: `Can't find ${req.originalUrl} on this server!` });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ status: 'error', message: 'Something went wrong!' });
});
