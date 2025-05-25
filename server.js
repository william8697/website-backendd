require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Email configuration
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

// Models
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: '' },
  isVerified: { type: Boolean, default: true },
  isAdmin: { type: Boolean, default: false },
  balance: { type: Number, default: 0 },
  portfolio: { type: Map, of: Number, default: {} },
  createdAt: { type: Date, default: Date.now },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  kycStatus: { type: String, enum: ['pending', 'approved', 'rejected', 'not_submitted'], default: 'not_submitted' },
  kycDetails: {
    firstName: String,
    lastName: String,
    address: String,
    city: String,
    country: String,
    idType: String,
    idNumber: String,
    idFront: String,
    idBack: String,
    selfie: String
  },
  settings: {
    currency: { type: String, default: 'USD' },
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    twoFA: { type: Boolean, default: false }
  },
  apiKey: { type: String, default: '' },
  lastLogin: { type: Date },
  loginHistory: [{ type: Date }],
  walletAddress: { type: String, default: '' },
  nonce: { type: String, default: () => crypto.randomBytes(16).toString('hex') }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell', 'convert'], required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion'], required: true },
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
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['superadmin', 'admin', 'support'], default: 'admin' },
  lastLogin: { type: Date },
  permissions: [String],
  createdAt: { type: Date, default: Date.now }
});

const CoinSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  marketCap: { type: Number },
  volume: { type: Number },
  change24h: { type: Number },
  lastUpdated: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Coin = mongoose.model('Coin', CoinSchema);

// Helper functions
const generateToken = (userId, isAdmin = false) => {
  return jwt.sign({ id: userId, isAdmin }, JWT_SECRET, { expiresIn: '7d' });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }

  try {
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(500).json({ success: false, message: 'Server error during authentication' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.adminToken;
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  const decoded = verifyToken(token);
  if (!decoded || !decoded.isAdmin) {
    return res.status(401).json({ success: false, message: 'Invalid admin token' });
  }

  try {
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Admin not found' });
    }

    req.admin = admin;
    next();
  } catch (err) {
    console.error('Admin authentication error:', err);
    res.status(500).json({ success: false, message: 'Server error during admin authentication' });
  }
};

// Initialize WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocketServer({ server });
const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  if (!token) {
    ws.close(1008, 'No token provided');
    return;
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    ws.close(1008, 'Invalid token');
    return;
  }

  const clientId = decoded.id;
  clients.set(clientId, ws);

  ws.on('message', (message) => {
    console.log(`Received message from ${clientId}: ${message}`);
  });

  ws.on('close', () => {
    clients.delete(clientId);
  });
});

const broadcastToUser = (userId, event, data) => {
  const ws = clients.get(userId.toString());
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ event, data }));
  }
};

// Initialize coins data
const initializeCoins = async () => {
  const coins = [
    { symbol: 'BTC', name: 'Bitcoin', price: 50000, marketCap: 950000000000, volume: 25000000000, change24h: 2.5 },
    { symbol: 'ETH', name: 'Ethereum', price: 3000, marketCap: 360000000000, volume: 15000000000, change24h: 1.8 },
    { symbol: 'BNB', name: 'Binance Coin', price: 400, marketCap: 60000000000, volume: 2000000000, change24h: -0.5 },
    { symbol: 'SOL', name: 'Solana', price: 100, marketCap: 40000000000, volume: 1800000000, change24h: 5.2 },
    { symbol: 'ADA', name: 'Cardano', price: 0.5, marketCap: 18000000000, volume: 800000000, change24h: -1.2 },
    { symbol: 'XRP', name: 'Ripple', price: 0.6, marketCap: 30000000000, volume: 2500000000, change24h: 0.8 },
    { symbol: 'DOT', name: 'Polkadot', price: 7, marketCap: 7000000000, volume: 350000000, change24h: -2.1 },
    { symbol: 'DOGE', name: 'Dogecoin', price: 0.15, marketCap: 20000000000, volume: 1200000000, change24h: 10.5 },
    { symbol: 'USDT', name: 'Tether', price: 1, marketCap: 80000000000, volume: 50000000000, change24h: 0 },
    { symbol: 'USDC', name: 'USD Coin', price: 1, marketCap: 50000000000, volume: 30000000000, change24h: 0 }
  ];

  try {
    for (const coin of coins) {
      await Coin.findOneAndUpdate(
        { symbol: coin.symbol },
        coin,
        { upsert: true, new: true }
      );
    }
    console.log('Coins initialized successfully');
  } catch (err) {
    console.error('Error initializing coins:', err);
  }
};

initializeCoins();

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Platform Backend');
});

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      name: name || '',
      isVerified: true
    });

    await user.save();

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        balance: user.balance,
        kycStatus: user.kycStatus
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    user.loginHistory.push(new Date());
    await user.save();

    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;

    if (!walletAddress || !signature) {
      return res.status(400).json({ success: false, message: 'Wallet address and signature are required' });
    }

    let user = await User.findOne({ walletAddress });
    if (!user) {
      user = new User({
        walletAddress,
        isVerified: true
      });
      await user.save();
    }

    user.nonce = crypto.randomBytes(16).toString('hex');
    user.lastLogin = new Date();
    user.loginHistory.push(new Date());
    await user.save();

    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Wallet login successful',
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        isVerified: user.isVerified,
        balance: user.balance
      }
    });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ success: false, message: 'Server error during wallet login' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: Object.fromEntries(user.portfolio),
        kycStatus: user.kycStatus,
        settings: user.settings,
        walletAddress: user.walletAddress
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Server error getting user data' });
  }
});

app.get('/api/v1/auth/verify', authenticate, (req, res) => {
  res.json({ success: true, message: 'Token is valid', user: req.user });
});

app.post('/api/v1/auth/logout', authenticate, (req, res) => {
  res.json({ success: true, message: 'Logout successful' });
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
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    const mailOptions = {
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your Crypto Trading Market account.</p>
        <p>Click this link to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, message: 'Server error during password reset' });
  }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: Object.fromEntries(user.portfolio),
        kycStatus: user.kycStatus,
        settings: user.settings,
        walletAddress: user.walletAddress,
        lastLogin: user.lastLogin
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Server error getting user data' });
  }
});

app.patch('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { name, settings } = req.body;

    if (name) user.name = name;
    if (settings) {
      if (settings.currency) user.settings.currency = settings.currency;
      if (settings.language) user.settings.language = settings.language;
      if (settings.theme) user.settings.theme = settings.theme;
      if (settings.notifications) {
        if (settings.notifications.email !== undefined) {
          user.settings.notifications.email = settings.notifications.email;
        }
        if (settings.notifications.push !== undefined) {
          user.settings.notifications.push = settings.notifications.push;
        }
      }
      if (settings.twoFA !== undefined) {
        user.settings.twoFA = settings.twoFA;
      }
    }

    await user.save();

    res.json({
      success: true,
      message: 'User updated successfully',
      user: {
        id: user._id,
        name: user.name,
        settings: user.settings
      }
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ success: false, message: 'Server error updating user' });
  }
});

app.post('/api/v1/users/kyc', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { 
      firstName, 
      lastName, 
      address, 
      city, 
      country, 
      idType, 
      idNumber 
    } = req.body;

    if (!firstName || !lastName || !address || !city || !country || !idType || !idNumber) {
      return res.status(400).json({ success: false, message: 'All KYC fields are required' });
    }

    user.kycDetails = {
      firstName,
      lastName,
      address,
      city,
      country,
      idType,
      idNumber,
      idFront: req.body.idFront || '',
      idBack: req.body.idBack || '',
      selfie: req.body.selfie || ''
    };
    user.kycStatus = 'pending';
    await user.save();

    res.json({ 
      success: true, 
      message: 'KYC submitted successfully', 
      kycStatus: user.kycStatus 
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({ success: false, message: 'Server error submitting KYC' });
  }
});

app.patch('/api/v1/users/password', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Current and new password are required' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Password update error:', err);
    res.status(500).json({ success: false, message: 'Server error updating password' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const apiKey = crypto.randomBytes(32).toString('hex');
    user.apiKey = apiKey;
    await user.save();

    res.json({ success: true, apiKey });
  } catch (err) {
    console.error('API key generation error:', err);
    res.status(500).json({ success: false, message: 'Server error generating API key' });
  }
});

app.delete('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Password is incorrect' });
    }

    await Promise.all([
      User.deleteOne({ _id: user._id }),
      Trade.deleteMany({ userId: user._id }),
      Transaction.deleteMany({ userId: user._id }),
      Ticket.deleteMany({ userId: user._id })
    ]);

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Account deletion error:', err);
    res.status(500).json({ success: false, message: 'Server error deleting account' });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    const coins = await Coin.find({});
    const coinPrices = {};
    coins.forEach(coin => {
      coinPrices[coin.symbol] = coin.price;
    });

    let portfolioValue = 0;
    const portfolioDetails = [];
    
    user.portfolio.forEach((amount, symbol) => {
      const price = coinPrices[symbol] || 0;
      const value = amount * price;
      portfolioValue += value;
      
      portfolioDetails.push({
        symbol,
        amount,
        price,
        value
      });
    });

    res.json({
      success: true,
      balance: user.balance,
      portfolio: portfolioDetails,
      totalValue: portfolioValue + user.balance
    });
  } catch (err) {
    console.error('Get portfolio error:', err);
    res.status(500).json({ success: false, message: 'Server error getting portfolio' });
  }
});

// Trade Routes
app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { symbol, amount } = req.body;

    if (!symbol || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Symbol and positive amount are required' });
    }

    const coin = await Coin.findOne({ symbol });
    if (!coin) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbol' });
    }

    const cost = amount * coin.price;
    if (user.balance < cost) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    user.balance -= cost;
    const currentAmount = user.portfolio.get(symbol) || 0;
    user.portfolio.set(symbol, currentAmount + amount);
    await user.save();

    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      fromCoin: 'USD',
      toCoin: symbol,
      amount,
      rate: coin.price,
      fee: 0
    });
    await trade.save();

    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: -cost,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: Object.fromEntries(user.portfolio) });
    broadcastToUser(user._id, 'TRADE_UPDATE', { trade });

    res.json({
      success: true,
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: Object.fromEntries(user.portfolio),
      trade
    });
  } catch (err) {
    console.error('Buy trade error:', err);
    res.status(500).json({ success: false, message: 'Server error executing trade' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { symbol, amount } = req.body;

    if (!symbol || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Symbol and positive amount are required' });
    }

    const coin = await Coin.findOne({ symbol });
    if (!coin) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbol' });
    }

    const currentAmount = user.portfolio.get(symbol) || 0;
    if (currentAmount < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient coin balance' });
    }

    const value = amount * coin.price;

    user.balance += value;
    user.portfolio.set(symbol, currentAmount - amount);
    if (user.portfolio.get(symbol) === 0) {
      user.portfolio.delete(symbol);
    }
    await user.save();

    const trade = new Trade({
      userId: user._id,
      type: 'sell',
      fromCoin: symbol,
      toCoin: 'USD',
      amount,
      rate: coin.price,
      fee: 0
    });
    await trade.save();

    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: value,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: Object.fromEntries(user.portfolio) });
    broadcastToUser(user._id, 'TRADE_UPDATE', { trade });

    res.json({
      success: true,
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: Object.fromEntries(user.portfolio),
      trade
    });
  } catch (err) {
    console.error('Sell trade error:', err);
    res.status(500).json({ success: false, message: 'Server error executing trade' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { limit = 10, page = 1 } = req.query;

    const trades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Trade.countDocuments({ userId: user._id });

    res.json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ success: false, message: 'Server error getting trade history' });
  }
});

// Exchange Routes (Arbitrage)
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = await Coin.find({}).select('symbol name price change24h');
    res.json({ success: true, coins });
  } catch (err) {
    console.error('Get coins error:', err);
    res.status(500).json({ success: false, message: 'Server error getting coins' });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;

    if (!from || !to) {
      return res.status(400).json({ success: false, message: 'From and to symbols are required' });
    }

    const fromCoin = await Coin.findOne({ symbol: from });
    const toCoin = await Coin.findOne({ symbol: to });

    if (!fromCoin || !toCoin) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
    }

    const rate = fromCoin.price / toCoin.price;

    res.json({ 
      success: true, 
      from: fromCoin.symbol, 
      to: toCoin.symbol, 
      rate,
      fromPrice: fromCoin.price,
      toPrice: toCoin.price
    });
  } catch (err) {
    console.error('Get exchange rate error:', err);
    res.status(500).json({ success: false, message: 'Server error getting exchange rate' });
  }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { from, to, amount } = req.body;

    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'From, to and positive amount are required' });
    }

    const fromCoin = await Coin.findOne({ symbol: from });
    const toCoin = await Coin.findOne({ symbol: to });

    if (!fromCoin || !toCoin) {
      return res.status(400).json({ success: false, message: 'Invalid coin symbols' });
    }

    const rate = fromCoin.price / toCoin.price;
    const convertedAmount = amount * rate;

    if (from === 'USD') {
      if (user.balance < amount) {
        return res.status(400).json({ success: false, message: 'Insufficient balance' });
      }

      user.balance -= amount;
      const currentToAmount = user.portfolio.get(to) || 0;
      user.portfolio.set(to, currentToAmount + convertedAmount);
    } else if (to === 'USD') {
      const currentFromAmount = user.portfolio.get(from) || 0;
      if (currentFromAmount < amount) {
        return res.status(400).json({ success: false, message: 'Insufficient coin balance' });
      }

      user.balance += convertedAmount;
      user.portfolio.set(from, currentFromAmount - amount);
      if (user.portfolio.get(from) === 0) {
        user.portfolio.delete(from);
      }
    } else {
      const currentFromAmount = user.portfolio.get(from) || 0;
      if (currentFromAmount < amount) {
        return res.status(400).json({ success: false, message: 'Insufficient coin balance' });
      }

      const currentToAmount = user.portfolio.get(to) || 0;
      user.portfolio.set(from, currentFromAmount - amount);
      user.portfolio.set(to, currentToAmount + convertedAmount);
      
      if (user.portfolio.get(from) === 0) {
        user.portfolio.delete(from);
      }
    }

    await user.save();

    const trade = new Trade({
      userId: user._id,
      type: 'convert',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      fee: 0
    });
    await trade.save();

    const transaction = new Transaction({
      userId: user._id,
      type: 'conversion',
      amount: amount,
      currency: from,
      status: 'completed'
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'PORTFOLIO_UPDATE', { portfolio: Object.fromEntries(user.portfolio) });
    broadcastToUser(user._id, 'TRADE_UPDATE', { trade });

    res.json({
      success: true,
      message: 'Conversion successful',
      from,
      to,
      amount,
      convertedAmount,
      rate,
      balance: user.balance,
      portfolio: Object.fromEntries(user.portfolio)
    });
  } catch (err) {
    console.error('Conversion error:', err);
    res.status(500).json({ success: false, message: 'Server error during conversion' });
  }
});

// Transaction Routes
app.get('/api/v1/transactions', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { limit = 10, page = 1, type } = req.query;

    const query = { userId: user._id };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ success: false, message: 'Server error getting transactions' });
  }
});

// Wallet Routes
app.post('/api/v1/wallet/deposit', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { amount, currency = 'USD' } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Positive amount is required' });
    }

    user.balance += amount;
    await user.save();

    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      currency,
      status: 'completed'
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'TRANSACTION_UPDATE', { transaction });

    res.json({
      success: true,
      message: 'Deposit successful',
      balance: user.balance,
      transaction
    });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({ success: false, message: 'Server error during deposit' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { amount, currency = 'USD', address } = req.body;

    if (!amount || amount <= 0 || !address) {
      return res.status(400).json({ success: false, message: 'Positive amount and address are required' });
    }

    if (user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    user.balance -= amount;
    await user.save();

    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: -amount,
      currency,
      status: 'pending',
      address
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'TRANSACTION_UPDATE', { transaction });

    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      balance: user.balance,
      transaction
    });
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({ success: false, message: 'Server error during withdrawal' });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { subject, message } = req.body;

    if (!subject || !message) {
      return res.status(400).json({ success: false, message: 'Subject and message are required' });
    }

    const ticket = new Ticket({
      userId: user._id,
      email: user.email,
      subject,
      message,
      status: 'open'
    });
    await ticket.save();

    res.json({
      success: true,
      message: 'Ticket created successfully',
      ticket
    });
  } catch (err) {
    console.error('Create ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error creating ticket' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { limit = 10, page = 1, status } = req.query;

    const query = { userId: user._id };
    if (status) query.status = status;

    const tickets = await Ticket.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Ticket.countDocuments(query);

    res.json({
      success: true,
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ success: false, message: 'Server error getting tickets' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { id } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await Ticket.findOne({ _id: id, userId: user._id });
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.responses.push({
      message,
      isAdmin: false
    });
    ticket.status = 'pending';
    await ticket.save();

    res.json({
      success: true,
      message: 'Reply added successfully',
      ticket
    });
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error replying to ticket' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = generateToken(admin._id, true);

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        name: admin.name,
        role: admin.role
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
  res.json({ success: true, message: 'Admin token is valid', admin: req.admin });
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const [usersCount, activeUsersCount, tradesCount, totalVolume, ticketsCount] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
      Trade.countDocuments(),
      Trade.aggregate([{ $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } }]),
      Ticket.countDocuments({ status: 'open' })
    ]);

    res.json({
      success: true,
      stats: {
        users: usersCount,
        activeUsers: activeUsersCount,
        trades: tradesCount,
        totalVolume: totalVolume[0]?.total || 0,
        openTickets: ticketsCount
      }
    });
  } catch (err) {
    console.error('Get dashboard stats error:', err);
    res.status(500).json({ success: false, message: 'Server error getting dashboard stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { limit = 10, page = 1, search } = req.query;

    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ success: false, message: 'Server error getting users' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount } = req.body;

    if (!amount) {
      return res.status(400).json({ success: false, message: 'Amount is required' });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.balance += amount;
    await user.save();

    const transaction = new Transaction({
      userId: user._id,
      type: amount > 0 ? 'deposit' : 'withdrawal',
      amount,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();

    broadcastToUser(user._id, 'BALANCE_UPDATE', { balance: user.balance });
    broadcastToUser(user._id, 'TRANSACTION_UPDATE', { transaction });

    res.json({
      success: true,
      message: 'Balance updated successfully',
      user: {
        id: user._id,
        email: user.email,
        balance: user.balance
      }
    });
  } catch (err) {
    console.error('Update user balance error:', err);
    res.status(500).json({ success: false, message: 'Server error updating user balance' });
  }
});

app.patch('/api/v1/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required' });
    }

    const user = await User.findByIdAndUpdate(
      id,
      { kycStatus: status },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      message: 'User status updated successfully',
      user: {
        id: user._id,
        email: user.email,
        kycStatus: user.kycStatus
      }
    });
  } catch (err) {
    console.error('Update user status error:', err);
    res.status(500).json({ success: false, message: 'Server error updating user status' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { limit = 10, page = 1, userId, type } = req.query;

    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;

    const trades = await Trade.find(query)
      .populate('userId', 'email name')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Trade.countDocuments(query);

    res.json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get trades error:', err);
    res.status(500).json({ success: false, message: 'Server error getting trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { limit = 10, page = 1, userId, type } = req.query;

    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .populate('userId', 'email name')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ success: false, message: 'Server error getting transactions' });
  }
});

app.patch('/api/v1/admin/transactions/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required' });
    }

    const transaction = await Transaction.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    ).populate('userId', 'email name');

    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }

    if (status === 'completed' && transaction.type === 'withdrawal') {
      // Already deducted during request, no need to do anything
    }

    broadcastToUser(transaction.userId._id, 'TRANSACTION_UPDATE', { transaction });

    res.json({
      success: true,
      message: 'Transaction status updated successfully',
      transaction
    });
  } catch (err) {
    console.error('Update transaction status error:', err);
    res.status(500).json({ success: false, message: 'Server error updating transaction status' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { limit = 10, page = 1, status } = req.query;

    const query = {};
    if (status) query.status = status;

    const tickets = await Ticket.find(query)
      .populate('userId', 'email name')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Ticket.countDocuments(query);

    res.json({
      success: true,
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ success: false, message: 'Server error getting tickets' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required' });
    }

    const ticket = await Ticket.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    ).populate('userId', 'email name');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.json({
      success: true,
      message: 'Ticket status updated successfully',
      ticket
    });
  } catch (err) {
    console.error('Update ticket status error:', err);
    res.status(500).json({ success: false, message: 'Server error updating ticket status' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await Ticket.findById(id).populate('userId', 'email name');
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.responses.push({
      message,
      isAdmin: true
    });
    ticket.status = 'pending';
    await ticket.save();

    res.json({
      success: true,
      message: 'Reply added successfully',
      ticket
    });
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error replying to ticket' });
  }
});

// Public Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const [usersCount, tradesCount, totalVolume] = await Promise.all([
      User.countDocuments(),
      Trade.countDocuments(),
      Trade.aggregate([{ $group: { _id: null, total: { $sum: { $multiply: ['$amount', '$rate'] } } }])
    ]);

    res.json({
      success: true,
      stats: {
        users: usersCount,
        trades: tradesCount,
        volume: totalVolume[0]?.total || 0
      }
    });
  } catch (err) {
    console.error('Get public stats error:', err);
    res.status(500).json({ success: false, message: 'Server error getting public stats' });
  }
});

app.get('/api/v1/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        question: 'How do I create an account?',
        answer: 'Click on the Sign Up button and fill in your details to create an account.',
        category: 'Account'
      },
      {
        question: 'How do I deposit funds?',
        answer: 'Go to the Wallet section and click on Deposit to add funds to your account.',
        category: 'Deposits'
      },
      {
        question: 'How do I trade cryptocurrencies?',
        answer: 'Navigate to the Trade section, select the coins you want to trade, enter the amount and execute the trade.',
        category: 'Trading'
      },
      {
        question: 'What is the minimum deposit amount?',
        answer: 'The minimum deposit amount is $10.',
        category: 'Deposits'
      },
      {
        question: 'How do I withdraw my funds?',
        answer: 'Go to the Wallet section, click on Withdraw, enter the amount and your wallet address.',
        category: 'Withdrawals'
      },
      {
        question: 'What fees do you charge?',
        answer: 'We charge a 0.1% fee on all trades.',
        category: 'Fees'
      },
      {
        question: 'How do I contact support?',
        answer: 'You can contact support through the Support section or by emailing support@cryptotradingmarket.com.',
        category: 'Support'
      },
      {
        question: 'Is KYC verification required?',
        answer: 'KYC verification is required for withdrawals above $1000 per day.',
        category: 'Verification'
      }
    ];

    res.json({ success: true, faqs });
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ success: false, message: 'Server error getting FAQs' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});
