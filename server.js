const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const multer = require('multer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.%';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '17581758..';
const FIXED_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const MAILTRAP_CONFIG = {
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
};

// MongoDB connection
mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

// Models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  walletAddress: { type: String, unique: true, sparse: true },
  country: String,
  currency: String,
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDocuments: [{
    type: { type: String },
    url: String,
    uploadedAt: Date
  }],
  balance: { type: Number, default: 0 },
  portfolio: [{
    coin: String,
    amount: Number,
    value: Number
  }],
  settings: {
    twoFactorEnabled: { type: Boolean, default: false },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    }
  },
  apiKey: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  type: { type: String, enum: ['buy', 'sell', 'convert'] },
  fromCoin: String,
  toCoin: String,
  amount: Number,
  rate: Number,
  fee: Number,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'bonus'] },
  amount: Number,
  coin: String,
  address: String,
  txHash: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  email: String,
  subject: String,
  message: String,
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    userId: mongoose.Schema.Types.ObjectId,
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: String,
  answer: String,
  category: String,
  order: Number,
  createdAt: { type: Date, default: Date.now }
}));

const SystemLog = mongoose.model('SystemLog', new mongoose.Schema({
  action: String,
  userId: mongoose.Schema.Types.ObjectId,
  ip: String,
  userAgent: String,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
}));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.isAdmin) return res.status(401).json({ error: 'Unauthorized' });

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Initialize database with admin user
const initializeAdmin = async () => {
  const adminExists = await User.findOne({ email: ADMIN_EMAIL });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await User.create({
      firstName: 'Admin',
      lastName: 'System',
      email: ADMIN_EMAIL,
      password: hashedPassword,
      isAdmin: true,
      isVerified: true,
      apiKey: crypto.randomBytes(16).toString('hex')
    });
    console.log('Admin user created');
  }
};

// Coin prices and arbitrage logic
const COINS = {
  BTC: { name: 'Bitcoin', price: 50000, volatility: 0.05 },
  ETH: { name: 'Ethereum', price: 3000, volatility: 0.07 },
  BNB: { name: 'Binance Coin', price: 500, volatility: 0.06 },
  SOL: { name: 'Solana', price: 100, volatility: 0.08 },
  XRP: { name: 'Ripple', price: 0.5, volatility: 0.04 },
  ADA: { name: 'Cardano', price: 0.4, volatility: 0.05 },
  DOGE: { name: 'Dogecoin', price: 0.1, volatility: 0.1 },
  DOT: { name: 'Polkadot', price: 5, volatility: 0.06 },
  SHIB: { name: 'Shiba Inu', price: 0.00001, volatility: 0.15 },
  AVAX: { name: 'Avalanche', price: 30, volatility: 0.07 }
};

const getCurrentPrice = (coin) => {
  const basePrice = COINS[coin].price;
  const volatility = COINS[coin].volatility;
  const change = (Math.random() * 2 - 1) * volatility;
  return basePrice * (1 + change);
};

const getConversionRate = (fromCoin, toCoin) => {
  const fromPrice = getCurrentPrice(fromCoin);
  const toPrice = getCurrentPrice(toCoin);
  return fromPrice / toPrice;
};

// Email transporter
const transporter = nodemailer.createTransport(MAILTRAP_CONFIG);

// WebSocket setup
const server = app.listen(PORT, async () => {
  await initializeAdmin();
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    clients.set(decoded.userId, ws);
    
    ws.on('close', () => {
      clients.delete(decoded.userId);
    });
    
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      clients.delete(decoded.userId);
    });
  } catch (err) {
    ws.close(1008, 'Unauthorized');
  }
});

const broadcastToUser = (userId, event, data) => {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ event, data }));
  }
};

// File upload
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Routes

// 1. Authentication Endpoints (8 endpoints)
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      apiKey: crypto.randomBytes(16).toString('hex')
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    
    await SystemLog.create({
      action: 'user_signup',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName } });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    user.lastLogin = new Date();
    await user.save();
    
    await SystemLog.create({
      action: 'user_login',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    const nonce = crypto.randomBytes(16).toString('hex');
    res.json({ nonce });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate nonce' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      user = await User.create({
        walletAddress,
        apiKey: crypto.randomBytes(16).toString('hex')
      });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    user.lastLogin = new Date();
    await user.save();
    
    await SystemLog.create({
      action: 'wallet_login',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ token, user: { id: user._id, walletAddress: user.walletAddress } });
  } catch (err) {
    res.status(500).json({ error: 'Wallet login failed' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    const user = await User.create({
      walletAddress,
      apiKey: crypto.randomBytes(16).toString('hex')
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    
    await SystemLog.create({
      action: 'wallet_signup',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ token, user: { id: user._id, walletAddress: user.walletAddress } });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Wallet already registered' });
    }
    res.status(500).json({ error: 'Wallet registration failed' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (user) {
      const resetToken = crypto.randomBytes(20).toString('hex');
      const resetExpires = Date.now() + 3600000; // 1 hour
      
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = resetExpires;
      await user.save();
      
      const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
      
      await transporter.sendMail({
        to: user.email,
        subject: 'Password Reset Request',
        html: `Please click <a href="${resetUrl}">here</a> to reset your password.`
      });
    }
    
    res.json({ message: 'If an account exists with that email, a reset link has been sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    await SystemLog.create({
      action: 'password_reset',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    await SystemLog.create({
      action: 'user_logout',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// 2. User Endpoints (15 endpoints)
app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.get('/api/v1/auth/status', authenticate, async (req, res) => {
  try {
    res.json({ isAuthenticated: true, user: { id: req.user._id, email: req.user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check auth status' });
  }
});

app.get('/api/v1/auth/check', authenticate, async (req, res) => {
  try {
    res.json({ isValid: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check auth status' });
  }
});

app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.get('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('settings');
    res.json(user.settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { settings } = req.body;
    await User.findByIdAndUpdate(req.user._id, { $set: { settings } });
    
    await SystemLog.create({
      action: 'update_settings',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { settings }
    });
    
    res.json({ message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.array('documents'), async (req, res) => {
  try {
    const documents = req.files.map(file => ({
      type: file.fieldname,
      url: `https://storage.example.com/kyc/${req.user._id}/${file.originalname}`,
      uploadedAt: new Date()
    }));
    
    await User.findByIdAndUpdate(req.user._id, {
      $push: { kycDocuments: { $each: documents } },
      kycStatus: 'pending'
    });
    
    await SystemLog.create({
      action: 'kyc_submission',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'KYC documents submitted for review' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit KYC documents' });
  }
});

app.patch('/api/v1/auth/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);
    
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    await SystemLog.create({
      action: 'password_change',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update password' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(16).toString('hex');
    await User.findByIdAndUpdate(req.user._id, { apiKey });
    
    await SystemLog.create({
      action: 'api_key_regeneration',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ apiKey });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate API key' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id });
    
    const exportData = {
      user,
      trades,
      transactions
    };
    
    await transporter.sendMail({
      to: user.email,
      subject: 'Your Data Export',
      html: `Your data export is attached.`,
      attachments: [{
        filename: 'user-data.json',
        content: JSON.stringify(exportData, null, 2)
      }]
    });
    
    await SystemLog.create({
      action: 'data_export',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'Data export sent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to export data' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    await Trade.deleteMany({ userId: req.user._id });
    await Transaction.deleteMany({ userId: req.user._id });
    
    await SystemLog.create({
      action: 'account_deletion',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

app.get('/api/v1/team', async (req, res) => {
  try {
    const team = [
      { name: 'John Doe', role: 'CEO', bio: 'Founder and CEO with 10+ years in crypto', avatar: '/team/john.jpg' },
      { name: 'Jane Smith', role: 'CTO', bio: 'Blockchain expert and technical lead', avatar: '/team/jane.jpg' },
      { name: 'Mike Johnson', role: 'CFO', bio: 'Financial strategist and investor', avatar: '/team/mike.jpg' },
      { name: 'Sarah Williams', role: 'CMO', bio: 'Marketing and growth specialist', avatar: '/team/sarah.jpg' }
    ];
    res.json(team);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch team data' });
  }
});

// 3. Trading Endpoints (12 endpoints)
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('portfolio balance');
    res.json({ portfolio: user.portfolio, balance: user.balance });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch portfolio' });
  }
});

app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'pending' }).sort({ createdAt: -1 });
    res.json(trades);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch active trades' });
  }
});

app.get('/api/v1/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(10);
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = Object.keys(COINS).map(symbol => ({
      symbol,
      name: COINS[symbol].name,
      price: getCurrentPrice(symbol),
      change: (Math.random() * 2 - 1) * COINS[symbol].volatility
    }));
    res.json(coins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch coins' });
  }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
  try {
    const rates = {};
    const coins = Object.keys(COINS);
    
    for (let i = 0; i < coins.length; i++) {
      for (let j = 0; j < coins.length; j++) {
        if (i !== j) {
          const pair = `${coins[i]}_${coins[j]}`;
          rates[pair] = getConversionRate(coins[i], coins[j]);
        }
      }
    }
    
    res.json(rates);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch rates' });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) {
      return res.status(400).json({ error: 'Missing from or to parameters' });
    }
    
    const rate = getConversionRate(from, to);
    res.json({ from, to, rate });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch rate' });
  }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = await User.findById(req.user._id);
    
    // Check if user has enough balance
    const fromCoinBalance = user.portfolio.find(c => c.coin === fromCoin);
    if (!fromCoinBalance || fromCoinBalance.amount < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const rate = getConversionRate(fromCoin, toCoin);
    const convertedAmount = amount * rate * 0.995; // 0.5% fee
    
    // Update portfolio
    await User.findByIdAndUpdate(req.user._id, {
      $inc: {
        'portfolio.$[elem].amount': -amount
      }
    }, {
      arrayFilters: [{ 'elem.coin': fromCoin }]
    });
    
    const toCoinExists = user.portfolio.some(c => c.coin === toCoin);
    if (toCoinExists) {
      await User.findByIdAndUpdate(req.user._id, {
        $inc: {
          'portfolio.$[elem].amount': convertedAmount
        }
      }, {
        arrayFilters: [{ 'elem.coin': toCoin }]
      });
    } else {
      await User.findByIdAndUpdate(req.user._id, {
        $push: {
          portfolio: {
            coin: toCoin,
            amount: convertedAmount,
            value: convertedAmount * getCurrentPrice(toCoin)
          }
        }
      });
    }
    
    // Create trade record
    const trade = await Trade.create({
      userId: user._id,
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate,
      fee: amount * rate * 0.005,
      status: 'completed'
    });
    
    // Create transaction record
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount,
      coin: fromCoin,
      status: 'completed'
    });
    
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount: convertedAmount,
      coin: toCoin,
      status: 'completed'
    });
    
    // Broadcast update
    const updatedUser = await User.findById(user._id).select('portfolio balance');
    broadcastToUser(user._id, 'portfolio_update', updatedUser);
    
    await SystemLog.create({
      action: 'coin_conversion',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { fromCoin, toCoin, amount }
    });
    
    res.json({ message: 'Conversion successful', trade });
  } catch (err) {
    res.status(500).json({ error: 'Conversion failed' });
  }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'completed' }).sort({ createdAt: -1 });
    res.json(trades);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.get('/api/v1/market/data', async (req, res) => {
  try {
    const marketData = Object.keys(COINS).map(symbol => ({
      symbol,
      price: getCurrentPrice(symbol),
      change: (Math.random() * 2 - 1) * COINS[symbol].volatility,
      volume: Math.random() * 1000000
    }));
    res.json(marketData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch market data' });
  }
});

app.get('/api/v1/market/detailed', async (req, res) => {
  try {
    const detailedData = Object.keys(COINS).map(symbol => ({
      symbol,
      name: COINS[symbol].name,
      price: getCurrentPrice(symbol),
      change24h: (Math.random() * 2 - 1) * COINS[symbol].volatility,
      high24h: getCurrentPrice(symbol) * (1 + Math.random() * 0.05),
      low24h: getCurrentPrice(symbol) * (1 - Math.random() * 0.05),
      volume: Math.random() * 1000000,
      marketCap: getCurrentPrice(symbol) * (1000000 + Math.random() * 9000000)
    }));
    res.json(detailedData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch detailed market data' });
  }
});

// 4. Wallet Endpoints (6 endpoints)
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    res.json({ address: FIXED_DEPOSIT_ADDRESS, memo: `User_${req.user._id}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get deposit address' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { coin, amount, address } = req.body;
    const user = await User.findById(req.user._id);
    
    // Check if user has enough balance
    const coinBalance = user.portfolio.find(c => c.coin === coin);
    if (!coinBalance || coinBalance.amount < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Update portfolio
    await User.findByIdAndUpdate(req.user._id, {
      $inc: {
        'portfolio.$[elem].amount': -amount
      }
    }, {
      arrayFilters: [{ 'elem.coin': coin }]
    });
    
    // Create transaction record
    const transaction = await Transaction.create({
      userId: user._id,
      type: 'withdrawal',
      amount,
      coin,
      address,
      status: 'pending'
    });
    
    // Broadcast update
    const updatedUser = await User.findById(user._id).select('portfolio balance');
    broadcastToUser(user._id, 'portfolio_update', updatedUser);
    
    await SystemLog.create({
      action: 'withdrawal_request',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { coin, amount, address }
    });
    
    res.json({ message: 'Withdrawal request submitted', transaction });
  } catch (err) {
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    const price = getCurrentPrice(coin);
    const totalCost = amount * price;
    
    const user = await User.findById(req.user._id);
    if (user.balance < totalCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Deduct balance
    user.balance -= totalCost;
    await user.save();
    
    // Add to portfolio
    const coinExists = user.portfolio.some(c => c.coin === coin);
    if (coinExists) {
      await User.findByIdAndUpdate(req.user._id, {
        $inc: {
          'portfolio.$[elem].amount': amount,
          'portfolio.$[elem].value': totalCost
        }
      }, {
        arrayFilters: [{ 'elem.coin': coin }]
      });
    } else {
      await User.findByIdAndUpdate(req.user._id, {
        $push: {
          portfolio: {
            coin,
            amount,
            value: totalCost
          }
        }
      });
    }
    
    // Create trade record
    const trade = await Trade.create({
      userId: user._id,
      type: 'buy',
      fromCoin: 'USD',
      toCoin: coin,
      amount,
      rate: price,
      fee: totalCost * 0.005, // 0.5% fee
      status: 'completed'
    });
    
    // Create transaction record
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount: totalCost,
      coin: 'USD',
      status: 'completed'
    });
    
    // Broadcast update
    const updatedUser = await User.findById(user._id).select('portfolio balance');
    broadcastToUser(user._id, 'portfolio_update', updatedUser);
    
    await SystemLog.create({
      action: 'buy_trade',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { coin, amount }
    });
    
    res.json({ message: 'Buy order executed', trade });
  } catch (err) {
    res.status(500).json({ error: 'Buy order failed' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    const price = getCurrentPrice(coin);
    const totalValue = amount * price;
    
    const user = await User.findById(req.user._id);
    const coinBalance = user.portfolio.find(c => c.coin === coin);
    if (!coinBalance || coinBalance.amount < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Add to balance
    user.balance += totalValue * 0.995; // 0.5% fee
    await user.save();
    
    // Remove from portfolio
    await User.findByIdAndUpdate(req.user._id, {
      $inc: {
        'portfolio.$[elem].amount': -amount,
        'portfolio.$[elem].value': -totalValue
      }
    }, {
      arrayFilters: [{ 'elem.coin': coin }]
    });
    
    // Create trade record
    const trade = await Trade.create({
      userId: user._id,
      type: 'sell',
      fromCoin: coin,
      toCoin: 'USD',
      amount,
      rate: price,
      fee: totalValue * 0.005, // 0.5% fee
      status: 'completed'
    });
    
    // Create transaction record
    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount,
      coin,
      status: 'completed'
    });
    
    // Broadcast update
    const updatedUser = await User.findById(user._id).select('portfolio balance');
    broadcastToUser(user._id, 'portfolio_update', updatedUser);
    
    await SystemLog.create({
      action: 'sell_trade',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { coin, amount }
    });
    
    res.json({ message: 'Sell order executed', trade });
  } catch (err) {
    res.status(500).json({ error: 'Sell order failed' });
  }
});

// 5. Support Endpoints (6 endpoints)
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ order: 1 });
    if (faqs.length === 0) {
      // Seed some FAQs if none exist
      const defaultFaqs = [
        { question: 'How do I sign up?', answer: 'Click the Sign Up button and follow the instructions.', category: 'General', order: 1 },
        { question: 'How do I deposit funds?', answer: 'Go to the Wallet section and use your deposit address.', category: 'Wallet', order: 2 },
        { question: 'How do I trade?', answer: 'Navigate to the Exchange section to buy and sell coins.', category: 'Trading', order: 3 },
        { question: 'What are the fees?', answer: 'We charge 0.5% fee on all trades.', category: 'Fees', order: 4 },
        { question: 'How do I contact support?', answer: 'Use the Support page to submit a ticket.', category: 'Support', order: 5 }
      ];
      await FAQ.insertMany(defaultFaqs);
      res.json(defaultFaqs);
    } else {
      res.json(faqs);
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch FAQs' });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

app.post('/api/v1/support/contact', upload.array('attachments'), async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    const attachments = req.files?.map(file => file.originalname) || [];
    
    const ticket = await SupportTicket.create({
      email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    await SystemLog.create({
      action: 'support_ticket',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { email, subject }
    });
    
    res.json({ message: 'Ticket submitted successfully', ticket });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit ticket' });
  }
});

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files?.map(file => file.originalname) || [];
    
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    await SystemLog.create({
      action: 'support_ticket',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { subject }
    });
    
    res.json({ message: 'Ticket submitted successfully', ticket });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit ticket' });
  }
});

app.post('/api/v1/support', authenticate, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files?.map(file => file.originalname) || [];
    
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    await SystemLog.create({
      action: 'support_ticket',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { subject }
    });
    
    res.json({ message: 'Ticket submitted successfully', ticket });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit ticket' });
  }
});

// 6. Statistics Endpoints (4 endpoints)
app.get('/api/v1/stats', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const tradeCount = await Trade.countDocuments({ status: 'completed' });
    const volume24h = await Trade.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      users: userCount,
      activeTraders: Math.floor(userCount * 0.7),
      trades: tradeCount,
      volume24h: volume24h[0]?.total || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// 7. Admin Endpoints (16 endpoints)
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isAdmin: true });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '8h' });
    user.lastLogin = new Date();
    await user.save();
    
    await SystemLog.create({
      action: 'admin_login',
      userId: user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, async (req, res) => {
  try {
    res.json({ isValid: true, user: req.user });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const newUsers24h = await User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    const tradeCount = await Trade.countDocuments();
    const volume24h = await Trade.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingKyc = await User.countDocuments({ kycStatus: 'pending' });
    const openTickets = await SupportTicket.countDocuments({ status: 'open' });
    
    res.json({
      users: userCount,
      newUsers24h,
      trades: tradeCount,
      volume24h: volume24h[0]?.total || 0,
      pendingKyc,
      openTickets
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, sort } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    
    let sortOption = { createdAt: -1 };
    if (sort === 'name') sortOption = { firstName: 1 };
    if (sort === 'email') sortOption = { email: 1 };
    if (sort === 'recent') sortOption = { lastLogin: -1 };
    
    const users = await User.find(query)
      .select('-password')
      .sort(sortOption)
      .skip(skip)
      .limit(limit);
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    
    res.json({ user, trades, transactions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { kycStatus, isVerified, isAdmin } = req.body;
    
    const updates = {};
    if (kycStatus) updates.kycStatus = kycStatus;
    if (isVerified !== undefined) updates.isVerified = isVerified;
    if (isAdmin !== undefined) updates.isAdmin = isAdmin;
    
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    
    if (kycStatus === 'verified') {
      await transporter.sendMail({
        to: user.email,
        subject: 'KYC Verification Complete',
        html: 'Your KYC documents have been verified. You can now access all platform features.'
      });
    }
    
    await SystemLog.create({
      action: 'admin_user_update',
      userId: req.user._id,
      targetUserId: req.params.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: updates
    });
    
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    
    const trades = await Trade.find(query)
      .populate('userId', 'email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Trade.countDocuments(query);
    
    res.json({ trades, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Transaction.countDocuments(query);
    
    res.json({ transactions, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) query.status = status;
    
    const tickets = await SupportTicket.find(query)
      .populate('userId', 'email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({ tickets, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'email firstName lastName')
      .populate('responses.userId', 'email firstName lastName isAdmin');
    
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch ticket' });
  }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = req.body;
    
    const updates = {};
    if (status) updates.status = status;
    
    const ticket = await SupportTicket.findByIdAndUpdate(req.params.id, updates, { new: true });
    
    if (response) {
      ticket.responses.push({
        userId: req.user._id,
        message: response,
        isAdmin: true
      });
      await ticket.save();
    }
    
    await SystemLog.create({
      action: 'admin_ticket_update',
      userId: req.user._id,
      ticketId: req.params.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { status, response: !!response }
    });
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update ticket' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { kycStatus: status || 'pending' };
    const users = await User.find(query)
      .select('firstName lastName email kycStatus kycDocuments createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch KYC submissions' });
  }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: status }, { new: true });
    
    await transporter.sendMail({
      to: user.email,
      subject: `KYC Submission ${status === 'verified' ? 'Approved' : 'Rejected'}`,
      html: `Your KYC submission has been ${status === 'verified' ? 'approved' : 'rejected'}.`
    });
    
    await SystemLog.create({
      action: 'admin_kyc_review',
      userId: req.user._id,
      targetUserId: req.params.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { status }
    });
    
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update KYC status' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, action, userId } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (action) query.action = action;
    if (userId) query.userId = userId;
    
    const logs = await SystemLog.find(query)
      .populate('userId', 'email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await SystemLog.countDocuments(query);
    
    res.json({ logs, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    // Broadcast to all connected clients
    clients.forEach((ws, userId) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ event: 'admin_broadcast', data: { message } }));
      }
    });
    
    await SystemLog.create({
      action: 'admin_broadcast',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { message }
    });
    
    res.json({ message: 'Broadcast sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send broadcast' });
  }
});

app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, this would come from a database
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.005,
      withdrawalFee: 0.001,
      depositEnabled: true,
      withdrawalEnabled: true,
      signupEnabled: true,
      kycRequired: true
    };
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, this would save to a database
    const { settings } = req.body;
    
    await SystemLog.create({
      action: 'admin_settings_update',
      userId: req.user._id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: settings
    });
    
    res.json({ message: 'Settings updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Serve static files (frontend)
app.use(express.static('public'));

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Handle errors
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong' });
});
