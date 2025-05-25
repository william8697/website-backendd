require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

// JWT Config
const JWT_SECRET = '17581758Na.%';

// Email configuration
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
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  balance: { type: Number, default: 0 },
  portfolio: { type: Object, default: {} },
  settings: {
    currency: { type: String, default: 'USD' },
    theme: { type: String, default: 'dark' },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false }
  },
  kyc: {
    verified: { type: Boolean, default: false },
    firstName: String,
    lastName: String,
    address: String,
    idNumber: String,
    idType: String,
    idFront: String,
    idBack: String,
    selfie: String
  },
  walletAddress: String,
  nonce: String,
  apiKey: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['buy', 'sell', 'convert'] },
  fromCoin: String,
  toCoin: String,
  amount: Number,
  rate: Number,
  fee: Number,
  status: { type: String, default: 'completed' },
  timestamp: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'] },
  amount: Number,
  currency: String,
  status: { type: String, default: 'pending' },
  txHash: String,
  address: String,
  timestamp: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: String,
  message: String,
  status: { type: String, default: 'open', enum: ['open', 'pending', 'resolved', 'closed'] },
  attachments: [String],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    timestamp: { type: Date, default: Date.now },
    isAdmin: Boolean
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);

// WebSocket Server
const server = app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
const wss = new WebSocket.Server({ server });

// WebSocket connections map
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
    
    ws.on('message', (message) => {
      const data = JSON.parse(message);
      handleWebSocketMessage(data, decoded.userId);
    });

    ws.on('close', () => {
      clients.delete(decoded.userId);
    });

    ws.send(JSON.stringify({ type: 'CONNECTION_ESTABLISHED', message: 'WebSocket connection established' }));
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

function handleWebSocketMessage(data, userId) {
  // Handle different types of WebSocket messages
  switch (data.type) {
    case 'PING':
      const client = clients.get(userId);
      if (client) {
        client.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
      }
      break;
    // Add more message types as needed
  }
}

function broadcastToUser(userId, data) {
  const client = clients.get(userId);
  if (client) {
    client.send(JSON.stringify(data));
  }
}

// Helper functions
function generateToken(user) {
  return jwt.sign(
    { userId: user._id, email: user.email, isAdmin: user.isAdmin },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

async function getCoinPrices() {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false');
    return response.data.reduce((acc, coin) => {
      acc[coin.symbol.toUpperCase()] = coin.current_price;
      return acc;
    }, {});
  } catch (error) {
    console.error('Error fetching coin prices:', error);
    return {
      BTC: 50000,
      ETH: 3000,
      BNB: 400,
      SOL: 100,
      ADA: 1,
      XRP: 0.8,
      DOT: 20,
      DOGE: 0.2,
      SHIB: 0.00001,
      MATIC: 1.5
    };
  }
}

async function calculateArbitrage(fromCoin, toCoin, amount) {
  const prices = await getCoinPrices();
  
  if (!prices[fromCoin] || !prices[toCoin]) {
    throw new Error('Invalid coin symbols');
  }

  // Simple arbitrage calculation (in a real app, this would be more complex)
  const fromPrice = prices[fromCoin];
  const toPrice = prices[toCoin];
  const rate = fromPrice / toPrice;
  const fee = 0.0025; // 0.25% fee
  const feeAmount = amount * fee;
  const amountAfterFee = amount - feeAmount;
  const convertedAmount = amountAfterFee * rate;

  return {
    rate,
    fee,
    feeAmount,
    convertedAmount,
    fromCoin,
    toCoin,
    fromAmount: amount,
    toAmount: convertedAmount
  };
}

// Authentication middleware
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Platform Backend');
});

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      password: hashedPassword,
      nonce: crypto.randomBytes(16).toString('hex')
    });

    await user.save();

    const token = generateToken(user);
    res.status(201).json({ token, user: { email: user.email, balance: user.balance, portfolio: user.portfolio } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    user.lastLogin = Date.now();
    await user.save();

    const token = generateToken(user);
    res.json({ 
      token, 
      user: { 
        email: user.email, 
        balance: user.balance, 
        portfolio: user.portfolio,
        isAdmin: user.isAdmin,
        settings: user.settings,
        kyc: user.kyc
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ message: 'Wallet address and signature are required' });
    }

    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      // Create new user if not exists
      user = new User({
        walletAddress,
        nonce: crypto.randomBytes(16).toString('hex'),
        email: `${walletAddress}@wallet.com`
      });
      await user.save();
    }

    // Verify signature (simplified - in production you'd use proper verification)
    if (signature !== `signature_for_${user.nonce}`) {
      return res.status(401).json({ message: 'Invalid signature' });
    }

    // Update nonce for next login
    user.nonce = crypto.randomBytes(16).toString('hex');
    user.lastLogin = Date.now();
    await user.save();

    const token = generateToken(user);
    res.json({ 
      token, 
      user: { 
        walletAddress: user.walletAddress, 
        balance: user.balance, 
        portfolio: user.portfolio,
        isAdmin: user.isAdmin
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during wallet login' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    res.json({ 
      user: { 
        email: req.user.email, 
        balance: req.user.balance, 
        portfolio: req.user.portfolio,
        isAdmin: req.user.isAdmin,
        settings: req.user.settings,
        kyc: req.user.kyc,
        walletAddress: req.user.walletAddress
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/auth/verify', authenticate, async (req, res) => {
  try {
    res.json({ 
      valid: true, 
      user: { 
        email: req.user.email, 
        isAdmin: req.user.isAdmin,
        balance: req.user.balance,
        portfolio: req.user.portfolio
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during logout' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user exists for security
      return res.json({ message: 'If an account exists with that email, a reset link has been sent' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }

    const user = await User.findOne({ 
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    res.json({ 
      user: { 
        email: req.user.email, 
        balance: req.user.balance, 
        portfolio: req.user.portfolio,
        settings: req.user.settings,
        kyc: req.user.kyc,
        walletAddress: req.user.walletAddress,
        createdAt: req.user.createdAt,
        isAdmin: req.user.isAdmin,
        apiKey: req.user.apiKey
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { currency, theme, notifications, twoFA } = req.body;
    
    const updates = {};
    if (currency) updates['settings.currency'] = currency;
    if (theme) updates['settings.theme'] = theme;
    if (notifications !== undefined) updates['settings.notifications'] = notifications;
    if (twoFA !== undefined) updates['settings.twoFA'] = twoFA;

    await User.findByIdAndUpdate(req.user._id, { $set: updates });
    
    const updatedUser = await User.findById(req.user._id);
    res.json({ settings: updatedUser.settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating settings' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const newApiKey = crypto.randomBytes(16).toString('hex');
    await User.findByIdAndUpdate(req.user._id, { $set: { apiKey: newApiKey } });
    res.json({ apiKey: newApiKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error generating API key' });
  }
});

app.post('/api/v1/users/kyc', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, address, idNumber, idType, idFront, idBack, selfie } = req.body;
    
    if (!firstName || !lastName || !address || !idNumber || !idType || !idFront || !idBack || !selfie) {
      return res.status(400).json({ message: 'All KYC fields are required' });
    }

    const kycData = {
      firstName,
      lastName,
      address,
      idNumber,
      idType,
      idFront,
      idBack,
      selfie,
      verified: false
    };

    await User.findByIdAndUpdate(req.user._id, { $set: { kyc: kycData } });
    res.json({ message: 'KYC submitted for verification' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error submitting KYC' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id });

    const data = {
      user: {
        email: user.email,
        balance: user.balance,
        portfolio: user.portfolio,
        settings: user.settings,
        kyc: user.kyc,
        createdAt: user.createdAt
      },
      trades,
      transactions
    };

    // In a real app, you might want to email this data or store it temporarily
    res.json({ data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error exporting data' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }

    const isMatch = await bcrypt.compare(password, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    await User.findByIdAndDelete(req.user._id);
    await Trade.deleteMany({ userId: req.user._id });
    await Transaction.deleteMany({ userId: req.user._id });
    await Ticket.deleteMany({ userId: req.user._id });

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error deleting account' });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'completed' })
      .sort({ timestamp: -1 })
      .limit(20);
    
    res.json({ trades });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching trades' });
  }
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    
    if (!coin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Valid coin and amount are required' });
    }

    const prices = await getCoinPrices();
    const coinPrice = prices[coin.toUpperCase()];
    
    if (!coinPrice) {
      return res.status(400).json({ message: 'Invalid coin symbol' });
    }

    const totalCost = amount * coinPrice;
    
    if (req.user.balance < totalCost) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Update user balance and portfolio
    const user = await User.findById(req.user._id);
    user.balance -= totalCost;
    
    if (!user.portfolio[coin]) {
      user.portfolio[coin] = 0;
    }
    
    user.portfolio[coin] += amount;
    await user.save();

    // Record trade
    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      fromCoin: 'USD',
      toCoin: coin,
      amount: totalCost,
      rate: coinPrice,
      fee: totalCost * 0.0025,
      status: 'completed'
    });
    await trade.save();

    // Record transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: totalCost,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    broadcastToUser(user._id, {
      type: 'PORTFOLIO_UPDATE',
      portfolio: user.portfolio
    });

    res.json({ 
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: user.portfolio
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing trade' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    
    if (!coin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Valid coin and amount are required' });
    }

    const prices = await getCoinPrices();
    const coinPrice = prices[coin.toUpperCase()];
    
    if (!coinPrice) {
      return res.status(400).json({ message: 'Invalid coin symbol' });
    }

    const user = await User.findById(req.user._id);
    
    if (!user.portfolio[coin] || user.portfolio[coin] < amount) {
      return res.status(400).json({ message: 'Insufficient coin balance' });
    }

    const totalValue = amount * coinPrice;
    const fee = totalValue * 0.0025;
    const amountAfterFee = totalValue - fee;

    // Update user balance and portfolio
    user.balance += amountAfterFee;
    user.portfolio[coin] -= amount;
    
    if (user.portfolio[coin] === 0) {
      delete user.portfolio[coin];
    }
    
    await user.save();

    // Record trade
    const trade = new Trade({
      userId: user._id,
      type: 'sell',
      fromCoin: coin,
      toCoin: 'USD',
      amount,
      rate: coinPrice,
      fee,
      status: 'completed'
    });
    await trade.save();

    // Record transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: amountAfterFee,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    broadcastToUser(user._id, {
      type: 'PORTFOLIO_UPDATE',
      portfolio: user.portfolio
    });

    res.json({ 
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: user.portfolio
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing trade' });
  }
});

app.post('/api/v1/trades/convert', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Valid coins and amount are required' });
    }

    const user = await User.findById(req.user._id);
    
    if (fromCoin !== 'USD' && (!user.portfolio[fromCoin] || user.portfolio[fromCoin] < amount)) {
      return res.status(400).json({ message: 'Insufficient coin balance' });
    }

    // Calculate arbitrage
    const arbitrageResult = await calculateArbitrage(fromCoin, toCoin, amount);
    
    if (fromCoin === 'USD') {
      if (user.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }
      
      user.balance -= amount;
      if (!user.portfolio[toCoin]) {
        user.portfolio[toCoin] = 0;
      }
      user.portfolio[toCoin] += arbitrageResult.toAmount;
    } else {
      user.portfolio[fromCoin] -= amount;
      if (user.portfolio[fromCoin] === 0) {
        delete user.portfolio[fromCoin];
      }
      
      if (!user.portfolio[toCoin]) {
        user.portfolio[toCoin] = 0;
      }
      user.portfolio[toCoin] += arbitrageResult.toAmount;
    }

    await user.save();

    // Record trade
    const trade = new Trade({
      userId: user._id,
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate: arbitrageResult.rate,
      fee: arbitrageResult.feeAmount,
      status: 'completed'
    });
    await trade.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    broadcastToUser(user._id, {
      type: 'PORTFOLIO_UPDATE',
      portfolio: user.portfolio
    });

    res.json({ 
      message: 'Conversion executed successfully',
      balance: user.balance,
      portfolio: user.portfolio,
      conversion: arbitrageResult
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing conversion' });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const prices = await getCoinPrices();
    const portfolio = req.user.portfolio;
    
    // Calculate portfolio value
    let totalValue = 0;
    const detailedPortfolio = {};
    
    for (const [coin, amount] of Object.entries(portfolio)) {
      const price = prices[coin] || 0;
      const value = amount * price;
      totalValue += value;
      
      detailedPortfolio[coin] = {
        amount,
        price,
        value
      };
    }

    res.json({ 
      portfolio: detailedPortfolio,
      totalValue,
      balance: req.user.balance,
      netWorth: req.user.balance + totalValue
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching portfolio' });
  }
});

// Market Data Routes
app.get('/api/v1/market/data', async (req, res) => {
  try {
    const prices = await getCoinPrices();
    const coins = Object.keys(prices).map(symbol => ({
      symbol,
      price: prices[symbol],
      change24h: (Math.random() * 10 - 5).toFixed(2) // Simulated change
    }));

    // Sort by top gainers and losers
    const topGainers = [...coins].sort((a, b) => b.change24h - a.change24h).slice(0, 5);
    const topLosers = [...coins].sort((a, b) => a.change24h - b.change24h).slice(0, 5);
    const trending = [...coins].sort(() => 0.5 - Math.random()).slice(0, 5);

    res.json({ 
      prices,
      topGainers,
      topLosers,
      trending
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching market data' });
  }
});

app.get('/api/v1/market/detailed/:coin', async (req, res) => {
  try {
    const { coin } = req.params;
    const prices = await getCoinPrices();
    const price = prices[coin.toUpperCase()];
    
    if (!price) {
      return res.status(404).json({ message: 'Coin not found' });
    }

    // Simulate detailed data
    const detailedData = {
      symbol: coin.toUpperCase(),
      price,
      change24h: (Math.random() * 10 - 5).toFixed(2),
      high24h: price * (1 + Math.random() * 0.05),
      low24h: price * (1 - Math.random() * 0.05),
      volume: (Math.random() * 1000000).toFixed(2),
      marketCap: (Math.random() * 1000000000).toFixed(2),
      allTimeHigh: price * (1 + Math.random() * 0.5),
      allTimeLow: price * (1 - Math.random() * 0.5)
    };

    res.json(detailedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching detailed coin data' });
  }
});

// Exchange Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const prices = await getCoinPrices();
    const coins = Object.keys(prices).map(symbol => ({
      symbol,
      name: symbol // In a real app, you'd have proper names
    }));
    
    res.json({ coins });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching coins' });
  }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
  try {
    const prices = await getCoinPrices();
    res.json({ rates: prices });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching rates' });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ message: 'From and to currencies are required' });
    }

    const arbitrageResult = await calculateArbitrage(from, to, 1);
    res.json({ 
      from,
      to,
      rate: arbitrageResult.rate,
      fee: arbitrageResult.fee,
      feeAmount: arbitrageResult.feeAmount
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error calculating rate' });
  }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Valid coins and amount are required' });
    }

    const user = await User.findById(req.user._id);
    
    if (fromCoin !== 'USD' && (!user.portfolio[fromCoin] || user.portfolio[fromCoin] < amount)) {
      return res.status(400).json({ message: 'Insufficient coin balance' });
    }

    // Calculate arbitrage
    const arbitrageResult = await calculateArbitrage(fromCoin, toCoin, amount);
    
    if (fromCoin === 'USD') {
      if (user.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }
      
      user.balance -= amount;
      if (!user.portfolio[toCoin]) {
        user.portfolio[toCoin] = 0;
      }
      user.portfolio[toCoin] += arbitrageResult.toAmount;
    } else {
      user.portfolio[fromCoin] -= amount;
      if (user.portfolio[fromCoin] === 0) {
        delete user.portfolio[fromCoin];
      }
      
      if (!user.portfolio[toCoin]) {
        user.portfolio[toCoin] = 0;
      }
      user.portfolio[toCoin] += arbitrageResult.toAmount;
    }

    await user.save();

    // Record trade
    const trade = new Trade({
      userId: user._id,
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate: arbitrageResult.rate,
      fee: arbitrageResult.feeAmount,
      status: 'completed'
    });
    await trade.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    broadcastToUser(user._id, {
      type: 'PORTFOLIO_UPDATE',
      portfolio: user.portfolio
    });

    res.json({ 
      message: 'Conversion executed successfully',
      balance: user.balance,
      portfolio: user.portfolio,
      conversion: arbitrageResult
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing conversion' });
  }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
  try {
    const conversions = await Trade.find({ 
      userId: req.user._id,
      type: 'convert'
    }).sort({ timestamp: -1 }).limit(20);
    
    res.json({ conversions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching conversion history' });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    // In a real app, this would generate a unique deposit address for the user
    res.json({ 
      address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
      memo: req.user._id.toString()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error generating deposit address' });
  }
});

app.post('/api/v1/wallet/deposit', authenticate, async (req, res) => {
  try {
    const { amount, currency, txHash } = req.body;
    
    if (!amount || !currency || !txHash || amount <= 0) {
      return res.status(400).json({ message: 'Valid amount, currency and txHash are required' });
    }

    // In a real app, you'd verify the transaction on the blockchain
    const user = await User.findById(req.user._id);
    user.balance += amount;
    await user.save();

    // Record transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      currency,
      status: 'completed',
      txHash
    });
    await transaction.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({ 
      message: 'Deposit recorded successfully',
      balance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing deposit' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { amount, currency, address } = req.body;
    
    if (!amount || !currency || !address || amount <= 0) {
      return res.status(400).json({ message: 'Valid amount, currency and address are required' });
    }

    const user = await User.findById(req.user._id);
    
    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // In a real app, you'd actually send the funds here
    user.balance -= amount;
    await user.save();

    // Record transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency,
      status: 'pending', // Would change to completed after blockchain confirmation
      address
    });
    await transaction.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({ 
      message: 'Withdrawal request submitted',
      balance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing withdrawal' });
  }
});

app.get('/api/v1/wallet/transactions', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ timestamp: -1 })
      .limit(20);
    
    res.json({ transactions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching transactions' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, these would come from a database
    const faqs = [
      {
        id: 1,
        question: 'How do I create an account?',
        answer: 'Click on the "Sign Up" button and follow the instructions to create your account.',
        category: 'Account'
      },
      {
        id: 2,
        question: 'How do I deposit funds?',
        answer: 'Go to the Wallet section and click on "Deposit". You will be provided with a deposit address.',
        category: 'Deposits'
      },
      {
        id: 3,
        question: 'What are the trading fees?',
        answer: 'Our trading fee is 0.25% per trade.',
        category: 'Trading'
      },
      {
        id: 4,
        question: 'How do I enable two-factor authentication?',
        answer: 'Go to your Account Settings and enable 2FA in the Security section.',
        category: 'Security'
      },
      {
        id: 5,
        question: 'How long do withdrawals take?',
        answer: 'Withdrawals are typically processed within 24 hours.',
        category: 'Withdrawals'
      }
    ];
    
    res.json({ faqs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching FAQs' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json({ tickets });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching tickets' });
  }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message, attachments } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }

    const ticket = new Ticket({
      userId: req.user._id,
      subject,
      message,
      attachments: attachments || []
    });
    await ticket.save();

    res.json({ 
      message: 'Ticket created successfully',
      ticket
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating ticket' });
  }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    res.json({ ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching ticket' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
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
            message,
            isAdmin: false
          }
        },
        $set: { status: 'pending' }
      },
      { new: true }
    );
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    res.json({ 
      message: 'Reply added successfully',
      ticket
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error replying to ticket' });
  }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const activeTrades = await Trade.countDocuments({ timestamp: { $gt: Date.now() - 86400000 } });
    const totalVolume = await Trade.aggregate([
      { $match: { timestamp: { $gt: Date.now() - 86400000 } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      users: userCount,
      activeTrades,
      dailyVolume: totalVolume[0]?.total || 0
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching stats' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    user.lastLogin = Date.now();
    await user.save();

    const token = generateToken(user);
    res.json({ 
      token, 
      user: { 
        email: user.email,
        isAdmin: user.isAdmin
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticate, adminOnly, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const activeUserCount = await User.countDocuments({ active: true });
    const tradeCount = await Trade.countDocuments();
    const todayTrades = await Trade.countDocuments({ timestamp: { $gt: Date.now() - 86400000 } });
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const todayVolume = await Trade.aggregate([
      { $match: { timestamp: { $gt: Date.now() - 86400000 } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingTickets = await Ticket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ 'kyc.verified': false, 'kyc.firstName': { $exists: true } });

    res.json({
      userCount,
      activeUserCount,
      tradeCount,
      todayTrades,
      totalVolume: totalVolume[0]?.total || 0,
      todayVolume: todayVolume[0]?.total || 0,
      pendingTickets,
      pendingKYC
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching admin stats' });
  }
});

app.get('/api/v1/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -nonce -resetToken -resetTokenExpiry');
    
    const total = await User.countDocuments(query);

    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

app.get('/api/v1/admin/users/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -nonce -resetToken -resetTokenExpiry');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const trades = await Trade.find({ userId: user._id }).sort({ timestamp: -1 }).limit(10);
    const transactions = await Transaction.find({ userId: user._id }).sort({ timestamp: -1 }).limit(10);
    const tickets = await Ticket.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);

    res.json({
      user,
      trades,
      transactions,
      tickets
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user details' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', authenticate, adminOnly, async (req, res) => {
  try {
    const { amount, operation } = req.body;
    
    if (!amount || !operation || (operation !== 'add' && operation !== 'subtract')) {
      return res.status(400).json({ message: 'Valid amount and operation are required' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (operation === 'add') {
      user.balance += amount;
    } else {
      if (user.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance to subtract' });
      }
      user.balance -= amount;
    }

    await user.save();

    // Record transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'admin_adjustment',
      amount,
      currency: 'USD',
      status: 'completed',
      adminId: req.user._id
    });
    await transaction.save();

    // Broadcast update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({ 
      message: 'Balance updated successfully',
      balance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user balance' });
  }
});

app.patch('/api/v1/admin/users/:id/status', authenticate, adminOnly, async (req, res) => {
  try {
    const { active } = req.body;
    
    if (typeof active !== 'boolean') {
      return res.status(400).json({ message: 'Active status is required' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { active } },
      { new: true }
    ).select('-password -nonce -resetToken -resetTokenExpiry');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      message: 'User status updated successfully',
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user status' });
  }
});

app.post('/api/v1/admin/users/:id/reset-password', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    user.password = hashedPassword;
    await user.save();

    // In a real app, you'd email the new password to the user
    res.json({ 
      message: 'Password reset successfully',
      newPassword // In production, don't send this back - email it instead
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

app.get('/api/v1/admin/trades', authenticate, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;

    const trades = await Trade.find(query)
      .populate('userId', 'email walletAddress')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Trade.countDocuments(query);

    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticate, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;

    const transactions = await Transaction.find(query)
      .populate('userId', 'email walletAddress')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);

    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching transactions' });
  }
});

app.patch('/api/v1/admin/transactions/:id/status', authenticate, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }

    const transaction = await Transaction.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true }
    ).populate('userId', 'email walletAddress');
    
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }

    // If it's a withdrawal and status is completed, we've already subtracted the balance
    // If it's a deposit and status is completed, add to balance
    if (status === 'completed' && transaction.type === 'deposit') {
      const user = await User.findById(transaction.userId);
      if (user) {
        user.balance += transaction.amount;
        await user.save();

        // Broadcast update
        broadcastToUser(user._id, {
          type: 'BALANCE_UPDATE',
          balance: user.balance
        });
      }
    }

    res.json({ 
      message: 'Transaction status updated successfully',
      transaction
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating transaction status' });
  }
});

app.get('/api/v1/admin/tickets', authenticate, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) query.status = status;

    const tickets = await Ticket.find(query)
      .populate('userId', 'email walletAddress')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Ticket.countDocuments(query);

    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'email walletAddress')
      .populate('responses.userId', 'email walletAddress isAdmin');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    res.json({ ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching ticket' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticate, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }

    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true }
    ).populate('userId', 'email walletAddress');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    res.json({ 
      message: 'Ticket status updated successfully',
      ticket
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating ticket status' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticate, adminOnly, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }

    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      {
        $push: {
          responses: {
            userId: req.user._id,
            message,
            isAdmin: true
          }
        },
        $set: { status: 'pending' }
      },
      { new: true }
    ).populate('userId', 'email walletAddress');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Notify user via WebSocket
    broadcastToUser(ticket.userId._id, {
      type: 'TICKET_UPDATE',
      ticketId: ticket._id,
      message: 'Admin has replied to your ticket'
    });

    res.json({ 
      message: 'Reply added successfully',
      ticket
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error replying to ticket' });
  }
});

app.get('/api/v1/admin/kyc', authenticate, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, verified } = req.query;
    const skip = (page - 1) * limit;
    
    let query = { 'kyc.firstName': { $exists: true } };
    if (typeof verified !== 'undefined') {
      query['kyc.verified'] = verified === 'true';
    }

    const users = await User.find(query)
      .select('email walletAddress kyc createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(query);

    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching KYC submissions' });
  }
});

app.patch('/api/v1/admin/kyc/:id/verify', authenticate, adminOnly, async (req, res) => {
  try {
    const { verified, reason } = req.body;
    
    if (typeof verified !== 'boolean') {
      return res.status(400).json({ message: 'Verified status is required' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { 'kyc.verified': verified } },
      { new: true }
    ).select('email walletAddress kyc createdAt');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'KYC_UPDATE',
      status: verified ? 'approved' : 'rejected',
      reason
    });

    res.json({ 
      message: 'KYC status updated successfully',
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating KYC status' });
  }
});

app.get('/api/v1/admin/logs', authenticate, adminOnly, async (req, res) => {
  try {
    // In a real app, you'd have a proper logging system
    res.json({ 
      logs: [],
      message: 'Log retrieval would be implemented in production'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching logs' });
  }
});

app.post('/api/v1/admin/broadcast', authenticate, adminOnly, async (req, res) => {
  try {
    const { message, userIds } = req.body;
    
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }

    if (userIds && userIds.length > 0) {
      // Send to specific users
      for (const userId of userIds) {
        broadcastToUser(userId, {
          type: 'ADMIN_BROADCAST',
          message,
          timestamp: Date.now()
        });
      }
    } else {
      // Broadcast to all connected users
      for (const [userId, client] of clients.entries()) {
        client.send(JSON.stringify({
          type: 'ADMIN_BROADCAST',
          message,
          timestamp: Date.now()
        }));
      }
    }

    res.json({ 
      message: 'Broadcast sent successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error sending broadcast' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});
