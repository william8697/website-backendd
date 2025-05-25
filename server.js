require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const multer = require('multer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app';

// Email configuration
const emailConfig = {
  user: process.env.EMAIL_USER || '7c707ac161af1c',
  pass: process.env.EMAIL_PASS || '6c08aa4f2c679a',
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525
};

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api/', apiLimiter);

// MongoDB connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Database models
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  walletAddress: { type: String, unique: true, sparse: true },
  nonce: { type: String },
  balance: { type: Number, default: 0 },
  portfolio: { type: Map, of: Number, default: {} },
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  kycData: { type: Object },
  settings: {
    currency: { type: String, default: 'USD' },
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false }
  },
  apiKey: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  baseCurrency: { type: String, required: true },
  quoteCurrency: { type: String, required: true },
  amount: { type: Number, required: true },
  price: { type: Number, required: true },
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion'], required: true },
  currency: { type: String, required: true },
  amount: { type: Number, required: true },
  address: { type: String },
  txHash: { type: String },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved', 'closed'], default: 'open' },
  attachments: { type: [String] },
  responses: [{
    message: String,
    from: String, // 'user' or 'support'
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security', 'other'], required: true },
  createdAt: { type: Date, default: Date.now }
}));

// Hardcoded coin data with manipulated prices
const coins = {
  bitcoin: { id: 'bitcoin', symbol: 'btc', name: 'Bitcoin', price: 50123.45, change24h: 2.34 },
  ethereum: { id: 'ethereum', symbol: 'eth', name: 'Ethereum', price: 3214.56, change24h: -1.23 },
  ripple: { id: 'ripple', symbol: 'xrp', name: 'Ripple', price: 0.5432, change24h: 5.67 },
  litecoin: { id: 'litecoin', symbol: 'ltc', name: 'Litecoin', price: 178.90, change24h: 0.89 },
  cardano: { id: 'cardano', symbol: 'ada', name: 'Cardano', price: 1.234, change24h: -3.45 },
  polkadot: { id: 'polkadot', symbol: 'dot', name: 'Polkadot', price: 34.56, change24h: 7.89 },
  dogecoin: { id: 'dogecoin', symbol: 'doge', name: 'Dogecoin', price: 0.1234, change24h: 12.34 },
  solana: { id: 'solana', symbol: 'sol', name: 'Solana', price: 145.67, change24h: -2.34 },
  avalanche: { id: 'avalanche', symbol: 'avax', name: 'Avalanche', price: 56.78, change24h: 4.56 },
  polygon: { id: 'polygon', symbol: 'matic', name: 'Polygon', price: 1.567, change24h: -0.78 }
};

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
    return res.status(401).json({ message: 'Authentication required' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  const user = await User.findById(decoded.id);
  if (!user) {
    return res.status(401).json({ message: 'User not found' });
  }

  req.user = user;
  req.isAdmin = decoded.isAdmin;
  next();
};

const authenticateAdmin = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  const decoded = verifyToken(token);
  if (!decoded || !decoded.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const user = await User.findById(decoded.id);
  if (!user || !user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  req.user = user;
  req.isAdmin = true;
  next();
};

// Initialize WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  // Extract token from URL query or headers
  const token = req.url.split('token=')[1] || req.headers['sec-websocket-protocol'];
  
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    ws.close(1008, 'Invalid or expired token');
    return;
  }

  // Store user ID with the WebSocket connection
  ws.userId = decoded.id;
  ws.isAdmin = decoded.isAdmin;

  ws.on('message', (message) => {
    // Handle incoming WebSocket messages if needed
    console.log('Received message:', message);
  });

  // Send initial connection confirmation
  ws.send(JSON.stringify({ type: 'CONNECTION_ESTABLISHED', data: { timestamp: new Date() } }));
});

// Broadcast function to send data to all connected clients or specific users
const broadcast = (data, userId = null, isAdmin = false) => {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      if (userId && client.userId === userId) {
        client.send(message);
      } else if (!userId && (!isAdmin || (isAdmin && client.isAdmin))) {
        client.send(message);
      }
    }
  });
};

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Platform Backend');
});

// Auth routes
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

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      balance: 0,
      portfolio: {}
    });

    await user.save();

    const token = generateToken(user._id);
    res.json({ token, user: { email: user.email, id: user._id, balance: user.balance } });
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

    const token = generateToken(user._id, user.isAdmin);
    res.json({ 
      token, 
      user: { 
        email: user.email, 
        id: user._id, 
        balance: user.balance,
        isAdmin: user.isAdmin,
        settings: user.settings
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({ message: 'Wallet address is required' });
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    let user = await User.findOne({ walletAddress });

    if (!user) {
      // Create a new user if wallet not found
      user = new User({
        walletAddress,
        nonce,
        balance: 0,
        portfolio: {}
      });
      await user.save();
    } else {
      // Update nonce for existing user
      user.nonce = nonce;
      await user.save();
    }

    res.json({ nonce });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error generating nonce' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ message: 'Wallet address and signature are required' });
    }

    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ message: 'Wallet not registered' });
    }

    // In a real app, you would verify the signature against the nonce here
    // For this example, we'll just check that a signature was provided
    if (!signature) {
      return res.status(401).json({ message: 'Invalid signature' });
    }

    const token = generateToken(user._id, user.isAdmin);
    res.json({ 
      token, 
      user: { 
        walletAddress: user.walletAddress, 
        id: user._id, 
        balance: user.balance,
        isAdmin: user.isAdmin,
        settings: user.settings
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during wallet login' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({ 
      user: { 
        email: user.email, 
        walletAddress: user.walletAddress,
        id: user._id, 
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin,
        settings: user.settings,
        kycStatus: user.kycStatus
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

app.get('/api/v1/auth/verify', authenticate, async (req, res) => {
  try {
    res.json({ valid: true, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error verifying token' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token on the server side
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
      // Return success even if email not found to prevent email enumeration
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    // Create email transporter
    const transporter = nodemailer.createTransport({
      host: emailConfig.host,
      port: emailConfig.port,
      auth: {
        user: emailConfig.user,
        pass: emailConfig.pass
      }
    });

    // Send email
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your Crypto Trading Market account.</p>
        <p>Click <a href="${resetUrl}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.json({ message: 'If an account exists with this email, a reset link has been sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing password reset' });
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

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

// User routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({ 
      user: { 
        email: user.email, 
        walletAddress: user.walletAddress,
        id: user._id, 
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin,
        settings: user.settings,
        kycStatus: user.kycStatus,
        createdAt: user.createdAt
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

app.get('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({ settings: user.settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user settings' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { currency, language, theme, notifications, twoFA } = req.body;

    if (currency) user.settings.currency = currency;
    if (language) user.settings.language = language;
    if (theme) user.settings.theme = theme;
    if (notifications !== undefined) user.settings.notifications = notifications;
    if (twoFA !== undefined) user.settings.twoFA = twoFA;

    await user.save();
    res.json({ settings: user.settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user settings' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = req.user;
    user.apiKey = crypto.randomBytes(16).toString('hex');
    await user.save();
    res.json({ apiKey: user.apiKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error generating API key' });
  }
});

app.post('/api/v1/users/kyc', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { name, address, documentType, documentNumber } = req.body;

    if (!name || !address || !documentType || !documentNumber) {
      return res.status(400).json({ message: 'All KYC fields are required' });
    }

    user.kycData = { name, address, documentType, documentNumber };
    user.kycStatus = 'pending';
    await user.save();

    res.json({ message: 'KYC submitted for review', kycStatus: user.kycStatus });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error submitting KYC' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    // In a real app, you would generate a comprehensive data export
    // For this example, we'll just return some basic user data
    const userData = {
      email: user.email,
      walletAddress: user.walletAddress,
      balance: user.balance,
      portfolio: user.portfolio,
      settings: user.settings,
      createdAt: user.createdAt
    };

    res.json({ 
      message: 'Data export generated successfully',
      data: userData
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error exporting data' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    await User.findByIdAndDelete(user._id);
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error deleting account' });
  }
});

// Portfolio and trading routes
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({ 
      balance: user.balance,
      portfolio: user.portfolio 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching portfolio' });
  }
});

app.get('/api/v1/market/data', async (req, res) => {
  try {
    // Return our hardcoded coin data
    res.json({ 
      coins: Object.values(coins),
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching market data' });
  }
});

app.get('/api/v1/market/detailed', async (req, res) => {
  try {
    // Return more detailed market data
    const detailedCoins = Object.values(coins).map(coin => ({
      ...coin,
      marketCap: coin.price * 1000000 * (0.8 + Math.random() * 0.4), // Simulate market cap
      volume24h: coin.price * 100000 * (0.5 + Math.random()), // Simulate 24h volume
      circulatingSupply: 1000000 * (0.8 + Math.random() * 0.4) // Simulate circulating supply
    }));

    res.json({ 
      coins: detailedCoins,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching detailed market data' });
  }
});

app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    // Return list of coins available for exchange
    res.json({ 
      coins: Object.values(coins).map(coin => ({
        id: coin.id,
        symbol: coin.symbol,
        name: coin.name
      })),
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching exchange coins' });
  }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
  try {
    // Return exchange rates between all coins
    const rates = {};
    const coinList = Object.values(coins);
    
    for (let i = 0; i < coinList.length; i++) {
      for (let j = 0; j < coinList.length; j++) {
        if (i !== j) {
          const from = coinList[i].id;
          const to = coinList[j].id;
          const rate = coinList[i].price / coinList[j].price;
          
          if (!rates[from]) rates[from] = {};
          rates[from][to] = rate;
        }
      }
    }

    res.json({ 
      rates,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching exchange rates' });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ message: 'From and to currencies are required' });
    }

    const fromCoin = coins[from.toLowerCase()];
    const toCoin = coins[to.toLowerCase()];
    
    if (!fromCoin || !toCoin) {
      return res.status(400).json({ message: 'Invalid currency specified' });
    }

    const rate = fromCoin.price / toCoin.price;
    res.json({ 
      from: fromCoin.id,
      to: toCoin.id,
      rate,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching exchange rate' });
  }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const conversions = await Transaction.find({ 
      userId: user._id,
      type: 'conversion'
    }).sort({ createdAt: -1 }).limit(10);

    res.json({ conversions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching conversion history' });
  }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid conversion parameters' });
    }

    const fromCoin = coins[from.toLowerCase()];
    const toCoin = coins[to.toLowerCase()];
    
    if (!fromCoin || !toCoin) {
      return res.status(400).json({ message: 'Invalid currency specified' });
    }

    // Check if user has enough of the "from" currency
    const fromBalance = user.portfolio.get(from) || 0;
    if (fromBalance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Calculate conversion
    const rate = fromCoin.price / toCoin.price;
    const convertedAmount = amount * rate;

    // Update user portfolio
    user.portfolio.set(from, fromBalance - amount);
    const toBalance = user.portfolio.get(to) || 0;
    user.portfolio.set(to, toBalance + convertedAmount);
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'conversion',
      currency: `${from}_to_${to}`,
      amount: amount,
      status: 'completed'
    });
    await transaction.save();

    // Broadcast update to user
    broadcast({
      type: 'CONVERSION_UPDATE',
      data: {
        from,
        to,
        amount,
        convertedAmount,
        rate,
        newFromBalance: user.portfolio.get(from),
        newToBalance: user.portfolio.get(to)
      }
    }, user._id);

    res.json({ 
      from,
      to,
      amount,
      convertedAmount,
      rate,
      newFromBalance: user.portfolio.get(from),
      newToBalance: user.portfolio.get(to)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing conversion' });
  }
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { coin, amount } = req.body;
    
    if (!coin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid trade parameters' });
    }

    const coinData = coins[coin.toLowerCase()];
    if (!coinData) {
      return res.status(400).json({ message: 'Invalid coin specified' });
    }

    const totalCost = amount * coinData.price;
    if (user.balance < totalCost) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Execute trade
    user.balance -= totalCost;
    const currentAmount = user.portfolio.get(coin) || 0;
    user.portfolio.set(coin, currentAmount + amount);
    await user.save();

    // Create trade record
    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      baseCurrency: coin,
      quoteCurrency: 'usd',
      amount: amount,
      price: coinData.price,
      total: totalCost,
      status: 'completed'
    });
    await trade.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      currency: coin,
      amount: amount,
      status: 'completed'
    });
    await transaction.save();

    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      data: { balance: user.balance }
    }, user._id);

    broadcast({
      type: 'PORTFOLIO_UPDATE',
      data: { portfolio: user.portfolio }
    }, user._id);

    broadcast({
      type: 'TRADE_UPDATE',
      data: { trade }
    }, user._id);

    res.json({ 
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: user.portfolio,
      trade
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing trade' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { coin, amount } = req.body;
    
    if (!coin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid trade parameters' });
    }

    const coinData = coins[coin.toLowerCase()];
    if (!coinData) {
      return res.status(400).json({ message: 'Invalid coin specified' });
    }

    // Check if user has enough of the coin to sell
    const currentAmount = user.portfolio.get(coin) || 0;
    if (currentAmount < amount) {
      return res.status(400).json({ message: 'Insufficient coin balance' });
    }

    // Execute trade
    const totalValue = amount * coinData.price;
    user.balance += totalValue;
    user.portfolio.set(coin, currentAmount - amount);
    await user.save();

    // Create trade record
    const trade = new Trade({
      userId: user._id,
      type: 'sell',
      baseCurrency: coin,
      quoteCurrency: 'usd',
      amount: amount,
      price: coinData.price,
      total: totalValue,
      status: 'completed'
    });
    await trade.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      currency: coin,
      amount: -amount,
      status: 'completed'
    });
    await transaction.save();

    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      data: { balance: user.balance }
    }, user._id);

    broadcast({
      type: 'PORTFOLIO_UPDATE',
      data: { portfolio: user.portfolio }
    }, user._id);

    broadcast({
      type: 'TRADE_UPDATE',
      data: { trade }
    }, user._id);

    res.json({ 
      message: 'Trade executed successfully',
      balance: user.balance,
      portfolio: user.portfolio,
      trade
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error executing trade' });
  }
});

app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const trades = await Trade.find({ 
      userId: user._id,
      status: 'completed'
    }).sort({ createdAt: -1 }).limit(10);

    res.json({ trades });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching active trades' });
  }
});

// Wallet routes
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    // Hardcoded deposit address as specified
    const depositAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
    res.json({ depositAddress });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching deposit address' });
  }
});

app.post('/api/v1/wallet/deposit', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { amount, txHash } = req.body;
    
    if (!amount || amount <= 0 || !txHash) {
      return res.status(400).json({ message: 'Invalid deposit parameters' });
    }

    // In a real app, you would verify the transaction on the blockchain
    // For this example, we'll just credit the user's balance
    user.balance += amount;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      currency: 'usd',
      amount: amount,
      txHash: txHash,
      status: 'completed'
    });
    await transaction.save();

    // Broadcast update
    broadcast({
      type: 'BALANCE_UPDATE',
      data: { balance: user.balance }
    }, user._id);

    broadcast({
      type: 'TRANSACTION_UPDATE',
      data: { transaction }
    }, user._id);

    res.json({ 
      message: 'Deposit processed successfully',
      balance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing deposit' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { amount, address } = req.body;
    
    if (!amount || amount <= 0 || !address) {
      return res.status(400).json({ message: 'Invalid withdrawal parameters' });
    }

    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // In a real app, you would initiate a blockchain transaction here
    // For this example, we'll just deduct the amount
    user.balance -= amount;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      currency: 'usd',
      amount: -amount,
      address: address,
      status: 'pending' // Would be 'completed' once the tx is confirmed
    });
    await transaction.save();

    // Broadcast update
    broadcast({
      type: 'BALANCE_UPDATE',
      data: { balance: user.balance }
    }, user._id);

    broadcast({
      type: 'TRANSACTION_UPDATE',
      data: { transaction }
    }, user._id);

    res.json({ 
      message: 'Withdrawal request submitted',
      balance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing withdrawal' });
  }
});

// Support routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ createdAt: -1 });
    res.json({ faqs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching FAQs' });
  }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }

    const ticket = new SupportTicket({
      userId: user._id,
      email: user.email,
      subject,
      message,
      status: 'open'
    });
    await ticket.save();

    // Broadcast to admin dashboard
    broadcast({
      type: 'SUPPORT_TICKET_UPDATE',
      data: { ticket }
    }, null, true);

    res.json({ 
      message: 'Support ticket created successfully',
      ticket
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating support ticket' });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const tickets = await SupportTicket.find({ userId: user._id }).sort({ createdAt: -1 });
    res.json({ tickets });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching support tickets' });
  }
});

// Stats route
app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const tradesCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: "$total" } } }
    ]);
    
    res.json({
      users: usersCount,
      trades: tradesCount,
      volume: totalVolume[0]?.total || 0,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching stats' });
  }
});

// Admin routes
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

    const token = generateToken(user._id, true);
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/verify', authenticateAdmin, async (req, res) => {
  try {
    res.json({ valid: true, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error verifying admin token' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    const tradesCount = await Trade.countDocuments();
    const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
    
    const dailyVolume = await Trade.aggregate([
      { 
        $match: { 
          createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } 
        } 
      },
      { $group: { _id: null, total: { $sum: "$total" } } }
    ]);

    res.json({
      users: usersCount,
      activeUsers: activeUsersCount,
      trades: tradesCount,
      pendingTickets,
      pendingKYC,
      dailyVolume: dailyVolume[0]?.total || 0,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching admin stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

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

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (userId) {
      query.userId = userId;
    }

    const trades = await Trade.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email');

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

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (userId) {
      query.userId = userId;
    }
    if (type) {
      query.type = type;
    }

    const transactions = await Transaction.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email');

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

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) {
      query.status = status;
    }

    const tickets = await SupportTicket.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email');

    const total = await SupportTicket.countDocuments(query);

    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching support tickets' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { kycStatus: status || 'pending' };

    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

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

app.put('/api/v1/admin/kyc/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.kycStatus = 'approved';
    await user.save();

    // Broadcast to user
    broadcast({
      type: 'KYC_UPDATE',
      data: { kycStatus: user.kycStatus }
    }, user._id);

    res.json({ message: 'KYC approved successfully', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error approving KYC' });
  }
});

app.put('/api/v1/admin/kyc/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.kycStatus = 'rejected';
    await user.save();

    // Broadcast to user
    broadcast({
      type: 'KYC_UPDATE',
      data: { kycStatus: user.kycStatus }
    }, user._id);

    res.json({ message: 'KYC rejected successfully', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error rejecting KYC' });
  }
});

app.put('/api/v1/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
  try {
    const { amount } = req.body;
    if (typeof amount !== 'number') {
      return res.status(400).json({ message: 'Invalid amount' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.balance += amount;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: amount > 0 ? 'deposit' : 'withdrawal',
      currency: 'usd',
      amount: amount,
      status: 'completed',
      adminAction: true
    });
    await transaction.save();

    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      data: { balance: user.balance }
    }, user._id);

    broadcast({
      type: 'TRANSACTION_UPDATE',
      data: { transaction }
    }, user._id);

    res.json({ message: 'Balance updated successfully', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user balance' });
  }
});

app.put('/api/v1/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (typeof status !== 'boolean') {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.isActive = status;
    await user.save();

    res.json({ message: 'User status updated successfully', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user status' });
  }
});

app.post('/api/v1/admin/users/:id/reset-password', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // In a real app, you would email the new password to the user
    res.json({ message: 'Password reset successfully', newPassword });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

app.put('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['open', 'in-progress', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    ticket.status = status;
    await ticket.save();

    // Broadcast to user
    if (ticket.userId) {
      broadcast({
        type: 'SUPPORT_TICKET_UPDATE',
        data: { ticket }
      }, ticket.userId);
    }

    res.json({ message: 'Ticket status updated successfully', ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating ticket status' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    ticket.responses.push({
      message,
      from: 'support'
    });
    await ticket.save();

    // Broadcast to user
    if (ticket.userId) {
      broadcast({
        type: 'SUPPORT_TICKET_UPDATE',
        data: { ticket }
      }, ticket.userId);
    }

    res.json({ message: 'Reply added successfully', ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error adding reply' });
  }
});

app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would fetch these from a settings collection
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.0025, // 0.25%
      withdrawalFee: 0.001, // 0.1%
      kycRequired: true,
      minDeposit: 10,
      minWithdrawal: 10
    };

    res.json({ settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching settings' });
  }
});

app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const { maintenanceMode, tradeFee, withdrawalFee, kycRequired, minDeposit, minWithdrawal } = req.body;
    
    // In a real app, you would save these to a settings collection
    const settings = {
      maintenanceMode: maintenanceMode || false,
      tradeFee: tradeFee || 0.0025,
      withdrawalFee: withdrawalFee || 0.001,
      kycRequired: kycRequired !== undefined ? kycRequired : true,
      minDeposit: minDeposit || 10,
      minWithdrawal: minWithdrawal || 10
    };

    // Broadcast to all clients
    broadcast({
      type: 'SETTINGS_UPDATE',
      data: { settings }
    });

    res.json({ message: 'Settings updated successfully', settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating settings' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }

    // Broadcast to all clients
    broadcast({
      type: 'ADMIN_BROADCAST',
      data: { message }
    });

    res.json({ message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error sending broadcast' });
  }
});

// Initialize some sample data if needed
async function initializeData() {
  try {
    // Create an admin user if none exists
    const adminExists = await User.findOne({ isAdmin: true });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const admin = new User({
        email: 'admin@crypto.com',
        password: hashedPassword,
        isAdmin: true,
        balance: 1000000
      });
      await admin.save();
      console.log('Admin user created');
    }

    // Create some FAQs if none exist
    const faqCount = await FAQ.countDocuments();
    if (faqCount === 0) {
      const faqs = [
        {
          question: 'How do I create an account?',
          answer: 'Click on the Sign Up button and follow the instructions to create your account.',
          category: 'account'
        },
        {
          question: 'How do I deposit funds?',
          answer: 'Go to the Wallet section and click on Deposit to get your deposit address.',
          category: 'deposits'
        },
        {
          question: 'What is the minimum deposit amount?',
          answer: 'The minimum deposit amount is $10 USD equivalent.',
          category: 'deposits'
        },
        {
          question: 'How do I buy cryptocurrencies?',
          answer: 'Navigate to the Trade section, select the cryptocurrency you want to buy, enter the amount, and confirm the trade.',
          category: 'trading'
        },
        {
          question: 'Are there any trading fees?',
          answer: 'Yes, we charge a 0.25% fee on each trade.',
          category: 'trading'
        },
        {
          question: 'How do I withdraw funds?',
          answer: 'Go to the Wallet section, click on Withdraw, enter the amount and destination address, and confirm the withdrawal.',
          category: 'withdrawals'
        },
        {
          question: 'What is KYC verification?',
          answer: 'KYC (Know Your Customer) is a process to verify your identity for security and regulatory purposes.',
          category: 'security'
        },
        {
          question: 'Is my personal information secure?',
          answer: 'Yes, we use industry-standard encryption and security measures to protect your data.',
          category: 'security'
        }
      ];

      await FAQ.insertMany(faqs);
      console.log('Sample FAQs created');
    }
  } catch (err) {
    console.error('Error initializing data:', err);
  }
}

initializeData();
