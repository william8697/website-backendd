require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const WebSocket = require('ws');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '24h';

// Email configuration
const transporter = nodemailer.createTransport({
  host: 'sandbox.sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Models
const User = require('./models/User')(mongoose);
const Trade = require('./models/Trade')(mongoose);
const Transaction = require('./models/Transaction')(mongoose);
const SupportTicket = require('./models/SupportTicket')(mongoose);
const KYC = require('./models/KYC')(mongoose);
const Admin = require('./models/Admin')(mongoose);
const Stats = require('./models/Stats')(mongoose);
const Team = require('./models/Team')(mongoose);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

// WebSocket connections map
const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      clients.set(decoded.userId, ws);
      
      ws.on('close', () => {
        clients.delete(decoded.userId);
      });
      
      ws.on('message', (message) => {
        handleWebSocketMessage(decoded.userId, message);
      });
    } catch (err) {
      ws.close(1008, 'Invalid token');
    }
  } else {
    ws.close(1008, 'No token provided');
  }
});

function handleWebSocketMessage(userId, message) {
  // Handle incoming WebSocket messages
  const data = JSON.parse(message);
  
  switch (data.type) {
    case 'subscribe':
      // Handle subscription requests
      break;
    case 'unsubscribe':
      // Handle unsubscription requests
      break;
    default:
      // Handle other message types
      break;
  }
}

function broadcastToUser(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

// Helper functions
const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

const generateRandomStats = () => {
  return {
    totalUsers: Math.floor(Math.random() * 10000) + 5000,
    activeTrades: Math.floor(Math.random() * 5000) + 1000,
    dailyVolume: (Math.random() * 1000 + 100).toFixed(2),
    totalProfit: (Math.random() * 500000 + 100000).toFixed(2)
  };
};

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Admin not found' });
    }
    
    req.admin = admin;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// Routes

// Auth Routes
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
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const apiKey = generateApiKey();
    
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      apiKey,
      balances: {
        BTC: 0,
        ETH: 0,
        USDT: 0,
        BNB: 0,
        XRP: 0
      }
    });
    
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        country: newUser.country,
        currency: newUser.currency,
        balances: newUser.balances
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        balances: user.balances
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature and create user
    const apiKey = generateApiKey();
    
    const newUser = new User({
      walletAddress,
      apiKey,
      balances: {
        BTC: 0,
        ETH: 0,
        USDT: 0,
        BNB: 0,
        XRP: 0
      }
    });
    
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        walletAddress: newUser.walletAddress,
        balances: newUser.balances
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // In a real app, you'd store this nonce associated with the wallet address
    // and verify it when the signed message comes back
    
    res.status(200).json({ success: true, nonce });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature against stored nonce
    // This is a simplified version - in production you'd need proper signature verification
    
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Wallet not registered' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        balances: user.balances
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if the email exists
      return res.status(200).json({ success: true, message: 'If an account exists with this email, a reset link has been sent' });
    }
    
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();
    
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      to: user.email,
      from: 'noreply@yourdomain.com',
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your account.</p>
        <p>Click this link to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ success: true, message: 'Reset link sent to email' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.patch('/api/v1/auth/update-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = req.user;
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    
    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/logout', auth, async (req, res) => {
  try {
    // In a real JWT system, you might want to implement a token blacklist
    // For now, we'll just return success and let the client delete the token
    
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/auth/status', auth, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      isAuthenticated: true,
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        country: req.user.country,
        currency: req.user.currency,
        balances: req.user.balances
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/auth/me', auth, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true,
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        country: req.user.country,
        currency: req.user.currency,
        balances: req.user.balances,
        kycStatus: req.user.kycStatus
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/auth/check', auth, async (req, res) => {
  try {
    res.status(200).json({ success: true, message: 'Session is valid' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// User Routes
app.get('/api/v1/users/me', auth, async (req, res) => {
  try {
    const user = req.user;
    
    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        balances: user.balances,
        kycStatus: user.kycStatus,
        twoFactorEnabled: user.twoFactorEnabled,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/users/settings', auth, async (req, res) => {
  try {
    const user = req.user;
    
    res.status(200).json({
      success: true,
      settings: {
        notificationPreferences: user.notificationPreferences || {},
        theme: user.theme || 'light',
        language: user.language || 'en',
        apiKey: user.apiKey
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.patch('/api/v1/users/settings', auth, async (req, res) => {
  try {
    const { notificationPreferences, theme, language } = req.body;
    const user = req.user;
    
    if (notificationPreferences) {
      user.notificationPreferences = notificationPreferences;
    }
    
    if (theme) {
      user.theme = theme;
    }
    
    if (language) {
      user.language = language;
    }
    
    await user.save();
    
    res.status(200).json({ success: true, message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/users/generate-api-key', auth, async (req, res) => {
  try {
    const user = req.user;
    user.apiKey = generateApiKey();
    await user.save();
    
    res.status(200).json({ success: true, apiKey: user.apiKey });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/users/kyc', auth, upload.array('documents', 3), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ success: false, message: 'No documents uploaded' });
    }
    
    const kyc = new KYC({
      userId: req.user._id,
      documentType,
      documentNumber,
      documents: files.map(file => file.path),
      status: 'pending'
    });
    
    await kyc.save();
    
    req.user.kycStatus = 'pending';
    await req.user.save();
    
    res.status(201).json({ success: true, message: 'KYC submitted for review' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/users/export-data', auth, async (req, res) => {
  try {
    const user = req.user;
    
    // In a real app, you'd generate a comprehensive data export
    // For now, we'll just return basic user data
    
    const exportData = {
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      },
      balances: user.balances,
      kycStatus: user.kycStatus
    };
    
    res.status(200).json({ success: true, data: exportData });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.delete('/api/v1/users/delete-account', auth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    
    // In a real app, you'd also want to delete or anonymize associated data
    
    res.status(200).json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', auth, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'active' })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({ success: true, trades });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/trades/buy', auth, async (req, res) => {
  try {
    const { coin, amount, price } = req.body;
    const user = req.user;
    
    // Validate balance
    const totalCost = amount * price;
    if (user.balances.USDT < totalCost) {
      return res.status(400).json({ success: false, message: 'Insufficient USDT balance' });
    }
    
    // Update balances
    user.balances.USDT -= totalCost;
    user.balances[coin] = (user.balances[coin] || 0) + amount;
    await user.save();
    
    // Create trade
    const trade = new Trade({
      userId: user._id,
      type: 'buy',
      coin,
      amount,
      price,
      total: totalCost,
      status: 'completed'
    });
    
    await trade.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: -totalCost,
      coin: 'USDT',
      description: `Bought ${amount} ${coin} at ${price} USDT each`,
      status: 'completed'
    });
    
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id.toString(), {
      type: 'balanceUpdate',
      balances: user.balances
    });
    
    res.status(201).json({ success: true, message: 'Trade executed successfully', trade });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/trades/sell', auth, async (req, res) => {
  try {
    const { coin, amount, price } = req.body;
    const user = req.user;
    
    // Validate balance
    if (!user.balances[coin] || user.balances[coin] < amount) {
      return res.status(400).json({ success: false, message: `Insufficient ${coin} balance` });
    }
    
    // Update balances
    const totalValue = amount * price;
    user.balances[coin] -= amount;
    user.balances.USDT += totalValue;
    await user.save();
    
    // Create trade
    const trade = new Trade({
      userId: user._id,
      type: 'sell',
      coin,
      amount,
      price,
      total: totalValue,
      status: 'completed'
    });
    
    await trade.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: totalValue,
      coin: 'USDT',
      description: `Sold ${amount} ${coin} at ${price} USDT each`,
      status: 'completed'
    });
    
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id.toString(), {
      type: 'balanceUpdate',
      balances: user.balances
    });
    
    res.status(201).json({ success: true, message: 'Trade executed successfully', trade });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Exchange Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = ['BTC', 'ETH', 'USDT', 'BNB', 'XRP'];
    res.status(200).json({ success: true, coins });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
  try {
    // Simulated rates with arbitrage logic
    const rates = {
      BTC: { USDT: 45000 + (Math.random() * 2000 - 1000) },
      ETH: { USDT: 3000 + (Math.random() * 200 - 100) },
      BNB: { USDT: 400 + (Math.random() * 20 - 10) },
      XRP: { USDT: 0.8 + (Math.random() * 0.2 - 0.1) },
      USDT: { BTC: 1/45000, ETH: 1/3000, BNB: 1/400, XRP: 1/0.8 }
    };
    
    // Cross rates
    rates.BTC.ETH = rates.BTC.USDT / rates.ETH.USDT;
    rates.ETH.BTC = 1 / rates.BTC.ETH;
    rates.BTC.BNB = rates.BTC.USDT / rates.BNB.USDT;
    rates.BNB.BTC = 1 / rates.BTC.BNB;
    rates.BTC.XRP = rates.BTC.USDT / rates.XRP.USDT;
    rates.XRP.BTC = 1 / rates.BTC.XRP;
    rates.ETH.BNB = rates.ETH.USDT / rates.BNB.USDT;
    rates.BNB.ETH = 1 / rates.ETH.BNB;
    rates.ETH.XRP = rates.ETH.USDT / rates.XRP.USDT;
    rates.XRP.ETH = 1 / rates.ETH.XRP;
    rates.BNB.XRP = rates.BNB.USDT / rates.XRP.USDT;
    rates.XRP.BNB = 1 / rates.BNB.XRP;
    
    res.status(200).json({ success: true, rates });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    const ratesResponse = await axios.get(`${req.protocol}://${req.get('host')}/api/v1/exchange/rates`);
    const rates = ratesResponse.data.rates;
    
    if (!rates[from] || !rates[from][to]) {
      return res.status(400).json({ success: false, message: 'Invalid currency pair' });
    }
    
    res.status(200).json({ success: true, rate: rates[from][to] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/exchange/convert', auth, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = req.user;
    
    // Get rates
    const ratesResponse = await axios.get(`${req.protocol}://${req.get('host')}/api/v1/exchange/rates`);
    const rates = ratesResponse.data.rates;
    
    if (!rates[fromCoin] || !rates[fromCoin][toCoin]) {
      return res.status(400).json({ success: false, message: 'Invalid currency pair' });
    }
    
    const rate = rates[fromCoin][toCoin];
    const convertedAmount = amount * rate;
    
    // Validate balance
    if (!user.balances[fromCoin] || user.balances[fromCoin] < amount) {
      return res.status(400).json({ success: false, message: `Insufficient ${fromCoin} balance` });
    }
    
    // Update balances
    user.balances[fromCoin] -= amount;
    user.balances[toCoin] = (user.balances[toCoin] || 0) + convertedAmount;
    await user.save();
    
    // Create transaction records
    const fromTransaction = new Transaction({
      userId: user._id,
      type: 'exchange',
      amount: -amount,
      coin: fromCoin,
      description: `Converted to ${toCoin}`,
      status: 'completed'
    });
    
    const toTransaction = new Transaction({
      userId: user._id,
      type: 'exchange',
      amount: convertedAmount,
      coin: toCoin,
      description: `Converted from ${fromCoin}`,
      status: 'completed'
    });
    
    await Promise.all([fromTransaction.save(), toTransaction.save()]);
    
    // Notify user via WebSocket
    broadcastToUser(user._id.toString(), {
      type: 'balanceUpdate',
      balances: user.balances
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Conversion successful',
      fromCoin,
      toCoin,
      amount,
      convertedAmount,
      rate
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/exchange/history', auth, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id, type: 'exchange' })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.status(200).json({ success: true, transactions });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', auth, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
      memo: req.user._id.toString()
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/wallet/withdraw', auth, async (req, res) => {
  try {
    const { coin, amount, address, memo } = req.body;
    const user = req.user;
    
    // Validate balance
    if (!user.balances[coin] || user.balances[coin] < amount) {
      return res.status(400).json({ success: false, message: `Insufficient ${coin} balance` });
    }
    
    // Validate minimum withdrawal
    if (amount < 0.001) {
      return res.status(400).json({ success: false, message: 'Minimum withdrawal is 0.001' });
    }
    
    // Update balance
    user.balances[coin] -= amount;
    await user.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: -amount,
      coin,
      description: `Withdrawal to ${address}`,
      status: 'pending',
      address,
      memo
    });
    
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id.toString(), {
      type: 'balanceUpdate',
      balances: user.balances
    });
    
    // In a real app, you'd process the withdrawal here
    
    res.status(201).json({ 
      success: true, 
      message: 'Withdrawal request submitted',
      transaction
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Market Routes
app.get('/api/v1/market/data', async (req, res) => {
  try {
    // Simulated market data with the same arbitrage logic
    const data = [
      {
        id: 'bitcoin',
        symbol: 'btc',
        name: 'Bitcoin',
        image: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png',
        current_price: 45000 + (Math.random() * 2000 - 1000),
        price_change_percentage_24h: (Math.random() * 10 - 5).toFixed(2),
        market_cap: 850000000000,
        total_volume: 30000000000
      },
      {
        id: 'ethereum',
        symbol: 'eth',
        name: 'Ethereum',
        image: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png',
        current_price: 3000 + (Math.random() * 200 - 100),
        price_change_percentage_24h: (Math.random() * 10 - 5).toFixed(2),
        market_cap: 350000000000,
        total_volume: 15000000000
      },
      {
        id: 'tether',
        symbol: 'usdt',
        name: 'Tether',
        image: 'https://assets.coingecko.com/coins/images/325/large/Tether.png',
        current_price: 1.00,
        price_change_percentage_24h: 0.00,
        market_cap: 80000000000,
        total_volume: 50000000000
      },
      {
        id: 'binancecoin',
        symbol: 'bnb',
        name: 'Binance Coin',
        image: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png',
        current_price: 400 + (Math.random() * 20 - 10),
        price_change_percentage_24h: (Math.random() * 10 - 5).toFixed(2),
        market_cap: 65000000000,
        total_volume: 2000000000
      },
      {
        id: 'ripple',
        symbol: 'xrp',
        name: 'XRP',
        image: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png',
        current_price: 0.8 + (Math.random() * 0.2 - 0.1),
        price_change_percentage_24h: (Math.random() * 10 - 5).toFixed(2),
        market_cap: 40000000000,
        total_volume: 3000000000
      }
    ];
    
    res.status(200).json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/market/detailed', async (req, res) => {
  try {
    // More detailed market data
    const data = await axios.get(`${req.protocol}://${req.get('host')}/api/v1/market/data`);
    
    const detailedData = data.data.data.map(coin => ({
      ...coin,
      price_change_percentage_7d: (Math.random() * 15 - 7.65).toFixed(2),
      price_change_percentage_30d: (Math.random() * 30 - 15).toFixed(2),
      price_change_percentage_1y: (Math.random() * 100 - 50).toFixed(2),
      circulating_supply: Math.floor(coin.market_cap / coin.current_price),
      total_supply: Math.floor(coin.market_cap / coin.current_price * 1.2),
      ath: coin.current_price * (1 + Math.random() * 2),
      ath_change_percentage: (Math.random() * 100).toFixed(2),
      atl: coin.current_price * (1 - Math.random()),
      atl_change_percentage: (Math.random() * 100).toFixed(2),
      last_updated: new Date().toISOString()
    }));
    
    res.status(200).json({ success: true, data: detailedData });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', auth, async (req, res) => {
  try {
    const user = req.user;
    const marketData = await axios.get(`${req.protocol}://${req.get('host')}/api/v1/market/data`);
    
    const portfolio = Object.entries(user.balances)
      .filter(([coin, balance]) => balance > 0)
      .map(([coin, balance]) => {
        const coinData = marketData.data.data.find(c => c.symbol === coin.toLowerCase());
        const value = coinData ? balance * coinData.current_price : 0;
        
        return {
          coin,
          balance,
          value,
          price: coinData?.current_price || 0,
          change24h: coinData?.price_change_percentage_24h || 0
        };
      });
    
    const totalValue = portfolio.reduce((sum, item) => sum + item.value, 0);
    
    res.status(200).json({ success: true, portfolio, totalValue });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const stats = await Stats.findOne().sort({ createdAt: -1 });
    
    if (!stats) {
      // Generate initial stats if none exist
      const newStats = new Stats(generateRandomStats());
      await newStats.save();
      return res.status(200).json({ success: true, stats: newStats });
    }
    
    res.status(200).json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Team Routes
app.get('/api/v1/team', async (req, res) => {
  try {
    const team = await Team.find().sort({ order: 1 });
    
    if (team.length === 0) {
      // Seed initial team data if none exists
      const initialTeam = [
        { name: 'John Doe', position: 'CEO', bio: 'Founder and CEO with 10+ years in blockchain', order: 1 },
        { name: 'Jane Smith', position: 'CTO', bio: 'Technology expert and blockchain architect', order: 2 },
        { name: 'Mike Johnson', position: 'CFO', bio: 'Financial strategist and investment specialist', order: 3 },
        { name: 'Sarah Williams', position: 'CMO', bio: 'Marketing guru with crypto expertise', order: 4 }
      ];
      
      await Team.insertMany(initialTeam);
      return res.status(200).json({ success: true, team: initialTeam });
    }
    
    res.status(200).json({ success: true, team });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        question: 'How do I create an account?',
        answer: 'Click on the Sign Up button and follow the instructions to create your account.',
        category: 'Account'
      },
      {
        question: 'How do I deposit funds?',
        answer: 'Go to the Wallet section and use the deposit address provided.',
        category: 'Wallet'
      },
      {
        question: 'How long do withdrawals take?',
        answer: 'Withdrawals are typically processed within 24 hours.',
        category: 'Wallet'
      },
      {
        question: 'What is the minimum deposit?',
        answer: 'There is no minimum deposit amount.',
        category: 'Wallet'
      },
      {
        question: 'How do I enable two-factor authentication?',
        answer: 'Go to your Account Settings and follow the 2FA setup instructions.',
        category: 'Security'
      }
    ];
    
    res.status(200).json({ success: true, faqs });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/support/my-tickets', auth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({ success: true, tickets });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/support/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    const ticket = new SupportTicket({
      name,
      email,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    res.status(201).json({ success: true, message: 'Support ticket created successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/support/tickets', auth, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const user = req.user;
    
    const ticket = new SupportTicket({
      userId: user._id,
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    res.status(201).json({ success: true, message: 'Support ticket created successfully', ticket });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ adminId: admin._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/verify', adminAuth, async (req, res) => {
  try {
    res.status(200).json({ success: true, message: 'Admin session is valid' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminAuth, async (req, res) => {
  try {
    const stats = await Stats.findOne().sort({ createdAt: -1 });
    const totalUsers = await User.countDocuments();
    const activeTrades = await Trade.countDocuments({ status: 'active' });
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
    const openTickets = await SupportTicket.countDocuments({ status: 'open' });
    
    res.status(200).json({
      success: true,
      stats: {
        ...stats.toObject(),
        totalUsers,
        activeTrades,
        pendingKYC,
        openTickets
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/users', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.status(200).json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);
    const kyc = await KYC.findOne({ userId: user._id });
    const tickets = await SupportTicket.find({ userId: user._id }).sort({ createdAt: -1 }).limit(3);
    
    res.status(200).json({
      success: true,
      user,
      trades,
      transactions,
      kyc,
      tickets
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.put('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const { balances, kycStatus, isActive } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (balances) {
      user.balances = balances;
    }
    
    if (kycStatus) {
      user.kycStatus = kycStatus;
    }
    
    if (typeof isActive === 'boolean') {
      user.isActive = isActive;
    }
    
    await user.save();
    
    res.status(200).json({ success: true, message: 'User updated successfully', user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/trades', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) {
      query.status = status;
    }
    
    const trades = await Trade.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email firstName lastName');
    
    const total = await Trade.countDocuments(query);
    
    res.status(200).json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (type) {
      query.type = type;
    }
    
    const transactions = await Transaction.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email firstName lastName');
    
    const total = await Transaction.countDocuments(query);
    
    res.status(200).json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/tickets', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) {
      query.status = status;
    }
    
    const tickets = await SupportTicket.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email firstName lastName');
    
    const total = await SupportTicket.countDocuments(query);
    
    res.status(200).json({
      success: true,
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/tickets/:id', adminAuth, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'email firstName lastName');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    res.status(200).json({ success: true, ticket });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.put('/api/v1/admin/tickets/:id', adminAuth, async (req, res) => {
  try {
    const { status, response } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    if (status) {
      ticket.status = status;
    }
    
    if (response) {
      ticket.responses = ticket.responses || [];
      ticket.responses.push({
        adminId: req.admin._id,
        message: response,
        createdAt: new Date()
      });
    }
    
    await ticket.save();
    
    // Notify user via WebSocket if they're online
    if (ticket.userId) {
      broadcastToUser(ticket.userId.toString(), {
        type: 'ticketUpdate',
        ticketId: ticket._id,
        status: ticket.status
      });
    }
    
    res.status(200).json({ success: true, message: 'Ticket updated successfully', ticket });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/kyc', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) {
      query.status = status;
    }
    
    const kycList = await KYC.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'email firstName lastName');
    
    const total = await KYC.countDocuments(query);
    
    res.status(200).json({
      success: true,
      kycList,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/kyc/:id', adminAuth, async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('userId', 'email firstName lastName');
    
    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC record not found' });
    }
    
    res.status(200).json({ success: true, kyc });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.put('/api/v1/admin/kyc/:id', adminAuth, async (req, res) => {
  try {
    const { status, notes } = req.body;
    
    const kyc = await KYC.findById(req.params.id);
    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC record not found' });
    }
    
    if (status) {
      kyc.status = status;
      kyc.reviewedAt = new Date();
      kyc.reviewedBy = req.admin._id;
    }
    
    if (notes) {
      kyc.notes = notes;
    }
    
    await kyc.save();
    
    // Update user's KYC status
    const user = await User.findById(kyc.userId);
    if (user) {
      user.kycStatus = status;
      await user.save();
      
      // Notify user via WebSocket
      broadcastToUser(user._id.toString(), {
        type: 'kycUpdate',
        status
      });
    }
    
    res.status(200).json({ success: true, message: 'KYC updated successfully', kyc });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/logs', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (type) {
      query.type = type;
    }
    
    const logs = await Log.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await Log.countDocuments(query);
    
    res.status(200).json({
      success: true,
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/admin/broadcast', adminAuth, async (req, res) => {
  try {
    const { title, message, importance } = req.body;
    
    // In a real app, you'd store this broadcast and send it to all connected clients
    // For now, we'll just log it
    
    console.log(`Broadcast: ${title} - ${message} (${importance})`);
    
    res.status(200).json({ success: true, message: 'Broadcast sent successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/settings', adminAuth, async (req, res) => {
  try {
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.001,
      withdrawalFee: 0.0005,
      depositEnabled: true,
      withdrawalEnabled: true,
      newRegistrations: true,
      apiDocsUrl: 'https://website-xi-ten-52.vercel.app/api-docs'
    };
    
    res.status(200).json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/admin/settings', adminAuth, async (req, res) => {
  try {
    // In a real app, you'd save these settings to the database
    // For now, we'll just acknowledge the request
    
    res.status(200).json({ success: true, message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Models (defined inline for single-file deployment)
function createModels(mongoose) {
  const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, select: false },
    walletAddress: { type: String, unique: true, sparse: true },
    country: { type: String },
    currency: { type: String, default: 'USD' },
    apiKey: { type: String, unique: true },
    balances: {
      BTC: { type: Number, default: 0 },
      ETH: { type: Number, default: 0 },
      USDT: { type: Number, default: 0 },
      BNB: { type: Number, default: 0 },
      XRP: { type: Number, default: 0 }
    },
    kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
    twoFactorEnabled: { type: Boolean, default: false },
    notificationPreferences: { type: Object, default: {} },
    theme: { type: String, default: 'light' },
    language: { type: String, default: 'en' },
    isActive: { type: Boolean, default: true },
    resetToken: { type: String },
    resetTokenExpiry: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  });

  userSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
  });

  const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['buy', 'sell'], required: true },
    coin: { type: String, required: true },
    amount: { type: Number, required: true },
    price: { type: Number, required: true },
    total: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
  });

  const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'exchange'], required: true },
    amount: { type: Number, required: true },
    coin: { type: String, required: true },
    description: { type: String },
    address: { type: String },
    memo: { type: String },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
  });

  const supportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String },
    email: { type: String },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
    responses: [{
      adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
      message: { type: String },
      createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  });

  supportTicketSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
  });

  const kycSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    documentType: { type: String, required: true },
    documentNumber: { type: String, required: true },
    documents: [{ type: String, required: true }],
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
    notes: { type: String },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    reviewedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
  });

  const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
  });

  const statsSchema = new mongoose.Schema({
    totalUsers: { type: Number, default: 0 },
    activeTrades: { type: Number, default: 0 },
    dailyVolume: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
  });

  const teamSchema = new mongoose.Schema({
    name: { type: String, required: true },
    position: { type: String, required: true },
    bio: { type: String, required: true },
    order: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
  });

  const logSchema = new mongoose.Schema({
    type: { type: String, required: true },
    message: { type: String, required: true },
    data: { type: Object },
    createdAt: { type: Date, default: Date.now }
  });

  return {
    User: mongoose.model('User', userSchema),
    Trade: mongoose.model('Trade', tradeSchema),
    Transaction: mongoose.model('Transaction', transactionSchema),
    SupportTicket: mongoose.model('SupportTicket', supportTicketSchema),
    KYC: mongoose.model('KYC', kycSchema),
    Admin: mongoose.model('Admin', adminSchema),
    Stats: mongoose.model('Stats', statsSchema),
    Team: mongoose.model('Team', teamSchema),
    Log: mongoose.model('Log', logSchema)
  };
}
