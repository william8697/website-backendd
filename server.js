require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const http = require('http');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email configuration
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

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  walletAddress: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  kycStatus: { type: String, enum: ['not_verified', 'pending', 'verified', 'rejected'], default: 'not_verified' },
  kycDocs: {
    idFront: String,
    idBack: String,
    selfie: String
  },
  isAdmin: { type: Boolean, default: false },
  settings: {
    theme: { type: String, default: 'light' },
    language: { type: String, default: 'en' },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false }
  },
  apiKey: { type: String, default: uuidv4() },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  profitLoss: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in_progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    fromAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const CoinPriceSchema = new mongoose.Schema({
  coinId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  symbol: { type: String, required: true },
  currentPrice: { type: Number, required: true },
  priceChange24h: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const CoinPrice = mongoose.model('CoinPrice', CoinPriceSchema);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

// WebSocket Server
const wss = new WebSocket.Server({ server });

const broadcast = (data) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'auth') {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          const user = await User.findById(decoded.userId);
          
          if (user) {
            ws.userId = user._id;
            ws.isAdmin = user.isAdmin;
            ws.send(JSON.stringify({ type: 'auth_success' }));
            
            // Send initial data based on user type
            if (user.isAdmin) {
              const stats = await getAdminStats();
              ws.send(JSON.stringify({ type: 'admin_stats', data: stats }));
            } else {
              const userData = await getUserData(user._id);
              ws.send(JSON.stringify({ type: 'user_data', data: userData }));
            }
          }
        } catch (err) {
          ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid token' }));
        }
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
    }
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

// Helper functions
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
};

const verifyToken = async (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('User not found');
    return user;
  } catch (err) {
    throw err;
  }
};

const getUserData = async (userId) => {
  const user = await User.findById(userId);
  const trades = await Trade.find({ userId }).sort({ createdAt: -1 }).limit(5);
  const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 }).limit(5);
  const balance = user.balance;
  
  return { user, trades, transactions, balance };
};

const getAdminStats = async () => {
  const totalUsers = await User.countDocuments();
  const activeUsers = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } });
  const totalTrades = await Trade.countDocuments();
  const totalVolume = await Trade.aggregate([
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
  const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
  
  return {
    totalUsers,
    activeUsers,
    totalTrades,
    totalVolume: totalVolume[0]?.total || 0,
    pendingTickets,
    pendingKYC
  };
};

const updateCoinPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false');
    const prices = response.data;
    
    for (const coin of prices) {
      await CoinPrice.findOneAndUpdate(
        { coinId: coin.id },
        {
          name: coin.name,
          symbol: coin.symbol,
          currentPrice: coin.current_price,
          priceChange24h: coin.price_change_percentage_24h,
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    }
    
    console.log('Coin prices updated');
  } catch (err) {
    console.error('Error updating coin prices:', err);
  }
};

// Update coin prices every 5 minutes
setInterval(updateCoinPrices, 5 * 60 * 1000);
updateCoinPrices();

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    const user = await verifyToken(token);
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    const user = await verifyToken(token);
    if (!user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      balance: 0
    });
    
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    res.status(201).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    // Check if wallet already registered
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ error: 'Wallet already registered' });
    }
    
    // Create user
    const user = new User({
      firstName,
      lastName,
      walletAddress,
      country,
      currency,
      balance: 0
    });
    
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    res.status(201).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // Find user
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ error: 'Wallet not registered' });
    }
    
    // Verify signature would happen here in a real implementation
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/logout', authMiddleware, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user doesn't exist for security
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }
    
    // Generate reset token
    const resetToken = generateToken(user._id);
    const resetLink = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    // Send email
    await transporter.sendMail({
      from: 'support@cryptotrading.com',
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetLink}">Reset Password</a>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });
    
    res.json({ message: 'Password reset link sent to email' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ error: 'Invalid token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// User Routes
app.get('/api/v1/users/me', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/users/update', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    const user = req.user;
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (country) user.country = country;
    if (currency) user.currency = currency;
    
    await user.save();
    
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/users/update-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/users/update-settings', authMiddleware, async (req, res) => {
  try {
    const { theme, language, notifications, twoFA } = req.body;
    const user = req.user;
    
    if (theme) user.settings.theme = theme;
    if (language) user.settings.language = language;
    if (notifications !== undefined) user.settings.notifications = notifications;
    if (twoFA !== undefined) user.settings.twoFA = twoFA;
    
    await user.save();
    
    res.json({ settings: user.settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/users/kyc', authMiddleware, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const user = req.user;
    const files = req.files;
    
    if (!files.idFront || !files.idBack || !files.selfie) {
      return res.status(400).json({ error: 'All documents are required' });
    }
    
    user.kycStatus = 'pending';
    user.kycDocs = {
      idFront: files.idFront[0].path,
      idBack: files.idBack[0].path,
      selfie: files.selfie[0].path
    };
    
    await user.save();
    
    // Notify admin via WebSocket
    broadcast({ type: 'kyc_submitted', userId: user._id });
    
    res.json({ message: 'KYC documents submitted for review', user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/users/generate-api-key', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    user.apiKey = uuidv4();
    await user.save();
    
    res.json({ apiKey: user.apiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/users/export-data', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    
    // Get all user data
    const userData = await User.findById(user._id);
    const trades = await Trade.find({ userId: user._id });
    const transactions = await Transaction.find({ userId: user._id });
    
    const data = {
      user: userData,
      trades,
      transactions
    };
    
    // In a real app, you might generate a CSV or PDF here
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/v1/users/delete-account', authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;
    const user = req.user;
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Password is incorrect' });
    }
    
    // Delete user data
    await Trade.deleteMany({ userId: user._id });
    await Transaction.deleteMany({ userId: user._id });
    await SupportTicket.deleteMany({ userId: user._id });
    await User.findByIdAndDelete(user._id);
    
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trade Routes
app.get('/api/v1/trades', authMiddleware, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({ trades });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/trades/execute', authMiddleware, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = req.user;
    
    // Get current prices
    const fromCoinData = await CoinPrice.findOne({ coinId: fromCoin });
    const toCoinData = await CoinPrice.findOne({ coinId: toCoin });
    
    if (!fromCoinData || !toCoinData) {
      return res.status(400).json({ error: 'Invalid coin selection' });
    }
    
    // Calculate equivalent amount
    const fromValue = amount * fromCoinData.currentPrice;
    const toAmount = fromValue / toCoinData.currentPrice;
    
    // Simulate arbitrage profit/loss (-5% to +5%)
    const profitLossPercent = (Math.random() * 10) - 5;
    const profitLoss = (fromValue * profitLossPercent) / 100;
    const finalAmount = toAmount + (toAmount * profitLossPercent / 100);
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate: toCoinData.currentPrice / fromCoinData.currentPrice,
      profitLoss,
      status: 'completed'
    });
    
    await trade.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: finalAmount,
      currency: toCoin,
      status: 'completed'
    });
    
    await transaction.save();
    
    // Update user balance (simplified - in real app you'd have balances per coin)
    user.balance += profitLoss;
    await user.save();
    
    // Notify user via WebSocket
    broadcast({
      type: 'trade_executed',
      userId: user._id,
      trade,
      transaction,
      balance: user.balance,
      profitLoss
    });
    
    res.json({ 
      trade,
      transaction,
      finalAmount,
      profitLoss,
      message: profitLoss >= 0 ? 
        `Trade successful! You made a profit of $${profitLoss.toFixed(2)}` : 
        `Trade completed. You had a loss of $${Math.abs(profitLoss).toFixed(2)}`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Transaction Routes
app.get('/api/v1/transactions', authMiddleware, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({ transactions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/transactions/deposit', authMiddleware, async (req, res) => {
  try {
    const { amount, currency } = req.body;
    const user = req.user;
    
    // In a real app, you'd generate a deposit address or connect to a payment processor
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      currency,
      status: 'pending'
    });
    
    await transaction.save();
    
    // Simulate deposit completion after 5 seconds
    setTimeout(async () => {
      transaction.status = 'completed';
      await transaction.save();
      
      user.balance += amount;
      await user.save();
      
      broadcast({
        type: 'deposit_completed',
        userId: user._id,
        transaction,
        balance: user.balance
      });
    }, 5000);
    
    res.json({ 
      transaction,
      message: 'Deposit initiated. Your balance will update once confirmed.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/transactions/withdraw', authMiddleware, async (req, res) => {
  try {
    const { amount, currency, address } = req.body;
    const user = req.user;
    
    // Check balance
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Create withdrawal transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending'
    });
    
    await transaction.save();
    
    // Simulate withdrawal processing
    setTimeout(async () => {
      transaction.status = 'completed';
      await transaction.save();
      
      user.balance -= amount;
      await user.save();
      
      broadcast({
        type: 'withdrawal_completed',
        userId: user._id,
        transaction,
        balance: user.balance
      });
    }, 5000);
    
    res.json({ 
      transaction,
      message: 'Withdrawal initiated. Please allow time for processing.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Support Routes
app.get('/api/v1/support/tickets', authMiddleware, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({ tickets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/support/tickets', authMiddleware, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const files = req.files;
    
    const ticket = new SupportTicket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments: files?.map(file => file.path) || []
    });
    
    await ticket.save();
    
    // Notify admin via WebSocket
    broadcast({ type: 'new_ticket', ticket });
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/support/tickets/:id', authMiddleware, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      fromAdmin: false
    });
    
    await ticket.save();
    
    // Notify admin via WebSocket
    broadcast({ type: 'ticket_reply', ticketId: ticket._id });
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public Routes
app.get('/api/v1/coins', async (req, res) => {
  try {
    const coins = await CoinPrice.find().sort({ marketCap: -1 });
    res.json({ coins });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/coins/:id', async (req, res) => {
  try {
    const coin = await CoinPrice.findOne({ coinId: req.params.id });
    if (!coin) {
      return res.status(404).json({ error: 'Coin not found' });
    }
    
    res.json({ coin });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      totalUsers,
      totalTrades,
      totalVolume: totalVolume[0]?.total || 0,
      activeTraders: Math.floor(totalUsers * 0.7) // Simulate 70% active
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I create an account?',
            answer: 'Click on the Sign Up button and fill in the required details.'
          },
          {
            question: 'How do I verify my account?',
            answer: 'Go to your account settings and submit the required KYC documents.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'How do I place a trade?',
            answer: 'Navigate to the trading section, select the coins you want to trade, and enter the amount.'
          },
          {
            question: 'What is the minimum trade amount?',
            answer: 'The minimum trade amount is $100 equivalent.'
          }
        ]
      }
    ];
    
    res.json({ faqs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin user
    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = generateToken(user._id);
    
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminMiddleware, async (req, res) => {
  try {
    const stats = await getAdminStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/users', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/users/:id', adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/admin/users/:id', adminMiddleware, async (req, res) => {
  try {
    const { kycStatus, isAdmin } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (kycStatus) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    
    await user.save();
    
    // Notify user if KYC status changed
    if (kycStatus) {
      broadcast({
        type: 'kyc_status_changed',
        userId: user._id,
        status: kycStatus
      });
    }
    
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/trades', adminMiddleware, async (req, res) => {
  try {
    const trades = await Trade.find().sort({ createdAt: -1 }).populate('userId');
    res.json({ trades });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/transactions', adminMiddleware, async (req, res) => {
  try {
    const transactions = await Transaction.find().sort({ createdAt: -1 }).populate('userId');
    res.json({ transactions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/tickets', adminMiddleware, async (req, res) => {
  try {
    const tickets = await SupportTicket.find().sort({ createdAt: -1 }).populate('userId');
    res.json({ tickets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/tickets/:id', adminMiddleware, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id).populate('userId');
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', adminMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      fromAdmin: true
    });
    
    ticket.status = 'in_progress';
    await ticket.save();
    
    // Notify user via WebSocket
    broadcast({
      type: 'ticket_admin_reply',
      ticketId: ticket._id,
      userId: ticket.userId
    });
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', adminMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    // Notify user if resolved
    if (status === 'resolved') {
      broadcast({
        type: 'ticket_resolved',
        ticketId: ticket._id,
        userId: ticket.userId
      });
    }
    
    res.json({ ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/kyc', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find({ kycStatus: 'pending' });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/logs', adminMiddleware, async (req, res) => {
  try {
    // In a real app, you'd have a proper logging system
    const logs = [];
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/admin/broadcast', adminMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    
    broadcast({
      type: 'admin_broadcast',
      message
    });
    
    res.json({ message: 'Broadcast sent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/admin/settings', adminMiddleware, async (req, res) => {
  try {
    // In a real app, you'd have system settings
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.001,
      withdrawalFee: 0.005
    };
    
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/v1/admin/settings', adminMiddleware, async (req, res) => {
  try {
    // In a real app, you'd update system settings
    res.json({ message: 'Settings updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve static files (for file uploads)
app.use('/uploads', express.static('uploads'));

// Default admin user creation (run once)
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin@cryptotrading.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@1234', 10);
      const admin = new User({
        firstName: 'Admin',
        lastName: 'User',
        email: 'admin@cryptotrading.com',
        password: hashedPassword,
        isAdmin: true,
        kycStatus: 'verified'
      });
      await admin.save();
      console.log('Default admin user created');
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
};

createDefaultAdmin();

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
