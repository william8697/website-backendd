require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Database models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  walletAddress: String,
  walletProvider: String,
  country: String,
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDocs: [{
    type: { type: String, enum: ['passport', 'id', 'license'] },
    front: String,
    back: String,
  }],
  isAdmin: { type: Boolean, default: false },
  settings: {
    theme: { type: String, default: 'light' },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false },
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  apiKey: String,
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  fromCoin: String,
  toCoin: String,
  amount: Number,
  rate: Number,
  resultAmount: Number,
  fee: Number,
  type: { type: String, enum: ['buy', 'sell', 'arbitrage'] },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'] },
  amount: Number,
  currency: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  reference: String,
  details: String,
  createdAt: { type: Date, default: Date.now },
}));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: String,
  message: String,
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  attachments: [String],
  replies: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now },
  }],
  createdAt: { type: Date, default: Date.now },
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: String,
  answer: String,
  category: { type: String, enum: ['account', 'trading', 'deposits', 'general'] },
  createdAt: { type: Date, default: Date.now },
}));

const Coin = mongoose.model('Coin', new mongoose.Schema({
  symbol: { type: String, unique: true },
  name: String,
  price: Number,
  change24h: Number,
  lastUpdated: Date,
}));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const storage = multer.memoryStorage();
const upload = multer({ storage });

// JWT verification middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findById(decoded.userId);
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'auth') {
        try {
          const decoded = jwt.verify(data.token, process.env.JWT_SECRET || '17581758Na.%');
          const user = await User.findById(decoded.userId);
          if (user) {
            ws.userId = user._id;
            ws.isAdmin = user.isAdmin;
          }
        } catch (error) {
          ws.close();
        }
      }
    } catch (error) {
      console.error('WebSocket error:', error);
    }
  });
});

function broadcastToUser(userId, data) {
  wss.clients.forEach((client) => {
    if (client.userId && client.userId.toString() === userId.toString() && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

function broadcastToAdmins(data) {
  wss.clients.forEach((client) => {
    if (client.isAdmin && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// Coin data updater
async function updateCoinPrices() {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false');
    const coins = response.data;
    
    for (const coin of coins) {
      await Coin.findOneAndUpdate(
        { symbol: coin.symbol.toLowerCase() },
        {
          symbol: coin.symbol.toLowerCase(),
          name: coin.name,
          price: coin.current_price,
          change24h: coin.price_change_percentage_24h,
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    }
    
    console.log('Coin prices updated');
  } catch (error) {
    console.error('Error updating coin prices:', error);
  }
}

// Update coin prices every 5 minutes
setInterval(updateCoinPrices, 5 * 60 * 1000);
updateCoinPrices();

// Arbitrage calculation (using the same logic as in index.html)
async function calculateArbitrageOpportunities() {
  const coins = await Coin.find().limit(20); // Limit to top 20 coins for performance
  const opportunities = [];
  
  for (let i = 0; i < coins.length; i++) {
    for (let j = 0; j < coins.length; j++) {
      if (i !== j) {
        const fromCoin = coins[i];
        const toCoin = coins[j];
        
        // Calculate potential profit (same logic as frontend)
        const baseRate = fromCoin.price / toCoin.price;
        const marketSpread = 0.002; // 0.2% spread
        const effectiveRate = baseRate * (1 - marketSpread);
        
        // Simulate price fluctuations (-7.65% to +15.89% as in index.html)
        const fluctuation = -7.65 + Math.random() * (15.89 - (-7.65));
        const fluctuatedRate = effectiveRate * (1 + fluctuation / 100);
        
        const potentialProfit = (fluctuatedRate - effectiveRate) / effectiveRate * 100;
        
        if (potentialProfit > 1.5) { // Only show opportunities with >1.5% profit
          opportunities.push({
            fromCoin: fromCoin.symbol,
            toCoin: toCoin.symbol,
            fromPrice: fromCoin.price,
            toPrice: toCoin.price,
            profitPercentage: potentialProfit,
            timestamp: new Date()
          });
        }
      }
    }
  }
  
  return opportunities;
}

// Trading logic (same as in index.html)
async function executeTrade(userId, fromCoin, toCoin, amount) {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  
  const fromCoinData = await Coin.findOne({ symbol: fromCoin.toLowerCase() });
  const toCoinData = await Coin.findOne({ symbol: toCoin.toLowerCase() });
  
  if (!fromCoinData || !toCoinData) throw new Error('Invalid coin selection');
  
  // Calculate rate with spread (same as frontend)
  const baseRate = fromCoinData.price / toCoinData.price;
  const marketSpread = 0.002; // 0.2% spread
  const effectiveRate = baseRate * (1 - marketSpread);
  
  // Apply random fluctuation (-7.65% to +15.89%)
  const fluctuation = -7.65 + Math.random() * (15.89 - (-7.65));
  const fluctuatedRate = effectiveRate * (1 + fluctuation / 100);
  
  const resultAmount = amount * fluctuatedRate;
  const fee = resultAmount * 0.001; // 0.1% fee
  
  // Create trade record
  const trade = new Trade({
    userId,
    fromCoin,
    toCoin,
    amount,
    rate: fluctuatedRate,
    resultAmount: resultAmount - fee,
    fee,
    type: 'arbitrage',
    status: 'completed'
  });
  
  await trade.save();
  
  // Update user balance
  user.balance += resultAmount - fee;
  await user.save();
  
  // Create transaction record
  const transaction = new Transaction({
    userId,
    type: 'trade',
    amount: resultAmount - fee,
    currency: toCoin,
    status: 'completed',
    reference: `TRADE-${trade._id}`,
    details: `Converted ${amount} ${fromCoin} to ${resultAmount - fee} ${toCoin}`
  });
  
  await transaction.save();
  
  // Broadcast updates
  broadcastToUser(userId, {
    type: 'BALANCE_UPDATE',
    balance: user.balance
  });
  
  broadcastToUser(userId, {
    type: 'TRADE_UPDATE',
    trade: trade.toObject()
  });
  
  return {
    success: true,
    amount: resultAmount - fee,
    rate: fluctuatedRate,
    fee
  };
}

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Platform Backend');
});

// Auth routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Validate password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET || '17581758Na.%', { expiresIn: '1d' });
    
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency: currency || 'USD',
      verificationToken,
      balance: 0
    });
    
    await user.save();
    
    // Send verification email
    const verificationUrl = `https://website-xi-ten-52.vercel.app/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: '"Crypto Trading Platform" <noreply@cryptotrading.com>',
      to: email,
      subject: 'Verify Your Email',
      html: `<p>Please click <a href="${verificationUrl}">here</a> to verify your email address.</p>`
    });
    
    res.status(201).json({ message: 'User created successfully. Please check your email for verification.' });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      console.error(error);
      res.status(500).json({ error: 'Server error during signup' });
    }
  }
});

app.post('/api/v1/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    
    const user = await User.findOneAndUpdate(
      { email: decoded.email, verificationToken: token },
      { isVerified: true, verificationToken: null },
      { new: true }
    );
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }
    
    // Create JWT for immediate login
    const authToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || '17581758Na.%',
      { expiresIn: '7d' }
    );
    
    res.json({
      message: 'Email verified successfully',
      token: authToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired verification token' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Create JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || '17581758Na.%',
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: user.balance,
        isVerified: user.isVerified,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature, provider } = req.body;
    
    // In a real implementation, you would verify the signature here
    // For demo purposes, we'll just check if the wallet exists
    
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      // Create new user if wallet doesn't exist
      user = new User({
        walletAddress,
        walletProvider: provider,
        balance: 0,
        isVerified: true // Wallet users are automatically verified
      });
      await user.save();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Create JWT
    const token = jwt.sign(
      { userId: user._id, walletAddress: user.walletAddress },
      process.env.JWT_SECRET || '17581758Na.%',
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        balance: user.balance,
        isVerified: user.isVerified,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during wallet login' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      // For security, don't reveal if email exists
      return res.json({ message: 'If an account with this email exists, a reset link has been sent' });
    }
    
    const resetToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || '17581758Na.%',
      { expiresIn: '1h' }
    );
    
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    await transporter.sendMail({
      from: '"Crypto Trading Platform" <noreply@cryptotrading.com>',
      to: email,
      subject: 'Password Reset',
      html: `<p>Please click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 1 hour.</p>`
    });
    
    res.json({ message: 'If an account with this email exists, a reset link has been sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Validate password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findOne({
      _id: decoded.userId,
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired reset token' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real implementation, you might want to invalidate the token
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error during logout' });
  }
});

// User routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        walletAddress: req.user.walletAddress,
        walletProvider: req.user.walletProvider,
        balance: req.user.balance,
        currency: req.user.currency,
        isVerified: req.user.isVerified,
        kycStatus: req.user.kycStatus,
        isAdmin: req.user.isAdmin,
        settings: req.user.settings,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching user data' });
  }
});

app.patch('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    
    // Prevent certain fields from being updated
    delete updates.email;
    delete updates.password;
    delete updates.balance;
    delete updates.isAdmin;
    
    Object.assign(req.user, updates);
    await req.user.save();
    
    res.json({ message: 'Profile updated successfully', user: req.user });
  } catch (error) {
    res.status(500).json({ error: 'Server error updating profile' });
  }
});

app.patch('/api/v1/users/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Validate password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' });
    }
    
    const isMatch = await bcrypt.compare(currentPassword, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    req.user.password = hashedPassword;
    await req.user.save();
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error updating password' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.array('documents'), async (req, res) => {
  try {
    if (req.user.kycStatus === 'verified') {
      return res.status(400).json({ error: 'KYC already verified' });
    }
    
    const { type, personalDetails } = req.body;
    
    // In a real implementation, you would save the uploaded files to storage
    // For demo, we'll just store the file names
    const kycDocs = req.files.map(file => ({
      type,
      front: file.originalname,
      back: file.originalname // For demo, same file for front/back
    }));
    
    req.user.kycDocs = kycDocs;
    req.user.kycStatus = 'pending';
    await req.user.save();
    
    // Notify admin
    broadcastToAdmins({
      type: 'KYC_SUBMISSION',
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });
    
    res.json({ message: 'KYC documents submitted for review' });
  } catch (error) {
    res.status(500).json({ error: 'Server error submitting KYC' });
  }
});

// Trading routes
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: 'pending'
    }).sort({ createdAt: -1 }).limit(10);
    
    res.json({ trades });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching active trades' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user._id,
      status: { $in: ['completed', 'failed'] }
    }).sort({ createdAt: -1 }).limit(50);
    
    res.json({ trades });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching trade history' });
  }
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (req.user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const result = await executeTrade(req.user._id, fromCoin, toCoin, amount);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error executing trade' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // In a real implementation, you would check if user has enough of fromCoin
    // For demo, we'll just proceed
    
    const result = await executeTrade(req.user._id, fromCoin, toCoin, amount);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error executing trade' });
  }
});

app.get('/api/v1/arbitrage/opportunities', authenticate, async (req, res) => {
  try {
    const opportunities = await calculateArbitrageOpportunities();
    res.json({ opportunities });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching arbitrage opportunities' });
  }
});

app.post('/api/v1/arbitrage/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (req.user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const result = await executeTrade(req.user._id, fromCoin, toCoin, amount);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error executing arbitrage' });
  }
});

// Coin routes
app.get('/api/v1/coins', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ price: -1 }).limit(100);
    res.json({ coins });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching coins' });
  }
});

app.get('/api/v1/coins/:symbol', async (req, res) => {
  try {
    const coin = await Coin.findOne({ symbol: req.params.symbol.toLowerCase() });
    if (!coin) {
      return res.status(404).json({ error: 'Coin not found' });
    }
    res.json({ coin });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching coin' });
  }
});

// Transaction routes
app.get('/api/v1/transactions', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ transactions });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// Support routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ category: 1 });
    res.json({ faqs });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching FAQs' });
  }
});

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    // In a real implementation, you would save the attachments to storage
    const attachments = req.files.map(file => file.originalname);
    
    const ticket = new Ticket({
      userId: req.user._id,
      subject,
      message,
      attachments
    });
    
    await ticket.save();
    
    // Notify admin
    broadcastToAdmins({
      type: 'NEW_TICKET',
      ticketId: ticket._id,
      subject: ticket.subject
    });
    
    res.json({ message: 'Ticket created successfully', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Server error creating ticket' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ tickets });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching tickets' });
  }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching ticket' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await Ticket.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      {
        $push: {
          replies: {
            userId: req.user._id,
            message,
            isAdmin: false
          }
        },
        status: 'pending'
      },
      { new: true }
    );
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    // Notify admin
    broadcastToAdmins({
      type: 'TICKET_REPLY',
      ticketId: ticket._id,
      subject: ticket.subject
    });
    
    res.json({ message: 'Reply added successfully', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Server error replying to ticket' });
  }
});

// Admin routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isAdmin: true });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email, isAdmin: true },
      process.env.JWT_SECRET || '17581758Na.%',
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const verifiedUsersCount = await User.countDocuments({ isVerified: true });
    const tradesCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('firstName lastName email createdAt');
    
    const recentTrades = await Trade.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email');
    
    res.json({
      stats: {
        users: usersCount,
        verifiedUsers: verifiedUsersCount,
        trades: tradesCount,
        volume: totalVolume[0]?.total || 0
      },
      recentUsers,
      recentTrades
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching admin dashboard' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    const transactions = await Transaction.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.json({
      user,
      trades,
      transactions
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching user details' });
  }
});

app.patch('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { balance, isVerified, isAdmin, kycStatus } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (balance !== undefined) user.balance = balance;
    if (isVerified !== undefined) user.isVerified = isVerified;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    if (kycStatus !== undefined) user.kycStatus = kycStatus;
    
    await user.save();
    
    // Notify user if balance changed
    if (balance !== undefined) {
      broadcastToUser(user._id, {
        type: 'BALANCE_UPDATE',
        balance: user.balance
      });
    }
    
    res.json({ message: 'User updated successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Server error updating user' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const trades = await Trade.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    const total = await Trade.countDocuments(query);
    
    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, type, status } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    
    const query = {};
    if (status) query.status = status;
    
    const tickets = await Ticket.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    const total = await Ticket.countDocuments(query);
    
    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email')
      .populate('replies.userId', 'firstName lastName email isAdmin');
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching ticket' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      {
        $push: {
          replies: {
            userId: req.user._id,
            message,
            isAdmin: true
          }
        },
        status: req.body.status || 'pending'
      },
      { new: true }
    )
      .populate('userId', 'firstName lastName email')
      .populate('replies.userId', 'firstName lastName email isAdmin');
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    // Notify user
    broadcastToUser(ticket.userId._id, {
      type: 'TICKET_UPDATE',
      ticketId: ticket._id,
      status: ticket.status
    });
    
    res.json({ message: 'Reply added successfully', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Server error replying to ticket' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    
    const query = { kycStatus: status || 'pending' };
    
    const users = await User.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.json({
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error fetching KYC submissions' });
  }
});

app.post('/api/v1/admin/kyc/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'verified' },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_UPDATE',
      status: 'verified'
    });
    
    res.json({ message: 'KYC approved successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Server error approving KYC' });
  }
});

app.post('/api/v1/admin/kyc/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'rejected', kycDocs: [] }, // Clear docs so they can resubmit
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_UPDATE',
      status: 'rejected',
      reason
    });
    
    res.json({ message: 'KYC rejected successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Server error rejecting KYC' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
