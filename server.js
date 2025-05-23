require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const WebSocket = require('ws');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { ethers } = require('ethers');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  walletAddress: { type: String },
  walletProvider: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  balances: {
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    USDT: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 },
    XRP: { type: Number, default: 0 },
    SOL: { type: Number, default: 0 },
    ADA: { type: Number, default: 0 },
    DOGE: { type: Number, default: 0 },
    DOT: { type: Number, default: 0 },
    MATIC: { type: Number, default: 0 }
  },
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  twoFactorEnabled: { type: Boolean, default: false },
  apiKey: { type: String },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'transfer'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  fee: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [{ type: String }],
  responses: [{
    message: { type: String },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

const KYC = mongoose.model('KYC', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  documentType: { type: String, enum: ['passport', 'driver_license', 'national_id'], required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNotes: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security', 'general'], required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const AdminLog = mongoose.model('AdminLog', new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: { type: String },
  targetId: { type: mongoose.Schema.Types.ObjectId },
  details: { type: Object },
  ipAddress: { type: String },
  createdAt: { type: Date, default: Date.now }
}));

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '24h' });
};

// Email Configuration
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Crypto Price Cache
let priceCache = {};
const CRYPTO_LIST = ['bitcoin', 'ethereum', 'tether', 'binancecoin', 'ripple', 'solana', 'cardano', 'dogecoin', 'polkadot', 'matic-network'];

// Fetch crypto prices from CoinGecko
const fetchCryptoPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
      params: {
        vs_currency: 'usd',
        ids: CRYPTO_LIST.join(','),
        price_change_percentage: '1h,24h,7d'
      }
    });
    
    response.data.forEach(coin => {
      priceCache[coin.symbol.toUpperCase()] = {
        price: coin.current_price,
        change1h: coin.price_change_percentage_1h_in_currency,
        change24h: coin.price_change_percentage_24h_in_currency,
        change7d: coin.price_change_percentage_7d_in_currency,
        marketCap: coin.market_cap,
        volume: coin.total_volume,
        lastUpdated: Date.now()
      };
    });
    
    console.log('Crypto prices updated');
  } catch (error) {
    console.error('Error fetching crypto prices:', error.message);
    // Fallback to previous prices if API fails
  }
};

// Initial fetch and periodic updates
fetchCryptoPrices();
setInterval(fetchCryptoPrices, 60000); // Update every minute

// Arbitrage Logic (from index.html)
const findArbitrageOpportunities = () => {
  const opportunities = [];
  const coins = Object.keys(priceCache);
  
  for (let i = 0; i < coins.length; i++) {
    for (let j = 0; j < coins.length; j++) {
      if (i !== j) {
        const fromCoin = coins[i];
        const toCoin = coins[j];
        const fromPrice = priceCache[fromCoin]?.price || 0;
        const toPrice = priceCache[toCoin]?.price || 0;
        
        if (fromPrice > 0 && toPrice > 0) {
          const rate = toPrice / fromPrice;
          const reverseRate = fromPrice / toPrice;
          
          // Check for price differences (simplified arbitrage logic)
          if (Math.abs(rate - reverseRate) > 0.01) {
            opportunities.push({
              fromCoin,
              toCoin,
              rate,
              potentialProfit: Math.abs(rate - reverseRate) * 100,
              timestamp: Date.now()
            });
          }
        }
      }
    }
  }
  
  return opportunities.slice(0, 5); // Return top 5 opportunities
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user || !user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// API Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    // Validation
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }
    
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters with uppercase, number, and special character' 
      });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already in use' });
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
      currency: currency || 'USD',
      apiKey: uuidv4()
    });
    
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    // Send welcome email
    const mailOptions = {
      from: 'support@cryptotrading.com',
      to: email,
      subject: 'Welcome to Crypto Trading Platform',
      html: `<p>Hi ${firstName},</p>
             <p>Your account has been successfully created!</p>
             <p>Start trading and explore arbitrage opportunities on our platform.</p>`
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(201).json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        balances: user.balances,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    const token = generateToken(user._id);
    
    res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        balances: user.balances,
        currency: user.currency,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature, provider } = req.body;
    
    // Verify signature (simplified for example)
    const message = `Login to Crypto Trading Platform - ${Date.now()}`;
    const recoveredAddress = ethers.utils.verifyMessage(message, signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ success: false, message: 'Signature verification failed' });
    }
    
    // Find or create user
    let user = await User.findOne({ walletAddress: walletAddress.toLowerCase() });
    
    if (!user) {
      // Create new wallet user
      user = new User({
        walletAddress: walletAddress.toLowerCase(),
        walletProvider: provider || 'unknown',
        balances: {},
        apiKey: uuidv4()
      });
      
      await user.save();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    const token = generateToken(user._id);
    
    res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        balance: user.balance,
        balances: user.balances,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Wallet login error:', error);
    res.status(500).json({ success: false, message: 'Server error during wallet login' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // Return success even if email doesn't exist to prevent email enumeration
      return res.json({ success: true, message: 'If an account exists, a reset email has been sent' });
    }
    
    // Generate reset token (valid for 1 hour)
    const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    
    // Send reset email
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      from: 'support@cryptotrading.com',
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Hi ${user.firstName},</p>
             <p>You requested a password reset. Click the link below to reset your password:</p>
             <p><a href="${resetUrl}">Reset Password</a></p>
             <p>This link will expire in 1 hour.</p>`
    };
    
    await transporter.sendMail(mailOptions);
    
    res.json({ success: true, message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(newPassword)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters with uppercase, number, and special character' 
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ success: false, message: 'Reset token has expired' });
    }
    res.status(500).json({ success: false, message: 'Server error during password reset' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({ 
      success: true, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        walletProvider: user.walletProvider,
        balance: user.balance,
        balances: user.balances,
        currency: user.currency,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        twoFactorEnabled: user.twoFactorEnabled,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching user data' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real implementation, you might want to invalidate the token
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Server error during logout' });
  }
});

// User Routes
app.patch('/api/v1/users/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;
    
    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }
    
    // Validate new password
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(newPassword)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters with uppercase, number, and special character' 
      });
    }
    
    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ success: false, message: 'Server error updating password' });
  }
});

app.patch('/api/v1/users/update-profile', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    const user = req.user;
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (country) user.country = country;
    if (currency) user.currency = currency;
    
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        country: user.country,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'Server error updating profile' });
  }
});

app.post('/api/v1/users/kyc', authenticate, async (req, res) => {
  try {
    const { documentType, documentFront, documentBack, selfie } = req.body;
    const user = req.user;
    
    // In a real implementation, you would upload files to storage (S3, etc.)
    // Here we're just storing the file references
    
    const kyc = new KYC({
      userId: user._id,
      documentType,
      documentFront,
      documentBack,
      selfie,
      status: 'pending'
    });
    
    await kyc.save();
    
    // Update user KYC status
    user.kycStatus = 'pending';
    await user.save();
    
    res.json({ success: true, message: 'KYC submitted for review' });
  } catch (error) {
    console.error('KYC submission error:', error);
    res.status(500).json({ success: false, message: 'Server error submitting KYC' });
  }
});

app.get('/api/v1/users/kyc-status', authenticate, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ userId: req.user._id }).sort({ createdAt: -1 });
    
    res.json({ 
      success: true, 
      status: kyc?.status || 'none',
      reviewNotes: kyc?.reviewNotes,
      updatedAt: kyc?.updatedAt
    });
  } catch (error) {
    console.error('KYC status error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching KYC status' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = req.user;
    user.apiKey = uuidv4();
    await user.save();
    
    res.json({ success: true, apiKey: user.apiKey });
  } catch (error) {
    console.error('API key generation error:', error);
    res.status(500).json({ success: false, message: 'Server error generating API key' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    // Gather all user data
    const [trades, transactions, tickets] = await Promise.all([
      Trade.find({ userId: user._id }),
      Transaction.find({ userId: user._id }),
      Ticket.find({ userId: user._id })
    ]);
    
    const userData = {
      profile: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        country: user.country,
        currency: user.currency,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      },
      balances: user.balances,
      trades,
      transactions,
      tickets
    };
    
    // In a real implementation, you would generate a downloadable file
    // For now, we'll just return the data
    res.json({ success: true, data: userData });
  } catch (error) {
    console.error('Export data error:', error);
    res.status(500).json({ success: false, message: 'Server error exporting data' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    const user = req.user;
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Password is incorrect' });
    }
    
    // In a real implementation, you might want to soft delete or anonymize data
    await User.deleteOne({ _id: user._id });
    
    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ success: false, message: 'Server error deleting account' });
  }
});

// Trading Routes
app.get('/api/v1/trades/market-data', async (req, res) => {
  try {
    // Get trending coins
    const trendingResponse = await axios.get('https://api.coingecko.com/api/v3/search/trending');
    const trendingCoins = trendingResponse.data.coins.map(coin => ({
      id: coin.item.id,
      name: coin.item.name,
      symbol: coin.item.symbol,
      price: coin.item.price_btc,
      thumb: coin.item.thumb
    }));
    
    res.json({
      success: true,
      prices: priceCache,
      trending: trendingCoins,
      arbitrageOpportunities: findArbitrageOpportunities()
    });
  } catch (error) {
    console.error('Market data error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching market data',
      // Fallback data
      prices: priceCache,
      trending: [],
      arbitrageOpportunities: []
    });
  }
});

app.post('/api/v1/trades/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = req.user;
    
    // Validate minimum trade amount
    if (amount < 100) {
      return res.status(400).json({ success: false, message: 'Minimum trade amount is $100' });
    }
    
    // Check if user has sufficient balance
    if (user.balances[fromCoin] === undefined || user.balances[fromCoin] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Get current prices
    const fromPrice = priceCache[fromCoin]?.price || 0;
    const toPrice = priceCache[toCoin]?.price || 0;
    
    if (fromPrice <= 0 || toPrice <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid coin prices' });
    }
    
    // Calculate conversion rate
    const rate = toPrice / fromPrice;
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.001; // 0.1% fee
    
    // Update user balances
    user.balances[fromCoin] -= amount;
    user.balances[toCoin] = (user.balances[toCoin] || 0) + (convertedAmount - fee);
    await user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed'
    });
    await trade.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: convertedAmount - fee,
      currency: toCoin,
      status: 'completed'
    });
    await transaction.save();
    
    res.json({ 
      success: true, 
      message: 'Trade executed successfully',
      convertedAmount: convertedAmount - fee,
      fee,
      newBalances: user.balances
    });
    
    // Notify via WebSocket
    notifyUser(user._id, 'TRADE_UPDATE', {
      tradeId: trade._id,
      fromCoin,
      toCoin,
      amount,
      convertedAmount: convertedAmount - fee,
      fee,
      status: 'completed',
      newBalances: user.balances
    });
  } catch (error) {
    console.error('Trade execution error:', error);
    res.status(500).json({ success: false, message: 'Server error executing trade' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Trade.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Trade history error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching trade history' });
  }
});

app.get('/api/v1/trades/arbitrage-opportunities', async (req, res) => {
  try {
    res.json({
      success: true,
      opportunities: findArbitrageOpportunities()
    });
  } catch (error) {
    console.error('Arbitrage opportunities error:', error);
    res.status(500).json({ success: false, message: 'Server error finding arbitrage opportunities' });
  }
});

// Transaction Routes
app.get('/api/v1/transactions', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { userId: req.user._id };
    if (type) query.type = type;
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching transactions' });
  }
});

app.post('/api/v1/transactions/deposit', authenticate, async (req, res) => {
  try {
    const { currency, amount } = req.body;
    const user = req.user;
    
    // In a real implementation, you would integrate with a payment processor
    // For now, we'll simulate a deposit
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      currency,
      status: 'completed'
    });
    await transaction.save();
    
    // Update user balance
    user.balances[currency] = (user.balances[currency] || 0) + amount;
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Deposit completed successfully',
      newBalance: user.balances[currency]
    });
    
    // Notify via WebSocket
    notifyUser(user._id, 'BALANCE_UPDATE', {
      currency,
      newBalance: user.balances[currency],
      transactionId: transaction._id
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ success: false, message: 'Server error processing deposit' });
  }
});

app.post('/api/v1/transactions/withdraw', authenticate, async (req, res) => {
  try {
    const { currency, amount, address } = req.body;
    const user = req.user;
    
    // Validate minimum withdrawal amount
    if (amount < 350) {
      return res.status(400).json({ success: false, message: 'Minimum withdrawal amount is $350' });
    }
    
    // Check if user has sufficient balance
    if (user.balances[currency] === undefined || user.balances[currency] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Validate address (simplified)
    if (!address || address.length < 10) {
      return res.status(400).json({ success: false, message: 'Invalid withdrawal address' });
    }
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending' // In a real implementation, you'd process this asynchronously
    });
    await transaction.save();
    
    // Update user balance (immediately deduct)
    user.balances[currency] -= amount;
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Withdrawal request submitted',
      newBalance: user.balances[currency],
      transactionId: transaction._id
    });
    
    // Notify via WebSocket
    notifyUser(user._id, 'BALANCE_UPDATE', {
      currency,
      newBalance: user.balances[currency],
      transactionId: transaction._id
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Server error processing withdrawal' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const { category } = req.query;
    
    const query = { isActive: true };
    if (category) query.category = category;
    
    const faqs = await FAQ.find(query).sort({ createdAt: -1 });
    
    res.json({ success: true, faqs });
  } catch (error) {
    console.error('FAQs error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching FAQs' });
  }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message, attachments } = req.body;
    const user = req.user;
    
    const ticket = new Ticket({
      userId: user._id,
      email: user.email,
      subject,
      message,
      attachments: attachments || [],
      status: 'open'
    });
    
    await ticket.save();
    
    // Send confirmation email
    const mailOptions = {
      from: 'support@cryptotrading.com',
      to: user.email,
      subject: `Support Ticket Created: ${ticket._id}`,
      html: `<p>Hi ${user.firstName},</p>
             <p>Your support ticket has been created with ID: ${ticket._id}</p>
             <p>Subject: ${subject}</p>
             <p>We'll get back to you as soon as possible.</p>`
    };
    
    await transporter.sendMail(mailOptions);
    
    res.json({ success: true, ticketId: ticket._id });
  } catch (error) {
    console.error('Ticket creation error:', error);
    res.status(500).json({ success: false, message: 'Server error creating support ticket' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { status } = req.query;
    
    const query = { userId: req.user._id };
    if (status) query.status = status;
    
    const tickets = await Ticket.find(query).sort({ createdAt: -1 });
    
    res.json({ success: true, tickets });
  } catch (error) {
    console.error('Tickets error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching tickets' });
  }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    res.json({ success: true, ticket });
  } catch (error) {
    console.error('Ticket error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching ticket' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      isAdmin: false
    });
    
    await ticket.save();
    
    res.json({ success: true, message: 'Reply added successfully' });
  } catch (error) {
    console.error('Ticket reply error:', error);
    res.status(500).json({ success: false, message: 'Server error replying to ticket' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    const token = generateToken(user._id);
    
    res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ success: false, message: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      verifiedUsers,
      totalTrades,
      totalVolume,
      pendingKYC,
      openTickets
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isVerified: true }),
      Trade.countDocuments(),
      Transaction.aggregate([{ $match: { type: 'trade' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]),
      KYC.countDocuments({ status: 'pending' }),
      Ticket.countDocuments({ status: 'open' })
    ]);
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        verifiedUsers,
        totalTrades,
        totalVolume: totalVolume[0]?.total || 0,
        pendingKYC,
        openTickets
      }
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching dashboard stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;
    
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
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(query);
    
    res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching users' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const [trades, transactions, tickets] = await Promise.all([
      Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5),
      Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5),
      Ticket.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5)
    ]);
    
    res.json({
      success: true,
      user,
      trades,
      transactions,
      tickets
    });
  } catch (error) {
    console.error('Admin user error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching user' });
  }
});

app.patch('/api/v1/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    user.isVerified = status === 'verified';
    await user.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'update_user_status',
      target: 'user',
      targetId: user._id,
      details: { status }
    });
    await log.save();
    
    res.json({ success: true, message: 'User status updated' });
  } catch (error) {
    console.error('User status error:', error);
    res.status(500).json({ success: false, message: 'Server error updating user status' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
  try {
    const { currency, amount, reason } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Update balance
    user.balances[currency] = (user.balances[currency] || 0) + amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: amount > 0 ? 'deposit' : 'withdrawal',
      amount: Math.abs(amount),
      currency,
      status: 'completed',
      adminNote: reason || 'Admin adjustment'
    });
    await transaction.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'adjust_user_balance',
      target: 'user',
      targetId: user._id,
      details: { currency, amount, reason }
    });
    await log.save();
    
    res.json({ success: true, message: 'Balance updated', newBalance: user.balances[currency] });
    
    // Notify user via WebSocket
    notifyUser(user._id, 'BALANCE_UPDATE', {
      currency,
      newBalance: user.balances[currency],
      transactionId: transaction._id,
      adminAction: true
    });
  } catch (error) {
    console.error('Balance adjustment error:', error);
    res.status(500).json({ success: false, message: 'Server error adjusting balance' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    
    const query = {};
    if (status) query.status = status;
    
    const kycRequests = await KYC.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, kycRequests });
  } catch (error) {
    console.error('KYC requests error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching KYC requests' });
  }
});

app.patch('/api/v1/admin/kyc/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status, notes } = req.body;
    
    const kyc = await KYC.findById(req.params.id).populate('userId');
    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC request not found' });
    }
    
    kyc.status = status;
    kyc.reviewedBy = req.user._id;
    kyc.reviewNotes = notes;
    kyc.updatedAt = new Date();
    await kyc.save();
    
    // Update user KYC status
    const user = await User.findById(kyc.userId._id);
    if (user) {
      user.kycStatus = status;
      await user.save();
    }
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'kyc_review',
      target: 'kyc',
      targetId: kyc._id,
      details: { status, notes }
    });
    await log.save();
    
    // Notify user via email
    if (kyc.userId.email) {
      const mailOptions = {
        from: 'support@cryptotrading.com',
        to: kyc.userId.email,
        subject: `KYC Verification ${status}`,
        html: `<p>Hi ${kyc.userId.firstName},</p>
               <p>Your KYC verification has been ${status}.</p>
               ${notes ? `<p>Notes: ${notes}</p>` : ''}`
      };
      
      await transporter.sendMail(mailOptions);
    }
    
    res.json({ success: true, message: `KYC request ${status}` });
  } catch (error) {
    console.error('KYC status error:', error);
    res.status(500).json({ success: false, message: 'Server error updating KYC status' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (userId) query.userId = userId;
    
    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Trade.countDocuments(query);
    
    res.json({
      success: true,
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin trades error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, type, userId } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (type) query.type = type;
    if (userId) query.userId = userId;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      success: true,
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching transactions' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) query.status = status;
    
    const tickets = await Ticket.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Ticket.countDocuments(query);
    
    res.json({
      success: true,
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin tickets error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    res.json({ success: true, ticket });
  } catch (error) {
    console.error('Admin ticket error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching ticket' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      isAdmin: true
    });
    
    ticket.status = 'in-progress';
    await ticket.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'ticket_reply',
      target: 'ticket',
      targetId: ticket._id
    });
    await log.save();
    
    // Notify user via email
    if (ticket.userId?.email) {
      const mailOptions = {
        from: 'support@cryptotrading.com',
        to: ticket.userId.email,
        subject: `Reply to your ticket: ${ticket._id}`,
        html: `<p>Hi ${ticket.userId.firstName},</p>
               <p>An admin has replied to your support ticket:</p>
               <p>${message}</p>`
      };
      
      await transporter.sendMail(mailOptions);
    }
    
    res.json({ success: true, message: 'Reply added successfully' });
  } catch (error) {
    console.error('Admin ticket reply error:', error);
    res.status(500).json({ success: false, message: 'Server error replying to ticket' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'ticket_status_change',
      target: 'ticket',
      targetId: ticket._id,
      details: { status }
    });
    await log.save();
    
    // Notify user via email if resolved
    if (status === 'resolved' && ticket.userId?.email) {
      const mailOptions = {
        from: 'support@cryptotrading.com',
        to: ticket.userId.email,
        subject: `Ticket Resolved: ${ticket._id}`,
        html: `<p>Hi ${ticket.userId.firstName},</p>
               <p>Your support ticket has been marked as resolved.</p>`
      };
      
      await transporter.sendMail(mailOptions);
    }
    
    res.json({ success: true, message: 'Ticket status updated' });
  } catch (error) {
    console.error('Ticket status error:', error);
    res.status(500).json({ success: false, message: 'Server error updating ticket status' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, action } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (action) query.action = action;
    
    const logs = await AdminLog.find(query)
      .populate('adminId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await AdminLog.countDocuments(query);
    
    res.json({
      success: true,
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin logs error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching logs' });
  }
});

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws, req) => {
  // Extract token from query parameters
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;
    
    // Store the connection with user ID
    clients.set(userId, ws);
    
    ws.on('close', () => {
      clients.delete(userId);
    });
    
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      clients.delete(userId);
    });
    
  } catch (error) {
    console.error('WebSocket auth error:', error);
    ws.close(1008, 'Invalid token');
  }
});

// Function to notify a specific user via WebSocket
const notifyUser = (userId, type, data) => {
  const ws = clients.get(userId.toString());
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
};

// Function to broadcast to all connected clients
const broadcast = (type, data) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type, data }));
    }
  });
};

// Broadcast arbitrage opportunities periodically
setInterval(() => {
  const opportunities = findArbitrageOpportunities();
  if (opportunities.length > 0) {
    broadcast('ARBITRAGE_OPPORTUNITY', { opportunities });
  }
}, 30000); // Every 30 seconds

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});
