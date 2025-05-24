require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// JWT Secret
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

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  country: { type: String, required: true },
  currency: { type: String, default: 'USD' },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  walletAddress: { type: String },
  walletProvider: { type: String },
  balance: { type: Number, default: 0 },
  portfolio: { type: Map, of: Number, default: {} },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: { type: String, required: true },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'auth') {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          const user = await User.findById(decoded.id);
          
          if (user) {
            ws.userId = user._id;
            ws.isAdmin = user.isAdmin;
            ws.send(JSON.stringify({ type: 'auth', status: 'success' }));
          } else {
            ws.send(JSON.stringify({ type: 'auth', status: 'failed', message: 'User not found' }));
          }
        } catch (err) {
          ws.send(JSON.stringify({ type: 'auth', status: 'failed', message: 'Invalid token' }));
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

// Broadcast function for WebSocket
function broadcast(userId, data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.userId && client.userId.toString() === userId.toString()) {
      client.send(JSON.stringify(data));
    }
  });
}

// Broadcast to admin
function broadcastToAdmin(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.isAdmin) {
      client.send(JSON.stringify(data));
    }
  });
}

// Helper functions
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
};

const sendVerificationEmail = async (user) => {
  const verificationUrl = `https://website-xi-ten-52.vercel.app/verify?token=${user.verificationToken}`;
  
  const mailOptions = {
    from: '"Crypto Trading Platform" <no-reply@cryptotrading.com>',
    to: user.email,
    subject: 'Verify Your Email',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2d3748;">Welcome to Crypto Trading Platform</h2>
        <p>Please click the button below to verify your email address:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background-color: #4299e1; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Verify Email</a>
        <p>If you didn't create an account with us, please ignore this email.</p>
        <p style="margin-top: 30px; color: #718096;">© ${new Date().getFullYear()} Crypto Trading Platform. All rights reserved.</p>
      </div>
    `
  };
  
  await transporter.sendMail(mailOptions);
};

const sendPasswordResetEmail = async (user) => {
  const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${user.resetPasswordToken}`;
  
  const mailOptions = {
    from: '"Crypto Trading Platform" <no-reply@cryptotrading.com>',
    to: user.email,
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2d3748;">Password Reset Request</h2>
        <p>We received a request to reset your password. Click the button below to reset it:</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #4299e1; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Reset Password</a>
        <p>If you didn't request a password reset, please ignore this email.</p>
        <p style="margin-top: 30px; color: #718096;">© ${new Date().getFullYear()} Crypto Trading Platform. All rights reserved.</p>
      </div>
    `
  };
  
  await transporter.sendMail(mailOptions);
};

// Get coin prices from CoinGecko API
const getCoinPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
      params: {
        vs_currency: 'usd',
        ids: 'bitcoin,ethereum,ripple,cardano,polkadot,solana,dogecoin',
        order: 'market_cap_desc',
        per_page: 100,
        page: 1,
        sparkline: false
      }
    });
    
    const prices = {};
    response.data.forEach(coin => {
      prices[coin.id] = coin.current_price;
    });
    
    return prices;
  } catch (err) {
    console.error('Error fetching coin prices:', err);
    return null;
  }
};

// API Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already in use' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const verificationToken = uuidv4();
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency: currency || 'USD',
      verificationToken,
      portfolio: {
        bitcoin: 0,
        ethereum: 0,
        ripple: 0,
        cardano: 0,
        polkadot: 0,
        solana: 0,
        dogecoin: 0
      }
    });
    
    await user.save();
    
    // Send verification email
    await sendVerificationEmail(user);
    
    // Generate token
    const token = generateToken(user);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = generateToken(user);
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, walletProvider, signature } = req.body;
    
    // Find user by wallet address
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      // Create new user if not exists
      user = new User({
        walletAddress,
        walletProvider,
        isVerified: true,
        balance: 0,
        portfolio: {
          bitcoin: 0,
          ethereum: 0,
          ripple: 0,
          cardano: 0,
          polkadot: 0,
          solana: 0,
          dogecoin: 0
        }
      });
      await user.save();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = generateToken(user);
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        walletProvider: user.walletProvider,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

app.post('/api/v1/auth/verify-email', async (req, res) => {
  try {
    const { token } = req.body;
    
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid verification token' });
    }
    
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();
    
    res.json({ success: true, message: 'Email verified successfully' });
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // Return success even if email doesn't exist to prevent email enumeration
      return res.json({ success: true, message: 'If your email is registered, you will receive a password reset link' });
    }
    
    // Generate reset token
    user.resetPasswordToken = uuidv4();
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
    await sendPasswordResetEmail(user);
    
    res.json({ success: true, message: 'Password reset link sent to your email' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
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
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  // Since we're using JWT, logout is handled client-side by removing the token
  res.json({ success: true, message: 'Logged out successfully' });
});

// User Routes
app.get('/api/v1/users/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin,
        walletAddress: user.walletAddress,
        walletProvider: user.walletProvider
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/users/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const { firstName, lastName, country, currency } = req.body;
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (country) user.country = country;
    if (currency) user.currency = currency;
    
    await user.save();
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/users/change-password', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const { currentPassword, newPassword } = req.body;
    
    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Trade Routes
app.get('/api/v1/market/prices', async (req, res) => {
  try {
    const prices = await getCoinPrices();
    
    if (!prices) {
      return res.status(500).json({ success: false, message: 'Failed to fetch prices' });
    }
    
    res.json({ success: true, prices });
  } catch (err) {
    console.error('Get market prices error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/trades/convert', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const { fromCoin, toCoin, amount } = req.body;
    
    // Get current prices
    const prices = await getCoinPrices();
    if (!prices) {
      return res.status(500).json({ success: false, message: 'Failed to fetch prices' });
    }
    
    // Check if coins exist in our system
    if (!prices[fromCoin] || !prices[toCoin]) {
      return res.status(400).json({ success: false, message: 'Invalid coin selection' });
    }
    
    // Calculate conversion rate with arbitrage logic
    const fromPrice = prices[fromCoin];
    const toPrice = prices[toCoin];
    const rate = fromPrice / toPrice;
    
    // Apply arbitrage logic (5% spread)
    const spread = 0.05;
    const effectiveRate = rate * (1 - spread);
    
    // Calculate amount to receive
    const receiveAmount = amount * effectiveRate;
    
    // Check if user has enough balance
    if (user.portfolio[fromCoin] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Update user portfolio
    user.portfolio[fromCoin] -= amount;
    user.portfolio[toCoin] = (user.portfolio[toCoin] || 0) + receiveAmount;
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate: effectiveRate,
      fee: amount * spread,
      status: 'completed'
    });
    
    await trade.save();
    await user.save();
    
    // Broadcast balance update via WebSocket
    broadcast(user._id, {
      type: 'balance_update',
      balance: user.balance,
      portfolio: user.portfolio
    });
    
    // Broadcast to admin if it's a large trade
    if (amount * fromPrice > 10000) { // $10,000 threshold
      broadcastToAdmin({
        type: 'large_trade',
        userId: user._id,
        fromCoin,
        toCoin,
        amount,
        rate: effectiveRate,
        timestamp: new Date()
      });
    }
    
    res.json({
      success: true,
      fromCoin,
      toCoin,
      amount,
      receiveAmount,
      rate: effectiveRate,
      fee: amount * spread,
      newBalance: user.portfolio
    });
  } catch (err) {
    console.error('Trade conversion error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/trades/history', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const trades = await Trade.find({ userId: decoded.id }).sort({ createdAt: -1 }).limit(50);
    
    res.json({ success: true, trades });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Get current prices
    const prices = await getCoinPrices();
    if (!prices) {
      return res.status(500).json({ success: false, message: 'Failed to fetch prices' });
    }
    
    // Calculate portfolio value
    let totalValue = 0;
    const portfolioWithValue = {};
    
    for (const [coin, amount] of Object.entries(user.portfolio)) {
      if (prices[coin] && amount > 0) {
        const value = amount * prices[coin];
        portfolioWithValue[coin] = {
          amount,
          value,
          price: prices[coin]
        };
        totalValue += value;
      }
    }
    
    res.json({
      success: true,
      portfolio: portfolioWithValue,
      totalValue,
      balance: user.balance
    });
  } catch (err) {
    console.error('Get portfolio error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin user
    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = generateToken(user);
    
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
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/dashboard-stats', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findById(decoded.id);
    
    if (!admin || !admin.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    // Get stats
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $group: {
          _id: null,
          totalVolume: { $sum: '$amount' }
        }
      }
    ]);
    
    // Recent users
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('firstName lastName email createdAt');
    
    // Recent trades
    const recentTrades = await Trade.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email');
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        verifiedUsers,
        totalTrades,
        totalVolume: totalVolume[0]?.totalVolume || 0
      },
      recentUsers,
      recentTrades
    });
  } catch (err) {
    console.error('Admin dashboard stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findById(decoded.id);
    
    if (!admin || !admin.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    const { page = 1, limit = 20, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {
      $or: [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ]
    };
    
    const users = await User.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');
    
    const total = await User.countDocuments(query);
    
    res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('Admin get users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findById(decoded.id);
    
    if (!admin || !admin.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    const { amount, coin } = req.body;
    const userId = req.params.id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Update balance
    if (coin === 'USD') {
      user.balance += parseFloat(amount);
    } else {
      user.portfolio[coin] = (user.portfolio[coin] || 0) + parseFloat(amount);
    }
    
    await user.save();
    
    // Broadcast balance update
    broadcast(user._id, {
      type: 'balance_update',
      balance: user.balance,
      portfolio: user.portfolio
    });
    
    res.json({ success: true, message: 'Balance updated successfully' });
  } catch (err) {
    console.error('Admin update user balance error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    const ticket = new SupportTicket({
      name,
      email,
      subject,
      message
    });
    
    await ticket.save();
    
    res.json({ success: true, ticket });
  } catch (err) {
    console.error('Create support ticket error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ category: 1, createdAt: -1 });
    
    // Group by category
    const faqsByCategory = {};
    faqs.forEach(faq => {
      if (!faqsByCategory[faq.category]) {
        faqsByCategory[faq.category] = [];
      }
      faqsByCategory[faq.category].push(faq);
    });
    
    res.json({ success: true, faqs: faqsByCategory });
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Static page routes
app.get('/about.html', (req, res) => {
  res.json({ success: true, message: 'About page data would be served here' });
});

app.get('/account.html', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        isVerified: user.isVerified,
        balance: user.balance,
        portfolio: user.portfolio,
        walletAddress: user.walletAddress,
        walletProvider: user.walletProvider,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (err) {
    console.error('Account page error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/dashboard.html', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Get market prices
    const prices = await getCoinPrices();
    if (!prices) {
      return res.status(500).json({ success: false, message: 'Failed to fetch prices' });
    }
    
    // Calculate portfolio value
    let totalValue = 0;
    const portfolioWithValue = {};
    
    for (const [coin, amount] of Object.entries(user.portfolio)) {
      if (prices[coin] && amount > 0) {
        const value = amount * prices[coin];
        portfolioWithValue[coin] = {
          amount,
          value,
          price: prices[coin]
        };
        totalValue += value;
      }
    }
    
    // Get recent trades
    const recentTrades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        portfolio: portfolioWithValue,
        totalValue
      },
      prices,
      recentTrades
    });
  } catch (err) {
    console.error('Dashboard page error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/faqs.html', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ category: 1, createdAt: -1 });
    
    // Group by category
    const faqsByCategory = {};
    faqs.forEach(faq => {
      if (!faqsByCategory[faq.category]) {
        faqsByCategory[faq.category] = [];
      }
      faqsByCategory[faq.category].push(faq);
    });
    
    res.json({ success: true, faqs: faqsByCategory });
  } catch (err) {
    console.error('FAQs page error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/forgot-password.html', (req, res) => {
  res.json({ success: true, message: 'Forgot password page would be served here' });
});

app.get('/index.html', async (req, res) => {
  try {
    // Get market prices
    const prices = await getCoinPrices();
    if (!prices) {
      return res.status(500).json({ success: false, message: 'Failed to fetch prices' });
    }
    
    // Get trending coins
    const trendingResponse = await axios.get('https://api.coingecko.com/api/v3/search/trending');
    const trendingCoins = trendingResponse.data.coins.map(coin => ({
      id: coin.item.id,
      name: coin.item.name,
      symbol: coin.item.symbol,
      price: prices[coin.item.id] || 0,
      change24h: coin.item.data.price_change_percentage_24h.usd || 0
    }));
    
    res.json({
      success: true,
      prices,
      trendingCoins
    });
  } catch (err) {
    console.error('Index page error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/login.html', (req, res) => {
  res.json({ success: true, message: 'Login page would be served here' });
});

app.get('/logout.html', (req, res) => {
  res.json({ success: true, message: 'Logout page would be served here' });
});

app.get('/signup.html', (req, res) => {
  res.json({ success: true, message: 'Signup page would be served here' });
});

app.get('/support.html', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    let userTickets = [];
    
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        
        if (user) {
          userTickets = await SupportTicket.find({ email: user.email })
            .sort({ createdAt: -1 })
            .limit(5);
        }
      } catch (err) {
        console.error('Token verification failed for support page:', err);
      }
    }
    
    const faqs = await FAQ.find().sort({ category: 1, createdAt: -1 });
    
    // Group by category
    const faqsByCategory = {};
    faqs.forEach(faq => {
      if (!faqsByCategory[faq.category]) {
        faqsByCategory[faq.category] = [];
      }
      faqsByCategory[faq.category].push(faq);
    });
    
    res.json({
      success: true,
      faqs: faqsByCategory,
      userTickets
    });
  } catch (err) {
    console.error('Support page error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
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
