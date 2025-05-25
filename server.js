require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xssClean = require('xss-clean');
const morgan = require('morgan');
const winston = require('winston');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { createServer } = require('http');
const { Server } = require('socket.io');

// Initialize Express app
const app = express();
const httpServer = createServer(app);

// Initialize Socket.IO with CORS configuration
const io = new Server(httpServer, {
  cors: {
    origin: [
      'https://website-xi-ten-52.vercel.app',
      'http://localhost:3000'
    ],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(helmet());
app.use(xssClean());
app.use(cors({
  origin: [
    'https://website-xi-ten-52.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(express.json({ limit: '10kb' }));
app.use(morgan('combined'));

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  country: { type: String, required: true },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  walletAddress: { type: String },
  walletProvider: { type: String },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  isAdmin: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDetails: {
    documentType: String,
    documentNumber: String,
    documentImage: String,
    selfieImage: String
  },
  settings: {
    theme: { type: String, default: 'light' },
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    twoFactorAuth: { type: Boolean, default: false }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  convertedAmount: { type: Number, required: true },
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
  details: { type: Object },
  createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved', 'closed'], default: 'open' },
  attachments: [{ type: String }],
  responses: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const CoinSchema = new mongoose.Schema({
  coinId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  symbol: { type: String, required: true },
  currentPrice: { type: Number, required: true },
  priceChange24h: { type: Number, required: true },
  priceChangePercentage24h: { type: Number, required: true },
  marketCap: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const Coin = mongoose.model('Coin', CoinSchema);

// Simulated coin data (would normally come from CoinGecko API)
const simulatedCoins = [
  { coinId: 'bitcoin', name: 'Bitcoin', symbol: 'BTC', currentPrice: 50000, priceChange24h: 500, priceChangePercentage24h: 1.0, marketCap: 950000000000 },
  { coinId: 'ethereum', name: 'Ethereum', symbol: 'ETH', currentPrice: 3000, priceChange24h: 30, priceChangePercentage24h: 1.0, marketCap: 360000000000 },
  { coinId: 'binancecoin', name: 'Binance Coin', symbol: 'BNB', currentPrice: 400, priceChange24h: 4, priceChangePercentage24h: 1.0, marketCap: 64000000000 },
  { coinId: 'ripple', name: 'XRP', symbol: 'XRP', currentPrice: 0.5, priceChange24h: 0.005, priceChangePercentage24h: 1.0, marketCap: 25000000000 },
  { coinId: 'cardano', name: 'Cardano', symbol: 'ADA', currentPrice: 0.45, priceChange24h: 0.0045, priceChangePercentage24h: 1.0, marketCap: 15000000000 },
  { coinId: 'solana', name: 'Solana', symbol: 'SOL', currentPrice: 100, priceChange24h: 1, priceChangePercentage24h: 1.0, marketCap: 40000000000 },
  { coinId: 'polkadot', name: 'Polkadot', symbol: 'DOT', currentPrice: 7, priceChange24h: 0.07, priceChangePercentage24h: 1.0, marketCap: 7000000000 },
  { coinId: 'dogecoin', name: 'Dogecoin', symbol: 'DOGE', currentPrice: 0.15, priceChange24h: 0.0015, priceChangePercentage24h: 1.0, marketCap: 20000000000 }
];

// Update coin prices periodically with simulated fluctuations
async function updateCoinPrices() {
  try {
    for (const coin of simulatedCoins) {
      // Simulate price fluctuation between -7.65% and +15.89%
      const fluctuation = (Math.random() * 0.2365 - 0.0765);
      const newPrice = coin.currentPrice * (1 + fluctuation);
      const priceChange24h = newPrice - coin.currentPrice;
      const priceChangePercentage24h = (priceChange24h / coin.currentPrice) * 100;
      
      await Coin.findOneAndUpdate(
        { coinId: coin.coinId },
        {
          name: coin.name,
          symbol: coin.symbol,
          currentPrice: newPrice,
          priceChange24h: priceChange24h,
          priceChangePercentage24h: priceChangePercentage24h,
          marketCap: coin.marketCap * (1 + fluctuation * 0.8), // Market cap changes slightly less
          lastUpdated: new Date()
        },
        { upsert: true, new: true }
      );
    }
    logger.info('Coin prices updated successfully');
  } catch (error) {
    logger.error('Error updating coin prices:', error);
  }
}

// Initial coin data setup
async function initializeCoinData() {
  try {
    const count = await Coin.countDocuments();
    if (count === 0) {
      await Coin.insertMany(simulatedCoins);
      logger.info('Initial coin data inserted');
    }
  } catch (error) {
    logger.error('Error initializing coin data:', error);
  }
}

// Initialize coin data and start periodic updates
initializeCoinData().then(() => {
  // Update prices every 30 seconds
  setInterval(updateCoinPrices, 30000);
});

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Not authorized to access this resource' });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findOne({ _id: decoded._id, isAdmin: true });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Not authorized as admin' });
    }

    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Not authorized to access this resource' });
  }
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  logger.info('New WebSocket connection');

  socket.on('authenticate', async (token, callback) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
      const user = await User.findOne({ _id: decoded._id });

      if (!user) {
        return callback({ success: false, message: 'User not found' });
      }

      socket.userId = user._id;
      socket.join(user._id.toString());
      callback({ success: true, user: { id: user._id, email: user.email } });
    } catch (error) {
      callback({ success: false, message: 'Authentication failed' });
    }
  });

  socket.on('disconnect', () => {
    logger.info('WebSocket disconnected');
  });
});

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

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = uuidv4();

    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency: currency || 'USD',
      verificationToken,
      isVerified: true // Skipping email verification as per requirements
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET || '17581758Na.%', { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        token,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isVerified: user.isVerified
        }
      }
    });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Error creating user' });
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

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET || '17581758Na.%', { expiresIn: '7d' });

    res.json({
      success: true,
      message: 'Logged in successfully',
      data: {
        token,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isVerified: user.isVerified,
          isAdmin: user.isAdmin
        }
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Error logging in' });
  }
});

app.post('/api/v1/auth/admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET || '17581758Na.%', { expiresIn: '7d' });

    res.json({
      success: true,
      message: 'Admin logged in successfully',
      data: {
        token,
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isVerified: user.isVerified,
          isAdmin: user.isAdmin
        }
      }
    });
  } catch (error) {
    logger.error('Admin login error:', error);
    res.status(500).json({ success: false, message: 'Error logging in as admin' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Return success even if email doesn't exist to prevent email enumeration
      return res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent' });
    }

    const resetToken = uuidv4();
    const resetExpires = Date.now() + 3600000; // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetExpires;
    await user.save();

    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your account.</p>
        <p>Click <a href="${resetUrl}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent' });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Error processing password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    logger.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

app.post('/api/v1/auth/logout', auth, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Error logging out' });
  }
});

app.get('/api/v1/auth/me', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          isVerified: req.user.isVerified,
          balance: req.user.balance,
          currency: req.user.currency,
          isAdmin: req.user.isAdmin,
          kycStatus: req.user.kycStatus,
          settings: req.user.settings
        }
      }
    });
  } catch (error) {
    logger.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Error fetching user data' });
  }
});

app.get('/api/v1/auth/verify', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        isValid: true,
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          isVerified: req.user.isVerified,
          isAdmin: req.user.isAdmin
        }
      }
    });
  } catch (error) {
    logger.error('Token verification error:', error);
    res.status(500).json({ success: false, message: 'Error verifying token' });
  }
});

app.get('/api/v1/auth/check', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        isAuthenticated: true,
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          isVerified: req.user.isVerified,
          isAdmin: req.user.isAdmin
        }
      }
    });
  } catch (error) {
    logger.error('Auth check error:', error);
    res.status(500).json({ success: false, message: 'Error checking authentication' });
  }
});

// User Routes
app.get('/api/v1/users/me', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          country: req.user.country,
          currency: req.user.currency,
          balance: req.user.balance,
          isVerified: req.user.isVerified,
          kycStatus: req.user.kycStatus,
          createdAt: req.user.createdAt,
          settings: req.user.settings
        }
      }
    });
  } catch (error) {
    logger.error('Get user profile error:', error);
    res.status(500).json({ success: false, message: 'Error fetching user profile' });
  }
});

app.patch('/api/v1/users/me', auth, async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['firstName', 'lastName', 'country', 'currency', 'settings'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).json({ success: false, message: 'Invalid updates' });
    }

    updates.forEach(update => req.user[update] = req.body[update]);
    await req.user.save();

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          email: req.user.email,
          country: req.user.country,
          currency: req.user.currency,
          settings: req.user.settings
        }
      }
    });
  } catch (error) {
    logger.error('Update user error:', error);
    res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});

app.patch('/api/v1/users/update-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    const isMatch = await bcrypt.compare(currentPassword, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    req.user.password = await bcrypt.hash(newPassword, 10);
    await req.user.save();

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    logger.error('Update password error:', error);
    res.status(500).json({ success: false, message: 'Error updating password' });
  }
});

app.post('/api/v1/users/kyc', auth, async (req, res) => {
  try {
    const { documentType, documentNumber, documentImage, selfieImage } = req.body;

    if (!documentType || !documentNumber || !documentImage || !selfieImage) {
      return res.status(400).json({ success: false, message: 'All KYC fields are required' });
    }

    req.user.kycDetails = {
      documentType,
      documentNumber,
      documentImage,
      selfieImage
    };
    req.user.kycStatus = 'pending';
    await req.user.save();

    res.json({ success: true, message: 'KYC submitted successfully' });
  } catch (error) {
    logger.error('KYC submission error:', error);
    res.status(500).json({ success: false, message: 'Error submitting KYC' });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', auth, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'completed' })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      data: {
        trades
      }
    });
  } catch (error) {
    logger.error('Get active trades error:', error);
    res.status(500).json({ success: false, message: 'Error fetching active trades' });
  }
});

app.get('/api/v1/trades/history', auth, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({
      success: true,
      data: {
        trades
      }
    });
  } catch (error) {
    logger.error('Get trade history error:', error);
    res.status(500).json({ success: false, message: 'Error fetching trade history' });
  }
});

app.post('/api/v1/trades/buy', auth, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;

    // Get current coin prices
    const fromCoinData = await Coin.findOne({ coinId: fromCoin });
    const toCoinData = await Coin.findOne({ coinId: toCoin });

    if (!fromCoinData || !toCoinData) {
      return res.status(400).json({ success: false, message: 'Invalid coin selection' });
    }

    // Calculate conversion rate (simplified)
    const rate = toCoinData.currentPrice / fromCoinData.currentPrice;
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.01; // 1% fee

    // Check if user has sufficient balance
    if (req.user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      convertedAmount: convertedAmount - fee,
      fee,
      status: 'completed'
    });

    await trade.save();

    // Update user balance
    req.user.balance -= amount;
    await req.user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'trade',
      amount: amount,
      currency: fromCoin,
      status: 'completed',
      details: {
        toCoin: toCoin,
        convertedAmount: convertedAmount - fee,
        rate: rate,
        fee: fee
      }
    });

    await transaction.save();

    // Notify user via WebSocket
    io.to(req.user._id.toString()).emit('trade_update', {
      type: 'buy',
      fromCoin,
      toCoin,
      amount,
      convertedAmount: convertedAmount - fee,
      fee,
      newBalance: req.user.balance
    });

    res.json({
      success: true,
      message: 'Trade executed successfully',
      data: {
        trade: {
          id: trade._id,
          fromCoin,
          toCoin,
          amount,
          convertedAmount: convertedAmount - fee,
          fee,
          rate,
          status: 'completed',
          createdAt: trade.createdAt
        },
        newBalance: req.user.balance
      }
    });
  } catch (error) {
    logger.error('Buy trade error:', error);
    res.status(500).json({ success: false, message: 'Error executing trade' });
  }
});

app.post('/api/v1/trades/sell', auth, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;

    // Get current coin prices
    const fromCoinData = await Coin.findOne({ coinId: fromCoin });
    const toCoinData = await Coin.findOne({ coinId: toCoin });

    if (!fromCoinData || !toCoinData) {
      return res.status(400).json({ success: false, message: 'Invalid coin selection' });
    }

    // Calculate conversion rate (simplified)
    const rate = toCoinData.currentPrice / fromCoinData.currentPrice;
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.01; // 1% fee

    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      convertedAmount: convertedAmount - fee,
      fee,
      status: 'completed'
    });

    await trade.save();

    // Update user balance (in a real app, you'd track individual coin balances)
    req.user.balance += convertedAmount - fee;
    await req.user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'trade',
      amount: amount,
      currency: fromCoin,
      status: 'completed',
      details: {
        toCoin: toCoin,
        convertedAmount: convertedAmount - fee,
        rate: rate,
        fee: fee
      }
    });

    await transaction.save();

    // Notify user via WebSocket
    io.to(req.user._id.toString()).emit('trade_update', {
      type: 'sell',
      fromCoin,
      toCoin,
      amount,
      convertedAmount: convertedAmount - fee,
      fee,
      newBalance: req.user.balance
    });

    res.json({
      success: true,
      message: 'Trade executed successfully',
      data: {
        trade: {
          id: trade._id,
          fromCoin,
          toCoin,
          amount,
          convertedAmount: convertedAmount - fee,
          fee,
          rate,
          status: 'completed',
          createdAt: trade.createdAt
        },
        newBalance: req.user.balance
      }
    });
  } catch (error) {
    logger.error('Sell trade error:', error);
    res.status(500).json({ success: false, message: 'Error executing trade' });
  }
});

// Exchange Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ marketCap: -1 });
    res.json({
      success: true,
      data: {
        coins
      }
    });
  } catch (error) {
    logger.error('Get coins error:', error);
    res.status(500).json({ success: false, message: 'Error fetching coins' });
  }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
  try {
    const { fromCoin, toCoin } = req.query;

    const fromCoinData = await Coin.findOne({ coinId: fromCoin });
    const toCoinData = await Coin.findOne({ coinId: toCoin });

    if (!fromCoinData || !toCoinData) {
      return res.status(400).json({ success: false, message: 'Invalid coin selection' });
    }

    const rate = toCoinData.currentPrice / fromCoinData.currentPrice;
    const feePercentage = 0.01; // 1% fee
    const fee = rate * feePercentage;
    const finalRate = rate - fee;

    res.json({
      success: true,
      data: {
        fromCoin,
        toCoin,
        rate: finalRate,
        feePercentage,
        fee,
        timestamp: new Date()
      }
    });
  } catch (error) {
    logger.error('Get exchange rate error:', error);
    res.status(500).json({ success: false, message: 'Error fetching exchange rate' });
  }
});

app.post('/api/v1/exchange/convert', auth, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;

    // Get current coin prices
    const fromCoinData = await Coin.findOne({ coinId: fromCoin });
    const toCoinData = await Coin.findOne({ coinId: toCoin });

    if (!fromCoinData || !toCoinData) {
      return res.status(400).json({ success: false, message: 'Invalid coin selection' });
    }

    // Calculate conversion rate (simplified)
    const rate = toCoinData.currentPrice / fromCoinData.currentPrice;
    const convertedAmount = amount * rate;
    const fee = convertedAmount * 0.01; // 1% fee
    const finalAmount = convertedAmount - fee;

    // Check if user has sufficient balance
    if (req.user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      convertedAmount: finalAmount,
      fee,
      status: 'completed'
    });

    await trade.save();

    // Update user balance
    req.user.balance -= amount;
    req.user.balance += finalAmount;
    await req.user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'conversion',
      amount: amount,
      currency: fromCoin,
      status: 'completed',
      details: {
        toCoin: toCoin,
        convertedAmount: finalAmount,
        rate: rate,
        fee: fee
      }
    });

    await transaction.save();

    // Notify user via WebSocket
    io.to(req.user._id.toString()).emit('conversion_update', {
      fromCoin,
      toCoin,
      amount,
      convertedAmount: finalAmount,
      fee,
      newBalance: req.user.balance
    });

    res.json({
      success: true,
      message: 'Conversion completed successfully',
      data: {
        conversion: {
          id: trade._id,
          fromCoin,
          toCoin,
          amount,
          convertedAmount: finalAmount,
          fee,
          rate,
          status: 'completed',
          createdAt: trade.createdAt
        },
        newBalance: req.user.balance
      }
    });
  } catch (error) {
    logger.error('Convert coins error:', error);
    res.status(500).json({ success: false, message: 'Error converting coins' });
  }
});

app.get('/api/v1/exchange/history', auth, async (req, res) => {
  try {
    const history = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);

    res.json({
      success: true,
      data: {
        history
      }
    });
  } catch (error) {
    logger.error('Get exchange history error:', error);
    res.status(500).json({ success: false, message: 'Error fetching exchange history' });
  }
});

// Market Data Routes
app.get('/api/v1/market/data', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ marketCap: -1 }).limit(10);
    const trending = await Coin.find().sort({ priceChangePercentage24h: -1 }).limit(5);

    res.json({
      success: true,
      data: {
        market: {
          totalMarketCap: coins.reduce((sum, coin) => sum + coin.marketCap, 0),
          totalVolume: coins.reduce((sum, coin) => sum + (coin.marketCap * 0.1), 0), // Simulated volume
          btcDominance: coins.find(c => c.coinId === 'bitcoin')?.marketCap / 
                        coins.reduce((sum, coin) => sum + coin.marketCap, 0) * 100 || 40
        },
        coins,
        trending
      }
    });
  } catch (error) {
    logger.error('Get market data error:', error);
    res.status(500).json({ success: false, message: 'Error fetching market data' });
  }
});

app.get('/api/v1/market/detailed', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ marketCap: -1 });

    res.json({
      success: true,
      data: {
        coins
      }
    });
  } catch (error) {
    logger.error('Get detailed market data error:', error);
    res.status(500).json({ success: false, message: 'Error fetching detailed market data' });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', auth, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    // Simplified portfolio - in a real app you'd track individual coin balances
    const portfolio = trades.reduce((acc, trade) => {
      if (!acc[trade.toCoin]) {
        acc[trade.toCoin] = 0;
      }
      acc[trade.toCoin] += trade.convertedAmount;
      return acc;
    }, {});

    res.json({
      success: true,
      data: {
        balance: req.user.balance,
        portfolio,
        recentTransactions: transactions
      }
    });
  } catch (error) {
    logger.error('Get portfolio error:', error);
    res.status(500).json({ success: false, message: 'Error fetching portfolio' });
  }
});

// Transaction Routes
app.get('/api/v1/transactions/recent', auth, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      data: {
        transactions
      }
    });
  } catch (error) {
    logger.error('Get recent transactions error:', error);
    res.status(500).json({ success: false, message: 'Error fetching transactions' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I create an account?',
            answer: 'Click on the Sign Up button and fill in the required details to create your account.'
          },
          {
            question: 'How do I reset my password?',
            answer: 'Click on the Forgot Password link on the login page and follow the instructions.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'How do I buy cryptocurrency?',
            answer: 'Navigate to the Trade section, select the cryptocurrency you want to buy, enter the amount, and confirm the transaction.'
          },
          {
            question: 'What are the trading fees?',
            answer: 'Our trading fee is 1% of the transaction amount.'
          }
        ]
      },
      {
        category: 'Deposits & Withdrawals',
        questions: [
          {
            question: 'How do I deposit funds?',
            answer: 'Go to the Wallet section and select Deposit. Follow the instructions to transfer funds to your account.'
          },
          {
            question: 'How long do withdrawals take?',
            answer: 'Withdrawals are typically processed within 24 hours.'
          }
        ]
      }
    ];

    res.json({
      success: true,
      data: {
        faqs
      }
    });
  } catch (error) {
    logger.error('Get FAQs error:', error);
    res.status(500).json({ success: false, message: 'Error fetching FAQs' });
  }
});

app.post('/api/v1/support/tickets', auth, async (req, res) => {
  try {
    const { subject, message, attachments } = req.body;

    if (!subject || !message) {
      return res.status(400).json({ success: false, message: 'Subject and message are required' });
    }

    const ticket = new SupportTicket({
      userId: req.user._id,
      subject,
      message,
      attachments: attachments || []
    });

    await ticket.save();

    res.json({
      success: true,
      message: 'Ticket created successfully',
      data: {
        ticket: {
          id: ticket._id,
          subject,
          status: ticket.status,
          createdAt: ticket.createdAt
        }
      }
    });
  } catch (error) {
    logger.error('Create ticket error:', error);
    res.status(500).json({ success: false, message: 'Error creating support ticket' });
  }
});

app.get('/api/v1/support/tickets', auth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: {
        tickets
      }
    });
  } catch (error) {
    logger.error('Get tickets error:', error);
    res.status(500).json({ success: false, message: 'Error fetching support tickets' });
  }
});

app.get('/api/v1/support/tickets/:id', auth, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.json({
      success: true,
      data: {
        ticket
      }
    });
  } catch (error) {
    logger.error('Get ticket error:', error);
    res.status(500).json({ success: false, message: 'Error fetching ticket' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', auth, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.responses.push({
      userId: req.user._id,
      message,
      isAdmin: false
    });
    ticket.status = 'in-progress';
    ticket.updatedAt = new Date();
    await ticket.save();

    res.json({
      success: true,
      message: 'Reply added successfully',
      data: {
        ticket: {
          id: ticket._id,
          status: ticket.status,
          updatedAt: ticket.updatedAt
        }
      }
    });
  } catch (error) {
    logger.error('Reply to ticket error:', error);
    res.status(500).json({ success: false, message: 'Error replying to ticket' });
  }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    const recentTrades = await Trade.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email');

    res.json({
      success: true,
      data: {
        stats: {
          totalUsers,
          verifiedUsers,
          totalTrades,
          totalVolume: totalVolume[0]?.total || 0
        },
        recentTrades
      }
    });
  } catch (error) {
    logger.error('Get admin dashboard stats error:', error);
    res.status(500).json({ success: false, message: 'Error fetching dashboard stats' });
  }
});

app.get('/api/v1/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find()
      .sort({ createdAt: -1 })
      .select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');

    res.json({
      success: true,
      data: {
        users
      }
    });
  } catch (error) {
    logger.error('Get users error:', error);
    res.status(500).json({ success: false, message: 'Error fetching users' });
  }
});

app.get('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const trades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    const transactions = await Transaction.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      data: {
        user,
        trades,
        transactions
      }
    });
  } catch (error) {
    logger.error('Get user details error:', error);
    res.status(500).json({ success: false, message: 'Error fetching user details' });
  }
});

app.patch('/api/v1/admin/users/:id/status', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive: status === 'active' },
      { new: true }
    ).select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      message: 'User status updated successfully',
      data: {
        user
      }
    });
  } catch (error) {
    logger.error('Update user status error:', error);
    res.status(500).json({ success: false, message: 'Error updating user status' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', adminAuth, async (req, res) => {
  try {
    const { amount, operation } = req.body;

    if (!['add', 'subtract'].includes(operation)) {
      return res.status(400).json({ success: false, message: 'Invalid operation' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (operation === 'add') {
      user.balance += amount;
    } else {
      if (user.balance < amount) {
        return res.status(400).json({ success: false, message: 'Insufficient balance' });
      }
      user.balance -= amount;
    }

    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: operation === 'add' ? 'deposit' : 'withdrawal',
      amount: amount,
      currency: 'USD',
      status: 'completed',
      details: {
        adminAction: true,
        adminId: req.user._id
      }
    });

    await transaction.save();

    // Notify user via WebSocket
    io.to(user._id.toString()).emit('balance_update', {
      type: operation === 'add' ? 'deposit' : 'withdrawal',
      amount,
      newBalance: user.balance,
      adminAction: true
    });

    res.json({
      success: true,
      message: `Balance ${operation === 'add' ? 'added' : 'subtracted'} successfully`,
      data: {
        newBalance: user.balance
      }
    });
  } catch (error) {
    logger.error('Update user balance error:', error);
    res.status(500).json({ success: false, message: 'Error updating user balance' });
  }
});

app.get('/api/v1/admin/trades', adminAuth, async (req, res) => {
  try {
    const trades = await Trade.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');

    res.json({
      success: true,
      data: {
        trades
      }
    });
  } catch (error) {
    logger.error('Get trades error:', error);
    res.status(500).json({ success: false, message: 'Error fetching trades' });
  }
});

app.get('/api/v1/admin/transactions', adminAuth, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');

    res.json({
      success: true,
      data: {
        transactions
      }
    });
  } catch (error) {
    logger.error('Get transactions error:', error);
    res.status(500).json({ success: false, message: 'Error fetching transactions' });
  }
});

app.get('/api/v1/admin/tickets', adminAuth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');

    res.json({
      success: true,
      data: {
        tickets
      }
    });
  } catch (error) {
    logger.error('Get tickets error:', error);
    res.status(500).json({ success: false, message: 'Error fetching tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', adminAuth, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.json({
      success: true,
      data: {
        ticket
      }
    });
  } catch (error) {
    logger.error('Get ticket error:', error);
    res.status(500).json({ success: false, message: 'Error fetching ticket' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', adminAuth, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await SupportTicket.findById(req.params.id);

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.responses.push({
      userId: req.user._id,
      message,
      isAdmin: true
    });
    ticket.status = 'in-progress';
    ticket.updatedAt = new Date();
    await ticket.save();

    // Notify user via WebSocket
    io.to(ticket.userId.toString()).emit('ticket_update', {
      ticketId: ticket._id,
      status: ticket.status,
      hasNewReply: true
    });

    res.json({
      success: true,
      message: 'Reply added successfully',
      data: {
        ticket: {
          id: ticket._id,
          status: ticket.status,
          updatedAt: ticket.updatedAt
        }
      }
    });
  } catch (error) {
    logger.error('Admin reply to ticket error:', error);
    res.status(500).json({ success: false, message: 'Error replying to ticket' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    if (!['open', 'in-progress', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status, updatedAt: new Date() },
      { new: true }
    );

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    // Notify user via WebSocket
    io.to(ticket.userId.toString()).emit('ticket_update', {
      ticketId: ticket._id,
      status: ticket.status
    });

    res.json({
      success: true,
      message: 'Ticket status updated successfully',
      data: {
        ticket: {
          id: ticket._id,
          status: ticket.status,
          updatedAt: ticket.updatedAt
        }
      }
    });
  } catch (error) {
    logger.error('Update ticket status error:', error);
    res.status(500).json({ success: false, message: 'Error updating ticket status' });
  }
});

app.get('/api/v1/admin/kyc', adminAuth, async (req, res) => {
  try {
    const pendingKyc = await User.find({ kycStatus: 'pending' })
      .select('firstName lastName email kycStatus kycDetails createdAt');

    res.json({
      success: true,
      data: {
        pendingKyc
      }
    });
  } catch (error) {
    logger.error('Get pending KYC error:', error);
    res.status(500).json({ success: false, message: 'Error fetching pending KYC' });
  }
});

app.patch('/api/v1/admin/kyc/:id/approve', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'verified' },
      { new: true }
    ).select('firstName lastName email kycStatus');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Notify user via WebSocket
    io.to(user._id.toString()).emit('kyc_update', {
      status: 'verified'
    });

    res.json({
      success: true,
      message: 'KYC approved successfully',
      data: {
        user
      }
    });
  } catch (error) {
    logger.error('Approve KYC error:', error);
    res.status(500).json({ success: false, message: 'Error approving KYC' });
  }
});

app.patch('/api/v1/admin/kyc/:id/reject', adminAuth, async (req, res) => {
  try {
    const { reason } = req.body;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { 
        kycStatus: 'rejected',
        'kycDetails.rejectionReason': reason
      },
      { new: true }
    ).select('firstName lastName email kycStatus');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Notify user via WebSocket
    io.to(user._id.toString()).emit('kyc_update', {
      status: 'rejected',
      reason
    });

    res.json({
      success: true,
      message: 'KYC rejected successfully',
      data: {
        user
      }
    });
  } catch (error) {
    logger.error('Reject KYC error:', error);
    res.status(500).json({ success: false, message: 'Error rejecting KYC' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  console.log(`Server running on port ${PORT}`);
});
