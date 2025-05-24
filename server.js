require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:<OWlondlAbn3bJuj4>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app/';

// Email configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(limiter);

// MongoDB connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Database models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  walletAddress: { type: String },
  walletProvider: { type: String },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  verified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  settings: {
    theme: { type: String, default: 'light' },
    notifications: { type: Boolean, default: true },
    twoFactor: { type: Boolean, default: false }
  },
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
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'fee'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  details: { type: Object },
  createdAt: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  attachments: { type: [String] },
  responses: [{
    message: String,
    from: String, // 'user' or 'support'
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const KYCSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  documentType: { type: String, enum: ['passport', 'id_card', 'driver_license'], required: true },
  documentNumber: { type: String, required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNotes: { type: String },
  submittedAt: { type: Date, default: Date.now },
  reviewedAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);
const KYC = mongoose.model('KYC', KYCSchema);

// WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

// Track connected clients
const clients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    
    // Store the connection with user ID
    clients.set(userId, ws);
    
    ws.on('close', () => {
      clients.delete(userId);
    });
    
    // Send initial balance update
    User.findById(userId).then(user => {
      if (user) {
        ws.send(JSON.stringify({
          type: 'BALANCE_UPDATE',
          balance: user.balance
        }));
      }
    });
    
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Helper functions
const sendWebSocketMessage = (userId, message) => {
  const ws = clients.get(userId.toString());
  if (ws) {
    ws.send(JSON.stringify(message));
  }
};

const generateToken = (userId, role = 'user') => {
  return jwt.sign({ userId, role }, JWT_SECRET, { expiresIn: '24h' });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Simulated coin data (in a real app, this would come from an API)
const coins = {
  BTC: { name: 'Bitcoin', price: 50000, change24h: 2.5 },
  ETH: { name: 'Ethereum', price: 3000, change24h: -1.2 },
  LTC: { name: 'Litecoin', price: 150, change24h: 0.8 },
  XRP: { name: 'Ripple', price: 0.5, change24h: 3.1 },
  USDT: { name: 'Tether', price: 1, change24h: 0 }
};

// Simulate price fluctuations
setInterval(() => {
  for (const coin in coins) {
    if (coin !== 'USDT') {
      const fluctuation = (Math.random() * 0.2 - 0.1); // -5% to +5%
      coins[coin].price *= (1 + fluctuation);
      coins[coin].change24h = fluctuation * 100;
    }
  }
}, 30000); // Update every 30 seconds

// API Routes

// Auth routes
app.post('/api/v1/auth/signup', [
  body('firstName').notEmpty().trim().escape(),
  body('lastName').notEmpty().trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  body('confirmPassword').custom((value, { req }) => value === req.body.password),
  body('country').notEmpty().trim().escape(),
  body('currency').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { firstName, lastName, email, password, country, currency } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      verified: true // Skip email verification as requested
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    // Send welcome email
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: email,
        subject: 'Welcome to Crypto Trading Market',
        html: `<p>Hi ${firstName},</p>
               <p>Your account has been successfully created!</p>
               <p>Start trading now and take advantage of our arbitrage opportunities.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send welcome email:', emailErr);
    }

    res.status(201).json({ token, userId: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id, user.role);

    res.json({ token, userId: user._id, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, walletProvider, signature } = req.body;

    // Find user by wallet address
    let user = await User.findOne({ walletAddress });

    if (!user) {
      // Create new user if not found
      user = new User({
        walletAddress,
        walletProvider,
        verified: true,
        balance: 0
      });
      await user.save();
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id, user.role);

    res.json({ token, userId: user._id, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', async (req, res) => {
  // In a real app, you might want to invalidate the token
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v1/auth/verify', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    res.json({ user, role: decoded.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user doesn't exist for security
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour

    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    // Send email
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    await emailTransporter.sendMail({
      from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
      to: email,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p>
             <p><a href="${resetUrl}">${resetUrl}</a></p>
             <p>This link will expire in 1 hour.</p>`
    });

    res.json({ message: 'Reset link sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/auth/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  body('confirmPassword').custom((value, { req }) => value === req.body.password)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { token, password } = req.body;

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Hash new password
    const hashedPassword = await hashPassword(password);

    // Update password and clear reset token
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// User routes
app.get('/api/v1/users/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/users/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { firstName, lastName, country, currency, settings } = req.body;

    const user = await User.findByIdAndUpdate(
      decoded.userId,
      { firstName, lastName, country, currency, settings },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/users/change-password', [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  body('confirmPassword').custom((value, { req }) => value === req.body.newPassword)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check current password
    const isMatch = await comparePassword(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update password
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Trade routes
app.get('/api/v1/trades/active', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const trades = await Trade.find({ 
      userId: decoded.userId,
      status: { $in: ['pending', 'completed'] }
    }).sort({ createdAt: -1 });

    res.json({ trades });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/trades/history', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const trades = await Trade.find({ 
      userId: decoded.userId
    }).sort({ createdAt: -1 });

    res.json({ trades });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/trades/buy', [
  body('fromCoin').notEmpty().isIn(Object.keys(coins)),
  body('toCoin').notEmpty().isIn(Object.keys(coins)),
  body('amount').notEmpty().isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { fromCoin, toCoin, amount } = req.body;

    // Get user
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user has enough balance
    if (fromCoin === 'USDT') {
      if (user.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }
    } else {
      // For non-USDT trades, we'd need to convert to USDT equivalent
      // This is simplified for the example
      return res.status(400).json({ message: 'Only USDT trades are supported in this example' });
    }

    // Calculate rate and fee
    const rate = coins[toCoin].price;
    const fee = amount * 0.001; // 0.1% fee
    const totalCost = amount + fee;

    // Create trade
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed' // In real app, this might be pending until confirmed
    });

    await trade.save();

    // Update user balance
    user.balance -= totalCost;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: -totalCost,
      currency: fromCoin,
      status: 'completed',
      details: {
        tradeId: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        fee
      }
    });

    await transaction.save();

    // Send WebSocket update
    sendWebSocketMessage(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    sendWebSocketMessage(user._id, {
      type: 'TRADE_UPDATE',
      trade: trade.toObject()
    });

    res.json({ trade });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/trades/sell', [
  body('fromCoin').notEmpty().isIn(Object.keys(coins)),
  body('toCoin').notEmpty().isIn(Object.keys(coins)),
  body('amount').notEmpty().isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { fromCoin, toCoin, amount } = req.body;

    // Get user
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // In a real app, you'd check if user has enough of the fromCoin
    // This is simplified for the example

    // Calculate rate and fee
    const rate = coins[toCoin].price;
    const fee = amount * 0.001; // 0.1% fee
    const totalReceived = amount * rate - fee;

    // Create trade
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed' // In real app, this might be pending until confirmed
    });

    await trade.save();

    // Update user balance (in USDT for this example)
    user.balance += totalReceived;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: totalReceived,
      currency: toCoin,
      status: 'completed',
      details: {
        tradeId: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        fee
      }
    });

    await transaction.save();

    // Send WebSocket update
    sendWebSocketMessage(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    sendWebSocketMessage(user._id, {
      type: 'TRADE_UPDATE',
      trade: trade.toObject()
    });

    res.json({ trade });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Arbitrage routes
app.get('/api/v1/arbitrage/opportunities', async (req, res) => {
  try {
    // In a real app, this would calculate actual arbitrage opportunities
    // For this example, we'll simulate some opportunities
    
    const opportunities = [];
    
    for (const fromCoin in coins) {
      for (const toCoin in coins) {
        if (fromCoin !== toCoin) {
          const buyPrice = coins[fromCoin].price;
          const sellPrice = coins[toCoin].price;
          
          // Simulate some arbitrage opportunities
          if (Math.random() > 0.7) {
            const profit = (Math.random() * 5).toFixed(2); // 0-5% profit
            opportunities.push({
              fromCoin,
              toCoin,
              buyPrice,
              sellPrice,
              profit: `${profit}%`,
              expiration: Date.now() + 300000 // 5 minutes
            });
          }
        }
      }
    }
    
    res.json({ opportunities });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/arbitrage/execute', [
  body('fromCoin').notEmpty().isIn(Object.keys(coins)),
  body('toCoin').notEmpty().isIn(Object.keys(coins)),
  body('amount').notEmpty().isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { fromCoin, toCoin, amount } = req.body;

    // Get user
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user has enough balance
    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Calculate profit (simulated)
    const profitPercentage = (Math.random() * 5).toFixed(2); // 0-5% profit
    const profit = amount * (profitPercentage / 100);
    const totalReceived = amount + profit;
    const fee = amount * 0.001; // 0.1% fee

    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate: coins[toCoin].price,
      fee,
      status: 'completed',
      isArbitrage: true,
      arbitrageProfit: profit
    });

    await trade.save();

    // Update user balance
    user.balance = user.balance - amount + totalReceived - fee;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount: totalReceived - fee - amount, // net profit
      currency: toCoin,
      status: 'completed',
      details: {
        tradeId: trade._id,
        fromCoin,
        toCoin,
        amount,
        profit,
        fee,
        isArbitrage: true
      }
    });

    await transaction.save();

    // Send WebSocket update
    sendWebSocketMessage(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    sendWebSocketMessage(user._id, {
      type: 'TRADE_UPDATE',
      trade: trade.toObject()
    });

    res.json({ 
      trade,
      profit,
      newBalance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Transaction routes
app.get('/api/v1/transactions/recent', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const transactions = await Transaction.find({ 
      userId: decoded.userId 
    }).sort({ createdAt: -1 }).limit(10);

    res.json({ transactions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/transactions/history', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { page = 1, limit = 20 } = req.query;

    const transactions = await Transaction.find({ 
      userId: decoded.userId 
    })
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(parseInt(limit));

    const total = await Transaction.countDocuments({ userId: decoded.userId });

    res.json({ 
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Support routes
app.post('/api/v1/support/tickets', [
  body('subject').notEmpty().trim().escape(),
  body('message').notEmpty().trim().escape(),
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  const { subject, message, email, attachments = [] } = req.body;

  try {
    let userId = null;
    
    if (token) {
      const decoded = verifyToken(token);
      if (decoded) {
        userId = decoded.userId;
      }
    }

    const ticket = new Ticket({
      userId,
      email,
      subject,
      message,
      attachments
    });

    await ticket.save();

    // Send confirmation email
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market Support" <support@cryptotradingmarket.com>',
        to: email,
        subject: `Support Ticket #${ticket._id}`,
        html: `<p>Thank you for contacting support. Your ticket has been received.</p>
               <p><strong>Subject:</strong> ${subject}</p>
               <p><strong>Message:</strong> ${message}</p>
               <p>We'll get back to you as soon as possible.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send ticket confirmation email:', emailErr);
    }

    res.status(201).json({ ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/support/tickets', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const tickets = await Ticket.find({ 
      userId: decoded.userId 
    }).sort({ createdAt: -1 });

    res.json({ tickets });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, these would come from a database
    const faqs = [
      {
        category: 'Account',
        question: 'How do I create an account?',
        answer: 'Click the Sign Up button and fill in your details. You can use either email or connect your crypto wallet.'
      },
      {
        category: 'Account',
        question: 'How do I reset my password?',
        answer: 'Go to the Forgot Password page and enter your email. You\'ll receive a link to reset your password.'
      },
      {
        category: 'Trading',
        question: 'How do I buy cryptocurrency?',
        answer: 'Navigate to the Trade section, select the coins you want to trade, enter the amount, and confirm the transaction.'
      },
      {
        category: 'Trading',
        question: 'What are the trading fees?',
        answer: 'Our standard trading fee is 0.1% per trade. Fees may vary for certain promotions or high-volume traders.'
      },
      {
        category: 'Deposits',
        question: 'How do I deposit funds?',
        answer: 'Go to the Wallet section and select Deposit. You\'ll receive a wallet address to send funds to.'
      },
      {
        category: 'Deposits',
        question: 'How long do deposits take?',
        answer: 'Deposit times vary by cryptocurrency. Most deposits are credited within 10-30 minutes after confirmation on the blockchain.'
      }
    ];

    res.json({ faqs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// KYC routes
app.post('/api/v1/kyc/submit', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { documentType, documentNumber, documentFront, documentBack, selfie } = req.body;

    // Check if user already has a pending or approved KYC
    const existingKYC = await KYC.findOne({ 
      userId: decoded.userId,
      status: { $in: ['pending', 'approved'] }
    });

    if (existingKYC) {
      return res.status(400).json({ message: 'You already have a KYC submission in progress' });
    }

    // Create KYC record
    const kyc = new KYC({
      userId: decoded.userId,
      documentType,
      documentNumber,
      documentFront,
      documentBack,
      selfie,
      status: 'pending'
    });

    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(decoded.userId, { kycStatus: 'pending' });

    res.status(201).json({ kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/kyc/status', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.userId).select('kycStatus');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    let kycDetails = null;
    if (user.kycStatus !== 'none') {
      kycDetails = await KYC.findOne({ userId: decoded.userId }).sort({ submittedAt: -1 });
    }

    res.json({ 
      status: user.kycStatus,
      details: kycDetails
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin routes
app.post('/api/v1/admin/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    // Find admin user
    const user = await User.findOne({ email, role: 'admin' });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id, user.role);

    res.json({ token, userId: user._id, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/dashboard-stats', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Get stats
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5);
    const recentTrades = await Trade.find().sort({ createdAt: -1 }).limit(5).populate('userId', 'email');

    res.json({
      totalUsers,
      activeUsers,
      totalTrades,
      totalVolume: totalVolume.length ? totalVolume[0].total : 0,
      recentUsers,
      recentTrades
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { page = 1, limit = 20, search = '' } = req.query;

    const query = {
      role: 'user',
      $or: [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ]
    };

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
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
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', [
  body('amount').isFloat(),
  body('currency').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { id } = req.params;
    const { amount, currency, note } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update balance (simplified - in real app you'd handle different currencies)
    user.balance += amount;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: amount > 0 ? 'deposit' : 'withdrawal',
      amount: Math.abs(amount),
      currency,
      status: 'completed',
      details: {
        adminAction: true,
        adminId: decoded.userId,
        note
      }
    });

    await transaction.save();

    // Send WebSocket update if user is connected
    sendWebSocketMessage(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({ 
      user: await User.findById(id).select('-password'),
      newBalance: user.balance
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/kyc/pending', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const kycSubmissions = await KYC.find({ status: 'pending' })
      .populate('userId', 'email firstName lastName')
      .sort({ submittedAt: 1 });

    res.json({ kycSubmissions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/admin/kyc/:id/approve', [
  body('notes').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { id } = req.params;
    const { notes } = req.body;

    const kyc = await KYC.findById(id);
    if (!kyc) {
      return res.status(404).json({ message: 'KYC submission not found' });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({ message: 'KYC submission is not pending' });
    }

    // Update KYC status
    kyc.status = 'approved';
    kyc.reviewedBy = decoded.userId;
    kyc.reviewNotes = notes;
    kyc.reviewedAt = new Date();
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.userId, { kycStatus: 'verified' });

    // Send notification email
    const user = await User.findById(kyc.userId);
    if (user && user.email) {
      try {
        await emailTransporter.sendMail({
          from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
          to: user.email,
          subject: 'KYC Verification Approved',
          html: `<p>Dear ${user.firstName},</p>
                 <p>Your KYC verification has been approved. You now have full access to all platform features.</p>
                 <p>Thank you for completing the verification process.</p>`
        });
      } catch (emailErr) {
        console.error('Failed to send KYC approval email:', emailErr);
      }
    }

    res.json({ kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/admin/kyc/:id/reject', [
  body('reason').notEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { id } = req.params;
    const { reason } = req.body;

    const kyc = await KYC.findById(id);
    if (!kyc) {
      return res.status(404).json({ message: 'KYC submission not found' });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({ message: 'KYC submission is not pending' });
    }

    // Update KYC status
    kyc.status = 'rejected';
    kyc.reviewedBy = decoded.userId;
    kyc.reviewNotes = reason;
    kyc.reviewedAt = new Date();
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.userId, { kycStatus: 'rejected' });

    // Send notification email
    const user = await User.findById(kyc.userId);
    if (user && user.email) {
      try {
        await emailTransporter.sendMail({
          from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
          to: user.email,
          subject: 'KYC Verification Rejected',
          html: `<p>Dear ${user.firstName},</p>
                 <p>Your KYC verification has been rejected for the following reason:</p>
                 <p><strong>${reason}</strong></p>
                 <p>Please correct the issues and submit your KYC information again.</p>`
        });
      } catch (emailErr) {
        console.error('Failed to send KYC rejection email:', emailErr);
      }
    }

    res.json({ kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Coin data routes
app.get('/api/v1/coins', async (req, res) => {
  try {
    res.json({ coins });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/coins/:symbol', async (req, res) => {
  try {
    const { symbol } = req.params;
    const coin = coins[symbol.toUpperCase()];
    
    if (!coin) {
      return res.status(404).json({ message: 'Coin not found' });
    }

    res.json({ coin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve static files (for frontend)
app.get('*', (req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});
