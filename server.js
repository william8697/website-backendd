require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: function() { return !this.walletAddress } },
  walletAddress: { type: String, unique: true, sparse: true },
  country: { type: String, required: true },
  currency: { type: String, default: 'USD' },
  balance: {
    USD: { type: Number, default: 0 },
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 }
  },
  kycStatus: { type: String, enum: ['not_verified', 'pending', 'verified', 'rejected'], default: 'not_verified' },
  kycDocuments: {
    idFront: String,
    idBack: String,
    selfie: String
  },
  settings: {
    theme: { type: String, default: 'light' },
    language: { type: String, default: 'en' },
    notifications: { type: Boolean, default: true },
    twoFactor: { type: Boolean, default: false }
  },
  apiKey: { type: String, default: () => uuidv4() },
  isAdmin: { type: Boolean, default: false },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  profit: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  coin: { type: String, required: true },
  amount: { type: Number, required: true },
  address: String,
  txHash: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  attachments: [String],
  status: { type: String, enum: ['open', 'in_progress', 'resolved'], default: 'open' },
  responses: [{
    message: String,
    fromAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security'], required: true },
  createdAt: { type: Date, default: Date.now }
}));

const ActivityLog = mongoose.model('ActivityLog', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  ipAddress: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
}));

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

// Helper functions
const generateAuthToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'User not found' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || !user.isAdmin) return res.status(403).json({ message: 'Admin access required' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

const broadcast = (data) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'subscribe' && data.userId) {
        ws.userId = data.userId;
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
});

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      balance: { USD: 1000 } // Starting balance
    });

    await user.save();
    
    const token = generateAuthToken(user);
    
    // Log activity
    await ActivityLog.create({
      userId: user._id,
      action: 'signup',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({ token, user: { 
      id: user._id, 
      email: user.email, 
      firstName: user.firstName, 
      lastName: user.lastName,
      balance: user.balance
    }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ message: 'Wallet already registered' });
    }

    // In a real app, you would verify the signature here
    const user = new User({
      firstName,
      lastName,
      walletAddress,
      country,
      currency,
      balance: { USD: 1000 } // Starting balance
    });

    await user.save();
    
    const token = generateAuthToken(user);
    
    // Log activity
    await ActivityLog.create({
      userId: user._id,
      action: 'wallet_signup',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({ token, user: { 
      id: user._id, 
      walletAddress: user.walletAddress, 
      firstName: user.firstName, 
      lastName: user.lastName,
      balance: user.balance
    }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during wallet signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateAuthToken(user);
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Log activity
    await ActivityLog.create({
      userId: user._id,
      action: 'login',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ token, user: { 
      id: user._id, 
      email: user.email, 
      firstName: user.firstName, 
      lastName: user.lastName,
      balance: user.balance,
      isAdmin: user.isAdmin
    }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ message: 'Wallet not registered' });
    }

    // In a real app, you would verify the signature here
    const token = generateAuthToken(user);
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Log activity
    await ActivityLog.create({
      userId: user._id,
      action: 'wallet_login',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ token, user: { 
      id: user._id, 
      walletAddress: user.walletAddress, 
      firstName: user.firstName, 
      lastName: user.lastName,
      balance: user.balance,
      isAdmin: user.isAdmin
    }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during wallet login' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token here
    // Log activity
    await ActivityLog.create({
      userId: req.user._id,
      action: 'logout',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during logout' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal whether the email exists
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;

    // Send email
    await transporter.sendMail({
      from: 'support@cryptotradingmarket.com',
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });

    res.json({ message: 'If an account exists with this email, a reset link has been sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

app.get('/api/v1/auth/check', authenticate, (req, res) => {
  res.json({ 
    user: { 
      id: req.user._id, 
      email: req.user.email, 
      firstName: req.user.firstName, 
      lastName: req.user.lastName,
      balance: req.user.balance,
      isAdmin: req.user.isAdmin
    } 
  });
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true }).select('-password');
    
    // Broadcast balance update if balance changed
    if (updates.balance) {
      broadcast({
        type: 'BALANCE_UPDATE',
        userId: user._id.toString(),
        balance: user.balance
      });
    }

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/users/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { idFront, idBack, selfie } = req.files;
    
    const user = await User.findById(req.user._id);
    user.kycStatus = 'pending';
    user.kycDocuments = {
      idFront: idFront ? idFront[0].path : null,
      idBack: idBack ? idBack[0].path : null,
      selfie: selfie ? selfie[0].path : null
    };
    
    await user.save();

    res.json({ message: 'KYC submitted for review' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during KYC submission' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.apiKey = uuidv4();
    await user.save();

    res.json({ apiKey: user.apiKey });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id });

    const data = {
      user,
      trades,
      transactions
    };

    // In a real app, you might generate a CSV or PDF here and email it
    res.json(data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Password is incorrect' });
    }

    await User.findByIdAndDelete(req.user._id);
    await Trade.deleteMany({ userId: req.user._id });
    await Transaction.deleteMany({ userId: req.user._id });

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ 
      userId: req.user._id,
      status: 'pending'
    }).sort({ createdAt: -1 });

    res.json(trades);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ 
      userId: req.user._id,
      status: { $ne: 'pending' }
    }).sort({ createdAt: -1 });

    res.json(trades);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Arbitrage logic
const calculateArbitrageOpportunities = (coinPrices) => {
  const opportunities = [];
  const coins = Object.keys(coinPrices);
  
  for (let i = 0; i < coins.length; i++) {
    for (let j = 0; j < coins.length; j++) {
      if (i === j) continue;
      
      const fromCoin = coins[i];
      const toCoin = coins[j];
      const rate = coinPrices[fromCoin] / coinPrices[toCoin];
      
      // Simulate some profit (in a real app, you'd compare with actual exchange rates)
      const profit = Math.random() * 5; // Random profit between 0-5%
      
      opportunities.push({
        fromCoin,
        toCoin,
        rate,
        profit
      });
    }
  }
  
  return opportunities.sort((a, b) => b.profit - a.profit);
};

app.get('/api/v1/arbitrage/opportunities', authenticate, async (req, res) => {
  try {
    // Simulated coin prices (in a real app, fetch from an exchange API)
    const coinPrices = {
      BTC: 50000,
      ETH: 3000,
      BNB: 400,
      USD: 1
    };
    
    const opportunities = calculateArbitrageOpportunities(coinPrices);
    res.json(opportunities);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/arbitrage/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // Validate user has enough balance
    const user = await User.findById(req.user._id);
    if (user.balance[fromCoin] < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    
    // Simulated coin prices (in a real app, fetch from an exchange API)
    const coinPrices = {
      BTC: 50000,
      ETH: 3000,
      BNB: 400,
      USD: 1
    };
    
    const rate = coinPrices[fromCoin] / coinPrices[toCoin];
    const profit = Math.random() * 5; // Random profit between 0-5%
    const receivedAmount = (amount * rate) * (1 + profit/100);
    
    // Update balances
    user.balance[fromCoin] -= amount;
    user.balance[toCoin] = (user.balance[toCoin] || 0) + receivedAmount;
    await user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      profit,
      status: 'completed'
    });
    await trade.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      coin: toCoin,
      amount: receivedAmount,
      status: 'completed'
    });
    await transaction.save();
    
    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      userId: user._id.toString(),
      balance: user.balance
    });
    
    broadcast({
      type: 'TRADE_UPDATE',
      userId: user._id.toString(),
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        profit,
        status: 'completed',
        createdAt: trade.createdAt
      }
    });
    
    res.json({ 
      message: 'Trade executed successfully',
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        receivedAmount,
        rate,
        profit,
        status: 'completed',
        createdAt: trade.createdAt
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during trade execution' });
  }
});

// Wallet Routes
app.post('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    const { coin } = req.body;
    
    // In a real app, you'd generate a unique deposit address for the user
    // Here we just return a simulated address
    const addresses = {
      BTC: '3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5',
      ETH: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
      BNB: 'bnb1q3l4k5kj5l6k7j8h9g0hj2k3l4m5n6p7q8r9s0t'
    };
    
    res.json({ address: addresses[coin] || 'Simulated deposit address' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { coin, amount, address } = req.body;
    
    // Validate user has enough balance
    const user = await User.findById(req.user._id);
    if (user.balance[coin] < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    
    // Simulate withdrawal processing
    user.balance[coin] -= amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      coin,
      amount,
      address,
      status: 'pending',
      txHash: `0x${Math.random().toString(16).substr(2, 64)}` // Simulated tx hash
    });
    await transaction.save();
    
    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      userId: user._id.toString(),
      balance: user.balance
    });
    
    broadcast({
      type: 'TRANSACTION_UPDATE',
      userId: user._id.toString(),
      transaction: {
        id: transaction._id,
        type: 'withdrawal',
        coin,
        amount,
        address,
        status: 'pending',
        txHash: transaction.txHash,
        createdAt: transaction.createdAt
      }
    });
    
    // Simulate transaction completion after some time
    setTimeout(async () => {
      transaction.status = 'completed';
      await transaction.save();
      
      broadcast({
        type: 'TRANSACTION_UPDATE',
        userId: user._id.toString(),
        transaction: {
          id: transaction._id,
          type: 'withdrawal',
          coin,
          amount,
          address,
          status: 'completed',
          txHash: transaction.txHash,
          createdAt: transaction.createdAt
        }
      });
    }, 30000); // 30 seconds
    
    res.json({ 
      message: 'Withdrawal request received',
      transaction: {
        id: transaction._id,
        type: 'withdrawal',
        coin,
        amount,
        address,
        status: 'pending',
        txHash: transaction.txHash,
        createdAt: transaction.createdAt
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during withdrawal' });
  }
});

app.get('/api/v1/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ 
      userId: req.user._id 
    }).sort({ createdAt: -1 }).limit(10);

    res.json(transactions);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ createdAt: -1 });
    res.json(faqs);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments', 5), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files?.map(file => file.path) || [];
    
    const ticket = new SupportTicket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments
    });
    await ticket.save();
    
    res.json({ 
      message: 'Ticket created successfully',
      ticket: {
        id: ticket._id,
        subject,
        status: 'open',
        createdAt: ticket.createdAt
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during ticket creation' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ 
      userId: req.user._id 
    }).sort({ createdAt: -1 });

    res.json(tickets);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    res.json(ticket);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      fromAdmin: false
    });
    await ticket.save();
    
    res.json({ 
      message: 'Reply added successfully',
      ticket: {
        id: ticket._id,
        responses: ticket.responses
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ kycStatus: 'verified' });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
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
      totalUsers,
      verifiedUsers,
      totalTrades,
      totalVolume: totalVolume[0]?.total || 0,
      recentUsers,
      recentTrades
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    
    const query = search 
      ? {
          $or: [
            { firstName: { $regex: search, $options: 'i' } },
            { lastName: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
          ]
        }
      : {};
    
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
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    
    res.json({
      user,
      trades,
      transactions
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { kycStatus, isAdmin } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (kycStatus) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    
    await user.save();
    
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId } = req.query;
    
    const query = userId ? { userId } : {};
    
    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    const total = await Trade.countDocuments(query);
    
    res.json({
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId, type } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    
    const query = status ? { status } : {};
    
    const tickets = await SupportTicket.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    res.json(ticket);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      fromAdmin: true
    });
    
    ticket.status = 'in_progress';
    await ticket.save();
    
    res.json({ 
      message: 'Reply added successfully',
      ticket: {
        id: ticket._id,
        responses: ticket.responses
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    res.json({ 
      message: 'Status updated successfully',
      ticket: {
        id: ticket._id,
        status: ticket.status
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/admin/faqs', authenticateAdmin, async (req, res) => {
  try {
    const { question, answer, category } = req.body;
    
    const faq = new FAQ({
      question,
      answer,
      category
    });
    await faq.save();
    
    res.json(faq);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/v1/admin/faqs/:id', authenticateAdmin, async (req, res) => {
  try {
    const { question, answer, category } = req.body;
    
    const faq = await FAQ.findById(req.params.id);
    if (!faq) {
      return res.status(404).json({ message: 'FAQ not found' });
    }
    
    if (question) faq.question = question;
    if (answer) faq.answer = answer;
    if (category) faq.category = category;
    
    await faq.save();
    
    res.json(faq);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/v1/admin/faqs/:id', authenticateAdmin, async (req, res) => {
  try {
    const faq = await FAQ.findByIdAndDelete(req.params.id);
    if (!faq) {
      return res.status(404).json({ message: 'FAQ not found' });
    }
    
    res.json({ message: 'FAQ deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    // Broadcast to all connected clients
    broadcast({
      type: 'BROADCAST_MESSAGE',
      message,
      timestamp: new Date()
    });
    
    res.json({ message: 'Broadcast sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Static Pages (for frontend routes)
app.get('/about.html', (req, res) => {
  res.json({ message: 'About page data would be served here' });
});

app.get('/account.html', authenticate, (req, res) => {
  res.json({ message: 'Account page data would be served here' });
});

app.get('/admin.html', authenticateAdmin, (req, res) => {
  res.json({ message: 'Admin page data would be served here' });
});

app.get('/dashboard.html', authenticate, (req, res) => {
  res.json({ message: 'Dashboard page data would be served here' });
});

app.get('/faqs.html', (req, res) => {
  res.json({ message: 'FAQs page data would be served here' });
});

app.get('/forgot-password.html', (req, res) => {
  res.json({ message: 'Forgot password page data would be served here' });
});

app.get('/index.html', (req, res) => {
  res.json({ message: 'Home page data would be served here' });
});

app.get('/login.html', (req, res) => {
  res.json({ message: 'Login page data would be served here' });
});

app.get('/logout.html', (req, res) => {
  res.json({ message: 'Logout page data would be served here' });
});

app.get('/signup.html', (req, res) => {
  res.json({ message: 'Signup page data would be served here' });
});

app.get('/support.html', (req, res) => {
  res.json({ message: 'Support page data would be served here' });
});

// Error handling
app.use((req, res, next) => {
  res.status(404).json({ message: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});
