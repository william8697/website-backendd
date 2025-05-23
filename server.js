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
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Database connection
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

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '1d';

// Email configuration
const emailTransporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
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
const ActivityLog = require('./models/ActivityLog')(mongoose);
const ArbitrageOpportunity = require('./models/ArbitrageOpportunity')(mongoose);

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

// Utility functions
const generateAuthToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized, no token' });
  }

  try {
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Not authorized, user not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
  }
};

const adminProtect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized, no token' });
  }

  try {
    const decoded = verifyToken(token);
    const admin = await Admin.findById(decoded.id).select('-password');
    
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Not authorized, admin not found' });
    }

    req.admin = admin;
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
  }
};

const logActivity = async (userId, activityType, details) => {
  try {
    await ActivityLog.create({
      user: userId,
      activityType,
      details,
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });
  } catch (err) {
    console.error('Error logging activity:', err);
  }
};

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection');

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'authenticate') {
        try {
          const decoded = verifyToken(data.token);
          
          if (data.userType === 'user') {
            const user = await User.findById(decoded.id);
            if (user) {
              ws.userId = user._id;
              ws.userType = 'user';
              ws.send(JSON.stringify({ type: 'authentication', success: true }));
              return;
            }
          } else if (data.userType === 'admin') {
            const admin = await Admin.findById(decoded.id);
            if (admin) {
              ws.userId = admin._id;
              ws.userType = 'admin';
              ws.send(JSON.stringify({ type: 'authentication', success: true }));
              return;
            }
          }
          
          ws.send(JSON.stringify({ type: 'authentication', success: false, message: 'Invalid token' }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'authentication', success: false, message: 'Invalid token' }));
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

const broadcastToUser = (userId, message) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.userId && client.userId.toString() === userId.toString() && client.userType === 'user') {
      client.send(JSON.stringify(message));
    }
  });
};

const broadcastToAdmins = (message) => {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.userType === 'admin') {
      client.send(JSON.stringify(message));
    }
  });
};

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      balances: {
        BTC: 0,
        ETH: 0,
        USDT: 0,
        BNB: 0,
        XRP: 0
      }
    });

    // Generate token
    const token = generateAuthToken(user._id);

    // Log activity
    await logActivity(user._id, 'signup', { method: 'email' });

    // Send welcome email
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: email,
        subject: 'Welcome to Crypto Trading Market',
        html: `<h1>Welcome ${firstName}!</h1><p>Your account has been successfully created.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send welcome email:', emailErr);
    }

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
        balances: user.balances,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;

    // Verify signature
    // In a real app, you'd verify the signature against the wallet address
    // This is a simplified version
    if (!walletAddress || !signature) {
      return res.status(400).json({ success: false, message: 'Wallet address and signature are required' });
    }

    // Check if wallet already exists
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Wallet already registered' });
    }

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      walletAddress,
      country,
      currency,
      balances: {
        BTC: 0,
        ETH: 0,
        USDT: 0,
        BNB: 0,
        XRP: 0
      },
      isWalletUser: true
    });

    // Generate token
    const token = generateAuthToken(user._id);

    // Log activity
    await logActivity(user._id, 'signup', { method: 'wallet', walletAddress });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        country: user.country,
        currency: user.currency,
        balances: user.balances,
        createdAt: user.createdAt,
        isWalletUser: true
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate token
    const token = generateAuthToken(user._id);

    // Log activity
    await logActivity(user._id, 'login', { method: 'email' });

    // Prepare user data to return
    const userData = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      walletAddress: user.walletAddress,
      country: user.country,
      currency: user.currency,
      balances: user.balances,
      createdAt: user.createdAt,
      isWalletUser: user.isWalletUser
    };

    res.status(200).json({
      success: true,
      token,
      user: userData
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;

    // Verify signature
    // In a real app, you'd verify the signature against the wallet address
    // This is a simplified version
    if (!walletAddress || !signature) {
      return res.status(400).json({ success: false, message: 'Wallet address and signature are required' });
    }

    // Check if wallet exists
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Wallet not registered' });
    }

    // Generate token
    const token = generateAuthToken(user._id);

    // Log activity
    await logActivity(user._id, 'login', { method: 'wallet', walletAddress });

    // Prepare user data to return
    const userData = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      walletAddress: user.walletAddress,
      country: user.country,
      currency: user.currency,
      balances: user.balances,
      createdAt: user.createdAt,
      isWalletUser: true
    };

    res.status(200).json({
      success: true,
      token,
      user: userData
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if email doesn't exist
      return res.status(200).json({ 
        success: true, 
        message: 'If your email is registered, you will receive a password reset link' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();

    // Send email
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: user.email,
        subject: 'Password Reset Request',
        html: `
          <p>You requested a password reset for your Crypto Trading Market account.</p>
          <p>Click this link to reset your password:</p>
          <a href="${resetUrl}">${resetUrl}</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      });

      res.status(200).json({ 
        success: true, 
        message: 'If your email is registered, you will receive a password reset link' 
      });
    } catch (emailErr) {
      console.error('Failed to send password reset email:', emailErr);
      res.status(500).json({ success: false, message: 'Failed to send password reset email' });
    }
  } catch (err) {
    console.error(err);
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
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Log activity
    await logActivity(user._id, 'password_reset', {});

    // Send confirmation email
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: user.email,
        subject: 'Password Reset Confirmation',
        html: `<p>Your Crypto Trading Market password has been successfully reset.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send password reset confirmation email:', emailErr);
    }

    res.status(200).json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', protect, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token on the server side
    // For now, we'll just respond successfully since JWT is stateless
    
    // Log activity
    await logActivity(req.user._id, 'logout', {});
    
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/auth/check', protect, async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      user: req.user 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// User Routes
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/users/update-profile', protect, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { firstName, lastName, country, currency },
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Log activity
    await logActivity(user._id, 'profile_update', { fields: Object.keys(req.body) });

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/auth/update-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');

    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    // Log activity
    await logActivity(user._id, 'password_change', {});

    // Send email notification
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: user.email,
        subject: 'Password Changed',
        html: `<p>Your Crypto Trading Market password was recently changed. If you didn't make this change, please contact support immediately.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send password change notification:', emailErr);
    }

    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// KYC Routes
app.post('/api/v1/users/kyc', protect, upload.array('documents', 3), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    const files = req.files;

    if (!documentType || !documentNumber || !files || files.length < 3) {
      return res.status(400).json({ 
        success: false, 
        message: 'Document type, number, and all 3 files (front, back, selfie) are required' 
      });
    }

    // Check if user already has a pending or approved KYC
    const existingKYC = await KYC.findOne({ user: req.user._id, status: { $in: ['pending', 'approved'] } });
    if (existingKYC) {
      return res.status(400).json({ 
        success: false, 
        message: 'You already have a KYC submission that is pending or approved' 
      });
    }

    // Create KYC record
    const kyc = await KYC.create({
      user: req.user._id,
      documentType,
      documentNumber,
      documentFront: files[0].path,
      documentBack: files[1].path,
      selfie: files[2].path,
      status: 'pending'
    });

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user._id, { kycStatus: 'pending' });

    // Log activity
    await logActivity(req.user._id, 'kyc_submission', {});

    // Notify admins
    broadcastToAdmins({
      type: 'NEW_KYC_SUBMISSION',
      message: 'New KYC submission received',
      kycId: kyc._id,
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });

    res.status(201).json({ success: true, kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/users/kyc-status', protect, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ user: req.user._id }).sort({ createdAt: -1 });

    res.status(200).json({ 
      success: true, 
      status: kyc ? kyc.status : 'not_submitted',
      details: kyc || null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/balances', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('balances');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({ success: true, balances: user.balances });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/wallet/deposit-address', protect, async (req, res) => {
  try {
    const { coin } = req.body;
    
    if (!['BTC', 'ETH', 'USDT', 'BNB', 'XRP'].includes(coin)) {
      return res.status(400).json({ success: false, message: 'Invalid coin' });
    }

    // In a real app, you'd generate or retrieve a deposit address from your wallet service
    // For demo, we'll generate a random string
    const depositAddress = `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy_${Date.now()}`;
    const depositMemo = coin === 'XRP' ? `MEMO_${req.user._id.toString().slice(-8)}` : undefined;

    res.status(200).json({ 
      success: true, 
      address: depositAddress,
      memo: depositMemo
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { coin, amount, address, memo } = req.body;
    
    if (!['BTC', 'ETH', 'USDT', 'BNB', 'XRP'].includes(coin)) {
      return res.status(400).json({ success: false, message: 'Invalid coin' });
    }

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    if (!address) {
      return res.status(400).json({ success: false, message: 'Address is required' });
    }

    // Get user with current balances
    const user = await User.findById(req.user._id);
    
    // Check balance
    if (user.balances[coin] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Check minimum withdrawal amount
    const minWithdrawal = {
      BTC: 0.001,
      ETH: 0.01,
      USDT: 50,
      BNB: 0.1,
      XRP: 20
    };

    if (amount < minWithdrawal[coin]) {
      return res.status(400).json({ 
        success: false, 
        message: `Minimum withdrawal amount for ${coin} is ${minWithdrawal[coin]}`
      });
    }

    // Deduct from balance
    user.balances[coin] = parseFloat((user.balances[coin] - amount).toFixed(8));
    await user.save();

    // Create withdrawal transaction
    const transaction = await Transaction.create({
      user: user._id,
      type: 'withdrawal',
      coin,
      amount,
      address,
      memo,
      status: 'pending'
    });

    // Log activity
    await logActivity(user._id, 'withdrawal_request', { coin, amount, address });

    // Notify admins
    broadcastToAdmins({
      type: 'NEW_WITHDRAWAL',
      message: 'New withdrawal request',
      transactionId: transaction._id,
      userId: user._id,
      userName: `${user.firstName} ${user.lastName}`,
      coin,
      amount
    });

    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'WITHDRAWAL_REQUESTED',
      message: 'Withdrawal request submitted',
      transactionId: transaction._id,
      coin,
      amount
    });

    res.status(200).json({ 
      success: true, 
      message: 'Withdrawal request submitted',
      transaction
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/wallet/transactions', protect, async (req, res) => {
  try {
    const { type, coin, limit = 10, page = 1 } = req.query;
    
    const query = { user: req.user._id };
    if (type) query.type = type;
    if (coin) query.coin = coin;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const transactions = await Transaction.find(query, null, options);
    const total = await Transaction.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Trade Routes
app.get('/api/v1/trades/market-data', async (req, res) => {
  try {
    // In a real app, you'd fetch this from a crypto API like CoinGecko or Binance
    // For demo, we'll return static data
    const marketData = {
      BTC: { price: 50000, change24h: 2.5 },
      ETH: { price: 3000, change24h: -1.2 },
      USDT: { price: 1, change24h: 0 },
      BNB: { price: 400, change24h: 3.7 },
      XRP: { price: 0.5, change24h: 5.2 }
    };

    res.status(200).json({ success: true, marketData });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/trades/execute', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!['BTC', 'ETH', 'USDT', 'BNB', 'XRP'].includes(fromCoin) || 
        !['BTC', 'ETH', 'USDT', 'BNB', 'XRP'].includes(toCoin)) {
      return res.status(400).json({ success: false, message: 'Invalid coin(s)' });
    }

    if (fromCoin === toCoin) {
      return res.status(400).json({ success: false, message: 'Cannot trade the same coin' });
    }

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    // Get user with current balances
    const user = await User.findById(req.user._id);
    
    // Check balance
    if (user.balances[fromCoin] < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Get market prices (in a real app, this would be from an API)
    const marketPrices = {
      BTC: { price: 50000, fee: 0.001 },
      ETH: { price: 3000, fee: 0.003 },
      USDT: { price: 1, fee: 0.01 },
      BNB: { price: 400, fee: 0.002 },
      XRP: { price: 0.5, fee: 0.005 }
    };

    // Calculate conversion
    const fromValue = amount * marketPrices[fromCoin].price;
    const toAmount = (fromValue * (1 - marketPrices[toCoin].fee)) / marketPrices[toCoin].price;

    // Update balances
    user.balances[fromCoin] = parseFloat((user.balances[fromCoin] - amount).toFixed(8));
    user.balances[toCoin] = parseFloat((user.balances[toCoin] + toAmount).toFixed(8));
    await user.save();

    // Create trade record
    const trade = await Trade.create({
      user: user._id,
      fromCoin,
      toCoin,
      fromAmount: amount,
      toAmount,
      fee: marketPrices[toCoin].fee,
      rate: toAmount / amount,
      status: 'completed'
    });

    // Log activity
    await logActivity(user._id, 'trade_executed', { fromCoin, toCoin, amount, toAmount });

    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'TRADE_EXECUTED',
      message: 'Trade completed successfully',
      tradeId: trade._id,
      fromCoin,
      toCoin,
      fromAmount: amount,
      toAmount
    });

    res.status(200).json({ 
      success: true, 
      message: 'Trade executed successfully',
      trade,
      newBalances: user.balances
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/trades/history', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, limit = 10, page = 1 } = req.query;
    
    const query = { user: req.user._id };
    if (fromCoin) query.fromCoin = fromCoin;
    if (toCoin) query.toCoin = toCoin;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const trades = await Trade.find(query, null, options);
    const total = await Trade.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Arbitrage Routes
app.get('/api/v1/arbitrage/opportunities', protect, async (req, res) => {
  try {
    // In a real app, you'd calculate arbitrage opportunities from market data
    // For demo, we'll return some static opportunities
    const opportunities = [
      {
        id: 1,
        pair: 'BTC/USDT',
        exchange1: 'Binance',
        exchange2: 'Coinbase',
        buyPrice: 49500,
        sellPrice: 50200,
        profitPercentage: 1.4,
        volume: 2500000
      },
      {
        id: 2,
        pair: 'ETH/USDT',
        exchange1: 'Kraken',
        exchange2: 'Binance',
        buyPrice: 2950,
        sellPrice: 3020,
        profitPercentage: 2.3,
        volume: 1800000
      },
      {
        id: 3,
        pair: 'BNB/BTC',
        exchange1: 'Binance',
        exchange2: 'Huobi',
        buyPrice: 0.0078,
        sellPrice: 0.0081,
        profitPercentage: 3.8,
        volume: 950000
      }
    ];

    res.status(200).json({ success: true, opportunities });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/arbitrage/execute', protect, async (req, res) => {
  try {
    const { opportunityId, amount } = req.body;
    
    if (isNaN(amount) || amount < 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Minimum arbitrage amount is $100 equivalent' 
      });
    }

    // Get user with current balances
    const user = await User.findById(req.user._id);
    
    // Check USDT balance (assuming arbitrage requires USDT)
    if (user.balances.USDT < amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient USDT balance for arbitrage' 
      });
    }

    // Get opportunity (in real app, this would be from DB or API)
    const opportunity = {
      id: 1,
      pair: 'BTC/USDT',
      exchange1: 'Binance',
      exchange2: 'Coinbase',
      buyPrice: 49500,
      sellPrice: 50200,
      profitPercentage: 1.4,
      volume: 2500000
    };

    if (opportunityId != opportunity.id) {
      return res.status(404).json({ success: false, message: 'Opportunity not found' });
    }

    // Calculate profit (simplified)
    const profit = (amount * opportunity.profitPercentage) / 100;
    const fee = profit * 0.2; // 20% platform fee
    const userProfit = profit - fee;

    // Update balances
    user.balances.USDT = parseFloat((user.balances.USDT - amount).toFixed(2));
    user.balances.USDT = parseFloat((user.balances.USDT + amount + userProfit).toFixed(2));
    await user.save();

    // Create arbitrage record
    const arbitrage = await ArbitrageOpportunity.create({
      user: user._id,
      opportunityId,
      pair: opportunity.pair,
      amount,
      profit: userProfit,
      fee,
      status: 'completed'
    });

    // Log activity
    await logActivity(user._id, 'arbitrage_executed', { 
      opportunityId, 
      amount, 
      profit: userProfit 
    });

    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'ARBITRAGE_COMPLETED',
      message: 'Arbitrage trade completed',
      arbitrageId: arbitrage._id,
      amount,
      profit: userProfit
    });

    res.status(200).json({ 
      success: true, 
      message: 'Arbitrage executed successfully',
      arbitrage,
      newBalances: user.balances
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/arbitrage/history', protect, async (req, res) => {
  try {
    const { limit = 10, page = 1 } = req.query;
    
    const query = { user: req.user._id };

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const arbitrages = await ArbitrageOpportunity.find(query, null, options);
    const total = await ArbitrageOpportunity.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      arbitrages,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files;

    if (!subject || !message) {
      return res.status(400).json({ success: false, message: 'Subject and message are required' });
    }

    // Create ticket
    const ticket = await SupportTicket.create({
      user: req.user._id,
      subject,
      message,
      attachments: attachments ? attachments.map(file => file.path) : [],
      status: 'open'
    });

    // Log activity
    await logActivity(req.user._id, 'support_ticket_created', { ticketId: ticket._id });

    // Notify admins
    broadcastToAdmins({
      type: 'NEW_SUPPORT_TICKET',
      message: 'New support ticket created',
      ticketId: ticket._id,
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`,
      subject
    });

    res.status(201).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = { user: req.user._id };
    if (status) query.status = status;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const tickets = await SupportTicket.find(query, null, options);
    const total = await SupportTicket.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/tickets/:id', protect, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { message } = req.body;
    const attachments = req.files;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    if (ticket.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Cannot reply to closed ticket' });
    }

    const reply = {
      from: 'user',
      message,
      attachments: attachments ? attachments.map(file => file.path) : [],
      createdAt: new Date()
    };

    ticket.replies.push(reply);
    ticket.status = 'open'; // Re-open if it was pending
    await ticket.save();

    // Log activity
    await logActivity(req.user._id, 'support_ticket_replied', { ticketId: ticket._id });

    // Notify admins
    broadcastToAdmins({
      type: 'SUPPORT_TICKET_REPLY',
      message: 'User replied to support ticket',
      ticketId: ticket._id,
      userId: req.user._id,
      userName: `${req.user.firstName} ${req.user.lastName}`
    });

    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, these would come from a database
    const faqs = [
      {
        id: 1,
        category: 'Account',
        question: 'How do I create an account?',
        answer: 'Click on the "Sign Up" button and follow the instructions to create your account.'
      },
      {
        id: 2,
        category: 'Account',
        question: 'How do I verify my identity?',
        answer: 'Go to your account settings and submit the required documents for KYC verification.'
      },
      {
        id: 3,
        category: 'Trading',
        question: 'What is the minimum trade amount?',
        answer: 'The minimum trade amount is $10 equivalent in any supported cryptocurrency.'
      },
      {
        id: 4,
        category: 'Trading',
        question: 'How do I execute an arbitrage trade?',
        answer: 'Navigate to the arbitrage section, select an opportunity, and click "Execute Trade".'
      },
      {
        id: 5,
        category: 'Deposits & Withdrawals',
        question: 'How long do deposits take?',
        answer: 'Deposits typically take 1-3 network confirmations before appearing in your account.'
      },
      {
        id: 6,
        category: 'Deposits & Withdrawals',
        question: 'What are the withdrawal fees?',
        answer: 'Withdrawal fees vary by cryptocurrency and are displayed before you confirm the withdrawal.'
      }
    ];

    res.status(200).json({ success: true, faqs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    // In a real app, these would be calculated from database records
    const stats = {
      activeUsers: 12453,
      totalTrades: 892456,
      tradingVolume: 125000000,
      arbitrageOpportunities: 342,
      activeSupportTickets: 87
    };

    res.status(200).json({ success: true, stats });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if admin exists
    const admin = await Admin.findOne({ email }).select('+password');
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate token
    const token = generateAuthToken(admin._id);

    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        firstName: admin.firstName,
        lastName: admin.lastName,
        role: admin.role
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res) => {
  try {
    // Count users
    const totalUsers = await User.countDocuments();
    const newUsersToday = await User.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });

    // Count trades and volume
    const totalTrades = await Trade.countDocuments();
    const tradesToday = await Trade.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    const tradeVolumeToday = await Trade.aggregate([
      { $match: { createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } } },
      { $group: { _id: null, total: { $sum: { $multiply: ['$fromAmount', '$rate'] } } } }
    ]);

    // Count arbitrage
    const totalArbitrage = await ArbitrageOpportunity.countDocuments();
    const arbitrageToday = await ArbitrageOpportunity.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    const arbitrageProfitToday = await ArbitrageOpportunity.aggregate([
      { $match: { createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } } },
      { $group: { _id: null, total: { $sum: '$profit' } } }
    ]);

    // Support tickets
    const openTickets = await SupportTicket.countDocuments({ status: 'open' });
    const pendingTickets = await SupportTicket.countDocuments({ status: 'pending' });

    // KYC
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });

    const stats = {
      users: {
        total: totalUsers,
        newToday: newUsersToday
      },
      trades: {
        total: totalTrades,
        today: tradesToday,
        volumeToday: tradeVolumeToday[0]?.total || 0
      },
      arbitrage: {
        total: totalArbitrage,
        today: arbitrageToday,
        profitToday: arbitrageProfitToday[0]?.total || 0
      },
      support: {
        openTickets,
        pendingTickets
      },
      kyc: {
        pending: pendingKYC
      }
    };

    res.status(200).json({ success: true, stats });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users', adminProtect, async (req, res) => {
  try {
    const { search, status, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { walletAddress: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.status = status;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const users = await User.find(query, '-password', options);
    const total = await User.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get user's trades, transactions, etc.
    const [trades, transactions, arbitrages, tickets] = await Promise.all([
      Trade.find({ user: user._id }).sort({ createdAt: -1 }).limit(5),
      Transaction.find({ user: user._id }).sort({ createdAt: -1 }).limit(5),
      ArbitrageOpportunity.find({ user: user._id }).sort({ createdAt: -1 }).limit(5),
      SupportTicket.find({ user: user._id }).sort({ createdAt: -1 }).limit(5)
    ]);

    const kyc = await KYC.findOne({ user: user._id }).sort({ createdAt: -1 });

    res.status(200).json({ 
      success: true, 
      user,
      kyc,
      recentActivity: {
        trades,
        transactions,
        arbitrages,
        tickets
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/users/:id/status', adminProtect, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'user_status_change',
      details: {
        userId: user._id,
        previousStatus: user.status,
        newStatus: status
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    // Notify user via WebSocket if they're online
    broadcastToUser(user._id, {
      type: 'ACCOUNT_STATUS_CHANGED',
      message: `Your account status has been changed to ${status}`,
      status
    });

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/trades', adminProtect, async (req, res) => {
  try {
    const { userId, fromCoin, toCoin, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (userId) query.user = userId;
    if (fromCoin) query.fromCoin = fromCoin;
    if (toCoin) query.toCoin = toCoin;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const trades = await Trade.find(query, null, options).populate('user', 'firstName lastName email');
    const total = await Trade.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      trades,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/transactions', adminProtect, async (req, res) => {
  try {
    const { userId, type, coin, status, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (userId) query.user = userId;
    if (type) query.type = type;
    if (coin) query.coin = coin;
    if (status) query.status = status;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const transactions = await Transaction.find(query, null, options).populate('user', 'firstName lastName email');
    const total = await Transaction.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      transactions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/transactions/:id/status', adminProtect, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['pending', 'completed', 'failed', 'cancelled'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const transaction = await Transaction.findById(req.params.id).populate('user', 'firstName lastName email');
    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }

    // If completing a withdrawal, we've already deducted the amount during creation
    // If cancelling a withdrawal, we need to refund the user
    if (status === 'cancelled' && transaction.type === 'withdrawal' && transaction.status === 'pending') {
      const user = await User.findById(transaction.user);
      if (user) {
        user.balances[transaction.coin] = parseFloat((user.balances[transaction.coin] + transaction.amount).toFixed(8));
        await user.save();

        // Notify user
        broadcastToUser(user._id, {
          type: 'WITHDRAWAL_CANCELLED',
          message: 'Withdrawal cancelled and funds returned',
          transactionId: transaction._id,
          coin: transaction.coin,
          amount: transaction.amount
        });
      }
    }

    transaction.status = status;
    await transaction.save();

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'transaction_status_change',
      details: {
        transactionId: transaction._id,
        previousStatus: transaction.status,
        newStatus: status
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    res.status(200).json({ success: true, transaction });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/arbitrage', adminProtect, async (req, res) => {
  try {
    const { userId, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (userId) query.user = userId;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const arbitrages = await ArbitrageOpportunity.find(query, null, options).populate('user', 'firstName lastName email');
    const total = await ArbitrageOpportunity.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      arbitrages,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/support/tickets', adminProtect, async (req, res) => {
  try {
    const { status, search, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    if (search) {
      query.$or = [
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ];
    }

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const tickets = await SupportTicket.find(query, null, options)
      .populate('user', 'firstName lastName email');
    const total = await SupportTicket.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      tickets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/support/tickets/:id', adminProtect, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/support/tickets/:id/reply', adminProtect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { message } = req.body;
    const attachments = req.files;

    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    const ticket = await SupportTicket.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    const reply = {
      from: 'admin',
      adminId: req.admin._id,
      adminName: `${req.admin.firstName} ${req.admin.lastName}`,
      message,
      attachments: attachments ? attachments.map(file => file.path) : [],
      createdAt: new Date()
    };

    ticket.replies.push(reply);
    ticket.status = 'pending'; // Set to pending for user response
    await ticket.save();

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'support_ticket_replied',
      details: {
        ticketId: ticket._id,
        userId: ticket.user._id
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    // Notify user via WebSocket
    if (ticket.user) {
      broadcastToUser(ticket.user._id, {
        type: 'SUPPORT_TICKET_REPLY',
        message: 'Admin replied to your support ticket',
        ticketId: ticket._id,
        subject: ticket.subject
      });
    }

    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/support/tickets/:id/status', adminProtect, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['open', 'pending', 'closed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('user', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'support_ticket_status_change',
      details: {
        ticketId: ticket._id,
        previousStatus: ticket.status,
        newStatus: status,
        userId: ticket.user?._id
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    // Notify user if ticket is closed
    if (status === 'closed' && ticket.user) {
      broadcastToUser(ticket.user._id, {
        type: 'SUPPORT_TICKET_CLOSED',
        message: 'Your support ticket has been closed',
        ticketId: ticket._id,
        subject: ticket.subject
      });
    }

    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/kyc', adminProtect, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (status) query.status = status;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const kycSubmissions = await KYC.find(query, null, options)
      .populate('user', 'firstName lastName email');
    const total = await KYC.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      kycSubmissions,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/kyc/:id', adminProtect, async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC submission not found' });
    }

    res.status(200).json({ success: true, kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/kyc/:id/status', adminProtect, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    if (!['approved', 'rejected', 'pending'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    if (status === 'rejected' && !rejectionReason) {
      return res.status(400).json({ success: false, message: 'Rejection reason is required' });
    }

    const kyc = await KYC.findById(req.params.id)
      .populate('user', 'firstName lastName email');

    if (!kyc) {
      return res.status(404).json({ success: false, message: 'KYC submission not found' });
    }

    kyc.status = status;
    if (status === 'rejected') {
      kyc.rejectionReason = rejectionReason;
    }
    await kyc.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(kyc.user._id, { 
      kycStatus: status,
      ...(status === 'approved' ? { isVerified: true } : {})
    });

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'kyc_status_change',
      details: {
        kycId: kyc._id,
        userId: kyc.user._id,
        previousStatus: kyc.status,
        newStatus: status
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    // Notify user via WebSocket
    broadcastToUser(kyc.user._id, {
      type: 'KYC_STATUS_UPDATE',
      message: `Your KYC verification has been ${status}`,
      status,
      ...(status === 'rejected' ? { rejectionReason } : {})
    });

    // Send email notification
    try {
      await emailTransporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
        to: kyc.user.email,
        subject: `KYC Verification ${status.charAt(0).toUpperCase() + status.slice(1)}`,
        html: `
          <p>Your KYC verification has been <strong>${status}</strong>.</p>
          ${status === 'rejected' ? `<p>Reason: ${rejectionReason}</p><p>Please correct the issues and submit again.</p>` : ''}
          ${status === 'approved' ? `<p>Your account is now fully verified.</p>` : ''}
        `
      });
    } catch (emailErr) {
      console.error('Failed to send KYC status email:', emailErr);
    }

    res.status(200).json({ success: true, kyc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/logs', adminProtect, async (req, res) => {
  try {
    const { type, userId, adminId, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (type) query.activityType = type;
    if (userId) query.user = userId;
    if (adminId) query.admin = adminId;

    const options = {
      limit: parseInt(limit),
      skip: (parseInt(page) - 1) * parseInt(limit),
      sort: { createdAt: -1 }
    };

    const logs = await ActivityLog.find(query, null, options)
      .populate('user', 'firstName lastName email')
      .populate('admin', 'firstName lastName email');
    const total = await ActivityLog.countDocuments(query);

    res.status(200).json({ 
      success: true, 
      logs,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/v1/admin/broadcast', adminProtect, async (req, res) => {
  try {
    const { title, message, target } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ success: false, message: 'Title and message are required' });
    }

    // In a real app, you might save this broadcast to the database
    // For now, we'll just broadcast it to all connected clients

    if (target === 'all' || target === 'users') {
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.userType === 'user') {
          client.send(JSON.stringify({
            type: 'BROADCAST_MESSAGE',
            title,
            message,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    if (target === 'all' || target === 'admins') {
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.userType === 'admin') {
          client.send(JSON.stringify({
            type: 'BROADCAST_MESSAGE',
            title,
            message,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'broadcast_sent',
      details: {
        title,
        message,
        target
      },
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    res.status(200).json({ success: true, message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/v1/admin/settings', adminProtect, async (req, res) => {
  try {
    // In a real app, these would come from a database
    const settings = {
      platformFees: {
        trading: 0.0025,
        arbitrage: 0.2,
        withdrawal: {
          BTC: 0.0005,
          ETH: 0.01,
          USDT: 10,
          BNB: 0.05,
          XRP: 0.25
        }
      },
      minimumAmounts: {
        trade: 10,
        arbitrage: 100,
        withdrawal: {
          BTC: 0.001,
          ETH: 0.01,
          USDT: 50,
          BNB: 0.1,
          XRP: 20
        }
      },
      maintenanceMode: false,
      newRegistrations: true
    };

    res.status(200).json({ success: true, settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/v1/admin/settings', adminProtect, async (req, res) => {
  try {
    const { settings } = req.body;
    
    if (!settings) {
      return res.status(400).json({ success: false, message: 'Settings are required' });
    }

    // In a real app, you'd save these to a database
    // For now, we'll just return them

    // Log admin activity
    await ActivityLog.create({
      admin: req.admin._id,
      activityType: 'settings_updated',
      details: settings,
      ipAddress: 'req.ip' // In real app, you'd get this from req.ip
    });

    res.status(200).json({ 
      success: true, 
      message: 'Settings updated successfully',
      settings
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Serve static files (for uploaded files)
app.use('/uploads', express.static('uploads'));

// Models would be defined here in a separate file, but included inline for single-file requirement
function createModels(mongoose) {
  const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, select: false },
    walletAddress: { type: String },
    isWalletUser: { type: Boolean, default: false },
    country: { type: String, required: true },
    currency: { type: String, default: 'USD' },
    balances: {
      BTC: { type: Number, default: 0 },
      ETH: { type: Number, default: 0 },
      USDT: { type: Number, default: 0 },
      BNB: { type: Number, default: 0 },
      XRP: { type: Number, default: 0 }
    },
    kycStatus: { type: String, enum: ['not_submitted', 'pending', 'approved', 'rejected'], default: 'not_submitted' },
    isVerified: { type: Boolean, default: false },
    status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
  });

  const tradeSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    fromAmount: { type: Number, required: true },
    toAmount: { type: Number, required: true },
    fee: { type: Number, required: true },
    rate: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    createdAt: { type: Date, default: Date.now }
  });

  const transactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal'], required: true },
    coin: { type: String, required: true },
    amount: { type: Number, required: true },
    address: { type: String },
    memo: { type: String },
    txHash: { type: String },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
  });

  const supportTicketSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    attachments: [String],
    replies: [{
      from: { type: String, enum: ['user', 'admin'], required: true },
      adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
      adminName: { type: String },
      message: { type: String, required: true },
      attachments: [String],
      createdAt: { type: Date, default: Date.now }
    }],
    status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  });

  const kycSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    documentType: { type: String, required: true },
    documentNumber: { type: String, required: true },
    documentFront: { type: String, required: true },
    documentBack: { type: String },
    selfie: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    rejectionReason: { type: String },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    reviewedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
  });

  const adminSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
  });

  const activityLogSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    admin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    activityType: { type: String, required: true },
    details: { type: mongoose.Schema.Types.Mixed },
    ipAddress: { type: String },
    createdAt: { type: Date, default: Date.now }
  });

  const arbitrageOpportunitySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    opportunityId: { type: String, required: true },
    pair: { type: String, required: true },
    amount: { type: Number, required: true },
    profit: { type: Number, required: true },
    fee: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    createdAt: { type: Date, default: Date.now }
  });

  return {
    User: mongoose.model('User', userSchema),
    Trade: mongoose.model('Trade', tradeSchema),
    Transaction: mongoose.model('Transaction', transactionSchema),
    SupportTicket: mongoose.model('SupportTicket', supportTicketSchema),
    KYC: mongoose.model('KYC', kycSchema),
    Admin: mongoose.model('Admin', adminSchema),
    ActivityLog: mongoose.model('ActivityLog', activityLogSchema),
    ArbitrageOpportunity: mongoose.model('ArbitrageOpportunity', arbitrageOpportunitySchema)
  };
}
