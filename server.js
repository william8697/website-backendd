require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Database models
const User = require('./models/User')(mongoose);
const Admin = require('./models/Admin')(mongoose);
const Trade = require('./models/Trade')(mongoose);
const Transaction = require('./models/Transaction')(mongoose);
const SupportTicket = require('./models/SupportTicket')(mongoose);
const KycVerification = require('./models/KycVerification')(mongoose);
const ActivityLog = require('./models/ActivityLog')(mongoose);
const ArbitrageOpportunity = require('./models/ArbitrageOpportunity')(mongoose);

// JWT Configuration
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

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Initialize WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

// WebSocket connections map
const activeConnections = new Map();

// Broadcast function for WebSocket
function broadcast(message) {
  activeConnections.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  });
}

// Handle WebSocket connections
wss.on('connection', (ws, req) => {
  // Extract token from query parameters
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Authentication token missing');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    
    // Store connection with user ID
    activeConnections.set(userId, ws);
    
    ws.on('close', () => {
      activeConnections.delete(userId);
    });
    
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      activeConnections.delete(userId);
    });
    
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Default admin account creation
async function createDefaultAdmin() {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@crypto.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@1234', 10);
      const admin = new Admin({
        email: 'admin@crypto.com',
        password: hashedPassword,
        role: 'superadmin',
        firstName: 'System',
        lastName: 'Admin'
      });
      await admin.save();
      console.log('Default admin account created');
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
}
createDefaultAdmin();

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication token missing' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication token missing' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    
    if (!admin) {
      return res.status(401).json({ message: 'Admin not found' });
    }
    
    req.admin = admin;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Validate input
    if (!firstName || !lastName || !email || !password || !country || !currency) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
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
      balances: {
        BTC: 0,
        ETH: 0,
        USDT: 100 // Starting bonus
      }
    });
    
    await user.save();
    
    // Create JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: user._id,
      action: 'signup',
      details: 'User registered'
    });
    await activityLog.save();
    
    // Send welcome email
    const mailOptions = {
      from: 'support@cryptotrading.com',
      to: email,
      subject: 'Welcome to Crypto Trading Market',
      html: `<p>Hello ${firstName},</p>
             <p>Welcome to Crypto Trading Market! Your account has been successfully created.</p>
             <p>Start trading now and take advantage of our arbitrage opportunities.</p>`
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
        balances: user.balances
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: user._id,
      action: 'login',
      details: 'User logged in'
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balances: user.balances,
        kycStatus: user.kycStatus
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign({ adminId: admin._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'logout',
      details: 'User logged out'
    });
    await activityLog.save();
    
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ message: 'Server error during logout' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate input
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      // Return success even if email doesn't exist to prevent email enumeration
      return res.status(200).json({ message: 'If your email is registered, you will receive a password reset link' });
    }
    
    // Create reset token
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    
    // Save reset token to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      from: 'support@cryptotrading.com',
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Hello ${user.firstName},</p>
             <p>You requested a password reset for your Crypto Trading Market account.</p>
             <p>Click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 1 hour.</p>
             <p>If you didn't request this, please ignore this email.</p>`
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Validate input
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Find user
    const user = await User.findOne({
      _id: decoded.userId,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: user._id,
      action: 'password_reset',
      details: 'User reset password'
    });
    await activityLog.save();
    
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

app.get('/api/v1/auth/verify', authenticate, (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      balances: req.user.balances,
      kycStatus: req.user.kycStatus
    }
  });
});

app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
  res.status(200).json({
    success: true,
    admin: {
      id: req.admin._id,
      firstName: req.admin.firstName,
      lastName: req.admin.lastName,
      email: req.admin.email,
      role: req.admin.role
    }
  });
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
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
        kycStatus: req.user.kycStatus,
        createdAt: req.user.createdAt
      }
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ message: 'Server error getting user data' });
  }
});

app.patch('/api/v1/users/update', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    
    // Validate input
    if (!firstName || !lastName || !country || !currency) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Update user
    req.user.firstName = firstName;
    req.user.lastName = lastName;
    req.user.country = country;
    req.user.currency = currency;
    await req.user.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'profile_update',
      details: 'User updated profile'
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        country: req.user.country,
        currency: req.user.currency
      }
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ message: 'Server error updating user' });
  }
});

app.patch('/api/v1/users/update-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Validate input
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new password are required' });
    }
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    req.user.password = hashedPassword;
    await req.user.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'password_change',
      details: 'User changed password'
    });
    await activityLog.save();
    
    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ message: 'Server error updating password' });
  }
});

// KYC Routes
app.post('/api/v1/users/kyc', authenticate, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    
    // Validate input
    if (!documentType || !documentNumber || !req.files.idFront || !req.files.idBack || !req.files.selfie) {
      return res.status(400).json({ message: 'All fields and documents are required' });
    }
    
    // Check if KYC already exists
    const existingKyc = await KycVerification.findOne({ userId: req.user._id });
    if (existingKyc) {
      return res.status(400).json({ message: 'KYC verification already submitted' });
    }
    
    // Create KYC verification
    const kycVerification = new KycVerification({
      userId: req.user._id,
      documentType,
      documentNumber,
      idFront: req.files.idFront[0].path,
      idBack: req.files.idBack[0].path,
      selfie: req.files.selfie[0].path,
      status: 'pending'
    });
    
    await kycVerification.save();
    
    // Update user KYC status
    req.user.kycStatus = 'pending';
    await req.user.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'kyc_submission',
      details: 'User submitted KYC documents'
    });
    await activityLog.save();
    
    res.status(201).json({
      success: true,
      message: 'KYC documents submitted for verification',
      kycStatus: 'pending'
    });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({ message: 'Server error during KYC submission' });
  }
});

app.get('/api/v1/users/kyc/status', authenticate, async (req, res) => {
  try {
    const kycVerification = await KycVerification.findOne({ userId: req.user._id });
    
    if (!kycVerification) {
      return res.status(200).json({ kycStatus: 'not_submitted' });
    }
    
    res.status(200).json({
      kycStatus: kycVerification.status,
      documentType: kycVerification.documentType,
      submittedAt: kycVerification.createdAt
    });
  } catch (err) {
    console.error('KYC status error:', err);
    res.status(500).json({ message: 'Server error getting KYC status' });
  }
});

// Trade Routes
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'active' })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({ success: true, trades });
  } catch (err) {
    console.error('Get active trades error:', err);
    res.status(500).json({ message: 'Server error getting active trades' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.status(200).json({ success: true, trades });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ message: 'Server error getting trade history' });
  }
});

// Arbitrage Routes
app.get('/api/v1/arbitrage/opportunities', authenticate, async (req, res) => {
  try {
    // Simulate arbitrage opportunities (in a real app, this would come from market data)
    const opportunities = [
      {
        id: 'arb1',
        fromCoin: 'BTC',
        toCoin: 'ETH',
        exchangeRate: 18.5,
        potentialProfit: 2.5,
        timeLeft: 120
      },
      {
        id: 'arb2',
        fromCoin: 'ETH',
        toCoin: 'USDT',
        exchangeRate: 2100,
        potentialProfit: 1.8,
        timeLeft: 90
      },
      {
        id: 'arb3',
        fromCoin: 'USDT',
        toCoin: 'BTC',
        exchangeRate: 0.000052,
        potentialProfit: 3.2,
        timeLeft: 180
      }
    ];
    
    res.status(200).json({ success: true, opportunities });
  } catch (err) {
    console.error('Get arbitrage opportunities error:', err);
    res.status(500).json({ message: 'Server error getting arbitrage opportunities' });
  }
});

app.post('/api/v1/arbitrage/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // Validate input
    if (!fromCoin || !toCoin || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid trade parameters' });
    }
    
    // Check user balance
    if (req.user.balances[fromCoin] < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    
    // Minimum trade amount (equivalent to $100)
    let minAmount;
    if (fromCoin === 'BTC') {
      minAmount = 0.002; // ~$100 at $50,000/BTC
    } else if (fromCoin === 'ETH') {
      minAmount = 0.05; // ~$100 at $2,000/ETH
    } else {
      minAmount = 100; // 100 USDT
    }
    
    if (amount < minAmount) {
      return res.status(400).json({ message: `Minimum trade amount is ${minAmount} ${fromCoin}` });
    }
    
    // Simulate arbitrage trade (in a real app, this would connect to exchanges)
    const exchangeRates = {
      BTC: { ETH: 18.5, USDT: 50000 },
      ETH: { BTC: 0.054, USDT: 2000 },
      USDT: { BTC: 0.00002, ETH: 0.0005 }
    };
    
    const exchangeRate = exchangeRates[fromCoin][toCoin];
    const receivedAmount = amount * exchangeRate;
    
    // Simulate profit/loss (random between -5% to +10%)
    const profitFactor = 0.95 + Math.random() * 0.15;
    const finalAmount = receivedAmount * profitFactor;
    
    // Update user balances
    req.user.balances[fromCoin] -= amount;
    req.user.balances[toCoin] = (req.user.balances[toCoin] || 0) + finalAmount;
    await req.user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
      type: 'arbitrage',
      fromCoin,
      toCoin,
      amount,
      exchangeRate,
      receivedAmount: finalAmount,
      status: 'completed',
      profitLoss: finalAmount - receivedAmount
    });
    await trade.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'trade',
      amount: finalAmount,
      currency: toCoin,
      status: 'completed',
      details: `Arbitrage trade from ${amount} ${fromCoin} to ${finalAmount.toFixed(8)} ${toCoin}`
    });
    await transaction.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'arbitrage_trade',
      details: `Executed arbitrage trade from ${amount} ${fromCoin} to ${finalAmount.toFixed(8)} ${toCoin}`
    });
    await activityLog.save();
    
    // Broadcast trade update via WebSocket
    const wsMessage = {
      type: 'TRADE_UPDATE',
      data: {
        tradeId: trade._id,
        status: 'completed',
        profitLoss: trade.profitLoss
      }
    };
    
    if (activeConnections.has(req.user._id.toString())) {
      activeConnections.get(req.user._id.toString()).send(JSON.stringify(wsMessage));
    }
    
    res.status(200).json({
      success: true,
      message: 'Arbitrage trade executed successfully',
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        receivedAmount: finalAmount,
        profitLoss: trade.profitLoss
      }
    });
  } catch (err) {
    console.error('Execute arbitrage error:', err);
    res.status(500).json({ message: 'Server error executing arbitrage trade' });
  }
});

// Transaction Routes
app.get('/api/v1/transactions/recent', authenticate, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({ success: true, transactions });
  } catch (err) {
    console.error('Get recent transactions error:', err);
    res.status(500).json({ message: 'Server error getting recent transactions' });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    // Validate input
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }
    
    // Create support ticket
    const ticket = new SupportTicket({
      userId: req.user._id,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    // Log activity
    const activityLog = new ActivityLog({
      userId: req.user._id,
      action: 'support_ticket',
      details: 'User created support ticket'
    });
    await activityLog.save();
    
    res.status(201).json({
      success: true,
      message: 'Support ticket created successfully',
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        status: ticket.status,
        createdAt: ticket.createdAt
      }
    });
  } catch (err) {
    console.error('Create support ticket error:', err);
    res.status(500).json({ message: 'Server error creating support ticket' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.status(200).json({ success: true, tickets });
  } catch (err) {
    console.error('Get support tickets error:', err);
    res.status(500).json({ message: 'Server error getting support tickets' });
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
    
    res.status(200).json({ success: true, ticket });
  } catch (err) {
    console.error('Get support ticket error:', err);
    res.status(500).json({ message: 'Server error getting support ticket' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        id: 'faq1',
        category: 'Account',
        question: 'How do I create an account?',
        answer: 'Click on the Sign Up button and fill in your details to create an account.'
      },
      {
        id: 'faq2',
        category: 'Account',
        question: 'How do I reset my password?',
        answer: 'Go to the Forgot Password page and follow the instructions to reset your password.'
      },
      {
        id: 'faq3',
        category: 'Trading',
        question: 'What is the minimum trade amount?',
        answer: 'The minimum trade amount is equivalent to $100 in the currency you are trading from.'
      },
      {
        id: 'faq4',
        category: 'Trading',
        question: 'How does arbitrage trading work?',
        answer: 'Arbitrage trading takes advantage of price differences between markets to generate profit.'
      },
      {
        id: 'faq5',
        category: 'Deposits',
        question: 'How long do deposits take?',
        answer: 'Deposits are usually processed within 15 minutes, but may take longer during peak times.'
      },
      {
        id: 'faq6',
        category: 'Deposits',
        question: 'Is there a deposit fee?',
        answer: 'No, we do not charge any fees for deposits.'
      }
    ];
    
    res.status(200).json({ success: true, faqs });
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ message: 'Server error getting FAQs' });
  }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    // Get user count
    const userCount = await User.countDocuments();
    
    // Get active trades
    const activeTradeCount = await Trade.countDocuments({ status: 'active' });
    
    // Get total transaction volume
    const transactions = await Transaction.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
    ]);
    
    const totalVolume = transactions.length > 0 ? transactions[0].totalAmount : 0;
    
    // Get pending KYC verifications
    const pendingKycCount = await KycVerification.countDocuments({ status: 'pending' });
    
    // Get open support tickets
    const openTicketCount = await SupportTicket.countDocuments({ status: 'open' });
    
    res.status(200).json({
      success: true,
      stats: {
        userCount,
        activeTradeCount,
        totalVolume,
        pendingKycCount,
        openTicketCount
      }
    });
  } catch (err) {
    console.error('Get admin dashboard stats error:', err);
    res.status(500).json({ message: 'Server error getting admin dashboard stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('-password');
    
    const totalUsers = await User.countDocuments(query);
    
    res.status(200).json({
      success: true,
      users,
      total: totalUsers,
      page: parseInt(page),
      pages: Math.ceil(totalUsers / limit)
    });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Server error getting users' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const kycVerification = await KycVerification.findOne({ userId: user._id });
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);
    
    res.status(200).json({
      success: true,
      user,
      kycVerification,
      recentTrades: trades,
      recentTransactions: transactions
    });
  } catch (err) {
    console.error('Get user details error:', err);
    res.status(500).json({ message: 'Server error getting user details' });
  }
});

app.patch('/api/v1/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Log activity
    const activityLog = new ActivityLog({
      adminId: req.admin._id,
      action: 'user_status_change',
      details: `Changed user ${user.email} status to ${status}`
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'User status updated successfully',
      user
    });
  } catch (err) {
    console.error('Update user status error:', err);
    res.status(500).json({ message: 'Server error updating user status' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = '' } = req.query;
    
    const query = {};
    if (status) {
      query.status = status;
    }
    
    const trades = await Trade.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const totalTrades = await Trade.countDocuments(query);
    
    res.status(200).json({
      success: true,
      trades,
      total: totalTrades,
      page: parseInt(page),
      pages: Math.ceil(totalTrades / limit)
    });
  } catch (err) {
    console.error('Get trades error:', err);
    res.status(500).json({ message: 'Server error getting trades' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, type = '' } = req.query;
    
    const query = {};
    if (type) {
      query.type = type;
    }
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const totalTransactions = await Transaction.countDocuments(query);
    
    res.status(200).json({
      success: true,
      transactions,
      total: totalTransactions,
      page: parseInt(page),
      pages: Math.ceil(totalTransactions / limit)
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ message: 'Server error getting transactions' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = '' } = req.query;
    
    const query = {};
    if (status) {
      query.status = status;
    }
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const totalTickets = await SupportTicket.countDocuments(query);
    
    res.status(200).json({
      success: true,
      tickets,
      total: totalTickets,
      page: parseInt(page),
      pages: Math.ceil(totalTickets / limit)
    });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ message: 'Server error getting tickets' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['open', 'in_progress', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    // Log activity
    const activityLog = new ActivityLog({
      adminId: req.admin._id,
      action: 'ticket_status_change',
      details: `Changed ticket ${ticket._id} status to ${status}`
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'Ticket status updated successfully',
      ticket
    });
  } catch (err) {
    console.error('Update ticket status error:', err);
    res.status(500).json({ message: 'Server error updating ticket status' });
  }
});

app.post('/api/v1/admin/tickets/:id/response', authenticateAdmin, async (req, res) => {
  try {
    const { response } = req.body;
    
    if (!response) {
      return res.status(400).json({ message: 'Response is required' });
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { 
        $push: { responses: { adminId: req.admin._id, response } },
        status: 'in_progress'
      },
      { new: true }
    ).populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    
    // Log activity
    const activityLog = new ActivityLog({
      adminId: req.admin._id,
      action: 'ticket_response',
      details: `Responded to ticket ${ticket._id}`
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'Response added successfully',
      ticket
    });
  } catch (err) {
    console.error('Add ticket response error:', err);
    res.status(500).json({ message: 'Server error adding ticket response' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = '' } = req.query;
    
    const query = {};
    if (status) {
      query.status = status;
    }
    
    const kycVerifications = await KycVerification.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const totalKyc = await KycVerification.countDocuments(query);
    
    res.status(200).json({
      success: true,
      kycVerifications,
      total: totalKyc,
      page: parseInt(page),
      pages: Math.ceil(totalKyc / limit)
    });
  } catch (err) {
    console.error('Get KYC verifications error:', err);
    res.status(500).json({ message: 'Server error getting KYC verifications' });
  }
});

app.patch('/api/v1/admin/kyc/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    if (!['pending', 'verified', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    
    if (status === 'rejected' && !rejectionReason) {
      return res.status(400).json({ message: 'Rejection reason is required' });
    }
    
    const kycVerification = await KycVerification.findByIdAndUpdate(
      req.params.id,
      { status, rejectionReason: status === 'rejected' ? rejectionReason : undefined },
      { new: true }
    ).populate('userId', 'firstName lastName email');
    
    if (!kycVerification) {
      return res.status(404).json({ message: 'KYC verification not found' });
    }
    
    // Update user KYC status
    await User.findByIdAndUpdate(kycVerification.userId, { kycStatus: status });
    
    // Log activity
    const activityLog = new ActivityLog({
      adminId: req.admin._id,
      action: 'kyc_status_change',
      details: `Changed KYC status for user ${kycVerification.userId.email} to ${status}`
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'KYC status updated successfully',
      kycVerification
    });
  } catch (err) {
    console.error('Update KYC status error:', err);
    res.status(500).json({ message: 'Server error updating KYC status' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, action = '' } = req.query;
    
    const query = {};
    if (action) {
      query.action = action;
    }
    
    const logs = await ActivityLog.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email')
      .populate('adminId', 'firstName lastName email');
    
    const totalLogs = await ActivityLog.countDocuments(query);
    
    res.status(200).json({
      success: true,
      logs,
      total: totalLogs,
      page: parseInt(page),
      pages: Math.ceil(totalLogs / limit)
    });
  } catch (err) {
    console.error('Get activity logs error:', err);
    res.status(500).json({ message: 'Server error getting activity logs' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }
    
    // Broadcast message to all connected clients
    const broadcastMessage = {
      type: 'BROADCAST',
      data: {
        message,
        from: `${req.admin.firstName} ${req.admin.lastName}`,
        timestamp: new Date()
      }
    };
    
    broadcast(broadcastMessage);
    
    // Log activity
    const activityLog = new ActivityLog({
      adminId: req.admin._id,
      action: 'broadcast',
      details: `Sent broadcast message: ${message}`
    });
    await activityLog.save();
    
    res.status(200).json({
      success: true,
      message: 'Broadcast sent successfully'
    });
  } catch (err) {
    console.error('Broadcast error:', err);
    res.status(500).json({ message: 'Server error sending broadcast' });
  }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    // Get total users
    const userCount = await User.countDocuments();
    
    // Get active trades
    const activeTradeCount = await Trade.countDocuments({ status: 'active' });
    
    // Get total transaction volume
    const transactions = await Transaction.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
    ]);
    
    const totalVolume = transactions.length > 0 ? transactions[0].totalAmount : 0;
    
    res.status(200).json({
      success: true,
      stats: {
        users: userCount,
        activeTrades: activeTradeCount,
        totalVolume
      }
    });
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ message: 'Server error getting stats' });
  }
});

// Serve static files (for production)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'public')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});

// Database models (defined inline since we can't use separate files)
function createModels(mongoose) {
  const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    country: { type: String, required: true },
    currency: { type: String, required: true, default: 'USD' },
    balances: {
      BTC: { type: Number, default: 0 },
      ETH: { type: Number, default: 0 },
      USDT: { type: Number, default: 100 } // Starting bonus
    },
    kycStatus: { type: String, enum: ['not_submitted', 'pending', 'verified', 'rejected'], default: 'not_submitted' },
    status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    createdAt: { type: Date, default: Date.now }
  });

  const adminSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
    createdAt: { type: Date, default: Date.now }
  });

  const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['arbitrage', 'market', 'limit'], required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    amount: { type: Number, required: true },
    exchangeRate: { type: Number, required: true },
    receivedAmount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed', 'failed'], default: 'pending' },
    profitLoss: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
  });

  const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    details: String,
    createdAt: { type: Date, default: Date.now }
  });

  const supportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    responses: [{
      adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
      response: String,
      createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
  });

  const kycVerificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    documentType: { type: String, enum: ['passport', 'driver_license', 'id_card'], required: true },
    documentNumber: { type: String, required: true },
    idFront: { type: String, required: true },
    idBack: { type: String, required: true },
    selfie: { type: String, required: true },
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
    rejectionReason: String,
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    reviewedAt: Date,
    createdAt: { type: Date, default: Date.now }
  });

  const activityLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    action: { type: String, required: true },
    details: String,
    createdAt: { type: Date, default: Date.now }
  });

  const arbitrageOpportunitySchema = new mongoose.Schema({
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    exchangeRate: { type: Number, required: true },
    potentialProfit: { type: Number, required: true },
    timeLeft: { type: Number, required: true }, // in seconds
    createdAt: { type: Date, default: Date.now }
  });

  return {
    User: mongoose.model('User', userSchema),
    Admin: mongoose.model('Admin', adminSchema),
    Trade: mongoose.model('Trade', tradeSchema),
    Transaction: mongoose.model('Transaction', transactionSchema),
    SupportTicket: mongoose.model('SupportTicket', supportTicketSchema),
    KycVerification: mongoose.model('KycVerification', kycVerificationSchema),
    ActivityLog: mongoose.model('ActivityLog', activityLogSchema),
    ArbitrageOpportunity: mongoose.model('ArbitrageOpportunity', arbitrageOpportunitySchema)
  };
}
