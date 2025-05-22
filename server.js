require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: 'https://website-xi-ten-52.vercel.app',
  credentials: true
}));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Constants
const JWT_SECRET = '17581758Na.%';
const FRONTEND_URL = 'https://website-xi-ten-52.vercel.app';
const EMAIL_CONFIG = {
  user: '7c707ac161af1c',
  pass: '6c08aa4f2c679a',
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525
};

// Email transporter
const transporter = nodemailer.createTransport({
  host: EMAIL_CONFIG.host,
  port: EMAIL_CONFIG.port,
  auth: {
    user: EMAIL_CONFIG.user,
    pass: EMAIL_CONFIG.pass
  }
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
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
  isAdmin: { type: Boolean, default: false },
  apiKey: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  profit: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  coin: { type: String, required: true },
  amount: { type: Number, required: true },
  address: String,
  txHash: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const supportTicketSchema = new mongoose.Schema({
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
});

const adminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: String,
  details: Object,
  createdAt: { type: Date, default: Date.now }
});

const coinPriceSchema = new mongoose.Schema({
  coin: { type: String, required: true, unique: true },
  price: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
const AdminLog = mongoose.model('AdminLog', adminLogSchema);
const CoinPrice = mongoose.model('CoinPrice', coinPriceSchema);

// Helper functions
const generateApiKey = () => {
  return require('crypto').randomBytes(32).toString('hex');
};

const sendEmail = async (to, subject, text, html) => {
  try {
    await transporter.sendMail({
      from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
      to,
      subject,
      text,
      html
    });
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
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
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Initialize WebSocket server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

// WebSocket connection handler
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
            ws.send(JSON.stringify({ type: 'auth', status: 'success' }));
          }
        } catch (error) {
          ws.send(JSON.stringify({ type: 'auth', status: 'failed', error: 'Invalid token' }));
        }
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

// Broadcast function for WebSocket
const broadcast = (data, userId = null, isAdmin = false) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      if (userId && client.userId && client.userId.toString() === userId.toString()) {
        client.send(JSON.stringify(data));
      } else if (isAdmin && client.isAdmin) {
        client.send(JSON.stringify(data));
      } else if (!userId && !isAdmin) {
        client.send(JSON.stringify(data));
      }
    }
  });
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// API Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Validate input
    if (!firstName || !lastName || !email || !password || !country) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
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
      currency: currency || 'USD',
      apiKey: generateApiKey()
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Send welcome email
    await sendEmail(
      email,
      'Welcome to Crypto Trading Market',
      `Hi ${firstName},\n\nWelcome to Crypto Trading Market! Your account has been successfully created.`,
      `<h1>Welcome to Crypto Trading Market!</h1><p>Hi ${firstName},</p><p>Your account has been successfully created.</p>`
    );
    
    res.status(201).json({ 
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ error: 'Wallet address and signature are required' });
    }
    
    // Verify signature (simplified for example)
    // In production, you would verify the signature matches the wallet address
    
    // Check if wallet already exists
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ error: 'Wallet already registered' });
    }
    
    // Create user
    const user = new User({
      firstName: firstName || 'Wallet',
      lastName: lastName || 'User',
      walletAddress,
      country: country || 'Unknown',
      currency: currency || 'USD',
      apiKey: generateApiKey()
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({ 
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings
      }
    });
  } catch (error) {
    console.error('Wallet signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    if (!walletAddress || !signature) {
      return res.status(400).json({ error: 'Wallet address and signature are required' });
    }
    
    // Verify signature (simplified for example)
    // In production, you would verify the signature matches the wallet address
    
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({ error: 'Wallet not registered' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress,
        balance: user.balance,
        kycStatus: user.kycStatus,
        settings: user.settings,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Wallet login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if email exists
      return res.json({ message: 'If an account exists with this email, a password reset link has been sent' });
    }
    
    // Generate reset token (expires in 1 hour)
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    
    // Send reset email
    const resetLink = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    const emailSent = await sendEmail(
      email,
      'Password Reset Request',
      `You requested a password reset. Click this link to reset your password: ${resetLink}`,
      `<h1>Password Reset Request</h1><p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
    );
    
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send reset email' });
    }
    
    res.json({ message: 'If an account exists with this email, a password reset link has been sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }
    
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
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset token has expired' });
    }
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token on the server side
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings,
        isAdmin: req.user.isAdmin,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings,
        isAdmin: req.user.isAdmin,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    
    if (firstName) req.user.firstName = firstName;
    if (lastName) req.user.lastName = lastName;
    if (country) req.user.country = country;
    if (currency) req.user.currency = currency;
    
    await req.user.save();
    
    res.json({
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings,
        isAdmin: req.user.isAdmin,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { theme, language, notifications, twoFactor } = req.body;
    
    if (theme) req.user.settings.theme = theme;
    if (language) req.user.settings.language = language;
    if (notifications !== undefined) req.user.settings.notifications = notifications;
    if (twoFactor !== undefined) req.user.settings.twoFactor = twoFactor;
    
    await req.user.save();
    
    res.json({
      settings: req.user.settings
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const files = req.files;
    
    if (!files || !files.idFront || !files.idBack || !files.selfie) {
      return res.status(400).json({ error: 'All documents are required' });
    }
    
    req.user.kycStatus = 'pending';
    req.user.kycDocuments = {
      idFront: files.idFront[0].path,
      idBack: files.idBack[0].path,
      selfie: files.selfie[0].path
    };
    
    await req.user.save();
    
    // Notify admin about new KYC submission
    broadcast({
      type: 'KYC_SUBMITTED',
      userId: req.user._id,
      userEmail: req.user.email
    }, null, true);
    
    res.json({ 
      message: 'KYC documents submitted for verification',
      kycStatus: req.user.kycStatus
    });
  } catch (error) {
    console.error('KYC submission error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/users/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
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
    console.error('Password update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
  try {
    req.user.apiKey = generateApiKey();
    await req.user.save();
    
    res.json({ apiKey: req.user.apiKey });
  } catch (error) {
    console.error('API key generation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
  try {
    // In a real app, you would generate a comprehensive data export
    const userData = {
      profile: {
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        walletAddress: req.user.walletAddress,
        country: req.user.country,
        currency: req.user.currency,
        createdAt: req.user.createdAt
      },
      balance: req.user.balance,
      settings: req.user.settings,
      kycStatus: req.user.kycStatus
    };
    
    // Send email with data (in production, you might generate a downloadable file)
    const emailSent = await sendEmail(
      req.user.email,
      'Your Data Export from Crypto Trading Market',
      `Here's your exported data:\n\n${JSON.stringify(userData, null, 2)}`,
      `<h1>Your Data Export</h1><pre>${JSON.stringify(userData, null, 2)}</pre>`
    );
    
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send data export email' });
    }
    
    res.json({ message: 'Data export sent to your email' });
  } catch (error) {
    console.error('Data export error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    
    const isMatch = await bcrypt.compare(password, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Password is incorrect' });
    }
    
    // In production, you might want to anonymize data instead of deleting
    await User.findByIdAndDelete(req.user._id);
    
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Wallet Routes
app.post('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    const { coin } = req.body;
    
    if (!coin) {
      return res.status(400).json({ error: 'Coin is required' });
    }
    
    // In a real app, you would generate a unique deposit address for the user
    // For this example, we'll return a mock address
    const mockAddresses = {
      BTC: '3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5',
      ETH: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
      BNB: 'bnb1qxy2kgdxgjryq2k8px5n4ces2m4q4u8x0p5u6q'
    };
    
    const address = mockAddresses[coin] || `mock_${coin.toLowerCase()}_address_${req.user._id}`;
    
    // Create a deposit transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'deposit',
      coin,
      amount: 0, // Will be updated when deposit is detected
      address,
      status: 'pending'
    });
    
    await transaction.save();
    
    res.json({ address });
  } catch (error) {
    console.error('Deposit address error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { coin, amount, address } = req.body;
    
    if (!coin || !amount || !address) {
      return res.status(400).json({ error: 'Coin, amount, and address are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    // Check balance
    if (req.user.balance[coin] < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Deduct balance
    req.user.balance[coin] -= amount;
    await req.user.save();
    
    // Create withdrawal transaction
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'withdrawal',
      coin,
      amount,
      address,
      status: 'pending'
    });
    
    await transaction.save();
    
    // Broadcast balance update
    broadcast({
      type: 'BALANCE_UPDATE',
      userId: req.user._id,
      balance: req.user.balance
    }, req.user._id);
    
    res.json({ 
      message: 'Withdrawal request submitted',
      transactionId: transaction._id,
      balance: req.user.balance
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/wallet/transactions', authenticate, async (req, res) => {
  try {
    const { type, coin, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (type) query.type = type;
    if (coin) query.coin = coin;
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    res.json({ transactions });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Trade Routes (Arbitrage)
app.get('/api/v1/arbitrage/opportunities', authenticate, async (req, res) => {
  try {
    // In a real app, you would calculate actual arbitrage opportunities
    // For this example, we'll return mock data
    
    const mockOpportunities = [
      {
        fromCoin: 'BTC',
        toCoin: 'ETH',
        rate: 18.5,
        profit: 1.5
      },
      {
        fromCoin: 'ETH',
        toCoin: 'BNB',
        rate: 3.2,
        profit: 0.8
      },
      {
        fromCoin: 'BTC',
        toCoin: 'BNB',
        rate: 60.2,
        profit: 2.1
      }
    ];
    
    res.json({ opportunities: mockOpportunities });
  } catch (error) {
    console.error('Get arbitrage opportunities error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/arbitrage/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount) {
      return res.status(400).json({ error: 'From coin, to coin, and amount are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be positive' });
    }
    
    // Check balance
    if (req.user.balance[fromCoin] < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // In a real app, you would calculate the actual rate and profit
    // For this example, we'll use mock values
    const mockRates = {
      'BTC-ETH': 18.5,
      'ETH-BNB': 3.2,
      'BTC-BNB': 60.2
    };
    
    const rate = mockRates[`${fromCoin}-${toCoin}`] || 1;
    const profit = Math.random() * 5; // Random profit between 0-5%
    const receivedAmount = amount * rate * (1 + profit / 100);
    
    // Deduct from balance
    req.user.balance[fromCoin] -= amount;
    // Add to balance
    req.user.balance[toCoin] += receivedAmount;
    await req.user.save();
    
    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
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
      userId: req.user._id,
      type: 'trade',
      coin: fromCoin,
      amount: -amount,
      status: 'completed'
    });
    
    await transaction.save();
    
    const transaction2 = new Transaction({
      userId: req.user._id,
      type: 'trade',
      coin: toCoin,
      amount: receivedAmount,
      status: 'completed'
    });
    
    await transaction2.save();
    
    // Broadcast updates
    broadcast({
      type: 'BALANCE_UPDATE',
      userId: req.user._id,
      balance: req.user.balance
    }, req.user._id);
    
    broadcast({
      type: 'TRADE_UPDATE',
      userId: req.user._id,
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
    }, req.user._id);
    
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
      },
      balance: req.user.balance
    });
  } catch (error) {
    console.error('Trade execution error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (fromCoin) query.fromCoin = fromCoin;
    if (toCoin) query.toCoin = toCoin;
    
    const trades = await Trade.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    res.json({ trades });
  } catch (error) {
    console.error('Get trade history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Support Routes
app.post('/api/v1/support/tickets', authenticate, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files?.map(file => file.path) || [];
    
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }
    
    const ticket = new SupportTicket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    await ticket.save();
    
    // Notify admin about new ticket
    broadcast({
      type: 'NEW_TICKET',
      ticketId: ticket._id,
      subject: ticket.subject,
      userId: req.user._id
    }, null, true);
    
    res.json({ 
      message: 'Support ticket created successfully',
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        status: ticket.status,
        createdAt: ticket.createdAt
      }
    });
  } catch (error) {
    console.error('Create ticket error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = { userId: req.user._id };
    if (status) query.status = status;
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    res.json({ tickets });
  } catch (error) {
    console.error('Get tickets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (error) {
    console.error('Get ticket error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
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
    
    ticket.status = 'open'; // Reopen if closed
    await ticket.save();
    
    // Notify admin about ticket reply
    broadcast({
      type: 'TICKET_REPLY',
      ticketId: ticket._id,
      userId: req.user._id
    }, null, true);
    
    res.json({ 
      message: 'Reply added successfully',
      ticket: {
        id: ticket._id,
        status: ticket.status,
        responses: ticket.responses
      }
    });
  } catch (error) {
    console.error('Ticket reply error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, you would fetch FAQs from database
    // For this example, we'll return mock data
    const mockFaqs = [
      {
        category: 'Account',
        question: 'How do I create an account?',
        answer: 'Click on the Sign Up button and fill in your details.'
      },
      {
        category: 'Account',
        question: 'How do I reset my password?',
        answer: 'Go to the Forgot Password page and follow the instructions.'
      },
      {
        category: 'Trading',
        question: 'How does arbitrage trading work?',
        answer: 'Our platform identifies price differences across exchanges and executes trades to capture profits.'
      },
      {
        category: 'Deposits',
        question: 'How long do deposits take?',
        answer: 'Deposits are usually processed within 1-3 network confirmations.'
      }
    ];
    
    res.json({ faqs: mockFaqs });
  } catch (error) {
    console.error('Get FAQs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email, isAdmin: true });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ kycStatus: 'verified' });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    // Recent activity
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5);
    
    const recentTrades = await Trade.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email');
    
    res.json({
      stats: {
        totalUsers,
        verifiedUsers,
        totalTrades,
        totalVolume: totalVolume[0]?.total || 0
      },
      recentUsers,
      recentTrades
    });
  } catch (error) {
    console.error('Get admin stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
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
    if (status) query.kycStatus = status;
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('-password -apiKey');
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -apiKey');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's trades
    const trades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    // Get user's transactions
    const transactions = await Transaction.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    res.json({ user, trades, transactions });
  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.active = status === 'active';
    await user.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'UPDATE_USER_STATUS',
      target: `User ${user._id}`,
      details: { status: user.active ? 'active' : 'inactive' }
    });
    
    await log.save();
    
    res.json({ 
      message: 'User status updated successfully',
      user: {
        id: user._id,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/users/:id/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status || !['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Valid status is required' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.kycStatus = status;
    await user.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'UPDATE_KYC_STATUS',
      target: `User ${user._id}`,
      details: { status }
    });
    
    await log.save();
    
    // Notify user about KYC status update
    broadcast({
      type: 'KYC_STATUS_UPDATE',
      status,
      userId: user._id
    }, user._id);
    
    res.json({ 
      message: 'KYC status updated successfully',
      user: {
        id: user._id,
        kycStatus: user.kycStatus
      }
    });
  } catch (error) {
    console.error('Update KYC status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
  try {
    const { userId, fromCoin, toCoin, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (fromCoin) query.fromCoin = fromCoin;
    if (toCoin) query.toCoin = toCoin;
    
    const trades = await Trade.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const total = await Trade.countDocuments(query);
    
    res.json({ trades, total });
  } catch (error) {
    console.error('Get trades error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { userId, type, coin, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    if (coin) query.coin = coin;
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const total = await Transaction.countDocuments(query);
    
    res.json({ transactions, total });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { status, userId, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    if (userId) query.userId = userId;
    
    const tickets = await SupportTicket.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName email');
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({ tickets, total });
  } catch (error) {
    console.error('Get tickets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (error) {
    console.error('Get ticket error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
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
    
    // Notify user about ticket reply
    broadcast({
      type: 'TICKET_REPLY',
      ticketId: ticket._id,
      adminId: req.user._id
    }, ticket.userId);
    
    res.json({ 
      message: 'Reply added successfully',
      ticket: {
        id: ticket._id,
        status: ticket.status,
        responses: ticket.responses
      }
    });
  } catch (error) {
    console.error('Ticket reply error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status || !['open', 'in_progress', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'Valid status is required' });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'UPDATE_TICKET_STATUS',
      target: `Ticket ${ticket._id}`,
      details: { status }
    });
    
    await log.save();
    
    // Notify user about ticket status update
    if (ticket.userId) {
      broadcast({
        type: 'TICKET_STATUS_UPDATE',
        ticketId: ticket._id,
        status
      }, ticket.userId);
    }
    
    res.json({ 
      message: 'Ticket status updated successfully',
      ticket: {
        id: ticket._id,
        status: ticket.status
      }
    });
  } catch (error) {
    console.error('Update ticket status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const { status, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (status) query.kycStatus = status;
    else query.kycStatus = 'pending';
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('firstName lastName email walletAddress kycStatus kycDocuments createdAt');
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (error) {
    console.error('Get KYC submissions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const { action, adminId, limit = 10, page = 1 } = req.query;
    
    const query = {};
    if (action) query.action = action;
    if (adminId) query.adminId = adminId;
    
    const logs = await AdminLog.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('adminId', 'firstName lastName email');
    
    const total = await AdminLog.countDocuments(query);
    
    res.json({ logs, total });
  } catch (error) {
    console.error('Get admin logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    // Broadcast to all connected clients
    broadcast({
      type: 'ADMIN_BROADCAST',
      message,
      adminId: req.user._id,
      adminName: `${req.user.firstName} ${req.user.lastName}`
    });
    
    // Log admin action
    const log = new AdminLog({
      adminId: req.user._id,
      action: 'SEND_BROADCAST',
      details: { message }
    });
    
    await log.save();
    
    res.json({ message: 'Broadcast sent successfully' });
  } catch (error) {
    console.error('Broadcast error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Static Pages (for frontend routes)
app.get('/about.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

app.get('/account.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/faqs.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'faqs.html'));
});

app.get('/forgot-password.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/logout.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logout.html'));
});

app.get('/signup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/support.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'support.html'));
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
console.log(`Server started on port ${PORT}`);
