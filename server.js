require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app/';
const EMAIL_USER = process.env.EMAIL_USER || '7c707ac161af1c';
const EMAIL_PASS = process.env.EMAIL_PASS || '6c08aa4f2c679a';
const EMAIL_HOST = process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io';
const EMAIL_PORT = process.env.EMAIL_PORT || 2525;

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Middleware
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Database Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  walletAddress: { type: String, unique: true, sparse: true },
  country: { type: String },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  kycStatus: { type: String, enum: ['not_verified', 'pending', 'verified', 'rejected'], default: 'not_verified' },
  kycDocs: {
    idFront: { type: String },
    idBack: { type: String },
    selfie: { type: String }
  },
  isAdmin: { type: Boolean, default: false },
  twoFactorEnabled: { type: Boolean, default: false },
  apiKey: { type: String },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  profit: { type: Number },
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
  attachments: [{ type: String }],
  responses: [{
    message: { type: String },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const AdminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: { type: String },
  details: { type: Object },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

// Email transporter
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Utility Functions
const generateApiKey = () => uuidv4().replace(/-/g, '');

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

const verifyAdmin = async (req, res, next) => {
  const user = await User.findById(req.userId);
  if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
};

const getCoinPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false');
    return response.data.reduce((acc, coin) => {
      acc[coin.symbol.toUpperCase()] = coin.current_price;
      return acc;
    }, {});
  } catch (error) {
    console.error('Error fetching coin prices:', error);
    // Fallback prices if API fails
    return {
      BTC: 50000,
      ETH: 3000,
      BNB: 400,
      SOL: 100,
      XRP: 0.5,
      ADA: 0.4,
      DOGE: 0.1,
      DOT: 6,
      USDT: 1,
      USDC: 1
    };
  }
};

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Create default admin user if not exists
  createDefaultAdmin();
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'authenticate') {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          ws.userId = decoded.userId;
          const user = await User.findById(decoded.userId);
          if (user) {
            ws.isAdmin = user.isAdmin;
            ws.send(JSON.stringify({ type: 'auth_success' }));
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

const broadcastToUser = (userId, data) => {
  wss.clients.forEach(client => {
    if (client.userId === userId && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

const broadcastToAdmins = (data) => {
  wss.clients.forEach(client => {
    if (client.isAdmin && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

// Create default admin user
const createDefaultAdmin = async () => {
  try {
    const adminEmail = 'admin@cryptotrading.com';
    let admin = await User.findOne({ email: adminEmail });
    
    if (!admin) {
      const hashedPassword = await bcrypt.hash('Admin@1234', 10);
      admin = new User({
        firstName: 'Admin',
        lastName: 'User',
        email: adminEmail,
        password: hashedPassword,
        isAdmin: true,
        balance: 100000,
        kycStatus: 'verified'
      });
      await admin.save();
      console.log('Default admin user created');
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Routes

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
    try {
      await transporter.sendMail({
        from: '"Crypto Trading Market" <support@cryptotrading.com>',
        to: email,
        subject: 'Welcome to Crypto Trading Market',
        html: `<p>Hello ${firstName},</p>
               <p>Your account has been successfully created!</p>
               <p>Start trading and take advantage of our arbitrage opportunities.</p>`
      });
    } catch (emailErr) {
      console.error('Error sending welcome email:', emailErr);
    }
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;
    
    // Validate input
    if (!walletAddress || !signature) {
      return res.status(400).json({ error: 'Wallet address and signature are required' });
    }
    
    // Check if wallet already exists
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({ error: 'Wallet already registered' });
    }
    
    // Create user
    const user = new User({
      firstName: firstName || 'Wallet',
      lastName: lastName || 'User',
      email: email || `${walletAddress}@wallet.com`,
      walletAddress,
      country: country || 'Unknown',
      currency: currency || 'USD',
      apiKey: generateApiKey()
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, user: { id: user._id, walletAddress: user.walletAddress, firstName: user.firstName, lastName: user.lastName } });
  } catch (err) {
    console.error('Wallet signup error:', err);
    res.status(500).json({ error: 'Server error during wallet signup' });
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
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, isAdmin: user.isAdmin } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
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
    
    // In a real app, you would verify the signature here
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, user: { id: user._id, walletAddress: user.walletAddress, firstName: user.firstName, lastName: user.lastName, isAdmin: user.isAdmin } });
  } catch (err) {
    console.error('Wallet login error:', err);
    res.status(500).json({ error: 'Server error during wallet login' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if email doesn't exist
      return res.json({ message: 'If an account with this email exists, a password reset link has been sent' });
    }
    
    // Generate reset token
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    
    // Send reset email
    const resetLink = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    await transporter.sendMail({
      from: '"Crypto Trading Market" <support@cryptotrading.com>',
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Hello ${user.firstName},</p>
             <p>You requested a password reset. Click the link below to reset your password:</p>
             <p><a href="${resetLink}">Reset Password</a></p>
             <p>This link will expire in 1 hour.</p>`
    });
    
    res.json({ message: 'If an account with this email exists, a password reset link has been sent' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Find user
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ error: 'Invalid token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/logout', verifyToken, async (req, res) => {
  // In a real app, you might want to invalidate the token
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v1/auth/check', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (err) {
    console.error('Auth check error:', err);
    res.status(500).json({ error: 'Server error during auth check' });
  }
});

// User Routes
app.get('/api/v1/users/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Server error getting user' });
  }
});

app.patch('/api/v1/users/update', verifyToken, async (req, res) => {
  try {
    const { firstName, lastName, country, currency } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (country) user.country = country;
    if (currency) user.currency = currency;
    
    await user.save();
    
    res.json({ user: { id: user._id, firstName: user.firstName, lastName: user.lastName, country: user.country, currency: user.currency } });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

app.patch('/api/v1/users/update-password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ error: 'Server error updating password' });
  }
});

app.post('/api/v1/users/kyc', verifyToken, upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update KYC status and document paths
    user.kycStatus = 'pending';
    user.kycDocs = {
      idFront: req.files['idFront']?.[0]?.path,
      idBack: req.files['idBack']?.[0]?.path,
      selfie: req.files['selfie']?.[0]?.path
    };
    
    await user.save();
    
    // Notify admins
    broadcastToAdmins({
      type: 'KYC_SUBMITTED',
      userId: user._id,
      userName: `${user.firstName} ${user.lastName}`
    });
    
    res.json({ message: 'KYC documents submitted for review', kycStatus: user.kycStatus });
  } catch (err) {
    console.error('KYC submission error:', err);
    res.status(500).json({ error: 'Server error submitting KYC' });
  }
});

app.post('/api/v1/users/generate-api-key', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.apiKey = generateApiKey();
    await user.save();
    
    res.json({ apiKey: user.apiKey });
  } catch (err) {
    console.error('Generate API key error:', err);
    res.status(500).json({ error: 'Server error generating API key' });
  }
});

app.post('/api/v1/users/export-data', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id });
    const transactions = await Transaction.find({ userId: user._id });
    
    const data = {
      user,
      trades,
      transactions
    };
    
    // In a real app, you would generate a file and email it
    res.json({ data });
  } catch (err) {
    console.error('Export data error:', err);
    res.status(500).json({ error: 'Server error exporting data' });
  }
});

app.delete('/api/v1/users/delete-account', verifyToken, async (req, res) => {
  try {
    const { password } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Password is incorrect' });
    }
    
    // Delete user data
    await Trade.deleteMany({ userId: user._id });
    await Transaction.deleteMany({ userId: user._id });
    await SupportTicket.deleteMany({ userId: user._id });
    await User.deleteOne({ _id: user._id });
    
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'Server error deleting account' });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/balance', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('balance');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ balance: user.balance });
  } catch (err) {
    console.error('Get balance error:', err);
    res.status(500).json({ error: 'Server error getting balance' });
  }
});

app.post('/api/v1/wallet/deposit', verifyToken, async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // In a real app, you would generate a deposit address and wait for blockchain confirmation
    user.balance += amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });
    
    res.json({ balance: user.balance, transactionId: transaction._id });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({ error: 'Server error processing deposit' });
  }
});

app.post('/api/v1/wallet/withdraw', verifyToken, async (req, res) => {
  try {
    const { amount, address } = req.body;
    
    if (!amount || amount <= 0 || !address) {
      return res.status(400).json({ error: 'Invalid amount or address' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // In a real app, you would send the crypto to the address
    user.balance -= amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'completed',
      address
    });
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });
    
    res.json({ balance: user.balance, transactionId: transaction._id });
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({ error: 'Server error processing withdrawal' });
  }
});

// Trade Routes
app.get('/api/v1/trades/history', verifyToken, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ trades });
  } catch (err) {
    console.error('Get trade history error:', err);
    res.status(500).json({ error: 'Server error getting trade history' });
  }
});

app.post('/api/v1/trades/execute', verifyToken, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid trade parameters' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get current prices
    const prices = await getCoinPrices();
    
    if (!prices[fromCoin] || !prices[toCoin]) {
      return res.status(400).json({ error: 'Invalid coin symbols' });
    }
    
    // Calculate USD value
    const usdValue = amount * prices[fromCoin];
    
    // Check minimum trade amount
    if (usdValue < 100) {
      return res.status(400).json({ error: 'Minimum trade amount is $100 equivalent' });
    }
    
    // Check balance (simplified - in a real app, you'd have separate balances for each coin)
    if (user.balance < usdValue) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Calculate arbitrage opportunity (simplified)
    const rate = prices[fromCoin] / prices[toCoin];
    const profit = usdValue * 0.005; // 0.5% arbitrage profit
    
    // Execute trade
    user.balance += profit;
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
      amount: usdValue + profit,
      currency: 'USD',
      status: 'completed'
    });
    await transaction.save();
    
    // Notify user via WebSocket
    broadcastToUser(user._id, {
      type: 'TRADE_EXECUTED',
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        profit,
        status: 'completed'
      },
      balance: user.balance
    });
    
    // Notify admins
    broadcastToAdmins({
      type: 'NEW_TRADE',
      trade: {
        id: trade._id,
        userId: user._id,
        userName: `${user.firstName} ${user.lastName}`,
        fromCoin,
        toCoin,
        amount,
        profit
      }
    });
    
    res.json({ 
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        profit,
        status: 'completed'
      },
      balance: user.balance
    });
  } catch (err) {
    console.error('Execute trade error:', err);
    res.status(500).json({ error: 'Server error executing trade' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    // In a real app, these would come from a database
    const faqs = [
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I create an account?',
            answer: 'Click on the "Sign Up" button and follow the instructions to create your account.'
          },
          {
            question: 'How do I reset my password?',
            answer: 'Go to the login page and click "Forgot Password". Follow the instructions sent to your email.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'What is the minimum trade amount?',
            answer: 'The minimum trade amount is $100 equivalent.'
          },
          {
            question: 'How does arbitrage trading work?',
            answer: 'Our platform automatically identifies price differences across exchanges and executes trades to capture profits.'
          }
        ]
      },
      {
        category: 'Deposits & Withdrawals',
        questions: [
          {
            question: 'How long do deposits take?',
            answer: 'Deposits are typically processed within 15 minutes.'
          },
          {
            question: 'Is there a withdrawal fee?',
            answer: 'Yes, there is a small network fee for withdrawals.'
          }
        ]
      }
    ];
    
    res.json({ faqs });
  } catch (err) {
    console.error('Get FAQs error:', err);
    res.status(500).json({ error: 'Server error getting FAQs' });
  }
});

app.post('/api/v1/support/tickets', verifyToken, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }
    
    const user = await User.findById(req.userId);
    
    // Create ticket
    const ticket = new SupportTicket({
      userId: user._id,
      email: user.email,
      subject,
      message,
      attachments: req.files?.map(file => file.path)
    });
    await ticket.save();
    
    // Notify admins
    broadcastToAdmins({
      type: 'NEW_SUPPORT_TICKET',
      ticket: {
        id: ticket._id,
        subject,
        userId: user._id,
        userName: `${user.firstName} ${user.lastName}`
      }
    });
    
    res.json({ ticket: { id: ticket._id, subject, status: ticket.status } });
  } catch (err) {
    console.error('Create ticket error:', err);
    res.status(500).json({ error: 'Server error creating ticket' });
  }
});

app.get('/api/v1/support/tickets', verifyToken, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ tickets });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ error: 'Server error getting tickets' });
  }
});

app.get('/api/v1/support/tickets/:id', verifyToken, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({ _id: req.params.id, userId: req.userId });
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    res.json({ ticket });
  } catch (err) {
    console.error('Get ticket error:', err);
    res.status(500).json({ error: 'Server error getting ticket' });
  }
});

app.post('/api/v1/support/tickets/:id/reply', verifyToken, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    const ticket = await SupportTicket.findOne({ _id: req.params.id, userId: req.userId });
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.responses.push({
      message,
      isAdmin: false
    });
    
    ticket.status = 'open'; // Reopen if closed
    await ticket.save();
    
    // Notify admins
    broadcastToAdmins({
      type: 'TICKET_REPLY',
      ticketId: ticket._id,
      userId: req.userId
    });
    
    res.json({ ticket: { id: ticket._id, status: ticket.status } });
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ error: 'Server error replying to ticket' });
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
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/dashboard-stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    const tradesCount = await Trade.countDocuments();
    const todayTrades = await Trade.countDocuments({ createdAt: { $gt: new Date(new Date().setHours(0, 0, 0, 0)) } });
    const totalVolume = await Trade.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]);
    const todayVolume = await Trade.aggregate([
      { $match: { createdAt: { $gt: new Date(new Date().setHours(0, 0, 0, 0)) } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
    
    res.json({
      stats: {
        users: usersCount,
        activeUsers: activeUsersCount,
        totalTrades: tradesCount,
        todayTrades,
        totalVolume: totalVolume[0]?.total || 0,
        todayVolume: todayVolume[0]?.total || 0,
        pendingTickets,
        pendingKYC
      }
    });
  } catch (err) {
    console.error('Get admin stats error:', err);
    res.status(500).json({ error: 'Server error getting admin stats' });
  }
});

app.get('/api/v1/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    
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
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error getting users' });
  }
});

app.get('/api/v1/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    
    res.json({ user, trades, transactions });
  } catch (err) {
    console.error('Get user details error:', err);
    res.status(500).json({ error: 'Server error getting user details' });
  }
});

app.patch('/api/v1/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { balance, kycStatus, isAdmin } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (balance !== undefined) user.balance = balance;
    if (kycStatus) user.kycStatus = kycStatus;
    if (isAdmin !== undefined) user.isAdmin = isAdmin;
    
    await user.save();
    
    // Log admin action
    const adminLog = new AdminLog({
      adminId: req.userId,
      action: 'UPDATE_USER',
      target: `User ${req.params.id}`,
      details: req.body
    });
    await adminLog.save();
    
    // Notify user if balance changed
    if (balance !== undefined) {
      broadcastToUser(user._id, {
        type: 'BALANCE_UPDATE',
        balance: user.balance
      });
    }
    
    res.json({ user: { id: user._id, balance: user.balance, kycStatus: user.kycStatus, isAdmin: user.isAdmin } });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

app.get('/api/v1/admin/trades', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    
    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await Trade.countDocuments(query);
    
    res.json({ trades, total });
  } catch (err) {
    console.error('Get trades error:', err);
    res.status(500).json({ error: 'Server error getting trades' });
  }
});

app.get('/api/v1/admin/transactions', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, userId, type } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (type) query.type = type;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await Transaction.countDocuments(query);
    
    res.json({ transactions, total });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ error: 'Server error getting transactions' });
  }
});

app.get('/api/v1/admin/tickets', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    
    const query = {};
    if (status) query.status = status;
    
    const tickets = await SupportTicket.find(query)
      .populate('userId', 'firstName lastName email')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await SupportTicket.countDocuments(query);
    
    res.json({ tickets, total });
  } catch (err) {
    console.error('Get tickets error:', err);
    res.status(500).json({ error: 'Server error getting tickets' });
  }
});

app.get('/api/v1/admin/tickets/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    res.json({ ticket });
  } catch (err) {
    console.error('Get ticket error:', err);
    res.status(500).json({ error: 'Server error getting ticket' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', verifyToken, verifyAdmin, async (req, res) => {
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
      isAdmin: true
    });
    
    ticket.status = 'in_progress';
    await ticket.save();
    
    // Notify user
    if (ticket.userId) {
      broadcastToUser(ticket.userId, {
        type: 'TICKET_REPLY',
        ticketId: ticket._id
      });
    }
    
    res.json({ ticket: { id: ticket._id, status: ticket.status } });
  } catch (err) {
    console.error('Reply to ticket error:', err);
    res.status(500).json({ error: 'Server error replying to ticket' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['open', 'in_progress', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.status = status;
    await ticket.save();
    
    // Notify user
    if (ticket.userId && status === 'resolved') {
      broadcastToUser(ticket.userId, {
        type: 'TICKET_RESOLVED',
        ticketId: ticket._id
      });
    }
    
    res.json({ ticket: { id: ticket._id, status: ticket.status } });
  } catch (err) {
    console.error('Update ticket status error:', err);
    res.status(500).json({ error: 'Server error updating ticket status' });
  }
});

app.get('/api/v1/admin/kyc', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    
    const query = { kycStatus: status || 'pending' };
    
    const users = await User.find(query)
      .select('-password')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.json({ users, total });
  } catch (err) {
    console.error('Get KYC applications error:', err);
    res.status(500).json({ error: 'Server error getting KYC applications' });
  }
});

app.patch('/api/v1/admin/kyc/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.kycStatus = status;
    await user.save();
    
    // Log admin action
    const adminLog = new AdminLog({
      adminId: req.userId,
      action: 'KYC_REVIEW',
      target: `User ${req.params.id}`,
      details: { status }
    });
    await adminLog.save();
    
    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_STATUS_UPDATE',
      status: user.kycStatus
    });
    
    res.json({ user: { id: user._id, kycStatus: user.kycStatus } });
  } catch (err) {
    console.error('Update KYC status error:', err);
    res.status(500).json({ error: 'Server error updating KYC status' });
  }
});

app.post('/api/v1/admin/broadcast', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    // Broadcast to all connected users
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'ADMIN_BROADCAST',
          message
        }));
      }
    });
    
    // Log admin action
    const adminLog = new AdminLog({
      adminId: req.userId,
      action: 'BROADCAST',
      details: { message }
    });
    await adminLog.save();
    
    res.json({ message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error('Broadcast error:', err);
    res.status(500).json({ error: 'Server error sending broadcast' });
  }
});

app.get('/api/v1/admin/logs', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    
    const logs = await AdminLog.find()
      .populate('adminId', 'firstName lastName email')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await AdminLog.countDocuments();
    
    res.json({ logs, total });
  } catch (err) {
    console.error('Get admin logs error:', err);
    res.status(500).json({ error: 'Server error getting admin logs' });
  }
});

// Public Routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const tradesCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]);
    
    res.json({
      stats: {
        users: usersCount,
        trades: tradesCount,
        volume: totalVolume[0]?.total || 0
      }
    });
  } catch (err) {
    console.error('Get public stats error:', err);
    res.status(500).json({ error: 'Server error getting public stats' });
  }
});

// Serve static files (for production)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static('public'));
  
  // Handle SPA
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});
