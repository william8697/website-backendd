require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

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

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  walletAddress: { type: String },
  kycVerified: { type: Boolean, default: false },
  settings: {
    currency: { type: String, default: 'USD' },
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    notifications: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['buy', 'sell'] },
  coinFrom: { type: String, required: true },
  coinTo: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'] },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  createdAt: { type: Date, default: Date.now }
}));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));

const KYC = mongoose.model('KYC', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  fullName: { type: String, required: true },
  address: { type: String, required: true },
  documentType: { type: String, required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
}));

// JWT Configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '1d';

// Email Configuration
const transporter = nodemailer.createTransport({
  host: 'sandbox.sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// File Upload Configuration
const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Helper Functions
const generateToken = (userId, role) => {
  return jwt.sign({ id: userId, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Simulated Price Data (matching frontend logic)
const priceData = {
  bitcoin: { price: 45000, change24h: 2.5 },
  ethereum: { price: 3000, change24h: 1.8 },
  ripple: { price: 0.75, change24h: -0.5 },
  litecoin: { price: 150, change24h: 0.3 },
  cardano: { price: 1.2, change24h: 3.2 },
  polkadot: { price: 25, change24h: -1.2 },
  solana: { price: 120, change24h: 5.5 },
  avalanche: { price: 60, change24h: 2.8 },
  polygon: { price: 1.5, change24h: 1.1 },
  cosmos: { price: 20, change24h: -0.7 }
};

// API Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      password: hashedPassword,
      balance: 0,
      walletAddress: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k'
    });

    const token = generateToken(user._id, user.role);
    res.status(201).json({ token, user: { email: user.email, role: user.role, balance: user.balance } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.role);
    res.json({ token, user: { email: user.email, role: user.role, balance: user.balance } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if email doesn't exist
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }

    const resetToken = generateToken(user._id, user.role);
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`
    });

    res.json({ message: 'Password reset link sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing password reset' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email, role: 'admin' });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.role);
    res.json({ token, user: { email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeTrades = await Trade.countDocuments({ status: 'completed' });
    const pendingTickets = await Ticket.countDocuments({ status: 'open' });
    const totalBalance = await User.aggregate([
      { $group: { _id: null, total: { $sum: '$balance' } } }
    ]);

    res.json({
      usersCount,
      activeTrades,
      pendingTickets,
      totalBalance: totalBalance[0]?.total || 0
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching dashboard stats' });
  }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.email = { $regex: search, $options: 'i' };
    }

    const users = await User.find(query)
      .select('-password')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.json({
      users,
      total,
      page: Number(page),
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount } = req.body;

    if (!amount || isNaN(amount)) {
      return res.status(400).json({ message: 'Valid amount is required' });
    }

    const user = await User.findByIdAndUpdate(
      id,
      { $inc: { balance: amount } },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user balance' });
  }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user profile' });
  }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
  try {
    const { currency, language, theme, notifications } = req.body;
    const updates = {};

    if (currency) updates['settings.currency'] = currency;
    if (language) updates['settings.language'] = language;
    if (theme) updates['settings.theme'] = theme;
    if (notifications !== undefined) updates['settings.notifications'] = notifications;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true }
    ).select('-password');

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating settings' });
  }
});

app.post('/api/v1/users/kyc', authenticate, upload.fields([
  { name: 'documentFront', maxCount: 1 },
  { name: 'documentBack', maxCount: 1 }
]), async (req, res) => {
  try {
    const { fullName, address, documentType } = req.body;
    const files = req.files;

    if (!fullName || !address || !documentType || !files?.documentFront) {
      return res.status(400).json({ message: 'Required fields are missing' });
    }

    const kyc = await KYC.create({
      userId: req.user.id,
      fullName,
      address,
      documentType,
      documentFront: files.documentFront[0].path,
      documentBack: files.documentBack?.[0]?.path
    });

    res.json(kyc);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error submitting KYC' });
  }
});

// Trade Routes
app.get('/api/v1/market/data', (req, res) => {
  res.json(priceData);
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
  try {
    const { coinFrom, coinTo, amount } = req.body;
    if (!coinFrom || !coinTo || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid trade parameters' });
    }

    const fromPrice = priceData[coinFrom]?.price;
    const toPrice = priceData[coinTo]?.price;
    if (!fromPrice || !toPrice) {
      return res.status(400).json({ message: 'Invalid coin selection' });
    }

    const rate = toPrice / fromPrice;
    const totalCost = amount * rate;

    const user = await User.findById(req.user.id);
    if (user.balance < totalCost) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Deduct balance
    user.balance -= totalCost;
    await user.save();

    // Create trade record
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'buy',
      coinFrom,
      coinTo,
      amount,
      rate,
      status: 'completed'
    });

    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      amount: totalCost,
      currency: coinFrom,
      status: 'completed'
    });

    res.json({ trade, newBalance: user.balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing buy trade' });
  }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
  try {
    const { coinFrom, coinTo, amount } = req.body;
    if (!coinFrom || !coinTo || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid trade parameters' });
    }

    const fromPrice = priceData[coinFrom]?.price;
    const toPrice = priceData[coinTo]?.price;
    if (!fromPrice || !toPrice) {
      return res.status(400).json({ message: 'Invalid coin selection' });
    }

    const rate = fromPrice / toPrice;
    const totalValue = amount * rate;

    // Update user balance
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $inc: { balance: totalValue } },
      { new: true }
    );

    // Create trade record
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'sell',
      coinFrom,
      coinTo,
      amount,
      rate,
      status: 'completed'
    });

    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      amount: totalValue,
      currency: coinTo,
      status: 'completed'
    });

    res.json({ trade, newBalance: user.balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing sell trade' });
  }
});

app.get('/api/v1/trades/active', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({
      userId: req.user.id,
      status: 'completed'
    }).sort({ createdAt: -1 }).limit(10);

    res.json(trades);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching active trades' });
  }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ address: user.walletAddress || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching deposit address' });
  }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
  try {
    const { amount, address } = req.body;
    if (!amount || amount <= 0 || !address) {
      return res.status(400).json({ message: 'Valid amount and address are required' });
    }

    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Deduct balance
    user.balance -= amount;
    await user.save();

    // Create withdrawal transaction
    const transaction = await Transaction.create({
      userId: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      txHash: `WITHDRAW-${Date.now()}`
    });

    res.json({ transaction, newBalance: user.balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error processing withdrawal' });
  }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
  const faqs = [
    { id: 1, category: 'account', question: 'How do I create an account?', answer: 'Click on the signup button and follow the instructions.' },
    { id: 2, category: 'account', question: 'How do I reset my password?', answer: 'Use the forgot password feature on the login page.' },
    { id: 3, category: 'trading', question: 'How do I buy cryptocurrency?', answer: 'Navigate to the trading page and select the coins you want to trade.' },
    { id: 4, category: 'trading', question: 'What are the trading fees?', answer: 'We charge a 0.1% fee on all trades.' },
    { id: 5, category: 'deposits', question: 'How do I deposit funds?', answer: 'Use your wallet address to send funds to our platform.' },
    { id: 6, category: 'deposits', question: 'How long do deposits take?', answer: 'Deposits are usually processed within 10-30 minutes.' },
    { id: 7, category: 'withdrawals', question: 'How do I withdraw funds?', answer: 'Navigate to the wallet section and initiate a withdrawal.' },
    { id: 8, category: 'withdrawals', question: 'Are there withdrawal limits?', answer: 'Yes, standard limits are $10,000 per day for unverified accounts.' },
    { id: 9, category: 'security', question: 'Is my account secure?', answer: 'We use industry-standard security measures to protect your account.' },
    { id: 10, category: 'security', question: 'How do I enable 2FA?', answer: 'Go to your account settings and follow the 2FA setup instructions.' }
  ];

  res.json(faqs);
});

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }

    const attachments = req.files?.map(file => file.path) || [];
    const ticket = await Ticket.create({
      userId: req.user.id,
      subject,
      message,
      attachments
    });

    res.json(ticket);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating support ticket' });
  }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching support tickets' });
  }
});

// Stats Route
app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeTrades = await Trade.countDocuments({ status: 'completed' });
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.json({
      usersCount,
      activeTrades,
      totalVolume: totalVolume[0]?.total || 0,
      activeCoins: Object.keys(priceData).length
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching stats' });
  }
});

// Serve static files (for frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Catch-all route for frontend pages
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke on the server!' });
});

// Create HTTP server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// WebSocket Server
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  // Extract token from URL query
  const token = req.url.split('token=')[1];
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    ws.userId = decoded.id;
    ws.role = decoded.role;

    // Send initial connection message
    ws.send(JSON.stringify({
      type: 'connection',
      message: 'WebSocket connection established',
      timestamp: Date.now()
    }));

    // Handle messages
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        console.log('Received WebSocket message:', data);

        // Broadcast to all clients (example)
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'broadcast',
              message: 'New activity on the platform',
              data,
              timestamp: Date.now()
            }));
          }
        });
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    });

    // Handle disconnection
    ws.on('close', () => {
      console.log('Client disconnected');
    });
  } catch (err) {
    console.error('WebSocket authentication error:', err);
    ws.close(1008, 'Invalid or expired token');
  }
});

// Broadcast updates to all connected clients
function broadcastUpdate(type, data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type, data }));
    }
  });
}

// Example: Broadcast price updates every 30 seconds
setInterval(() => {
  // Simulate price changes
  for (const coin in priceData) {
    const change = (Math.random() - 0.5) * 2; // Random change between -1% and +1%
    priceData[coin].price *= (1 + change / 100);
    priceData[coin].change24h = change;
  }

  broadcastUpdate('PRICE_UPDATE', priceData);
}, 30000);
