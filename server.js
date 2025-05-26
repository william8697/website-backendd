require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB connection
mongoose.connect('mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  balance: { type: Number, default: 0 },
  walletAddress: { type: String, default: '' },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  result: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, default: 'open' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

// JWT middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    const decoded = jwt.verify(token, '17581758Na.%');
    req.user = await User.findById(decoded.userId);
    if (!req.user) return res.status(401).json({ message: 'User not found' });
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  next();
};

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Coin data (matching frontend logic)
const coins = {
  BTC: { name: 'Bitcoin', price: 58432.78, change: 2.34 },
  ETH: { name: 'Ethereum', price: 3124.56, change: -1.23 },
  BNB: { name: 'Binance Coin', price: 412.78, change: 5.67 },
  SOL: { name: 'Solana', price: 132.45, change: 8.91 },
  XRP: { name: 'Ripple', price: 0.5123, change: -3.45 },
  ADA: { name: 'Cardano', price: 0.4321, change: 1.23 },
  DOGE: { name: 'Dogecoin', price: 0.1234, change: 12.34 },
  DOT: { name: 'Polkadot', price: 6.78, change: -2.34 },
  SHIB: { name: 'Shiba Inu', price: 0.000023, change: 23.45 },
  AVAX: { name: 'Avalanche', price: 34.56, change: -5.67 }
};

// Calculate arbitrage rates (matching frontend logic)
const calculateRate = (fromCoin, toCoin) => {
  const fromPrice = coins[fromCoin].price;
  const toPrice = coins[toCoin].price;
  const baseRate = toPrice / fromPrice;
  
  // Apply consistent arbitrage logic
  const randomFactor = 1 + (Math.random() * 0.15 - 0.0765); // -7.65% to +15% range
  return baseRate * randomFactor;
};

// Routes

// Auth routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already in use' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      balance: 0
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, '17581758Na.%', { expiresIn: '7d' });

    // Set cookie and respond
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    // Generate token
    const token = jwt.sign({ userId: user._id }, '17581758Na.%', { expiresIn: '7d' });

    // Set cookie and respond
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout successful' });
});

app.get('/api/v1/auth/status', authenticate, (req, res) => {
  res.json({
    authenticated: true,
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      balance: req.user.balance,
      isAdmin: req.user.isAdmin
    }
  });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal whether email exists for security
      return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ userId: user._id }, '17581758Na.%', { expiresIn: '1h' });
    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;

    // Send email
    await transporter.sendMail({
      from: 'support@cryptotrade.com',
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link expires in 1 hour.</p>
      `
    });

    res.json({ message: 'If an account exists with this email, a reset link has been sent' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token
    const decoded = jwt.verify(token, '17581758Na.%');
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(400).json({ message: 'Invalid token' });

    // Update password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

// User routes
app.get('/api/v1/users/me', authenticate, (req, res) => {
  res.json({
    id: req.user._id,
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    email: req.user.email,
    balance: req.user.balance,
    isAdmin: req.user.isAdmin,
    walletAddress: req.user.walletAddress || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k'
  });
});

app.patch('/api/v1/users/update', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, walletAddress } = req.body;
    
    req.user.firstName = firstName || req.user.firstName;
    req.user.lastName = lastName || req.user.lastName;
    req.user.walletAddress = walletAddress || req.user.walletAddress;
    
    await req.user.save();
    
    res.json({
      message: 'User updated successfully',
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        balance: req.user.balance,
        walletAddress: req.user.walletAddress
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Trade routes
app.get('/api/v1/trades/rates', authenticate, (req, res) => {
  const rates = {};
  const coinSymbols = Object.keys(coins);
  
  // Calculate all possible rates
  for (let fromCoin of coinSymbols) {
    rates[fromCoin] = {};
    for (let toCoin of coinSymbols) {
      if (fromCoin !== toCoin) {
        rates[fromCoin][toCoin] = calculateRate(fromCoin, toCoin);
      }
    }
  }
  
  res.json({ rates });
});

app.post('/api/v1/trades/execute', authenticate, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // Validate input
    if (!coins[fromCoin] || !coins[toCoin]) {
      return res.status(400).json({ message: 'Invalid coin selection' });
    }
    
    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }
    
    // Calculate rate and result
    const rate = calculateRate(fromCoin, toCoin);
    const result = amount * rate;
    
    // Create trade record
    const trade = new Trade({
      userId: req.user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      result
    });
    
    await trade.save();
    
    res.json({
      message: 'Trade executed successfully',
      trade: {
        id: trade._id,
        fromCoin,
        toCoin,
        amount,
        rate,
        result,
        timestamp: trade.timestamp
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json({ trades });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Support routes
app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    const ticket = new SupportTicket({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      status: 'open'
    });
    
    await ticket.save();
    
    res.status(201).json({
      message: 'Support ticket created successfully',
      ticket: {
        id: ticket._id,
        subject: ticket.subject,
        status: ticket.status,
        createdAt: ticket.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json({ tickets });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/support/faqs', (req, res) => {
  const faqs = [
    {
      question: 'How do I create an account?',
      answer: 'Click on the Sign Up button and fill in your details to create an account.'
    },
    {
      question: 'How do I deposit funds?',
      answer: 'Go to the Wallet section and use the deposit address provided.'
    },
    {
      question: 'How are trading fees calculated?',
      answer: 'We charge a 0.1% fee on each trade which is automatically deducted.'
    },
    {
      question: 'How do I reset my password?',
      answer: 'Use the Forgot Password link on the login page to reset your password.'
    },
    {
      question: 'What is the minimum trade amount?',
      answer: 'There is no minimum trade amount, you can trade any amount you like.'
    }
  ];
  
  res.json({ faqs });
});

// Admin routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, isAdmin: true });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, '17581758Na.%', { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      message: 'Admin login successful',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/dashboard-stats', authenticate, isAdmin, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const tradeCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      userCount,
      tradeCount,
      totalVolume: totalVolume[0]?.total || 0
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/trades', authenticate, isAdmin, async (req, res) => {
  try {
    const trades = await Trade.find().populate('userId', 'firstName lastName email');
    res.json({ trades });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/v1/admin/tickets', authenticate, isAdmin, async (req, res) => {
  try {
    const tickets = await SupportTicket.find().populate('userId', 'firstName lastName email');
    res.json({ tickets });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.patch('/api/v1/admin/tickets/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
    
    res.json({
      message: 'Ticket updated successfully',
      ticket
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Stats route
app.get('/api/v1/stats', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const tradeCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      users: userCount,
      trades: tradeCount,
      volume: totalVolume[0]?.total || 0
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// WebSocket server
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  // Authenticate via cookies
  const cookies = req.headers.cookie;
  if (!cookies) {
    ws.close(1008, 'Authentication required');
    return;
  }
  
  const tokenCookie = cookies.split(';').find(c => c.trim().startsWith('token='));
  if (!tokenCookie) {
    ws.close(1008, 'Authentication required');
    return;
  }
  
  const token = tokenCookie.split('=')[1];
  
  try {
    const decoded = jwt.verify(token, '17581758Na.%');
    
    // Store user ID with connection
    ws.userId = decoded.userId;
    
    ws.on('message', (message) => {
      // Handle WebSocket messages if needed
    });
    
    ws.on('close', () => {
      // Clean up on connection close
    });
    
  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

// Broadcast function for real-time updates
function broadcast(userId, data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.userId === userId) {
      client.send(JSON.stringify(data));
    }
  });
}
