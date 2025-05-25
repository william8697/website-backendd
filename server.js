require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();

// Security middleware
app.use(helmet());
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use('/api', limiter);

// MongoDB connection
const DB = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(DB, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('DB connection successful!'));

// Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  portfolio: {
    BTC: { type: Number, default: 0 },
    ETH: { type: Number, default: 0 },
    BNB: { type: Number, default: 0 },
    USDT: { type: Number, default: 0 },
    XRP: { type: Number, default: 0 }
  },
  kycVerified: { type: Boolean, default: false },
  kycDetails: {
    fullName: String,
    address: String,
    idNumber: String,
    idType: String,
    idFront: String,
    idBack: String,
    selfie: String
  },
  settings: {
    currency: { type: String, default: 'USD' },
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    twoFA: { type: Boolean, default: false },
    apiKey: { type: String, default: uuidv4() }
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: String, // buy/sell
  fromCoin: String,
  toCoin: String,
  amount: Number,
  rate: Number,
  status: { type: String, default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: String, // deposit/withdrawal/trade
  amount: Number,
  currency: String,
  status: { type: String, default: 'completed' },
  details: String,
  createdAt: { type: Date, default: Date.now }
});

const supportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subject: String,
  message: String,
  status: { type: String, default: 'open' },
  attachments: [String],
  replies: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const kycSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'pending' }, // pending/approved/rejected
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNotes: String,
  submittedAt: { type: Date, default: Date.now },
  reviewedAt: Date
});

const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'admin' },
  permissions: [String],
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
const KYC = mongoose.model('KYC', kycSchema);
const Admin = mongoose.model('Admin', adminSchema);

// JWT
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';

const signToken = (id, role) => {
  return jwt.sign({ id, role }, JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.role);
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 24) * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none'
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

// Email setup
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// WebSocket setup
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});

const wss = new WebSocket.Server({ server });

const activeConnections = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    activeConnections.set(decoded.id, ws);

    ws.on('close', () => {
      activeConnections.delete(decoded.id);
    });

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'PING') {
          ws.send(JSON.stringify({ type: 'PONG' }));
        }
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    });

  } catch (err) {
    ws.close(1008, 'Invalid token');
  }
});

const broadcastToUser = (userId, event, data) => {
  const ws = activeConnections.get(userId);
  if (ws) {
    ws.send(JSON.stringify({ event, data }));
  }
};

// Middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      status: 'fail',
      message: 'You are not logged in! Please log in to get access.'
    });
  }

  try {
    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token does no longer exist.'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const adminProtect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      status: 'fail',
      message: 'You are not logged in! Please log in to get access.'
    });
  }

  try {
    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin || currentAdmin.role !== 'admin') {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not authorized to access this resource.'
      });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token. Please log in again.'
    });
  }
};

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Market Backend');
});

// Auth routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
      balance: 0,
      portfolio: {
        BTC: 0,
        ETH: 0,
        BNB: 0,
        USDT: 0,
        XRP: 0
      }
    });

    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    user.lastLogin = Date.now();
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        status: 'success',
        message: 'If the email exists, a reset link will be sent'
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetURL = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
      await transporter.sendMail({
        from: 'support@cryptotradingmarket.com',
        to: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        text: message
      });

      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!'
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      return res.status(500).json({
        status: 'fail',
        message: 'There was an error sending the email. Try again later!'
      });
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/auth/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    user.password = await bcrypt.hash(req.body.password, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Wallet routes
app.get('/api/v1/wallet/balance', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance,
        portfolio: user.portfolio
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/wallet/deposit', protect, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    user.balance += amount;
    await user.save();

    await Transaction.create({
      userId: user._id,
      type: 'deposit',
      amount,
      currency: 'USD',
      details: `Deposit of $${amount}`
    });

    broadcastToUser(user._id, 'BALANCE_UPDATE', {
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient funds'
      });
    }

    user.balance -= amount;
    await user.save();

    await Transaction.create({
      userId: user._id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      details: `Withdrawal of $${amount}`
    });

    broadcastToUser(user._id, 'BALANCE_UPDATE', {
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Trade routes
app.post('/api/v1/trades/buy', protect, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    const user = await User.findById(req.user.id);

    // In a real app, you would get the current price from an API
    const price = getCurrentPrice(coin);
    const totalCost = price * amount;

    if (user.balance < totalCost) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient funds'
      });
    }

    user.balance -= totalCost;
    user.portfolio[coin] = (user.portfolio[coin] || 0) + amount;
    await user.save();

    const trade = await Trade.create({
      userId: user._id,
      type: 'buy',
      fromCoin: 'USD',
      toCoin: coin,
      amount,
      rate: price
    });

    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount: totalCost,
      currency: 'USD',
      details: `Bought ${amount} ${coin} at $${price} each`
    });

    broadcastToUser(user._id, 'TRADE_UPDATE', {
      trade,
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        trade,
        balance: user.balance,
        portfolio: user.portfolio
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/trades/sell', protect, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    const user = await User.findById(req.user.id);

    if ((user.portfolio[coin] || 0) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient coins'
      });
    }

    // In a real app, you would get the current price from an API
    const price = getCurrentPrice(coin);
    const totalValue = price * amount;

    user.balance += totalValue;
    user.portfolio[coin] = (user.portfolio[coin] || 0) - amount;
    await user.save();

    const trade = await Trade.create({
      userId: user._id,
      type: 'sell',
      fromCoin: coin,
      toCoin: 'USD',
      amount,
      rate: price
    });

    await Transaction.create({
      userId: user._id,
      type: 'trade',
      amount: totalValue,
      currency: 'USD',
      details: `Sold ${amount} ${coin} at $${price} each`
    });

    broadcastToUser(user._id, 'TRADE_UPDATE', {
      trade,
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        trade,
        balance: user.balance,
        portfolio: user.portfolio
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/trades/history', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user.id }).sort('-createdAt');
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Exchange routes
app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = ['BTC', 'ETH', 'BNB', 'USDT', 'XRP'];
    res.status(200).json({
      status: 'success',
      data: {
        coins
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/exchange/rate/:from/:to', async (req, res) => {
  try {
    const { from, to } = req.params;
    // In a real app, you would get the current rate from an API
    const rate = getExchangeRate(from, to);
    res.status(200).json({
      status: 'success',
      data: {
        from,
        to,
        rate
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/exchange/convert', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const user = await User.findById(req.user.id);

    if ((user.portfolio[fromCoin] || 0) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient coins'
      });
    }

    // In a real app, you would get the current rate from an API
    const rate = getExchangeRate(fromCoin, toCoin);
    const convertedAmount = amount * rate;

    user.portfolio[fromCoin] = (user.portfolio[fromCoin] || 0) - amount;
    user.portfolio[toCoin] = (user.portfolio[toCoin] || 0) + convertedAmount;
    await user.save();

    const trade = await Trade.create({
      userId: user._id,
      type: 'convert',
      fromCoin,
      toCoin,
      amount,
      rate
    });

    await Transaction.create({
      userId: user._id,
      type: 'exchange',
      amount,
      currency: fromCoin,
      details: `Converted ${amount} ${fromCoin} to ${convertedAmount} ${toCoin} at rate ${rate}`
    });

    broadcastToUser(user._id, 'TRADE_UPDATE', {
      trade,
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        trade,
        balance: user.balance,
        portfolio: user.portfolio
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Support routes
app.post('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const ticket = await SupportTicket.create({
      userId: req.user.id,
      subject,
      message
    });

    res.status(201).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user.id }).sort('-createdAt');
    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        question: 'How do I sign up?',
        answer: 'Click on the signup button and fill in your details.',
        category: 'account'
      },
      {
        question: 'How do I deposit funds?',
        answer: 'Go to the wallet section and click on deposit.',
        category: 'wallet'
      },
      {
        question: 'How do I trade?',
        answer: 'Go to the trading section and select the coins you want to trade.',
        category: 'trading'
      }
    ];
    res.status(200).json({
      status: 'success',
      data: {
        faqs
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// User routes
app.patch('/api/v1/users/update-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id).select('+password');

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/users/update-me', protect, async (req, res) => {
  try {
    const { name, email } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, email },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/users/kyc', protect, async (req, res) => {
  try {
    const { fullName, address, idNumber, idType } = req.body;
    const user = await User.findById(req.user.id);

    user.kycDetails = {
      fullName,
      address,
      idNumber,
      idType
    };
    user.kycVerified = false;
    await user.save();

    await KYC.create({
      userId: user._id,
      status: 'pending'
    });

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Admin routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }

    const admin = await Admin.findOne({ email }).select('+password');
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    admin.lastLogin = Date.now();
    await admin.save();

    createSendToken(admin, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const tradesCount = await Trade.countDocuments();
    const deposits = await Transaction.aggregate([
      { $match: { type: 'deposit' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const withdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          users: usersCount,
          activeUsers: activeUsersCount,
          trades: tradesCount,
          totalDeposits: deposits.length ? deposits[0].total : 0,
          totalWithdrawals: withdrawals.length ? withdrawals[0].total : 0
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users', adminProtect, async (req, res) => {
  try {
    const users = await User.find().sort('-createdAt');
    res.status(200).json({
      status: 'success',
      results: users.length,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/users/:id/balance', adminProtect, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    user.balance += amount;
    await user.save();

    await Transaction.create({
      userId: user._id,
      type: 'admin-adjustment',
      amount,
      currency: 'USD',
      details: `Admin adjusted balance by $${amount}`
    });

    broadcastToUser(user._id, 'BALANCE_UPDATE', {
      balance: user.balance,
      portfolio: user.portfolio
    });

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/users/:id/status', adminProtect, async (req, res) => {
  try {
    const { active } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/kyc', adminProtect, async (req, res) => {
  try {
    const kycRequests = await KYC.find({ status: 'pending' })
      .populate('userId')
      .sort('-submittedAt');

    res.status(200).json({
      status: 'success',
      results: kycRequests.length,
      data: {
        kycRequests
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/approve', adminProtect, async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id);
    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC request not found'
      });
    }

    kyc.status = 'approved';
    kyc.reviewedBy = req.admin._id;
    kyc.reviewedAt = Date.now();
    await kyc.save();

    const user = await User.findById(kyc.userId);
    user.kycVerified = true;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/reject', adminProtect, async (req, res) => {
  try {
    const { reviewNotes } = req.body;
    const kyc = await KYC.findById(req.params.id);
    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC request not found'
      });
    }

    kyc.status = 'rejected';
    kyc.reviewedBy = req.admin._id;
    kyc.reviewedAt = Date.now();
    kyc.reviewNotes = reviewNotes;
    await kyc.save();

    const user = await User.findById(kyc.userId);
    user.kycVerified = false;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets', adminProtect, async (req, res) => {
  try {
    const tickets = await SupportTicket.find()
      .populate('userId')
      .sort('-createdAt');

    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', adminProtect, async (req, res) => {
  try {
    const { status } = req.body;
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'Ticket not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', adminProtect, async (req, res) => {
  try {
    const { message } = req.body;
    const ticket = await SupportTicket.findById(req.params.id);

    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'Ticket not found'
      });
    }

    ticket.replies.push({
      userId: req.admin._id,
      message,
      isAdmin: true
    });
    await ticket.save();

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Stats routes
app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const tradesCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          users: usersCount,
          activeUsers: activeUsersCount,
          trades: tradesCount,
          totalVolume: totalVolume.length ? totalVolume[0].total : 0
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Helper functions
function getCurrentPrice(coin) {
  const prices = {
    BTC: 50000,
    ETH: 3000,
    BNB: 400,
    USDT: 1,
    XRP: 0.5
  };
  return prices[coin] || 0;
}

function getExchangeRate(from, to) {
  const rates = {
    BTC: { ETH: 16.67, BNB: 125, USDT: 50000, XRP: 100000 },
    ETH: { BTC: 0.06, BNB: 7.5, USDT: 3000, XRP: 6000 },
    BNB: { BTC: 0.008, ETH: 0.133, USDT: 400, XRP: 800 },
    USDT: { BTC: 0.00002, ETH: 0.00033, BNB: 0.0025, XRP: 2 },
    XRP: { BTC: 0.00001, ETH: 0.00017, BNB: 0.00125, USDT: 0.5 }
  };
  return rates[from]?.[to] || 0;
}

// Error handling
app.all('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});
