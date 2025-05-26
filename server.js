require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const { createServer } = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const httpServer = createServer(app);

// Configure Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:<OWlondlAbn3bJuj4>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Define Mongoose schemas and models
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true },
  isAdmin: { type: Boolean, default: false },
  balance: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  country: { type: String },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDocuments: [{
    documentType: String,
    documentUrl: String,
    uploadedAt: Date
  }],
  settings: {
    twoFactorEnabled: { type: Boolean, default: false },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: false }
    }
  },
  apiKey: { type: String },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  this.updatedAt = Date.now();
  next();
});

const User = mongoose.model('User', userSchema);

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const Trade = mongoose.model('Trade', tradeSchema);

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'bonus'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

const supportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    fromAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

supportTicketSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

const faqSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true },
  order: { type: Number, default: 0 }
});

const FAQ = mongoose.model('FAQ', faqSchema);

// Email transporter configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// File upload configuration
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = './uploads';
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, `${Date.now()}${ext}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// JWT utility functions
const signToken = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET || '17581758Na.%', {
    expiresIn: process.env.JWT_EXPIRES_IN || '30d'
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.isAdmin);
  
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
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

// Authentication middleware
const protect = async (req, res, next) => {
  try {
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
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    
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

const restrictToAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({
      status: 'fail',
      message: 'You do not have permission to perform this action'
    });
  }
  next();
};

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
      const user = await User.findById(decoded.id);
      
      if (user) {
        socket.userId = user._id;
        socket.isAdmin = user.isAdmin;
        console.log(`User ${user.email} authenticated via WebSocket`);
        
        if (user.isAdmin) {
          socket.join('admin');
        }
      }
    } catch (err) {
      console.log('WebSocket authentication failed');
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Helper functions
const sendEmail = async (options) => {
  try {
    await transporter.sendMail({
      from: 'support@cryptotrade.com',
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    });
  } catch (err) {
    console.error('Error sending email:', err);
    throw err;
  }
};

const getCoinPrices = () => {
  // Simulated prices with the same arbitrage logic as frontend
  const basePrices = {
    btc: 50000,
    eth: 3000,
    bnb: 400,
    sol: 100,
    ada: 1.5,
    xrp: 0.8,
    doge: 0.2,
    dot: 25,
    uni: 15,
    link: 20
  };
  
  // Apply random fluctuation (-7.65% to +15.89%)
  const result = {};
  for (const [coin, price] of Object.entries(basePrices)) {
    const fluctuation = -0.0765 + Math.random() * (0.1589 + 0.0765);
    result[coin] = price * (1 + fluctuation);
  }
  
  return result;
};

const calculateExchangeRate = (fromCoin, toCoin) => {
  const prices = getCoinPrices();
  return prices[toCoin] / prices[fromCoin];
};

// Routes
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Welcome to the Crypto Trading Platform API'
  });
});

// Auth routes
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency,
      balance: 0
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already exists'
      });
    }
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

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    // In a real app, you would verify the signature here
    // For this example, we'll just trust the wallet address
    
    const existingUser = await User.findOne({ walletAddress });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet address already registered'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      walletAddress,
      country,
      currency,
      balance: 0
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // In a real app, you would verify the signature here
    
    const user = await User.findOne({ walletAddress });
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'No account found with this wallet address'
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

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal whether the email exists
      return res.status(200).json({
        status: 'success',
        message: 'If an account exists with this email, a password reset link has been sent'
      });
    }
    
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || '17581758Na.%', {
      expiresIn: '10m'
    });
    
    const resetUrl = `${process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app'}/reset-password?token=${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetUrl}.\nIf you didn't forget your password, please ignore this email!`;
    
    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message
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
        status: 'error',
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
    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }
    
    user.password = password;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/auth/update-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');
    
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
    user.password = newPassword;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/auth/status', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user
    }
  });
});

app.get('/api/v1/auth/check', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      isAuthenticated: true,
      isAdmin: req.user.isAdmin
    }
  });
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

// User routes
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
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

app.get('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: user.settings,
        kycStatus: user.kycStatus,
        apiKey: user.apiKey
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const { settings } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: { settings } },
      { new: true, runValidators: true }
    );
    
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

app.post('/api/v1/users/kyc', protect, upload.array('documents', 3), async (req, res) => {
  try {
    const documents = req.files.map(file => ({
      documentType: file.fieldname,
      documentUrl: `/uploads/${file.filename}`,
      uploadedAt: Date.now()
    }));
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        $push: { kycDocuments: { $each: documents } },
        $set: { kycStatus: 'pending' }
      },
      { new: true }
    );
    
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

app.post('/api/v1/users/generate-api-key', protect, async (req, res) => {
  try {
    const apiKey = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET || '17581758Na.%', {
      expiresIn: '365d'
    });
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { apiKey },
      { new: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        apiKey
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/users/export-data', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const trades = await Trade.find({ userId: req.user._id });
    const transactions = await Transaction.find({ userId: req.user._id });
    
    const data = {
      user,
      trades,
      transactions
    };
    
    // In a real app, you would generate a file and email it to the user
    // For this example, we'll just return the data
    
    res.status(200).json({
      status: 'success',
      data
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.delete('/api/v1/users/delete-account', protect, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    await Trade.deleteMany({ userId: req.user._id });
    await Transaction.deleteMany({ userId: req.user._id });
    
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Trade routes
app.get('/api/v1/exchange/coins', (req, res) => {
  const coins = ['btc', 'eth', 'bnb', 'sol', 'ada', 'xrp', 'doge', 'dot', 'uni', 'link'];
  res.status(200).json({
    status: 'success',
    data: coins
  });
});

app.get('/api/v1/exchange/rates', (req, res) => {
  const prices = getCoinPrices();
  res.status(200).json({
    status: 'success',
    data: prices
  });
});

app.get('/api/v1/exchange/rate', (req, res) => {
  const { from, to } = req.query;
  const rate = calculateExchangeRate(from, to);
  
  res.status(200).json({
    status: 'success',
    data: {
      from,
      to,
      rate
    }
  });
});

app.post('/api/v1/exchange/convert', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const rate = calculateExchangeRate(fromCoin, toCoin);
    const convertedAmount = amount * rate;
    
    // In a real app, you would check user balance and perform the conversion
    // For this example, we'll just record the trade
    
    const trade = await Trade.create({
      userId: req.user._id,
      fromCoin,
      toCoin,
      amount,
      rate,
      status: 'completed'
    });
    
    // Update user's balance (simplified)
    const user = await User.findById(req.user._id);
    
    // Notify via WebSocket
    io.to(req.user._id.toString()).emit('tradeUpdate', trade);
    if (user.isAdmin) {
      io.to('admin').emit('newTrade', trade);
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        trade,
        convertedAmount
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/exchange/history', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.status(200).json({
      status: 'success',
      data: trades
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/trades/active', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user._id, status: 'completed' })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({
      status: 'success',
      data: trades
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Wallet routes
app.get('/api/v1/wallet/deposit-address', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
      currency: 'BTC'
    }
  });
});

app.post('/api/v1/wallet/withdraw', protect, async (req, res) => {
  try {
    const { amount, address, currency } = req.body;
    
    if (req.user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'withdrawal',
      amount,
      currency,
      address,
      status: 'pending'
    });
    
    // In a real app, you would process the withdrawal
    // For this example, we'll just record it
    
    res.status(200).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/transactions/recent', protect, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({
      status: 'success',
      data: transactions
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Support routes
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find().sort({ order: 1 });
    
    res.status(200).json({
      status: 'success',
      data: faqs
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/support/my-tickets', protect, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.status(200).json({
      status: 'success',
      data: tickets
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/support/tickets', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    const ticket = await SupportTicket.create({
      userId: req.user._id,
      email: req.user.email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    // Notify admin via WebSocket
    io.to('admin').emit('newSupportTicket', ticket);
    
    res.status(201).json({
      status: 'success',
      data: ticket
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/support/contact', upload.array('attachments', 3), async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    const attachments = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    const ticket = await SupportTicket.create({
      email,
      subject,
      message,
      attachments,
      status: 'open'
    });
    
    // Notify admin via WebSocket
    io.to('admin').emit('newSupportTicket', ticket);
    
    res.status(201).json({
      status: 'success',
      data: ticket
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
    const userCount = await User.countDocuments();
    const tradeCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    res.status(200).json({
      status: 'success',
      data: {
        users: userCount,
        trades: tradeCount,
        volume: totalVolume[0]?.total || 0
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
    
    const user = await User.findOne({ email, isAdmin: true }).select('+password');
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/verify', protect, restrictToAdmin, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      isAdmin: true
    }
  });
});

app.get('/api/v1/admin/dashboard-stats', protect, restrictToAdmin, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const tradeCount = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
    
    res.status(200).json({
      status: 'success',
      data: {
        users: userCount,
        trades: tradeCount,
        volume: totalVolume[0]?.total || 0,
        pendingTickets,
        pendingKYC
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users', protect, restrictToAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .sort({ createdAt: -1 })
      .select('-password -__v');
    
    res.status(200).json({
      status: 'success',
      data: users
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/users/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    ).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/trades', protect, restrictToAdmin, async (req, res) => {
  try {
    const trades = await Trade.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: trades
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/transactions', protect, restrictToAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: transactions
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets', protect, restrictToAdmin, async (req, res) => {
  try {
    const tickets = await SupportTicket.find()
      .sort({ createdAt: -1 })
      .populate('userId', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: tickets
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'Ticket not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: ticket
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/tickets/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const { status, response } = req.body;
    
    const update = {};
    if (status) update.status = status;
    
    if (response) {
      update.$push = {
        responses: {
          message: response,
          fromAdmin: true
        }
      };
    }
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true }
    ).populate('userId', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'Ticket not found'
      });
    }
    
    // Notify user via WebSocket if they're connected
    if (ticket.userId) {
      io.to(ticket.userId._id.toString()).emit('ticketUpdate', ticket);
    }
    
    res.status(200).json({
      status: 'success',
      data: ticket
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/kyc', protect, restrictToAdmin, async (req, res) => {
  try {
    const users = await User.find({ kycStatus: 'pending' })
      .select('-password -__v');
    
    res.status(200).json({
      status: 'success',
      data: users
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/kyc/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: status },
      { new: true }
    ).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Notify user via WebSocket if they're connected
    io.to(user._id.toString()).emit('kycUpdate', user);
    
    res.status(200).json({
      status: 'success',
      data: user
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/logs', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would have a proper logging system
    // For this example, we'll just return some dummy data
    const logs = [
      { timestamp: new Date(), action: 'System started', user: 'System' },
      { timestamp: new Date(Date.now() - 1000 * 60 * 5), action: 'New user registered', user: 'admin' },
      { timestamp: new Date(Date.now() - 1000 * 60 * 10), action: 'Trade executed', user: 'user123' }
    ];
    
    res.status(200).json({
      status: 'success',
      data: logs
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/broadcast', protect, restrictToAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a message'
      });
    }
    
    // Broadcast to all connected clients
    io.emit('broadcast', { message, timestamp: new Date() });
    
    res.status(200).json({
      status: 'success',
      message: 'Broadcast sent'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/settings', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would fetch these from a database
    const settings = {
      maintenanceMode: false,
      tradeFee: 0.001,
      withdrawalFee: 0.0005,
      depositEnabled: true,
      withdrawalEnabled: true
    };
    
    res.status(200).json({
      status: 'success',
      data: settings
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/settings', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would save these to a database
    const settings = req.body;
    
    res.status(200).json({
      status: 'success',
      data: settings
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
  });
});

// 404 handler
app.all('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Start server
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Initialize some sample data if needed
async function initializeData() {
  try {
    const count = await FAQ.countDocuments();
    if (count === 0) {
      await FAQ.insertMany([
        {
          question: 'How do I create an account?',
          answer: 'Click on the Sign Up button and fill out the registration form.',
          category: 'Account',
          order: 1
        },
        {
          question: 'What is the minimum deposit amount?',
          answer: 'There is no minimum deposit amount.',
          category: 'Deposits',
          order: 2
        },
        {
          question: 'How long do withdrawals take?',
          answer: 'Withdrawals are typically processed within 24 hours.',
          category: 'Withdrawals',
          order: 3
        }
      ]);
      console.log('Sample FAQs created');
    }
    
    // Create an admin user if none exists
    const adminCount = await User.countDocuments({ isAdmin: true });
    if (adminCount === 0) {
      await User.create({
        firstName: 'Admin',
        lastName: 'User',
        email: 'admin@example.com',
        password: 'admin123',
        isAdmin: true
      });
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Error initializing data:', err);
  }
}

initializeData();
