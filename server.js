require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { Web3 } = require('web3');
const validator = require('validator');
const cloudinary = require('cloudinary').v2;

// Initialize Express app
const app = express();
const httpServer = createServer(app);

// WebSocket setup
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app',
    methods: ['GET', 'POST']
  }
});

// Admin WebSocket namespace
const adminIo = io.of('/api/v1/admin/ws');

// Constants
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const COINS = ['BTC', 'ETH', 'BNB', 'XRP', 'SOL', 'ADA', 'DOGE', 'DOT', 'MATIC', 'SHIB'];
const DEFAULT_BALANCE = 0;
const ARBITRAGE_RATE = 0.05; // 5% arbitrage opportunity

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:<OWlondlAbn3bJuj4>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://website-xi-ten-52.vercel.app',
  credentials: true
}));
app.use(mongoSanitize());
app.use(xss());
app.use(cookieParser());
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));
app.use(morgan('dev'));
app.use('/api', limiter);

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'] },
  lastName: { type: String, required: [true, 'Last name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: { 
    type: String,
    minlength: 8,
    select: false
  },
  walletAddress: { type: String, unique: true, sparse: true },
  country: { type: String, required: [true, 'Country is required'] },
  currency: { type: String, default: 'USD' },
  balance: { 
    type: Map,
    of: Number,
    default: () => {
      const balances = {};
      COINS.forEach(coin => balances[coin] = DEFAULT_BALANCE);
      return balances;
    }
  },
  apiKey: { type: String, select: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  kycDocuments: [{
    documentType: String,
    documentUrl: String,
    uploadedAt: Date
  }],
  isAdmin: { type: Boolean, default: false },
  active: { type: Boolean, default: true },
  lastLogin: Date,
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date
}, { timestamps: true });

UserSchema.methods.generateAuthToken = function() {
  return jwt.sign({ id: this._id, isAdmin: this.isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  fromCoin: { type: String, required: true, uppercase: true },
  toCoin: { type: String, required: true, uppercase: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  completedAt: Date
}, { timestamps: true });

const Trade = mongoose.model('Trade', TradeSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  amount: { type: Number, required: true },
  coin: { type: String, required: true, uppercase: true },
  address: String,
  txHash: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' }
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const TicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    isAdmin: Boolean,
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Ticket = mongoose.model('Ticket', TicketSchema);

const FAQSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true },
  category: { type: String, required: true }
});

const FAQ = mongoose.model('FAQ', FAQSchema);

// Helper functions
const signToken = id => jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  };
  
  res.cookie('jwt', token, cookieOptions);
  
  user.password = undefined;
  
  res.status(statusCode).json({
    status: 'success',
    token,
    data: { user }
  });
};

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Simulated price data
const getSimulatedPrices = () => {
  const prices = {};
  COINS.forEach(coin => {
    // Simulate price fluctuations between -7.65% and +15.89%
    const fluctuation = -0.0765 + Math.random() * (0.1589 + 0.0765);
    const basePrice = 100 * (1 + fluctuation);
    prices[coin] = parseFloat(basePrice.toFixed(4));
  });
  return prices;
};

// Calculate exchange rates with arbitrage
const calculateRates = (from, to) => {
  const prices = getSimulatedPrices();
  if (from === to) return 1;
  
  const directRate = prices[to] / prices[from];
  // Simulate arbitrage opportunity 5% of the time
  const hasArbitrage = Math.random() < 0.05;
  
  return hasArbitrage ? directRate * (1 + ARBITRAGE_RATE) : directRate;
};

// Auth middleware
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
    
    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id);
    
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
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

// File upload middleware
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image! Please upload only images.'), false);
    }
  }
});

// WebSocket connections
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = await jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (!user) {
        socket.emit('error', 'User not found');
        return socket.disconnect();
      }
      
      socket.userId = user._id;
      socket.join(user._id.toString());
      
      socket.emit('authenticated', { userId: user._id });
    } catch (err) {
      socket.emit('error', 'Authentication failed');
      socket.disconnect();
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

adminIo.on('connection', (socket) => {
  console.log('New admin connected');
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = await jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (!user || !user.isAdmin) {
        socket.emit('error', 'Admin not found');
        return socket.disconnect();
      }
      
      socket.userId = user._id;
      socket.join('admins');
      
      socket.emit('authenticated', { userId: user._id });
    } catch (err) {
      socket.emit('error', 'Authentication failed');
      socket.disconnect();
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Admin disconnected');
  });
});

// Routes

// Core Authentication & Session Endpoints
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
      password: await bcrypt.hash(password, 12),
      country,
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, country, currency } = req.body;
    
    // Verify signature
    const web3 = new Web3();
    const recoveredAddress = web3.eth.accounts.recover('Welcome to our platform', signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid signature'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      walletAddress,
      country,
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
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
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;
    
    // Verify signature
    const web3 = new Web3();
    const recoveredAddress = web3.eth.accounts.recover('Welcome back to our platform', signature);
    
    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid signature'
      });
    }
    
    const user = await User.findOne({ walletAddress });
    
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'No user found with this wallet address'
      });
    }
    
    user.lastLogin = Date.now();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
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

app.get('/api/v1/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/auth/verify', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { user: req.user }
  });
});

app.get('/api/v1/auth/status', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { isAuthenticated: true, user: req.user }
  });
});

app.get('/api/v1/auth/check', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { isValid: true }
  });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    
    if (!user) {
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a reset link'
      });
    }
    
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    
    const resetURL = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
    
    await transporter.sendMail({
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
    await user.save({ validateBeforeSave: false });
    
    res.status(500).json({
      status: 'fail',
      message: 'There was an error sending the email. Try again later!'
    });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet address is required'
      });
    }
    
    const nonce = Math.floor(Math.random() * 1000000).toString();
    
    res.status(200).json({
      status: 'success',
      data: { nonce }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// User Management Endpoints
app.get('/api/v1/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: { 
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        country: user.country,
        currency: user.currency,
        kycStatus: user.kycStatus
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.patch('/api/v1/users/settings', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'country', 'currency');
    
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: { user: updatedUser }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.patch('/api/v1/auth/update-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordChangedAt = Date.now() - 1000;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/users/kyc', protect, upload.array('documents', 3), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.kycStatus === 'approved') {
      return res.status(400).json({
        status: 'fail',
        message: 'KYC already approved'
      });
    }
    
    const uploadPromises = req.files.map(file => 
      new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream({ resource_type: 'auto' }, (error, result) => {
          if (error) reject(error);
          else resolve({
            documentType: file.originalname.split('.')[0],
            documentUrl: result.secure_url,
            uploadedAt: Date.now()
          });
        }).end(file.buffer);
      })
    );
    
    const documents = await Promise.all(uploadPromises);
    
    user.kycStatus = 'pending';
    user.kycDocuments = documents;
    await user.save();
    
    res.status(200).json({
      status: 'success',
      message: 'KYC documents uploaded successfully'
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/users/generate-api-key', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const apiKey = crypto.randomBytes(32).toString('hex');
    
    user.apiKey = apiKey;
    await user.save();
    
    res.status(200).json({
      status: 'success',
      data: { apiKey }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/users/export-data', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // In a real app, you would generate a file and send it via email or download
    res.status(200).json({
      status: 'success',
      message: 'Data export request received. You will receive an email shortly.'
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.delete('/api/v1/users/delete-account', protect, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { active: false });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
    const user = await User.findOne({ email, isAdmin: true }).select('+password');
    
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
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/verify', protect, restrictToAdmin, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { isAdmin: true }
  });
});

app.get('/api/v1/admin/dashboard-stats', protect, restrictToAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const tradesCount = await Trade.countDocuments();
    const transactionsCount = await Transaction.countDocuments();
    
    res.status(200).json({
      status: 'success',
      data: {
        users: usersCount,
        activeUsers: activeUsersCount,
        trades: tradesCount,
        transactions: transactionsCount
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users', protect, restrictToAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password -apiKey');
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      data: { users }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/users/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -apiKey');
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/users/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    }).select('-password -apiKey');
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/trades', protect, restrictToAdmin, async (req, res) => {
  try {
    const trades = await Trade.find().populate('user', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: { trades }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/transactions', protect, restrictToAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find().populate('user', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: { transactions }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/tickets/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    
    res.status(200).json({
      status: 'success',
      data: { ticket }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/tickets/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const ticket = await Ticket.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: { ticket }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/kyc/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('kycStatus kycDocuments');
    
    res.status(200).json({
      status: 'success',
      data: { kyc: user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.put('/api/v1/admin/kyc/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid KYC status'
      });
    }
    
    const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: status }, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/logs', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would query logs from a logging system
    res.status(200).json({
      status: 'success',
      data: { logs: [] }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/broadcast', protect, restrictToAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    io.emit('broadcast', { message });
    
    res.status(200).json({
      status: 'success',
      message: 'Broadcast sent successfully'
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/admin/settings', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would fetch settings from a database
    res.status(200).json({
      status: 'success',
      data: { settings: {} }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/admin/settings', protect, restrictToAdmin, async (req, res) => {
  try {
    // In a real app, you would save settings to a database
    res.status(200).json({
      status: 'success',
      message: 'Settings updated successfully'
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Exchange & Market Endpoints
app.get('/exchange/coins', (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { coins: COINS }
  });
});

app.get('/exchange/rates', (req, res) => {
  const rates = {};
  COINS.forEach(fromCoin => {
    rates[fromCoin] = {};
    COINS.forEach(toCoin => {
      rates[fromCoin][toCoin] = calculateRates(fromCoin, toCoin);
    });
  });
  
  res.status(200).json({
    status: 'success',
    data: { rates }
  });
});

app.get('/exchange/rate', (req, res) => {
  const { from, to } = req.query;
  
  if (!from || !to) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide from and to currencies'
    });
  }
  
  if (!COINS.includes(from) || !COINS.includes(to)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid currency'
    });
  }
  
  const rate = calculateRates(from, to);
  
  res.status(200).json({
    status: 'success',
    data: { from, to, rate }
  });
});

app.post('/exchange/convert', protect, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide from, to and amount'
      });
    }
    
    if (!COINS.includes(from) || !COINS.includes(to)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid currency'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (user.balance.get(from) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const rate = calculateRates(from, to);
    const convertedAmount = amount * rate;
    
    // Start transaction
    user.balance.set(from, user.balance.get(from) - amount);
    user.balance.set(to, (user.balance.get(to) || 0) + convertedAmount);
    
    const trade = await Trade.create({
      user: user._id,
      type: 'buy',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    
    await Transaction.create({
      user: user._id,
      type: 'trade',
      amount,
      coin: from,
      status: 'completed'
    });
    
    await user.save();
    
    // Emit balance update
    io.to(user._id.toString()).emit('balanceUpdate', { 
      balances: user.balance,
      tradeId: trade._id
    });
    
    res.status(200).json({
      status: 'success',
      data: { 
        from, 
        to, 
        amount, 
        rate, 
        convertedAmount,
        newBalances: user.balance
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/exchange/history', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ user: req.user.id })
      .sort('-createdAt')
      .limit(10);
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: { trades }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/market/data', (req, res) => {
  const prices = getSimulatedPrices();
  const marketData = COINS.map(coin => ({
    symbol: coin,
    price: prices[coin],
    change24h: -7.65 + Math.random() * (15.89 + 7.65) // Random change between -7.65% and +15.89%
  }));
  
  res.status(200).json({
    status: 'success',
    data: { marketData }
  });
});

app.get('/market/detailed', (req, res) => {
  const prices = getSimulatedPrices();
  const detailedData = COINS.map(coin => ({
    symbol: coin,
    price: prices[coin],
    change24h: -7.65 + Math.random() * (15.89 + 7.65),
    high24h: prices[coin] * (1 + Math.random() * 0.1),
    low24h: prices[coin] * (1 - Math.random() * 0.1),
    volume: Math.random() * 1000000
  }));
  
  res.status(200).json({
    status: 'success',
    data: { detailedData }
  });
});

// Wallet & Portfolio Endpoints
app.get('/wallet/deposit-address', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: { address: DEPOSIT_ADDRESS }
  });
});

app.post('/wallet/withdraw', protect, async (req, res) => {
  try {
    const { coin, amount, address } = req.body;
    
    if (!coin || !amount || !address) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide coin, amount and address'
      });
    }
    
    if (!COINS.includes(coin)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid coin'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (user.balance.get(coin) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // In a real app, you would process the withdrawal here
    user.balance.set(coin, user.balance.get(coin) - amount);
    await user.save();
    
    const transaction = await Transaction.create({
      user: user._id,
      type: 'withdrawal',
      amount,
      coin,
      address,
      status: 'pending'
    });
    
    // Emit balance update
    io.to(user._id.toString()).emit('balanceUpdate', { 
      balances: user.balance,
      transactionId: transaction._id
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Withdrawal request submitted',
      data: { transaction }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/portfolio', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const trades = await Trade.find({ user: req.user.id, status: 'completed' })
      .sort('-createdAt')
      .limit(5);
    
    const transactions = await Transaction.find({ user: req.user.id })
      .sort('-createdAt')
      .limit(5);
    
    res.status(200).json({
      status: 'success',
      data: { 
        balances: user.balance,
        recentTrades: trades,
        recentTransactions: transactions
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Trading Endpoints
app.post('/api/v1/trades/buy', protect, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide from, to and amount'
      });
    }
    
    if (!COINS.includes(from) || !COINS.includes(to)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid currency'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (user.balance.get(from) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const rate = calculateRates(from, to);
    const convertedAmount = amount * rate;
    
    // Start transaction
    user.balance.set(from, user.balance.get(from) - amount);
    user.balance.set(to, (user.balance.get(to) || 0) + convertedAmount);
    
    const trade = await Trade.create({
      user: user._id,
      type: 'buy',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    
    await Transaction.create({
      user: user._id,
      type: 'trade',
      amount,
      coin: from,
      status: 'completed'
    });
    
    await user.save();
    
    // Emit balance update
    io.to(user._id.toString()).emit('balanceUpdate', { 
      balances: user.balance,
      tradeId: trade._id
    });
    
    res.status(200).json({
      status: 'success',
      data: { 
        from, 
        to, 
        amount, 
        rate, 
        convertedAmount,
        newBalances: user.balance
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/trades/sell', protect, async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide from, to and amount'
      });
    }
    
    if (!COINS.includes(from) || !COINS.includes(to)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid currency'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (user.balance.get(from) < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const rate = calculateRates(from, to);
    const convertedAmount = amount * rate;
    
    // Start transaction
    user.balance.set(from, user.balance.get(from) - amount);
    user.balance.set(to, (user.balance.get(to) || 0) + convertedAmount);
    
    const trade = await Trade.create({
      user: user._id,
      type: 'sell',
      fromCoin: from,
      toCoin: to,
      amount,
      rate,
      status: 'completed'
    });
    
    await Transaction.create({
      user: user._id,
      type: 'trade',
      amount,
      coin: from,
      status: 'completed'
    });
    
    await user.save();
    
    // Emit balance update
    io.to(user._id.toString()).emit('balanceUpdate', { 
      balances: user.balance,
      tradeId: trade._id
    });
    
    res.status(200).json({
      status: 'success',
      data: { 
        from, 
        to, 
        amount, 
        rate, 
        convertedAmount,
        newBalances: user.balance
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/trades/active', protect, async (req, res) => {
  try {
    const trades = await Trade.find({ user: req.user.id, status: 'pending' })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      data: { trades }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/transactions/recent', protect, async (req, res) => {
  try {
    const transactions = await Transaction.find({ user: req.user.id })
      .sort('-createdAt')
      .limit(10);
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: { transactions }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Support & Contact Endpoints
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = await FAQ.find();
    
    res.status(200).json({
      status: 'success',
      results: faqs.length,
      data: { faqs }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/support/contact', async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    
    if (!email || !subject || !message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email, subject and message'
      });
    }
    
    const ticket = await Ticket.create({
      email,
      subject,
      message
    });
    
    res.status(201).json({
      status: 'success',
      message: 'Ticket created successfully',
      data: { ticket }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/support/tickets', protect, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide subject and message'
      });
    }
    
    const ticket = await Ticket.create({
      user: req.user.id,
      email: req.user.email,
      subject,
      message
    });
    
    res.status(201).json({
      status: 'success',
      message: 'Ticket created successfully',
      data: { ticket }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/support/my-tickets', protect, async (req, res) => {
  try {
    const tickets = await Ticket.find({ user: req.user.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: { tickets }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/support', protect, upload.array('attachments', 3), async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide subject and message'
      });
    }
    
    const uploadPromises = req.files.map(file => 
      new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream({ resource_type: 'auto' }, (error, result) => {
          if (error) reject(error);
          else resolve(result.secure_url);
        }).end(file.buffer);
      })
    );
    
    const attachments = await Promise.all(uploadPromises);
    
    const ticket = await Ticket.create({
      user: req.user.id,
      email: req.user.email,
      subject,
      message,
      attachments
    });
    
    res.status(201).json({
      status: 'success',
      message: 'Ticket created successfully',
      data: { ticket }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Team & Stats Endpoints
app.get('/api/v1/team', async (req, res) => {
  try {
    // In a real app, you would fetch team data from a database
    const team = [
      { name: 'John Doe', role: 'CEO', bio: 'Founder and CEO of the platform' },
      { name: 'Jane Smith', role: 'CTO', bio: 'Technical lead and blockchain expert' },
      { name: 'Mike Johnson', role: 'CFO', bio: 'Financial strategist and investor' }
    ];
    
    res.status(200).json({
      status: 'success',
      results: team.length,
      data: { team }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const tradesCount = await Trade.countDocuments();
    const transactionsCount = await Transaction.countDocuments();
    
    res.status(200).json({
      status: 'success',
      data: {
        users: usersCount,
        activeUsers: activeUsersCount,
        trades: tradesCount,
        transactions: transactionsCount
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Serve static files (for frontend)
app.use(express.static('public'));

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

module.exports = app;
