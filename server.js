require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { ethers } = require('ethers');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();

// WebSocket server
const server = require('http').createServer(app);
const wss = new WebSocket.Server({ server });
const adminWss = new WebSocket.Server({ noServer: true });

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:<OWlondlAbn3bJuj4>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const COOKIE_EXPIRES = process.env.COOKIE_EXPIRES || 30;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DEPOSIT_WALLET = process.env.DEPOSIT_WALLET || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const EMAIL_USER = process.env.EMAIL_USER || '7c707ac161af1c';
const EMAIL_PASS = process.env.EMAIL_PASS || '6c08aa4f2c679a';
const EMAIL_HOST = process.env.EMAIL_HOST || 'sandbox.sandbox.smtp.mailtrap.io';
const EMAIL_PORT = process.env.EMAIL_PORT || 2525;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Enhanced CORS configuration
const corsOptions = {
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  optionsSuccessStatus: 200
};

// Middleware
app.use(helmet());
app.options('*', cors(corsOptions)); // Enable preflight for all routes
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use('/api', limiter);

// Database connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email transporter
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

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
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Mongoose models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'] },
  lastName: { type: String, required: [true, 'Last name is required'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  password: { 
    type: String, 
    select: false,
    minlength: [8, 'Password must be at least 8 characters long'],
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }
  },
  walletAddress: { type: String, unique: true, sparse: true },
  nonce: { type: String, select: false },
  country: { type: String, required: [true, 'Country is required'] },
  currency: { type: String, default: 'USD', enum: ['USD', 'EUR', 'GBP', 'BTC', 'ETH'] },
  balance: { 
    type: Map,
    of: Number,
    default: {
      BTC: 0,
      ETH: 0,
      USDT: 0,
      BNB: 0,
      XRP: 0,
      SOL: 0,
      ADA: 0,
      DOGE: 0,
      DOT: 0,
      SHIB: 0
    }
  },
  kycStatus: { type: String, enum: ['not_submitted', 'pending', 'approved', 'rejected'], default: 'not_submitted' },
  kycDocs: [{
    docType: { type: String, enum: ['id', 'proof_of_address', 'selfie'] },
    docUrl: String,
    uploadedAt: Date
  }],
  apiKey: { type: String, select: false },
  isAdmin: { type: Boolean, default: false },
  active: { type: Boolean, default: true },
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Number },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date
}, { timestamps: true });

UserSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

UserSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

UserSchema.methods.generateNonce = function() {
  this.nonce = crypto.randomBytes(16).toString('hex');
  return this.nonce;
};

UserSchema.methods.generateApiKey = function() {
  this.apiKey = crypto.randomBytes(32).toString('hex');
  return this.apiKey;
};

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  completedAt: Date
}, { timestamps: true });

const Trade = mongoose.model('Trade', TradeSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'transfer'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  txHash: String,
  address: String,
  fee: { type: Number, default: 0 },
  completedAt: Date
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const TicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: function() { return !this.user; } },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    fromAdmin: Boolean,
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Ticket = mongoose.model('Ticket', TicketSchema);

const AdminLogSchema = new mongoose.Schema({
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  targetUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  targetModel: String,
  targetId: mongoose.Schema.Types.ObjectId,
  changes: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String
}, { timestamps: true });

const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

const SystemSettingSchema = new mongoose.Schema({
  maintenanceMode: { type: Boolean, default: false },
  tradingEnabled: { type: Boolean, default: true },
  withdrawalsEnabled: { type: Boolean, default: true },
  depositEnabled: { type: Boolean, default: true },
  tradeFee: { type: Number, default: 0.0025 }, // 0.25%
  withdrawalFee: { type: Map, of: Number, default: {} },
  lastUpdatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const SystemSetting = mongoose.model('SystemSetting', SystemSettingSchema);

const CoinSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  change24h: { type: Number, default: 0 },
  high24h: { type: Number, default: 0 },
  low24h: { type: Number, default: 0 },
  volume24h: { type: Number, default: 0 },
  marketCap: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now }
});

const Coin = mongoose.model('Coin', CoinSchema);

// Initialize default coins if not exists
async function initializeCoins() {
  const defaultCoins = [
    { symbol: 'BTC', name: 'Bitcoin', price: 50000, change24h: 2.5 },
    { symbol: 'ETH', name: 'Ethereum', price: 3000, change24h: -1.2 },
    { symbol: 'USDT', name: 'Tether', price: 1, change24h: 0 },
    { symbol: 'BNB', name: 'Binance Coin', price: 400, change24h: 3.7 },
    { symbol: 'XRP', name: 'XRP', price: 0.5, change24h: 5.2 },
    { symbol: 'SOL', name: 'Solana', price: 100, change24h: -2.3 },
    { symbol: 'ADA', name: 'Cardano', price: 0.8, change24h: 1.8 },
    { symbol: 'DOGE', name: 'Dogecoin', price: 0.15, change24h: 10.5 },
    { symbol: 'DOT', name: 'Polkadot', price: 20, change24h: -3.1 },
    { symbol: 'SHIB', name: 'Shiba Inu', price: 0.000025, change24h: 15.8 }
  ];

  for (const coin of defaultCoins) {
    await Coin.findOneAndUpdate(
      { symbol: coin.symbol },
      { $setOnInsert: coin },
      { upsert: true, new: true }
    );
  }
}

initializeCoins();

// Initialize system settings if not exists
async function initializeSystemSettings() {
  const settings = await SystemSetting.findOne();
  if (!settings) {
    await SystemSetting.create({
      tradeFee: 0.0025,
      withdrawalFee: {
        BTC: 0.0005,
        ETH: 0.005,
        USDT: 10
      }
    });
  }
}

initializeSystemSettings();

// JWT token generation
const signToken = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.isAdmin);
  const cookieOptions = {
    expires: new Date(Date.now() + COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove sensitive data from output
  user.password = undefined;
  user.nonce = undefined;
  user.apiKey = undefined;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

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

    const decoded = await jwt.verify(token, JWT_SECRET);
    const currentUser = await User.findById(decoded.id);

    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
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

// WebSocket authentication
const authenticateWebSocket = async (token) => {
  try {
    if (!token) return null;
    const decoded = await jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    return user;
  } catch (err) {
    return null;
  }
};

// WebSocket connections
const clients = new Map();
const adminClients = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  authenticateWebSocket(token).then(user => {
    if (!user) {
      ws.close(1008, 'Unauthorized');
      return;
    }
    
    clients.set(user._id.toString(), ws);
    
    ws.on('message', (message) => {
      // Handle incoming messages (e.g., balance updates, notifications)
      console.log(`Received message from user ${user._id}: ${message}`);
    });
    
    ws.on('close', () => {
      clients.delete(user._id.toString());
    });
    
    // Send initial data
    ws.send(JSON.stringify({
      type: 'connection_success',
      message: 'WebSocket connection established'
    }));
  });
});

server.on('upgrade', (request, socket, head) => {
  if (request.url === '/api/v1/admin/ws') {
    const token = request.headers['sec-websocket-protocol'];
    
    authenticateWebSocket(token).then(user => {
      if (!user || !user.isAdmin) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      
      adminWss.handleUpgrade(request, socket, head, (ws) => {
        adminClients.set(user._id.toString(), ws);
        
        ws.on('message', (message) => {
          // Handle admin messages
          console.log(`Received admin message from ${user._id}: ${message}`);
        });
        
        ws.on('close', () => {
          adminClients.delete(user._id.toString());
        });
        
        ws.send(JSON.stringify({
          type: 'admin_connection_success',
          message: 'Admin WebSocket connection established'
        }));
      });
    });
  } else {
    socket.destroy();
  }
});

// Broadcast to all connected clients
const broadcastToClients = (userId, data) => {
  const ws = clients.get(userId.toString());
  if (ws) {
    ws.send(JSON.stringify(data));
  }
};

const broadcastToAdminClients = (data) => {
  adminClients.forEach((ws) => {
    ws.send(JSON.stringify(data));
  });
};

// Helper functions
const getCoinPrices = async () => {
  const coins = await Coin.find();
  return coins.reduce((acc, coin) => {
    acc[coin.symbol] = coin.price;
    return acc;
  }, {});
};

const calculateConversionRate = (fromCoin, toCoin, prices) => {
  if (!prices[fromCoin] || !prices[toCoin]) return null;
  return prices[fromCoin] / prices[toCoin];
};

const updateUserBalance = async (userId, coin, amount) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  
  const currentBalance = user.balance.get(coin) || 0;
  user.balance.set(coin, currentBalance + amount);
  await user.save();
  
  // Notify user of balance change
  broadcastToClients(userId, {
    type: 'balance_update',
    coin,
    balance: user.balance.get(coin)
  });
  
  return user;
};

// Routes

// Core Authentication & Session
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
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already exists'
      });
    }
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
  try {
    const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid wallet address'
      });
    }
    
    // Verify signature
    const signingAddress = ethers.utils.verifyMessage('Welcome to our platform!', signature);
    if (signingAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid signature'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      walletAddress,
      country,
      currency
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet address already exists'
      });
    }
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
    
    const user = await User.findOne({ email }).select('+password +loginAttempts +lockUntil');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
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

app.get('/api/v1/auth/me', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user
    }
  });
});

app.get('/auth/verify', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user
    }
  });
});

app.get('/api/v1/auth/status', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      isAuthenticated: true,
      user: req.user
    }
  });
});

app.get('/api/v1/auth/check', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      isAuthenticated: true,
      user: req.user
    }
  });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'There is no user with that email address'
      });
    }
    
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    
    const resetURL = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
    
    try {
      await transporter.sendMail({
        from: 'support@cryptotrading.com',
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
      await user.save({ validateBeforeSave: false });
      
      return res.status(500).json({
        status: 'fail',
        message: 'There was an error sending the email. Try again later!'
      });
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid wallet address'
      });
    }
    
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      // Create a temporary user if not exists
      user = new User({
        walletAddress,
        firstName: 'Wallet',
        lastName: 'User',
        email: `${walletAddress}@wallet.com`,
        password: crypto.randomBytes(32).toString('hex'),
        country: 'Unknown',
        currency: 'USD'
      });
    }
    
    const nonce = user.generateNonce();
    await user.save();
    
    res.status(200).json({
      status: 'success',
      data: {
        nonce
      }
    });
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
    
    if (!ethers.utils.isAddress(walletAddress)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid wallet address'
      });
    }
    
    const user = await User.findOne({ walletAddress }).select('+nonce');
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'No user found with this wallet address'
      });
    }
    
    // Verify signature
    const signingAddress = ethers.utils.verifyMessage(user.nonce, signature);
    if (signingAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid signature'
      });
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// User Management
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
    res.status(400).json({
      status: 'fail',
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
        settings: {
          currency: user.currency,
          notifications: true, // Default for demo
          twoFactorEnabled: false // Default for demo
        }
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
    const { currency, notifications, twoFactorEnabled } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { currency },
      { new: true, runValidators: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: {
          currency: user.currency,
          notifications,
          twoFactorEnabled
        }
      }
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
    
    const user = await User.findById(req.user._id).select('+password');
    
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    user.password = newPassword;
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

app.post('/api/v1/users/kyc', protect, upload.array('documents'), async (req, res) => {
  try {
    const { docType } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please upload at least one document'
      });
    }
    
    const user = await User.findById(req.user._id);
    
    files.forEach(file => {
      user.kycDocs.push({
        docType,
        docUrl: `/uploads/${file.filename}`,
        uploadedAt: new Date()
      });
    });
    
    user.kycStatus = 'pending';
    await user.save();
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
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
    const user = await User.findById(req.user._id);
    const apiKey = user.generateApiKey();
    await user.save();
    
    res.status(200).json({
      status: 'success',
      data: {
        apiKey
      }
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
    const user = await User.findById(req.user._id);
    const trades = await Trade.find({ user: req.user._id });
    const transactions = await Transaction.find({ user: req.user._id });
    
    const data = {
      user,
      trades,
      transactions
    };
    
    // In a real app, you would generate a file and email it
    res.status(200).json({
      status: 'success',
      data
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
    await User.findByIdAndDelete(req.user._id);
    
    // Clean up related data
    await Trade.deleteMany({ user: req.user._id });
    await Transaction.deleteMany({ user: req.user._id });
    await Ticket.updateMany(
      { user: req.user._id },
      { $unset: { user: 1 }, email: 'deleted@user.com' }
    );
    
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });
    
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
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
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
    data: {
      isAdmin: true,
      user: req.user
    }
  });
});

app.get('/api/v1/admin/dashboard-stats', protect, restrictToAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const tradesCount = await Trade.countDocuments();
    const transactionsCount = await Transaction.countDocuments();
    const pendingTicketsCount = await Ticket.countDocuments({ status: 'open' });
    
    res.status(200).json({
      status: 'success',
      data: {
        usersCount,
        activeUsersCount,
        tradesCount,
        transactionsCount,
        pendingTicketsCount
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const users = await User.find()
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments();
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        users
      }
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
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
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
    const { active, kycStatus } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active, kycStatus },
      { new: true, runValidators: true }
    );
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user._id,
      action: 'update_user',
      targetUser: user._id,
      changes: { active, kycStatus }
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find()
      .populate('user', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Trade.countDocuments();
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      total,
      data: {
        trades
      }
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find()
      .populate('user', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Transaction.countDocuments();
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
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
    const ticket = await Ticket.findById(req.params.id)
      .populate('user', 'firstName lastName email');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
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
    const { status, response } = req.body;
    
    const ticket = await Ticket.findById(req.params.id);
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    if (status) ticket.status = status;
    
    if (response) {
      ticket.responses.push({
        message: response,
        fromAdmin: true
      });
    }
    
    await ticket.save();
    
    // Log admin action
    await AdminLog.create({
      admin: req.user._id,
      action: 'update_ticket',
      targetId: ticket._id,
      targetModel: 'Ticket',
      changes: { status, response }
    });
    
    // Notify user if they're connected via WebSocket
    if (ticket.user) {
      broadcastToClients(ticket.user, {
        type: 'ticket_update',
        ticketId: ticket._id,
        status: ticket.status
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
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
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        kycDocs: user.kycDocs,
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

app.put('/api/v1/admin/kyc/:id', protect, restrictToAdmin, async (req, res) => {
  try {
    const { kycStatus, rejectionReason } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus, ...(rejectionReason && { kycRejectionReason: rejectionReason }) },
      { new: true, runValidators: true }
    );
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user._id,
      action: 'update_kyc',
      targetUser: user._id,
      changes: { kycStatus, rejectionReason }
    });
    
    // Notify user
    broadcastToClients(user._id, {
      type: 'kyc_update',
      status: user.kycStatus,
      ...(rejectionReason && { rejectionReason })
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const logs = await AdminLog.find()
      .populate('admin', 'firstName lastName email')
      .populate('targetUser', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await AdminLog.countDocuments();
    
    res.status(200).json({
      status: 'success',
      results: logs.length,
      total,
      data: {
        logs
      }
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
    
    if (!message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a message to broadcast'
      });
    }
    
    // Broadcast to all connected clients
    clients.forEach((ws) => {
      ws.send(JSON.stringify({
        type: 'broadcast',
        message
      }));
    });
    
    // Log admin action
    await AdminLog.create({
      admin: req.user._id,
      action: 'broadcast',
      changes: { message }
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Broadcast sent to all connected users'
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
    const settings = await SystemSetting.findOne();
    
    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
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
    const { maintenanceMode, tradingEnabled, withdrawalsEnabled, depositEnabled, tradeFee, withdrawalFee } = req.body;
    
    const settings = await SystemSetting.findOneAndUpdate(
      {},
      { maintenanceMode, tradingEnabled, withdrawalsEnabled, depositEnabled, tradeFee, withdrawalFee, lastUpdatedBy: req.user._id },
      { new: true, upsert: true }
    );
    
    // Log admin action
    await AdminLog.create({
      admin: req.user._id,
      action: 'update_settings',
      changes: { maintenanceMode, tradingEnabled, withdrawalsEnabled, depositEnabled, tradeFee, withdrawalFee }
    });
    
    // Broadcast settings change to admins
    broadcastToAdminClients({
      type: 'settings_update',
      settings
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Exchange & Market
app.get('/exchange/coins', async (req, res) => {
  try {
    const coins = await Coin.find();
    
    res.status(200).json({
      status: 'success',
      results: coins.length,
      data: {
        coins
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/exchange/rates', async (req, res) => {
  try {
    const coins = await Coin.find();
    const rates = {};
    
    // Generate all possible conversion rates
    for (let i = 0; i < coins.length; i++) {
      for (let j = 0; j < coins.length; j++) {
        if (i !== j) {
          const key = `${coins[i].symbol}_${coins[j].symbol}`;
          rates[key] = coins[i].price / coins[j].price;
        }
      }
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        rates
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/exchange/rate', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide from and to coin symbols'
      });
    }
    
    const fromCoin = await Coin.findOne({ symbol: from.toUpperCase() });
    const toCoin = await Coin.findOne({ symbol: to.toUpperCase() });
    
    if (!fromCoin || !toCoin) {
      return res.status(404).json({
        status: 'fail',
        message: 'One or both coins not found'
      });
    }
    
    const rate = fromCoin.price / toCoin.price;
    
    res.status(200).json({
      status: 'success',
      data: {
        from: fromCoin.symbol,
        to: toCoin.symbol,
        rate
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/exchange/convert', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    if (!fromCoin || !toCoin || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide fromCoin, toCoin and amount'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user._id);
    const fromBalance = user.balance.get(fromCoin) || 0;
    
    if (fromBalance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const fromCoinData = await Coin.findOne({ symbol: fromCoin });
    const toCoinData = await Coin.findOne({ symbol: toCoin });
    
    if (!fromCoinData || !toCoinData) {
      return res.status(404).json({
        status: 'fail',
        message: 'One or both coins not found'
      });
    }
    
    const systemSettings = await SystemSetting.findOne();
    const rate = fromCoinData.price / toCoinData.price;
    const fee = amount * systemSettings.tradeFee;
    const convertedAmount = (amount - fee) * rate;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct from coin
      user.balance.set(fromCoin, fromBalance - amount);
      
      // Add to coin
      const toBalance = user.balance.get(toCoin) || 0;
      user.balance.set(toCoin, toBalance + convertedAmount);
      
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        user: req.user._id,
        type: 'buy',
        fromCoin,
        toCoin,
        amount,
        rate,
        fee,
        status: 'completed',
        completedAt: new Date()
      }], { session });
      
      // Create transaction record
      await Transaction.create([{
        user: req.user._id,
        type: 'trade',
        amount: -amount,
        currency: fromCoin,
        status: 'completed'
      }, {
        user: req.user._id,
        type: 'trade',
        amount: convertedAmount,
        currency: toCoin,
        status: 'completed'
      }], { session });
      
      await session.commitTransaction();
      
      // Notify user of balance changes
      broadcastToClients(user._id, {
        type: 'balance_update',
        updates: [
          { coin: fromCoin, balance: user.balance.get(fromCoin) },
          { coin: toCoin, balance: user.balance.get(toCoin) }
        ]
      });
      
      res.status(200).json({
        status: 'success',
        data: {
          fromCoin,
          toCoin,
          amount,
          convertedAmount,
          fee,
          rate,
          trade: trade[0]
        }
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/exchange/history', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find({ user: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Trade.countDocuments({ user: req.user._id });
    
    res.status(200).json({
      status: 'success',
      results: trades.length,
      total,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/market/data', async (req, res) => {
  try {
    const coins = await Coin.find();
    
    const marketData = coins.map(coin => ({
      symbol: coin.symbol,
      name: coin.name,
      price: coin.price,
      change24h: coin.change24h,
      high24h: coin.high24h,
      low24h: coin.low24h,
      volume24h: coin.volume24h,
      marketCap: coin.marketCap
    }));
    
    res.status(200).json({
      status: 'success',
      data: {
        marketData
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/market/detailed', async (req, res) => {
  try {
    const coins = await Coin.find();
    
    const detailedData = coins.map(coin => ({
      symbol: coin.symbol,
      name: coin.name,
      price: coin.price,
      change24h: coin.change24h,
      high24h: coin.high24h,
      low24h: coin.low24h,
      volume24h: coin.volume24h,
      marketCap: coin.marketCap,
      lastUpdated: coin.lastUpdated
    }));
    
    res.status(200).json({
      status: 'success',
      data: {
        detailedData
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Wallet & Portfolio
app.get('/wallet/deposit-address', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      address: DEPOSIT_WALLET,
      memo: `For user ${req.user._id}`
    }
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
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user._id);
    const balance = user.balance.get(coin) || 0;
    
    if (balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    const systemSettings = await SystemSetting.findOne();
    const fee = systemSettings.withdrawalFee[coin] || 0;
    const totalAmount = amount + fee;
    
    if (balance < totalAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient balance to cover amount + fee (${fee} ${coin})`
      });
    }
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct balance
      user.balance.set(coin, balance - totalAmount);
      await user.save({ session });
      
      // Create transaction record
      const transaction = await Transaction.create([{
        user: req.user._id,
        type: 'withdrawal',
        amount: -totalAmount,
        currency: coin,
        status: 'pending',
        address,
        fee
      }], { session });
      
      await session.commitTransaction();
      
      // Notify user of balance change
      broadcastToClients(user._id, {
        type: 'balance_update',
        coin,
        balance: user.balance.get(coin)
      });
      
      // Notify admins
      broadcastToAdminClients({
        type: 'new_withdrawal',
        transaction: transaction[0]
      });
      
      res.status(200).json({
        status: 'success',
        data: {
          transaction: transaction[0]
        }
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/api/v1/portfolio', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const coins = await Coin.find();
    const transactions = await Transaction.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    const portfolio = Array.from(user.balance.entries())
      .filter(([_, balance]) => balance > 0)
      .map(([symbol, balance]) => {
        const coin = coins.find(c => c.symbol === symbol);
        return {
          symbol,
          name: coin?.name || symbol,
          balance,
          value: coin ? balance * coin.price : 0
        };
      });
    
    const totalValue = portfolio.reduce((sum, item) => sum + item.value, 0);
    
    res.status(200).json({
      status: 'success',
      data: {
        portfolio,
        totalValue,
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

// Trading
app.post('/api/v1/trades/buy', protect, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    
    if (!coin || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide coin and amount'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('USDT') || 0;
    
    if (usdBalance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient USDT balance'
      });
    }
    
    const coinData = await Coin.findOne({ symbol: coin });
    
    if (!coinData) {
      return res.status(404).json({
        status: 'fail',
        message: 'Coin not found'
      });
    }
    
    const systemSettings = await SystemSetting.findOne();
    const rate = 1 / coinData.price; // USDT to coin rate
    const fee = amount * systemSettings.tradeFee;
    const coinAmount = (amount - fee) * rate;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct USDT
      user.balance.set('USDT', usdBalance - amount);
      
      // Add coin
      const coinBalance = user.balance.get(coin) || 0;
      user.balance.set(coin, coinBalance + coinAmount);
      
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        user: req.user._id,
        type: 'buy',
        fromCoin: 'USDT',
        toCoin: coin,
        amount,
        rate,
        fee,
        status: 'completed',
        completedAt: new Date()
      }], { session });
      
      // Create transaction record
      await Transaction.create([{
        user: req.user._id,
        type: 'trade',
        amount: -amount,
        currency: 'USDT',
        status: 'completed'
      }, {
        user: req.user._id,
        type: 'trade',
        amount: coinAmount,
        currency: coin,
        status: 'completed'
      }], { session });
      
      await session.commitTransaction();
      
      // Notify user of balance changes
      broadcastToClients(user._id, {
        type: 'balance_update',
        updates: [
          { coin: 'USDT', balance: user.balance.get('USDT') },
          { coin, balance: user.balance.get(coin) }
        ]
      });
      
      res.status(200).json({
        status: 'success',
        data: {
          coin,
          amount,
          coinAmount,
          fee,
          rate,
          trade: trade[0]
        }
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/trades/sell', protect, async (req, res) => {
  try {
    const { coin, amount } = req.body;
    
    if (!coin || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide coin and amount'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(req.user._id);
    const coinBalance = user.balance.get(coin) || 0;
    
    if (coinBalance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient ${coin} balance`
      });
    }
    
    const coinData = await Coin.findOne({ symbol: coin });
    
    if (!coinData) {
      return res.status(404).json({
        status: 'fail',
        message: 'Coin not found'
      });
    }
    
    const systemSettings = await SystemSetting.findOne();
    const rate = coinData.price; // coin to USDT rate
    const fee = amount * rate * systemSettings.tradeFee;
    const usdAmount = amount * rate - fee;
    
    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Deduct coin
      user.balance.set(coin, coinBalance - amount);
      
      // Add USDT
      const usdBalance = user.balance.get('USDT') || 0;
      user.balance.set('USDT', usdBalance + usdAmount);
      
      await user.save({ session });
      
      // Create trade record
      const trade = await Trade.create([{
        user: req.user._id,
        type: 'sell',
        fromCoin: coin,
        toCoin: 'USDT',
        amount,
        rate,
        fee,
        status: 'completed',
        completedAt: new Date()
      }], { session });
      
      // Create transaction record
      await Transaction.create([{
        user: req.user._id,
        type: 'trade',
        amount: -amount,
        currency: coin,
        status: 'completed'
      }, {
        user: req.user._id,
        type: 'trade',
        amount: usdAmount,
        currency: 'USDT',
        status: 'completed'
      }], { session });
      
      await session.commitTransaction();
      
      // Notify user of balance changes
      broadcastToClients(user._id, {
        type: 'balance_update',
        updates: [
          { coin, balance: user.balance.get(coin) },
          { coin: 'USDT', balance: user.balance.get('USDT') }
        ]
      });
      
      res.status(200).json({
        status: 'success',
        data: {
          coin,
          amount,
          usdAmount,
          fee,
          rate,
          trade: trade[0]
        }
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.get('/trades/active', protect, async (req, res) => {
  try {
    const activeTrades = await Trade.find({ user: req.user._id, status: 'pending' })
      .sort({ createdAt: -1 });
    
    res.status(200).json({
      status: 'success',
      data: {
        activeTrades
      }
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
    const recentTransactions = await Transaction.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.status(200).json({
      status: 'success',
      data: {
        recentTransactions
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Support & Contact
app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'General',
        questions: [
          {
            question: 'What is this platform?',
            answer: 'This is a cryptocurrency trading platform where you can buy, sell, and trade various digital assets.'
          },
          {
            question: 'How do I get started?',
            answer: 'Simply sign up for an account, complete the verification process, and you can start trading.'
          }
        ]
      },
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I reset my password?',
            answer: 'Click on the "Forgot Password" link on the login page and follow the instructions.'
          },
          {
            question: 'Is two-factor authentication available?',
            answer: 'Yes, you can enable 2FA in your account settings for added security.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'What are the trading fees?',
            answer: 'Our standard trading fee is 0.25% per trade. VIP members may qualify for lower fees.'
          },
          {
            question: 'How long do trades take to complete?',
            answer: 'Most trades are executed instantly, but some may take a few minutes depending on market conditions.'
          }
        ]
      }
    ];
    
    res.status(200).json({
      status: 'success',
      data: {
        faqs
      }
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
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields'
      });
    }
    
    const ticket = await Ticket.create({
      email,
      subject,
      message,
      attachments: []
    });
    
    // Send confirmation email
    await transporter.sendMail({
      from: 'support@cryptotrading.com',
      to: email,
      subject: 'Your support ticket has been received',
      text: `Thank you for contacting us. Your ticket #${ticket._id} has been received and we'll get back to you soon.`
    });
    
    // Notify admins
    broadcastToAdminClients({
      type: 'new_ticket',
      ticket
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
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
      user: req.user._id,
      subject,
      message,
      attachments: []
    });
    
    // Notify user
    broadcastToClients(req.user._id, {
      type: 'ticket_created',
      ticket
    });
    
    // Notify admins
    broadcastToAdminClients({
      type: 'new_ticket',
      ticket
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
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
    const tickets = await Ticket.find({ user: req.user._id })
      .sort({ createdAt: -1 });
    
    res.status(200).json({
      status: 'success',
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

app.post('/api/v1/support', protect, upload.array('attachments'), async (req, res) => {
  try {
    const { subject, message } = req.body;
    const attachments = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    if (!subject || !message) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide subject and message'
      });
    }
    
    const ticket = await Ticket.create({
      user: req.user._id,
      subject,
      message,
      attachments
    });
    
    // Notify user
    broadcastToClients(req.user._id, {
      type: 'ticket_created',
      ticket
    });
    
    // Notify admins
    broadcastToAdminClients({
      type: 'new_ticket',
      ticket
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Team & Stats
app.get('/api/v1/team', async (req, res) => {
  try {
    const team = [
      {
        name: 'John Doe',
        position: 'CEO',
        bio: 'Founder and CEO with 10+ years of experience in blockchain technology.',
        image: '/images/team/john.jpg'
      },
      {
        name: 'Jane Smith',
        position: 'CTO',
        bio: 'Technical lead with expertise in cryptocurrency exchanges and security.',
        image: '/images/team/jane.jpg'
      },
      {
        name: 'Mike Johnson',
        position: 'Head of Trading',
        bio: 'Former Wall Street trader now focused on crypto markets.',
        image: '/images/team/mike.jpg'
      }
    ];
    
    res.status(200).json({
      status: 'success',
      data: {
        team
      }
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
    const activeTrades = await Trade.countDocuments({ status: 'pending' });
    const completedTrades = await Trade.countDocuments({ status: 'completed' });
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.status(200).json({
      status: 'success',
      data: {
        usersCount,
        activeTrades,
        completedTrades,
        totalVolume: totalVolume[0]?.total || 0
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
});

// Serve static files (for uploaded documents)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Update coin prices periodically (simulating market changes)
setInterval(async () => {
  try {
    const coins = await Coin.find();
    
    for (const coin of coins) {
      if (coin.symbol === 'USDT') continue; // Stablecoin
      
      // Simulate price change (-7.65% to +15.89%)
      const changePercent = -7.65 + Math.random() * 23.54;
      const changeFactor = 1 + (changePercent / 100);
      
      coin.price = parseFloat((coin.price * changeFactor).toFixed(2));
      coin.change24h = parseFloat(changePercent.toFixed(2));
      
      // Update high/low based on new price
      if (coin.price > coin.high24h || !coin.high24h) {
        coin.high24h = coin.price;
      }
      if (coin.price < coin.low24h || !coin.low24h) {
        coin.low24h = coin.price;
      }
      
      // Simulate volume
      coin.volume24h = parseFloat((coin.volume24h * (0.9 + Math.random() * 0.2)).toFixed(2));
      
      await coin.save();
    }
    
    // Notify all clients of price updates
    const prices = coins.reduce((acc, coin) => {
      acc[coin.symbol] = coin.price;
      return acc;
    }, {});
    
    clients.forEach(ws => {
      ws.send(JSON.stringify({
        type: 'price_update',
        prices
      }));
    });
    
    adminClients.forEach(ws => {
      ws.send(JSON.stringify({
        type: 'price_update',
        prices
      }));
    });
  } catch (err) {
    console.error('Error updating coin prices:', err);
  }
}, 30000); // Update every 30 seconds
