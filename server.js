require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');

// Initialize Express app
const app = express();

// Middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// CORS configuration
const corsOptions = {
  origin: ['https://website-xi-ten-52.vercel.app', 'https://website-xi-ten-52.vercel.app/'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

// Database connection
const DB = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(DB, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('DB connection successful!'));

// Schemas
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'] },
  lastName: { type: String, required: [true, 'Last name is required'] },
  email: { type: String, required: [true, 'Email is required'], unique: true, lowercase: true },
  password: { type: String, select: false },
  country: { type: String, required: [true, 'Country is required'] },
  currency: { type: String, default: 'USD' },
  walletAddress: { type: String },
  walletProvider: { type: String },
  balance: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: true }, // Changed to true as per your requirement
  isAdmin: { type: Boolean, default: false },
  registrationCompleted: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDetails: {
    documentType: String,
    documentNumber: String,
    documentImage: String,
    selfieImage: String
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['super', 'support', 'kyc'], default: 'support' },
  lastLogin: Date,
  active: { type: Boolean, default: true }
});

adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const Admin = mongoose.model('Admin', adminSchema);

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell', 'arbitrage'], required: true },
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
  userId: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'fee', 'bonus'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  reference: { type: String, required: true },
  description: String,
  createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

const supportTicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    fromAdmin: Boolean,
    adminId: { type: mongoose.Schema.ObjectId, ref: 'Admin' },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  }
});

// JWT
const signToken = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET || '17581758Na.%', {
    expiresIn: process.env.JWT_EXPIRES_IN || '30d'
  });
};

const createSendToken = (user, statusCode, res, isAdmin = false) => {
  const token = signToken(user._id, isAdmin);
  
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 30) * 24 * 60 * 60 * 1000
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

// WebSocket Server
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`App running on port ${process.env.PORT || 3000}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'auth' && data.token) {
        jwt.verify(data.token, process.env.JWT_SECRET || '17581758Na.%', (err, decoded) => {
          if (err) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
            return ws.close();
          }
          
          ws.userId = decoded.id;
          ws.isAdmin = decoded.isAdmin;
          
          ws.send(JSON.stringify({ type: 'auth', status: 'success' }));
        });
      }
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

const broadcastToUser = (userId, data) => {
  wss.clients.forEach((client) => {
    if (client.userId === userId.toString() && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

const broadcastToAdmins = (data) => {
  wss.clients.forEach((client) => {
    if (client.isAdmin && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
};

// Routes
app.get('/api/v1/status', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'API is running'
  });
});

// Auth Routes
app.post('/api/v1/auth/signup', [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must contain at least one uppercase, one lowercase, one number and one special character'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  }),
  body('country').notEmpty().withMessage('Country is required'),
  body('currency').notEmpty().withMessage('Currency is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }
    
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency,
      registrationCompleted: false
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    if (!user.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated'
      });
    }
    
    user.lastLogin = Date.now();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/auth/wallet-login', async (req, res, next) => {
  try {
    const { walletAddress, walletProvider, signature } = req.body;
    
    if (!walletAddress || !walletProvider || !signature) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide wallet address, provider and signature'
      });
    }
    
    // In a real app, you would verify the signature here
    // For demo purposes, we'll skip that
    
    let user = await User.findOne({ walletAddress });
    
    if (!user) {
      // Create new user if not exists
      user = await User.create({
        walletAddress,
        walletProvider,
        isVerified: true,
        registrationCompleted: true
      });
    }
    
    if (!user.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated'
      });
    }
    
    user.lastLogin = Date.now();
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
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

app.post('/api/v1/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal if user exists or not
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }
    
    // Generate reset token
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || '17581758Na.%', {
      expiresIn: '10m'
    });
    
    // Send email
    const resetURL = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
    
    try {
      await transporter.sendMail({
        from: 'support@cryptotradingmarket.com',
        to: user.email,
        subject: 'Your password reset token (valid for 10 minutes)',
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
        status: 'error',
        message: 'There was an error sending the email. Try again later!'
      });
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/auth/reset-password/:token', [
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must contain at least one uppercase, one lowercase, one number and one special character'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  })
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.params;
    const { password } = req.body;
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'User no longer exists'
      });
    }
    
    user.password = password;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/auth/verify', async (req, res, next) => {
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
        message: 'The user belonging to this token no longer exists.'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        user: currentUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

// Protect middleware
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
        message: 'The user belonging to this token no longer exists.'
      });
    }
    
    if (!currentUser.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated'
      });
    }
    
    req.user = currentUser;
    next();
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
};

// Admin protect middleware
const adminProtect = async (req, res, next) => {
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
    
    if (!decoded.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }
    
    if (!currentAdmin.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated'
      });
    }
    
    req.admin = currentAdmin;
    next();
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
};

// User Routes
app.get('/api/v1/users/me', protect, async (req, res, next) => {
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
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/users/complete-registration', protect, async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { registrationCompleted: true },
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
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/users/update-password', protect, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must contain at least one uppercase, one lowercase, one number and one special character'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.newPassword) {
      throw new Error('Passwords do not match');
    }
    return true;
  })
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }
    
    user.password = newPassword;
    await user.save();
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/users/update-me', protect, [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('country').notEmpty().withMessage('Country is required'),
  body('currency').notEmpty().withMessage('Currency is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, country, currency } = req.body;
    
    if (email !== req.user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Email already in use'
        });
      }
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { firstName, lastName, email, country, currency },
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
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/users/kyc', protect, async (req, res, next) => {
  try {
    const { documentType, documentNumber, documentImage, selfieImage } = req.body;
    
    if (!documentType || !documentNumber || !documentImage || !selfieImage) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required KYC details'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        kycStatus: 'pending',
        kycDetails: {
          documentType,
          documentNumber,
          documentImage,
          selfieImage
        }
      },
      { new: true }
    );
    
    // Notify admins
    broadcastToAdmins({
      type: 'KYC_SUBMITTED',
      userId: user._id,
      message: 'New KYC submission'
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
      message: 'Something went wrong'
    });
  }
});

// Trade Routes
app.get('/api/v1/trades', protect, async (req, res, next) => {
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
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/trades/buy', protect, [
  body('fromCoin').notEmpty().withMessage('From coin is required'),
  body('toCoin').notEmpty().withMessage('To coin is required'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // In a real app, you would fetch the current rate from an exchange API
    // For demo purposes, we'll use a fixed rate
    const rate = 0.85; // Example rate
    
    // Calculate fee (1% of amount)
    const fee = amount * 0.01;
    const totalAmount = amount + fee;
    
    // Check if user has enough balance
    const user = await User.findById(req.user.id);
    
    if (user.balance < totalAmount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct from balance
    user.balance -= totalAmount;
    await user.save();
    
    // Create trade
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'buy',
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed'
    });
    
    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      amount: -totalAmount,
      currency: fromCoin,
      status: 'completed',
      reference: `TRADE-${trade._id}`,
      description: `Buy ${toCoin} with ${fromCoin}`
    });
    
    // Send real-time update
    broadcastToUser(req.user.id, {
      type: 'TRADE_UPDATE',
      trade,
      balance: user.balance
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/trades/sell', protect, [
  body('fromCoin').notEmpty().withMessage('From coin is required'),
  body('toCoin').notEmpty().withMessage('To coin is required'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // In a real app, you would fetch the current rate from an exchange API
    // For demo purposes, we'll use a fixed rate
    const rate = 1.15; // Example rate
    
    // Calculate fee (1% of amount)
    const fee = amount * 0.01;
    const receivedAmount = (amount * rate) - fee;
    
    // Create trade
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'sell',
      fromCoin,
      toCoin,
      amount,
      rate,
      fee,
      status: 'completed'
    });
    
    // Add to balance
    const user = await User.findById(req.user.id);
    user.balance += receivedAmount;
    await user.save();
    
    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      amount: receivedAmount,
      currency: toCoin,
      status: 'completed',
      reference: `TRADE-${trade._id}`,
      description: `Sell ${fromCoin} for ${toCoin}`
    });
    
    // Send real-time update
    broadcastToUser(req.user.id, {
      type: 'TRADE_UPDATE',
      trade,
      balance: user.balance
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        trade
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/trades/arbitrage', protect, [
  body('fromCoin').notEmpty().withMessage('From coin is required'),
  body('toCoin').notEmpty().withMessage('To coin is required'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { fromCoin, toCoin, amount } = req.body;
    
    // In a real app, you would implement actual arbitrage logic
    // For demo purposes, we'll simulate a profitable arbitrage opportunity
    
    // Simulate finding a profitable arbitrage opportunity
    const buyRate = 0.85; // Rate when buying
    const sellRate = 1.15; // Rate when selling
    
    // Calculate arbitrage profit (5% of amount)
    const profit = amount * 0.05;
    const totalAmount = amount + profit;
    
    // Check if user has enough balance
    const user = await User.findById(req.user.id);
    
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct initial amount
    user.balance -= amount;
    
    // Add profit
    user.balance += totalAmount;
    await user.save();
    
    // Create trade
    const trade = await Trade.create({
      userId: req.user.id,
      type: 'arbitrage',
      fromCoin,
      toCoin,
      amount,
      rate: buyRate, // Using buy rate as reference
      fee: 0, // No fee for arbitrage in this demo
      status: 'completed'
    });
    
    // Create transaction record
    await Transaction.create({
      userId: req.user.id,
      type: 'trade',
      amount: profit,
      currency: toCoin,
      status: 'completed',
      reference: `ARBITRAGE-${trade._id}`,
      description: `Arbitrage trade between ${fromCoin} and ${toCoin}`
    });
    
    // Send real-time update
    broadcastToUser(req.user.id, {
      type: 'TRADE_UPDATE',
      trade,
      balance: user.balance
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        trade,
        profit
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

// Transaction Routes
app.get('/api/v1/transactions', protect, async (req, res, next) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.id }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

// Support Routes
app.get('/api/v1/support/tickets', protect, async (req, res, next) => {
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
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/support/tickets', protect, [
  body('subject').notEmpty().withMessage('Subject is required'),
  body('message').notEmpty().withMessage('Message is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { subject, message } = req.body;
    
    const ticket = await SupportTicket.create({
      userId: req.user.id,
      email: req.user.email,
      subject,
      message,
      status: 'open'
    });
    
    // Notify admins
    broadcastToAdmins({
      type: 'NEW_TICKET',
      ticketId: ticket._id,
      message: 'New support ticket created'
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/support/tickets/:id', protect, async (req, res, next) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.id,
      userId: req.user.id
    });
    
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
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/support/tickets/:id/reply', protect, [
  body('message').notEmpty().withMessage('Message is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user.id
      },
      {
        $push: {
          responses: {
            message,
            fromAdmin: false,
            adminId: null
          }
        }
      },
      { new: true }
    );
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    // Notify admins
    broadcastToAdmins({
      type: 'TICKET_REPLY',
      ticketId: ticket._id,
      message: 'New reply to support ticket'
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

// Admin Routes
app.post('/api/v1/admin/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email }).select('+password');
    
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    if (!admin.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated'
      });
    }
    
    admin.lastLogin = Date.now();
    await admin.save();
    
    createSendToken(admin, 200, res, true);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res, next) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const totalTrades = await Trade.countDocuments();
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
        totalUsers,
        verifiedUsers,
        totalTrades,
        totalVolume: totalVolume.length ? totalVolume[0].total : 0
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/users', adminProtect, async (req, res, next) => {
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/users/:id', adminProtect, async (req, res, next) => {
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
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/admin/users/:id', adminProtect, async (req, res, next) => {
  try {
    const { active, balance, kycStatus } = req.body;
    
    const update = {};
    if (active !== undefined) update.active = active;
    if (balance !== undefined) update.balance = balance;
    if (kycStatus) {
      update.kycStatus = kycStatus;
      if (kycStatus === 'verified') {
        update.kycDetails = req.user.kycDetails;
      }
    }
    
    const user = await User.findByIdAndUpdate(req.params.id, update, {
      new: true,
      runValidators: true
    });
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    // Send real-time update if balance changed
    if (balance !== undefined) {
      broadcastToUser(user._id, {
        type: 'BALANCE_UPDATE',
        balance: user.balance
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/trades', adminProtect, async (req, res, next) => {
  try {
    const trades = await Trade.find().populate('userId').sort('-createdAt');
    
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/transactions', adminProtect, async (req, res, next) => {
  try {
    const transactions = await Transaction.find().populate('userId').sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/tickets', adminProtect, async (req, res, next) => {
  try {
    const tickets = await SupportTicket.find().populate('userId').sort('-createdAt');
    
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/tickets/:id', adminProtect, async (req, res, next) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id).populate('userId');
    
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
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/admin/tickets/:id/assign', adminProtect, async (req, res, next) => {
  try {
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      {
        status: 'in-progress',
        $push: {
          responses: {
            message: `Ticket assigned to ${req.admin.firstName} ${req.admin.lastName}`,
            fromAdmin: true,
            adminId: req.admin._id
          }
        }
      },
      { new: true }
    ).populate('userId');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    // Notify user
    if (ticket.userId) {
      broadcastToUser(ticket.userId._id, {
        type: 'TICKET_UPDATE',
        ticketId: ticket._id,
        message: 'Your ticket has been assigned to a support agent'
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
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/admin/tickets/:id/resolve', adminProtect, async (req, res, next) => {
  try {
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      {
        status: 'resolved',
        $push: {
          responses: {
            message: 'Ticket marked as resolved',
            fromAdmin: true,
            adminId: req.admin._id
          }
        }
      },
      { new: true }
    ).populate('userId');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    // Notify user
    if (ticket.userId) {
      broadcastToUser(ticket.userId._id, {
        type: 'TICKET_UPDATE',
        ticketId: ticket._id,
        message: 'Your ticket has been resolved'
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
      message: 'Something went wrong'
    });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', adminProtect, [
  body('message').notEmpty().withMessage('Message is required')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { message } = req.body;
    
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id,
      {
        $push: {
          responses: {
            message,
            fromAdmin: true,
            adminId: req.admin._id
          }
        }
      },
      { new: true }
    ).populate('userId');
    
    if (!ticket) {
      return res.status(404).json({
        status: 'fail',
        message: 'No ticket found with that ID'
      });
    }
    
    // Notify user
    if (ticket.userId) {
      broadcastToUser(ticket.userId._id, {
        type: 'TICKET_UPDATE',
        ticketId: ticket._id,
        message: 'New reply from support'
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
      message: 'Something went wrong'
    });
  }
});

app.get('/api/v1/admin/kyc', adminProtect, async (req, res, next) => {
  try {
    const kycSubmissions = await User.find({ kycStatus: 'pending' });
    
    res.status(200).json({
      status: 'success',
      results: kycSubmissions.length,
      data: {
        kycSubmissions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/approve', adminProtect, async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'verified' },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_UPDATE',
      status: 'verified',
      message: 'Your KYC has been approved'
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
      message: 'Something went wrong'
    });
  }
});

app.patch('/api/v1/admin/kyc/:id/reject', adminProtect, async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: 'rejected', kycDetails: null },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    
    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_UPDATE',
      status: 'rejected',
      message: 'Your KYC has been rejected'
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
      message: 'Something went wrong'
    });
  }
});

// Error handling for unhandled routes
app.all('*', (req, res, next) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  res.status(500).json({
    status: 'error',
    message: 'Something went very wrong!'
  });
});

process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err);
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
