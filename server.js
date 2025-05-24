require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const { createLogger, format, transports } = require('winston');
const { StatusCodes } = require('http-status-codes');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const axios = require('axios');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Configure Winston logger
const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' }),
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  ]
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: [
    'https://website-xi-ten-52.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Performance middleware
app.use(compression());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000
})
.then(() => logger.info('MongoDB connected successfully'))
.catch(err => logger.error('MongoDB connection error:', err));

// Database models
const userSchema = new mongoose.Schema({
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
      message: props => `${props.value} is not a valid email!`
    }
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  walletAddress: { type: String, default: null },
  walletProvider: { type: String, default: null },
  country: { type: String, required: [true, 'Country is required'] },
  currency: { type: String, default: 'USD', enum: ['USD', 'EUR', 'GBP'] },
  balance: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  kycStatus: { 
    type: String, 
    enum: ['none', 'pending', 'verified', 'rejected'], 
    default: 'none' 
  },
  kycDocs: [{
    type: { type: String, enum: ['passport', 'id', 'license'] },
    front: String,
    back: String,
  }],
  isAdmin: { type: Boolean, default: false },
  settings: {
    theme: { type: String, default: 'light', enum: ['light', 'dark'] },
    notifications: { type: Boolean, default: true },
    twoFA: { type: Boolean, default: false },
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  apiKey: String,
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ walletAddress: 1 }, { unique: true, sparse: true });

// Password hashing middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (err) {
    next(err);
  }
});

const User = mongoose.model('User', userSchema);

// Other models (Trade, Transaction, Ticket, FAQ, Coin) would be similarly defined
// with proper validation and error handling...

// Error handling middleware
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;
  err.status = err.status || 'error';

  logger.error(`${err.statusCode} - ${err.message}`);

  if (process.env.NODE_ENV === 'production') {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message
    });
  } else {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      error: err,
      stack: err.stack
    });
  }
};

// Auth routes with proper error handling
app.post('/api/v1/auth/signup', async (req, res, next) => {
  try {
    const { firstName, lastName, email, password, country, currency } = req.body;
    
    // Validate input
    if (!firstName || !lastName || !email || !password || !country) {
      throw new AppError('Please provide all required fields', StatusCodes.BAD_REQUEST);
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new AppError('Email already in use', StatusCodes.CONFLICT);
    }

    // Create user
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET || '17581758Na.%', { 
      expiresIn: '1d' 
    });

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      country,
      currency: currency || 'USD',
      verificationToken,
      balance: 0
    });

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify?token=${verificationToken}`;
    await sendEmail({
      email: user.email,
      subject: 'Verify your email',
      message: `Please click on the following link to verify your email: ${verificationUrl}`
    });

    res.status(StatusCodes.CREATED).json({
      status: 'success',
      message: 'Verification email sent'
    });

  } catch (err) {
    next(err);
  }
});

// Email sending utility
const sendEmail = async options => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
    port: process.env.EMAIL_PORT || 2525,
    auth: {
      user: process.env.EMAIL_USER || '7c707ac161af1c',
      pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
    }
  });

  const mailOptions = {
    from: 'Crypto Trading Platform <noreply@cryptotrading.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: options.html
  };

  await transporter.sendMail(mailOptions);
};

// Verification endpoint
app.post('/api/v1/auth/verify', async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!token) {
      throw new AppError('Verification token is required', StatusCodes.BAD_REQUEST);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findOneAndUpdate(
      { email: decoded.email, verificationToken: token },
      { isVerified: true, verificationToken: null },
      { new: true }
    );

    if (!user) {
      throw new AppError('Invalid or expired token', StatusCodes.BAD_REQUEST);
    }

    // Create JWT for immediate login
    const authToken = createToken(user._id);

    res.status(StatusCodes.OK).json({
      status: 'success',
      token: authToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });

  } catch (err) {
    next(err);
  }
});

// JWT token creation
const createToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET || '17581758Na.%', {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

// Login endpoint
app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      throw new AppError('Please provide email and password', StatusCodes.BAD_REQUEST);
    }

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new AppError('Incorrect email or password', StatusCodes.UNAUTHORIZED);
    }

    // 3) Check if user is verified
    if (!user.isVerified) {
      throw new AppError('Please verify your email first', StatusCodes.FORBIDDEN);
    }

    // 4) Update last login
    user.lastLogin = new Date();
    await user.save();

    // 5) If everything ok, send token to client
    const token = createToken(user._id);

    res.status(StatusCodes.OK).json({
      status: 'success',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified,
        isAdmin: user.isAdmin
      }
    });

  } catch (err) {
    next(err);
  }
});

// Protect middleware
const protect = async (req, res, next) => {
  try {
    // 1) Getting token and check if it's there
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      throw new AppError(
        'You are not logged in! Please log in to get access.',
        StatusCodes.UNAUTHORIZED
      );
    }

    // 2) Verification token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      throw new AppError(
        'The user belonging to this token does no longer exist.',
        StatusCodes.UNAUTHORIZED
      );
    }

    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      throw new AppError(
        'User recently changed password! Please log in again.',
        StatusCodes.UNAUTHORIZED
      );
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
  } catch (err) {
    next(err);
  }
};

// Restrict to admin middleware
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new AppError(
        'You do not have permission to perform this action',
        StatusCodes.FORBIDDEN
      );
    }
    next();
  };
};

// WebSocket server
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'auth') {
        try {
          const decoded = jwt.verify(data.token, process.env.JWT_SECRET || '17581758Na.%');
          const user = await User.findById(decoded.id);
          if (user) {
            ws.userId = user._id;
            ws.isAdmin = user.isAdmin;
          }
        } catch (err) {
          ws.close();
        }
      }
    } catch (err) {
      logger.error('WebSocket error:', err);
    }
  });
});

// Global error handler
app.use(errorHandler);

// Handle unhandled promise rejections
process.on('unhandledRejection', err => {
  logger.error('UNHANDLED REJECTION! Shutting down...');
  logger.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', err => {
  logger.error('UNCAUGHT EXCEPTION! Shutting down...');
  logger.error(err.name, err.message);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated!');
  });
});
