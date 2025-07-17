require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Redis = require('ioredis');
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
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');
const path = require('path');

// Initialize Express app
const app = express();

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://bithhash.vercel.app';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com';
const BTC_DEPOSIT_ADDRESS = process.env.BTC_DEPOSIT_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const REDIS_HOST = process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com';
const REDIS_PORT = process.env.REDIS_PORT || 14450;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR';
const SMTP_HOST = process.env.SMTP_HOST || 'sandbox.smtp.mailtrap.io';
const SMTP_PORT = process.env.SMTP_PORT || 2525;
const SMTP_USER = process.env.SMTP_USER || '7c707ac161af1c';
const SMTP_PASS = process.env.SMTP_PASS || '6c08aa4f2c679a';

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(limiter);
app.use(express.static(path.join(__dirname, 'public')));

// Redis client
const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD
});

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email transporter
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS
  }
});

// Google OAuth client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// MongoDB Schemas
const userSchema = new mongoose.Schema({
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
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  city: String,
  country: String,
  phone: String,
  photo: { type: String, default: 'default.jpg' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  active: { type: Boolean, default: true },
  emailVerified: { type: Boolean, default: false },
  verificationToken: String,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: String,
  balance: {
    main: { type: Number, default: 0 },
    active: { type: Number, default: 0 },
    matured: { type: Number, default: 0 },
    savings: { type: Number, default: 0 }
  },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.ObjectId, ref: 'User' },
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'none'], default: 'none' },
  kycDocuments: {
    front: String,
    back: String,
    selfie: String
  },
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  theme: { type: String, enum: ['light', 'dark'], default: 'dark' },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual populate for referrals
userSchema.virtual('referrals', {
  ref: 'User',
  foreignField: 'referredBy',
  localField: '_id'
});

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Pre-save middleware for password change timestamp
userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Method to check password
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Method to check if password changed after token was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

// Method to create verification token
userSchema.methods.createVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  this.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
  return verificationToken;
};

// Method to generate referral code
userSchema.methods.generateReferralCode = function() {
  this.referralCode = crypto.randomBytes(4).toString('hex');
};

// Method to setup 2FA
userSchema.methods.setupTwoFactor = function() {
  const secret = speakeasy.generateSecret({ length: 20 });
  this.twoFactorSecret = secret.base32;
  return secret.otpauth_url;
};

// Method to verify 2FA token
userSchema.methods.verifyTwoFactorToken = function(token) {
  return speakeasy.totp.verify({
    secret: this.twoFactorSecret,
    encoding: 'base32',
    token: token,
    window: 1
  });
};

const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'investment', 'earning', 'bonus', 'referral', 'loan', 'savings'],
    required: true
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  method: { type: String, enum: ['btc', 'credit_card', 'bank_transfer', 'internal'] },
  address: String,
  txHash: String,
  description: String,
  metadata: Object
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  startDate: { type: Date, default: Date.now },
  endDate: Date,
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  earnings: { type: Number, default: 0 },
  transactions: [{ type: mongoose.Schema.ObjectId, ref: 'Transaction' }]
}, { timestamps: true });

const Investment = mongoose.model('Investment', investmentSchema);

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  duration: { type: Number, required: true }, // in days
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number },
  dailyProfit: { type: Number, required: true }, // percentage
  referralBonus: { type: Number, default: 0 }, // percentage
  popular: { type: Boolean, default: false },
  active: { type: Boolean, default: true }
}, { timestamps: true });

const Plan = mongoose.model('Plan', planSchema);

const kycSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  documentType: { type: String, enum: ['id', 'passport', 'driver_license'], required: true },
  documentNumber: { type: String, required: true },
  documentFront: { type: String, required: true },
  documentBack: { type: String },
  selfie: { type: String, required: true },
  status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.ObjectId, ref: 'User' },
  reviewNotes: String
}, { timestamps: true });

const KYC = mongoose.model('KYC', kycSchema);

const loanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  collateral: { type: Number, required: true }, // BTC amount locked as collateral
  duration: { type: Number, required: true }, // in days
  interestRate: { type: Number, required: true }, // percentage
  status: { type: String, enum: ['pending', 'active', 'repaid', 'defaulted'], default: 'pending' },
  dueDate: Date,
  transactions: [{ type: mongoose.Schema.ObjectId, ref: 'Transaction' }]
}, { timestamps: true });

const Loan = mongoose.model('Loan', loanSchema);

const activitySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  ip: String,
  device: String,
  location: String,
  metadata: Object
}, { timestamps: true });

const Activity = mongoose.model('Activity', activitySchema);

const apiKeySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  key: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  permissions: [String],
  lastUsed: Date,
  active: { type: Boolean, default: true }
}, { timestamps: true });

const APIKey = mongoose.model('APIKey', apiKeySchema);

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'] },
  link: String
}, { timestamps: true });

const Notification = mongoose.model('Notification', notificationSchema);

// Helper functions
const signToken = (id, role) => {
  return jwt.sign({ id, role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.role);
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
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

const sendEmail = async (options) => {
  try {
    await transporter.sendMail({
      from: 'Bithash <no-reply@bithash.com>',
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    });
  } catch (err) {
    console.error('Error sending email:', err);
  }
};

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
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
    
    // Verify token
    const decoded = await jwt.verify(token, JWT_SECRET);
    
    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }
    
    // Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
      });
    }
    
    // Check if user is active
    if (!currentUser.active) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been deactivated. Please contact support.'
      });
    }
    
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token. Please log in again.'
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

// Cache middleware
const cache = (key, ttl = 60) => {
  return async (req, res, next) => {
    try {
      const cachedData = await redis.get(key);
      if (cachedData) {
        return res.status(200).json({
          status: 'success',
          data: JSON.parse(cachedData)
        });
      }
      next();
    } catch (err) {
      next();
    }
  };
};

// Routes
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Welcome to Bithash API'
  });
});

// Authentication routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, passwordConfirm, city, referredBy } = req.body;
    
    if (!firstName || !lastName || !email || !password || !passwordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields'
      });
    }
    
    if (password !== passwordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
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
      city,
      referralCode: crypto.randomBytes(4).toString('hex')
    });
    
    // Handle referral if exists
    if (referredBy) {
      const referrer = await User.findOne({ referralCode: referredBy });
      if (referrer) {
        newUser.referredBy = referrer._id;
        await newUser.save();
        
        // Create referral bonus transaction
        await Transaction.create({
          user: referrer._id,
          amount: 10, // $10 referral bonus
          type: 'referral',
          status: 'completed',
          description: `Referral bonus for ${newUser.email}`
        });
        
        // Update referrer's balance
        referrer.balance.main += 10;
        await referrer.save();
      }
    }
    
    // Send welcome email
    const verificationToken = newUser.createVerificationToken();
    await newUser.save({ validateBeforeSave: false });
    
    const verificationUrl = `${FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    const message = `Welcome to Bithash! Please verify your email by clicking on this link: ${verificationUrl}`;
    
    await sendEmail({
      email: newUser.email,
      subject: 'Welcome to Bithash - Verify Your Email',
      message,
      html: `<p>Welcome to Bithash! Please verify your email by clicking on this link: <a href="${verificationUrl}">Verify Email</a></p>`
    });
    
    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
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
        message: 'Your account has been deactivated. Please contact support.'
      });
    }
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      const tempToken = jwt.sign({ id: user._id, requires2FA: true }, JWT_SECRET, { expiresIn: '10m' });
      
      return res.status(200).json({
        status: 'success',
        requires2FA: true,
        tempToken
      });
    }
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Log activity
    await Activity.create({
      user: user._id,
      action: 'login',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { email, given_name, family_name, picture } = payload;
    
    let user = await User.findOne({ email });
    
    if (!user) {
      // Create new user
      user = await User.create({
        firstName: given_name,
        lastName: family_name,
        email,
        photo: picture,
        emailVerified: true,
        referralCode: crypto.randomBytes(4).toString('hex')
      });
      
      // Send welcome email
      await sendEmail({
        email: user.email,
        subject: 'Welcome to Bithash',
        message: 'Thank you for signing up with Google!',
        html: '<p>Thank you for signing up with Google!</p>'
      });
    }
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Log activity
    await Activity.create({
      user: user._id,
      action: 'google_login',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/2fa/verify', async (req, res) => {
  try {
    const { tempToken, token } = req.body;
    
    if (!tempToken || !token) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide both tokens'
      });
    }
    
    const decoded = await jwt.verify(tempToken, JWT_SECRET);
    
    if (!decoded.requires2FA) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    const isVerified = user.verifyTwoFactorToken(token);
    
    if (!isVerified) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid 2FA token'
      });
    }
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Log activity
    await Activity.create({
      user: user._id,
      action: 'login_with_2fa',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email'
      });
    }
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetUrl}.\nIf you didn't forget your password, please ignore this email!`;
    
    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message,
        html: `<p>Forgot your password? Click <a href="${resetUrl}">here</a> to reset it.</p>`
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

app.patch('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    
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
    
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    
    // Log activity
    await Activity.create({
      user: user._id,
      action: 'password_reset',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({
    status: 'success'
  });
});

// User routes
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -twoFactorSecret -verificationToken -passwordResetToken -passwordResetExpires');
    
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

app.get('/api/users/balance', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('balance');
    
    // Get BTC price from Redis or API
    let btcPrice = await redis.get('btc_price');
    
    if (!btcPrice) {
      // In a real app, you would fetch from CoinGecko or similar API
      btcPrice = 50000; // Default value if API fails
      await redis.set('btc_price', btcPrice, 'EX', 60); // Cache for 60 seconds
    } else {
      btcPrice = parseFloat(btcPrice);
    }
    
    // Calculate BTC values
    const balances = {
      main: {
        usd: user.balance.main,
        btc: user.balance.main / btcPrice
      },
      active: {
        usd: user.balance.active,
        btc: user.balance.active / btcPrice
      },
      matured: {
        usd: user.balance.matured,
        btc: user.balance.matured / btcPrice
      },
      savings: {
        usd: user.balance.savings,
        btc: user.balance.savings / btcPrice
      }
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        balances
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/users/profile', protect, async (req, res) => {
  try {
    // Filter out unwanted fields
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'city', 'country', 'phone', 'photo');
    
    // Update user
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret -verificationToken -passwordResetToken -passwordResetExpires');
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'update_profile',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: filteredBody
    });
    
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

app.patch('/api/users/password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;
    
    if (!currentPassword || !newPassword || !newPasswordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields'
      });
    }
    
    if (newPassword !== newPasswordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Current password is incorrect'
      });
    }
    
    user.password = newPassword;
    user.passwordConfirm = newPasswordConfirm;
    await user.save();
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'change_password',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    createSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/users/notifications', protect, async (req, res) => {
  try {
    const { email, sms, push } = req.body;
    
    const user = await User.findByIdAndUpdate(req.user.id, {
      'notifications.email': email,
      'notifications.sms': sms,
      'notifications.push': push
    }, {
      new: true
    }).select('notifications');
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'update_notifications',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { email, sms, push }
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        notifications: user.notifications
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/users/theme', protect, async (req, res) => {
  try {
    const { theme } = req.body;
    
    if (!['light', 'dark'].includes(theme)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid theme value'
      });
    }
    
    const user = await User.findByIdAndUpdate(req.user.id, { theme }, {
      new: true
    }).select('theme');
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'change_theme',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { theme }
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        theme: user.theme
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/users/activity', protect, async (req, res) => {
  try {
    const activities = await Activity.find({ user: req.user.id })
      .sort('-createdAt')
      .limit(50);
    
    res.status(200).json({
      status: 'success',
      results: activities.length,
      data: {
        activities
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/users/deactivate', protect, async (req, res) => {
  try {
    const { reason } = req.body;
    
    await User.findByIdAndUpdate(req.user.id, { active: false });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'account_deactivated',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { reason }
    });
    
    // Send notification email
    await sendEmail({
      email: req.user.email,
      subject: 'Your Bithash account has been deactivated',
      message: `Your account has been deactivated. Reason: ${reason}`,
      html: `<p>Your account has been deactivated. Reason: ${reason}</p>`
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Account deactivated successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// 2FA routes
app.get('/api/auth/2fa/totp/setup', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({
        status: 'fail',
        message: '2FA is already enabled'
      });
    }
    
    const otpauthUrl = user.setupTwoFactor();
    await user.save({ validateBeforeSave: false });
    
    // Generate QR code
    QRCode.toDataURL(otpauthUrl, (err, dataUrl) => {
      if (err) {
        return res.status(500).json({
          status: 'error',
          message: 'Error generating QR code'
        });
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          secret: user.twoFactorSecret,
          qrCode: dataUrl
        }
      });
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/2fa/totp/verify', protect, async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide the token'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (!user.twoFactorSecret) {
      return res.status(400).json({
        status: 'fail',
        message: '2FA is not set up'
      });
    }
    
    const isVerified = user.verifyTwoFactorToken(token);
    
    if (!isVerified) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }
    
    user.twoFactorEnabled = true;
    await user.save();
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'enable_2fa',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    res.status(200).json({
      status: 'success',
      message: '2FA enabled successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/auth/2fa/totp/disable', protect, async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide the token'
      });
    }
    
    const user = await User.findById(req.user.id);
    
    if (!user.twoFactorEnabled) {
      return res.status(400).json({
        status: 'fail',
        message: '2FA is not enabled'
      });
    }
    
    const isVerified = user.verifyTwoFactorToken(token);
    
    if (!isVerified) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }
    
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'disable_2fa',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    res.status(200).json({
      status: 'success',
      message: '2FA disabled successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// KYC routes
app.get('/api/kyc', protect, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ user: req.user.id }).sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      data: {
        kycStatus: kyc ? kyc.status : 'none',
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

app.post('/api/kyc', protect, async (req, res) => {
  try {
    const { documentType, documentNumber, documentFront, documentBack, selfie } = req.body;
    
    if (!documentType || !documentNumber || !documentFront || !selfie) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields'
      });
    }
    
    // Check if user already has pending KYC
    const existingKYC = await KYC.findOne({
      user: req.user.id,
      status: 'pending'
    });
    
    if (existingKYC) {
      return res.status(400).json({
        status: 'fail',
        message: 'You already have a pending KYC submission'
      });
    }
    
    const kyc = await KYC.create({
      user: req.user.id,
      documentType,
      documentNumber,
      documentFront,
      documentBack,
      selfie,
      status: 'pending'
    });
    
    // Update user KYC status
    await User.findByIdAndUpdate(req.user.id, { kycStatus: 'pending' });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'submit_kyc',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });
    
    res.status(201).json({
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

// Referral routes
app.get('/api/referrals', protect, async (req, res) => {
  try {
    const referrals = await User.find({ referredBy: req.user.id })
      .select('firstName lastName email createdAt');
    
    const referralEarnings = await Transaction.aggregate([
      {
        $match: {
          user: req.user._id,
          type: 'referral'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    const totalEarnings = referralEarnings.length > 0 ? referralEarnings[0].total : 0;
    
    res.status(200).json({
      status: 'success',
      data: {
        referrals,
        totalEarnings,
        referralCode: req.user.referralCode,
        referralLink: `${FRONTEND_URL}/signup.html?ref=${req.user.referralCode}`
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Transaction routes
app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, limit = 10, page = 1 } = req.query;
    
    const query = { user: req.user.id };
    if (type) query.type = type;
    
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find(query)
      .sort('-createdAt')
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/transactions/deposit', protect, async (req, res) => {
  try {
    const { amount, method } = req.body;
    
    if (!amount || !method) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and method'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    if (!['btc', 'credit_card', 'bank_transfer'].includes(method)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit method'
      });
    }
    
    const transaction = await Transaction.create({
      user: req.user.id,
      amount,
      type: 'deposit',
      method,
      status: method === 'btc' ? 'pending' : 'completed'
    });
    
    if (method === 'btc') {
      // For BTC deposits, we provide the deposit address
      transaction.address = BTC_DEPOSIT_ADDRESS;
      await transaction.save();
    } else {
      // For other methods, we immediately credit the user's account
      await User.findByIdAndUpdate(req.user.id, {
        $inc: { 'balance.main': amount }
      });
    }
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'deposit',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { amount, method }
    });
    
    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Deposit initiated',
      message: `Your deposit of $${amount} has been initiated`,
      type: 'success'
    });
    
    res.status(201).json({
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

app.post('/api/transactions/withdraw', protect, async (req, res) => {
  try {
    const { amount, method, address, notes } = req.body;
    
    if (!amount || !method || !address) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount, method and address'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    if (!['btc', 'bank_transfer'].includes(method)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid withdrawal method'
      });
    }
    
    // Check user balance
    const user = await User.findById(req.user.id);
    
    if (user.balance.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Check KYC status if withdrawal is > $1000
    if (amount > 1000 && user.kycStatus !== 'verified') {
      return res.status(400).json({
        status: 'fail',
        message: 'KYC verification required for withdrawals over $1000'
      });
    }
    
    // Create withdrawal transaction
    const transaction = await Transaction.create({
      user: req.user.id,
      amount,
      type: 'withdrawal',
      method,
      address,
      description: notes,
      status: 'pending'
    });
    
    // Deduct from user's balance
    user.balance.main -= amount;
    await user.save();
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'withdrawal',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { amount, method }
    });
    
    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Withdrawal requested',
      message: `Your withdrawal of $${amount} is being processed`,
      type: 'info'
    });
    
    res.status(201).json({
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

// Investment routes
app.get('/api/plans', cache('investment_plans'), async (req, res) => {
  try {
    const plans = await Plan.find({ active: true });
    
    // Cache plans for 1 hour
    await redis.set('investment_plans', JSON.stringify(plans), 'EX', 3600);
    
    res.status(200).json({
      status: 'success',
      results: plans.length,
      data: {
        plans
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/investments', protect, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user.id })
      .populate('plan')
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: investments.length,
      data: {
        investments
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/investments', protect, async (req, res) => {
  try {
    const { planId, amount } = req.body;
    
    if (!planId || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide planId and amount'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    // Get plan
    const plan = await Plan.findById(planId);
    
    if (!plan || !plan.active) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    // Check min amount
    if (amount < plan.minAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Minimum investment amount is $${plan.minAmount}`
      });
    }
    
    // Check max amount if exists
    if (plan.maxAmount && amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Maximum investment amount is $${plan.maxAmount}`
      });
    }
    
    // Check user balance
    const user = await User.findById(req.user.id);
    
    if (user.balance.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Create investment
    const investment = await Investment.create({
      user: req.user.id,
      plan: planId,
      amount,
      endDate: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000)
    });
    
    // Deduct from user's balance and add to active balance
    user.balance.main -= amount;
    user.balance.active += amount;
    await user.save();
    
    // Create transaction
    await Transaction.create({
      user: req.user.id,
      amount,
      type: 'investment',
      status: 'completed',
      description: `Investment in ${plan.name} plan`
    });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'create_investment',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { planId, amount }
    });
    
    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Investment created',
      message: `Your investment of $${amount} in ${plan.name} has been created`,
      type: 'success'
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Savings routes
app.post('/api/savings', protect, async (req, res) => {
  try {
    const { amount, duration } = req.body;
    
    if (!amount || !duration) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and duration'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    if (duration <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Duration must be greater than 0'
      });
    }
    
    // Check user balance
    const user = await User.findById(req.user.id);
    
    if (user.balance.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct from main balance and add to savings
    user.balance.main -= amount;
    user.balance.savings += amount;
    await user.save();
    
    // Create transaction
    await Transaction.create({
      user: req.user.id,
      amount,
      type: 'savings',
      status: 'completed',
      description: `Savings deposit for ${duration} days`
    });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'add_savings',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { amount, duration }
    });
    
    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Savings added',
      message: `Your savings of $${amount} has been added`,
      type: 'success'
    });
    
    res.status(201).json({
      status: 'success',
      message: 'Savings added successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Loan routes
app.get('/api/loans', protect, async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.user.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: loans.length,
      data: {
        loans
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/loans', protect, async (req, res) => {
  try {
    const { amount, duration, purpose } = req.body;
    
    if (!amount || !duration) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide amount and duration'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }
    
    if (duration <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Duration must be greater than 0'
      });
    }
    
    // Check user savings balance (collateral is 50% of loan amount)
    const collateral = amount * 0.5;
    const user = await User.findById(req.user.id);
    
    if (user.balance.savings < collateral) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient savings balance. You need at least $${collateral} in savings as collateral`
      });
    }
    
    // Check KYC status
    if (user.kycStatus !== 'verified') {
      return res.status(400).json({
        status: 'fail',
        message: 'KYC verification required for loans'
      });
    }
    
    // Create loan (interest rate is 5% for simplicity)
    const interestRate = 5;
    const loan = await Loan.create({
      user: req.user.id,
      amount,
      collateral,
      duration,
      interestRate,
      dueDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000)
    });
    
    // Lock collateral
    user.balance.savings -= collateral;
    await user.save();
    
    // Create transaction for collateral
    await Transaction.create({
      user: req.user.id,
      amount: collateral,
      type: 'loan',
      status: 'completed',
      description: `Collateral for loan #${loan._id}`
    });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'request_loan',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { amount, duration }
    });
    
    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Loan requested',
      message: `Your loan request of $${amount} is being processed`,
      type: 'info'
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        loan
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Notification routes
app.get('/api/notifications', protect, async (req, res) => {
  try {
    const { limit = 10, page = 1 } = req.query;
    
    const skip = (page - 1) * limit;
    
    const notifications = await Notification.find({ user: req.user.id })
      .sort('-createdAt')
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments({ user: req.user.id });
    
    res.status(200).json({
      status: 'success',
      results: notifications.length,
      total,
      data: {
        notifications
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.patch('/api/notifications/:id/read', protect, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, user: req.user.id },
      { read: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({
        status: 'fail',
        message: 'Notification not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        notification
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// API Key routes
app.get('/api/users/apikeys', protect, async (req, res) => {
  try {
    const apiKeys = await APIKey.find({ user: req.user.id, active: true })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: apiKeys.length,
      data: {
        apiKeys
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/users/apikeys', protect, async (req, res) => {
  try {
    const { name, permissions } = req.body;
    
    if (!name || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide name and permissions array'
      });
    }
    
    const apiKey = await APIKey.create({
      user: req.user.id,
      key: crypto.randomBytes(32).toString('hex'),
      name,
      permissions
    });
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'create_api_key',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { name }
    });
    
    res.status(201).json({
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

app.delete('/api/users/apikeys/:id', protect, async (req, res) => {
  try {
    const apiKey = await APIKey.findOneAndUpdate(
      { _id: req.params.id, user: req.user.id },
      { active: false },
      { new: true }
    );
    
    if (!apiKey) {
      return res.status(404).json({
        status: 'fail',
        message: 'API key not found'
      });
    }
    
    // Log activity
    await Activity.create({
      user: req.user.id,
      action: 'revoke_api_key',
      ip: req.ip,
      device: req.headers['user-agent'],
      location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      metadata: { name: apiKey.name }
    });
    
    res.status(200).json({
      status: 'success',
      message: 'API key revoked successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Admin routes
app.get('/api/admin/stats', protect, restrictTo('admin'), async (req, res) => {
  try {
    // Get stats from Redis if available
    const cachedStats = await redis.get('admin_stats');
    
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedStats)
      });
    }
    
    // Calculate stats
    const usersCount = await User.countDocuments();
    const activeUsersCount = await User.countDocuments({ active: true });
    const transactionsCount = await Transaction.countDocuments();
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
    const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
    
    const stats = {
      users: usersCount,
      activeUsers: activeUsersCount,
      transactions: transactionsCount,
      totalDeposits: totalDeposits.length > 0 ? totalDeposits[0].total : 0,
      totalWithdrawals: totalWithdrawals.length > 0 ? totalWithdrawals[0].total : 0,
      pendingKYC,
      pendingWithdrawals
    };
    
    // Cache stats for 5 minutes
    await redis.set('admin_stats', JSON.stringify(stats), 'EX', 300);
    
    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Global error handler
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
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Process investments daily (simplified example)
setInterval(async () => {
  try {
    const investments = await Investment.find({ status: 'active' });
    
    for (const investment of investments) {
      const plan = await Plan.findById(investment.plan);
      if (!plan) continue;
      
      // Calculate daily earnings
      const dailyEarning = investment.amount * (plan.dailyProfit / 100);
      investment.earnings += dailyEarning;
      
      // Check if investment period is over
      if (new Date() >= investment.endDate) {
        investment.status = 'completed';
        
        // Move from active to matured balance
        const user = await User.findById(investment.user);
        if (user) {
          user.balance.active -= investment.amount;
          user.balance.matured += investment.amount + investment.earnings;
          await user.save();
        }
      }
      
      await investment.save();
      
      // Create earning transaction
      await Transaction.create({
        user: investment.user,
        amount: dailyEarning,
        type: 'earning',
        status: 'completed',
        description: `Daily earnings from investment`
      });
    }
  } catch (err) {
    console.error('Error processing investments:', err);
  }
}, 24 * 60 * 60 * 1000); // Run once per day
