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
const csrf = require('csurf');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: 'https://bithhash.vercel.app',
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
app.use('/api/', limiter);

// Redis client
const redis = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// MongoDB connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT configuration
const JWT_SECRET = '17581758Na.%';
const JWT_EXPIRES_IN = '30d';

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '7c707ac161af1c',
    pass: '6c08aa4f2c679a'
  }
});

// Google OAuth client
const googleClient = new OAuth2Client('634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com');

// File upload configuration
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = './uploads/';
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
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// CSRF protection for admin routes
const adminCsrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String },
  country: { type: String },
  city: { type: String },
  address: { type: String },
  postalCode: { type: String },
  password: { type: String, select: false },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  googleId: { type: String, unique: true, sparse: true },
  isVerified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  twoFactorAuth: { type: Boolean, default: false },
  twoFactorSecret: String,
  kycStatus: {
    identity: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    address: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    facial: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' }
  },
  kycDocuments: [{
    type: { type: String, enum: ['identity', 'address', 'facial'] },
    front: String,
    back: String,
    selfie: String,
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
    reviewedBy: mongoose.Schema.Types.ObjectId,
    reviewedAt: Date,
    rejectionReason: String
  }],
  balances: {
    main: { type: Number, default: 0 },
    investment: { type: Number, default: 0 },
    savings: { type: Number, default: 0 },
    bonus: { type: Number, default: 0 }
  },
  btcAddress: { type: String, default: '' },
  apiKeys: [{
    name: String,
    key: String,
    secret: String,
    permissions: [String],
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  }],
  referralCode: { type: String, unique: true },
  referredBy: mongoose.Schema.Types.ObjectId,
  referralCount: { type: Number, default: 0 },
  referralEarnings: { type: Number, default: 0 },
  lastLogin: Date,
  loginHistory: [{
    ip: String,
    device: String,
    location: String,
    timestamp: { type: Date, default: Date.now }
  }],
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  }
}, { timestamps: true });

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

UserSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

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

UserSchema.methods.generateAuthToken = function() {
  return jwt.sign({ id: this._id, isAdmin: this.isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const User = mongoose.model('User', UserSchema);

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  minAmount: { type: Number, required: true },
  maxAmount: { type: Number, required: true },
  duration: { type: Number, required: true }, // in hours
  percentage: { type: Number, required: true },
  referralBonus: { type: Number, default: 5 },
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const Plan = mongoose.model('Plan', PlanSchema);

const InvestmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  expectedReturn: { type: Number, required: true },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  earnings: { type: Number, default: 0 },
  referralBonusPaid: { type: Boolean, default: false },
  referralBonusAmount: { type: Number, default: 0 }
}, { timestamps: true });

const Investment = mongoose.model('Investment', InvestmentSchema);

const TransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'earning', 'bonus', 'referral'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['btc', 'bank', 'card', 'internal'], required: true },
  reference: { type: String, required: true, unique: true },
  description: { type: String },
  metadata: mongoose.Schema.Types.Mixed,
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  processedAt: Date
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', TransactionSchema);

const LoanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  collateralAmount: { type: Number, required: true },
  collateralCurrency: { type: String, default: 'BTC' },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], default: 'pending' },
  repaymentAmount: { type: Number, required: true },
  startDate: Date,
  endDate: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  repaymentHistory: [{
    amount: Number,
    date: Date,
    transaction: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  }]
}, { timestamps: true });

const Loan = mongoose.model('Loan', LoanSchema);

const AdminActivitySchema = new mongoose.Schema({
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target: { type: String },
  targetId: mongoose.Schema.Types.ObjectId,
  ip: String,
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

const AdminActivity = mongoose.model('AdminActivity', AdminActivitySchema);

// Utility functions
const createAndSendToken = (user, statusCode, res) => {
  const token = user.generateAuthToken();
  const cookieOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };
  
  res.cookie('jwt', token, cookieOptions);
  
  user.password = undefined;
  
  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

const generateApiKey = () => {
  return crypto.randomBytes(16).toString('hex');
};

const generateReference = () => {
  return `TRX-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
};

// Seed initial data
const seedInitialData = async () => {
  // Check if admin exists
  const adminExists = await User.findOne({ email: 'admin@bithash.com' });
  if (!adminExists) {
    const admin = await User.create({
      firstName: 'Admin',
      lastName: 'BitHash',
      email: 'admin@bithash.com',
      password: 'SecureAdminPassword123!',
      isAdmin: true,
      isVerified: true,
      status: 'active',
      referralCode: 'ADMINREF'
    });
    console.log('Admin user created:', admin.email);
  }

  // Check if plans exist
  const plansCount = await Plan.countDocuments();
  if (plansCount === 0) {
    const plans = [
      {
        name: 'Starter Plan',
        description: '20% After 10 hours',
        minAmount: 30,
        maxAmount: 499,
        duration: 10,
        percentage: 20,
        referralBonus: 5
      },
      {
        name: 'Gold Plan',
        description: '40% After 24 hours',
        minAmount: 500,
        maxAmount: 1999,
        duration: 24,
        percentage: 40,
        referralBonus: 5
      },
      {
        name: 'Advance Plan',
        description: '60% After 48 hours',
        minAmount: 2000,
        maxAmount: 9999,
        duration: 48,
        percentage: 60,
        referralBonus: 5
      },
      {
        name: 'Exclusive Plan',
        description: '80% After 72 hours',
        minAmount: 10000,
        maxAmount: 30000,
        duration: 72,
        percentage: 80,
        referralBonus: 5
      },
      {
        name: 'Expert Plan',
        description: '100% After 96 hours',
        minAmount: 50000,
        maxAmount: 1000000,
        duration: 96,
        percentage: 100,
        referralBonus: 5
      }
    ];

    await Plan.insertMany(plans);
    console.log('Initial investment plans seeded');
  }
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

    if (currentUser.status !== 'active') {
      return res.status(403).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
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

const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({
      status: 'fail',
      message: 'This route is restricted to administrators only'
    });
  }
  next();
};

// Routes

// User Authentication Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, referralCode } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    // Check referral code if provided
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (!referrer) {
        return res.status(400).json({
          status: 'fail',
          message: 'Invalid referral code'
        });
      }
      referredBy = referrer._id;
    }

    // Create user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      referredBy,
      referralCode: crypto.randomBytes(4).toString('hex').toUpperCase()
    });

    // Update referrer's referral count if applicable
    if (referredBy) {
      await User.findByIdAndUpdate(referredBy, {
        $inc: { referralCount: 1 }
      });
    }

    // Send welcome email
    const mailOptions = {
      from: 'no-reply@bithash.com',
      to: newUser.email,
      subject: 'Welcome to BitHash',
      html: `<h1>Welcome to BitHash, ${newUser.firstName}!</h1>
             <p>Your account has been successfully created.</p>
             <p>Your referral code: <strong>${newUser.referralCode}</strong></p>`
    };

    await transporter.sendMail(mailOptions);

    createAndSendToken(newUser, 201, res);
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

    if (user.status !== 'active') {
      return res.status(403).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save();

    createAndSendToken(user, 200, res);
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
      audience: '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com'
    });
    const payload = ticket.getPayload();
    
    let user = await User.findOne({ email: payload.email });

    if (!user) {
      // Create new user with Google auth
      user = await User.create({
        firstName: payload.given_name,
        lastName: payload.family_name,
        email: payload.email,
        googleId: payload.sub,
        isVerified: payload.email_verified,
        referralCode: crypto.randomBytes(4).toString('hex').toUpperCase()
      });

      // Send welcome email
      const mailOptions = {
        from: 'no-reply@bithash.com',
        to: user.email,
        subject: 'Welcome to BitHash',
        html: `<h1>Welcome to BitHash, ${user.firstName}!</h1>
               <p>Your account has been successfully created with Google authentication.</p>
               <p>Your referral code: <strong>${user.referralCode}</strong></p>`
      };

      await transporter.sendMail(mailOptions);
    } else if (!user.googleId) {
      // User exists but hasn't used Google auth before - link account
      user.googleId = payload.sub;
      await user.save();
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save();

    createAndSendToken(user, 200, res);
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
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that email address'
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `https://bithhash.vercel.app/reset-password?token=${resetToken}`;

    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
      await transporter.sendMail({
        from: 'no-reply@bithash.com',
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
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createAndSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// User Routes
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -twoFactorSecret -passwordResetToken -passwordResetExpires');

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

app.put('/api/users/profile', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'phone', 'country', 'city');
    
    if (req.body.email) {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser && existingUser._id.toString() !== req.user._id.toString()) {
        return res.status(400).json({
          status: 'fail',
          message: 'Email already in use'
        });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret');

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

app.put('/api/users/address', protect, async (req, res) => {
  try {
    const filteredBody = filterObj(req.body, 'address', 'city', 'country', 'postalCode');
    
    const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret');

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

app.put('/api/users/password', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+password');

    if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong'
      });
    }

    user.password = req.body.newPassword;
    await user.save();

    createAndSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/users/api-keys', protect, async (req, res) => {
  try {
    const { name, permissions, expiresInDays } = req.body;
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (expiresInDays || 30));
    
    const apiKey = {
      name,
      key: generateApiKey(),
      secret: generateApiKey(),
      permissions: permissions || ['read'],
      expiresAt
    };
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $push: { apiKeys: apiKey } },
      { new: true }
    ).select('apiKeys');
    
    res.status(201).json({
      status: 'success',
      data: {
        apiKey: user.apiKeys.find(k => k.key === apiKey.key)
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Admin Routes
app.post('/api/admin/auth/login', async (req, res) => {
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

    if (!user.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access restricted to administrators only'
      });
    }

    if (user.status !== 'active') {
      return res.status(403).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Create CSRF token
    const csrfToken = crypto.randomBytes(32).toString('hex');
    await redis.set(`csrf:${user._id}`, csrfToken, 'EX', 3600); // 1 hour expiration

    // Update last login
    user.lastLogin = Date.now();
    await user.save();

    // Log admin activity
    await AdminActivity.create({
      admin: user._id,
      action: 'login',
      ip: req.ip
    });

    createAndSendToken(user, 200, res);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/admin/auth/logout', protect, isAdmin, async (req, res) => {
  try {
    // Invalidate CSRF token
    await redis.del(`csrf:${req.user._id}`);

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'logout',
      ip: req.ip
    });

    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/dashboard', protect, isAdmin, async (req, res) => {
  try {
    // Cache dashboard data for 5 minutes
    const cachedData = await redis.get('admin:dashboard');
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }

    // Get total users
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ status: 'active' });
    const suspendedUsers = await User.countDocuments({ status: 'suspended' });

    // Get total transactions
    const totalTransactions = await Transaction.countDocuments();
    const completedTransactions = await Transaction.countDocuments({ status: 'completed' });
    const pendingTransactions = await Transaction.countDocuments({ status: 'pending' });

    // Get total investments
    const totalInvestments = await Investment.countDocuments();
    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    const completedInvestments = await Investment.countDocuments({ status: 'completed' });

    // Get total deposits and withdrawals
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    // Get pending KYC
    const pendingKYC = await User.countDocuments({
      $or: [
        { 'kycStatus.identity': 'pending' },
        { 'kycStatus.address': 'pending' },
        { 'kycStatus.facial': 'pending' }
      ]
    });

    // Get pending withdrawals
    const pendingWithdrawals = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'pending'
    });

    const dashboardData = {
      totalUsers,
      activeUsers,
      suspendedUsers,
      totalTransactions,
      completedTransactions,
      pendingTransactions,
      totalInvestments,
      activeInvestments,
      completedInvestments,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      pendingKYC,
      pendingWithdrawals
    };

    // Cache the data
    await redis.set('admin:dashboard', JSON.stringify(dashboardData), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: dashboardData
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/users/growth', protect, isAdmin, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const cacheKey = `admin:users:growth:${days}`;

    // Check cache
    const cachedData = await redis.get(cacheKey);
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }

    const date = new Date();
    date.setDate(date.getDate() - parseInt(days));

    const users = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: date }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: {
          '_id.year': 1,
          '_id.month': 1,
          '_id.day': 1
        }
      },
      {
        $project: {
          _id: 0,
          date: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: {
                $dateFromParts: {
                  year: '$_id.year',
                  month: '$_id.month',
                  day: '$_id.day'
                }
              }
            }
          },
          count: 1
        }
      }
    ]);

    // Cache the data
    await redis.set(cacheKey, JSON.stringify(users), 'EX', 3600);

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

app.get('/api/admin/activity', protect, isAdmin, async (req, res) => {
  try {
    const activities = await AdminActivity.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('admin', 'firstName lastName email');

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/users', protect, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, status } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) {
      query.status = status;
    }

    const users = await User.find(query)
      .select('-password -twoFactorSecret -passwordResetToken -passwordResetExpires')
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: users
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/users/:id', protect, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -twoFactorSecret -passwordResetToken -passwordResetExpires');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
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

app.put('/api/admin/users/:id', protect, isAdmin, async (req, res) => {
  try {
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'phone',
      'country',
      'city',
      'address',
      'postalCode',
      'status',
      'isVerified',
      'isAdmin',
      'kycStatus',
      'balances'
    );

    // Prevent changing admin status of self
    if (req.user._id.toString() === req.params.id && 'isAdmin' in filteredBody) {
      delete filteredBody.isAdmin;
    }

    const updatedUser = await User.findByIdAndUpdate(req.params.id, filteredBody, {
      new: true,
      runValidators: true
    }).select('-password -twoFactorSecret');

    if (!updatedUser) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'update_user',
      target: 'User',
      targetId: updatedUser._id,
      ip: req.ip,
      metadata: filteredBody
    });

    res.status(200).json({
      status: 'success',
      data: updatedUser
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.delete('/api/admin/users/:id', protect, isAdmin, async (req, res) => {
  try {
    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({
        status: 'fail',
        message: 'You cannot delete your own account'
      });
    }

    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'delete_user',
      target: 'User',
      targetId: user._id,
      ip: req.ip
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

app.put('/api/admin/users/:id/status', protect, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }

    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({
        status: 'fail',
        message: 'You cannot change your own status'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select('-password -twoFactorSecret');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'change_user_status',
      target: 'User',
      targetId: user._id,
      ip: req.ip,
      metadata: { status }
    });

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

app.get('/api/admin/kyc/pending', protect, isAdmin, async (req, res) => {
  try {
    const users = await User.find({
      $or: [
        { 'kycStatus.identity': 'pending' },
        { 'kycStatus.address': 'pending' },
        { 'kycStatus.facial': 'pending' }
      ]
    })
    .select('firstName lastName email kycStatus kycDocuments createdAt')
    .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: users.length,
      data: users
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/kyc/:id', protect, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('firstName lastName email kycStatus kycDocuments');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
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

app.post('/api/admin/kyc/:id/review', protect, isAdmin, upload.array('documents', 3), async (req, res) => {
  try {
    const { type, status, rejectionReason } = req.body;
    const { id } = req.params;

    if (!['identity', 'address', 'facial'].includes(type)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid KYC type'
      });
    }

    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    // Update KYC status
    user.kycStatus[type] = status;
    
    // Update documents if provided
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        const docType = file.fieldname;
        if (['identity', 'address', 'facial'].includes(docType)) {
          const existingDocIndex = user.kycDocuments.findIndex(doc => doc.type === docType);
          if (existingDocIndex >= 0) {
            user.kycDocuments[existingDocIndex].status = status;
            user.kycDocuments[existingDocIndex].reviewedBy = req.user._id;
            user.kycDocuments[existingDocIndex].reviewedAt = new Date();
            user.kycDocuments[existingDocIndex].rejectionReason = rejectionReason;
          } else {
            user.kycDocuments.push({
              type: docType,
              [docType === 'facial' ? 'selfie' : 'front']: file.path,
              status,
              reviewedBy: req.user._id,
              reviewedAt: new Date(),
              rejectionReason
            });
          }
        }
      });
    }

    await user.save();

    // Send notification to user
    const mailOptions = {
      from: 'no-reply@bithash.com',
      to: user.email,
      subject: `Your ${type} verification has been ${status}`,
      html: `<p>Your ${type} verification has been ${status} by our team.</p>
             ${status === 'rejected' ? `<p>Reason: ${rejectionReason}</p>` : ''}
             <p>If you have any questions, please contact our support team.</p>`
    };

    await transporter.sendMail(mailOptions);

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'kyc_review',
      target: 'User',
      targetId: user._id,
      ip: req.ip,
      metadata: { type, status, rejectionReason }
    });

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

app.get('/api/admin/withdrawals/pending', protect, isAdmin, async (req, res) => {
  try {
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: withdrawals.length,
      data: withdrawals
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/withdrawals/:id', protect, isAdmin, async (req, res) => {
  try {
    const withdrawal = await Transaction.findOne({
      _id: req.params.id,
      type: 'withdrawal'
    }).populate('user', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'No withdrawal found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/admin/withdrawals/:id/process', protect, isAdmin, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    if (!['completed', 'failed'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }

    const withdrawal = await Transaction.findOne({
      _id: req.params.id,
      type: 'withdrawal',
      status: 'pending'
    }).populate('user');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'No pending withdrawal found with that ID'
      });
    }

    // Update withdrawal status
    withdrawal.status = status;
    withdrawal.processedBy = req.user._id;
    withdrawal.processedAt = new Date();
    
    if (status === 'failed' && rejectionReason) {
      withdrawal.metadata = withdrawal.metadata || {};
      withdrawal.metadata.rejectionReason = rejectionReason;
      
      // Refund the amount if withdrawal failed
      const user = await User.findById(withdrawal.user._id);
      user.balances.main += withdrawal.amount;
      await user.save();
    }

    await withdrawal.save();

    // Send notification to user
    const mailOptions = {
      from: 'no-reply@bithash.com',
      to: withdrawal.user.email,
      subject: `Your withdrawal has been ${status}`,
      html: `<p>Your withdrawal of $${withdrawal.amount} has been ${status}.</p>
             ${status === 'failed' ? `<p>Reason: ${rejectionReason}</p>` : ''}
             <p>Transaction ID: ${withdrawal.reference}</p>`
    };

    await transporter.sendMail(mailOptions);

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'process_withdrawal',
      target: 'Transaction',
      targetId: withdrawal._id,
      ip: req.ip,
      metadata: { status, rejectionReason }
    });

    res.status(200).json({
      status: 'success',
      data: withdrawal
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/admin/withdrawals/process-batch', protect, isAdmin, async (req, res) => {
  try {
    const { withdrawalIds, status } = req.body;
    
    if (!['completed', 'failed'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }

    if (!Array.isArray(withdrawalIds) || withdrawalIds.length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide withdrawal IDs to process'
      });
    }

    const withdrawals = await Transaction.find({
      _id: { $in: withdrawalIds },
      type: 'withdrawal',
      status: 'pending'
    }).populate('user');

    if (withdrawals.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'No pending withdrawals found with the provided IDs'
      });
    }

    const processedWithdrawals = [];
    const failedWithdrawals = [];
    
    for (const withdrawal of withdrawals) {
      try {
        withdrawal.status = status;
        withdrawal.processedBy = req.user._id;
        withdrawal.processedAt = new Date();
        
        if (status === 'failed') {
          // Refund the amount if withdrawal failed
          const user = await User.findById(withdrawal.user._id);
          user.balances.main += withdrawal.amount;
          await user.save();
          failedWithdrawals.push(withdrawal);
        } else {
          processedWithdrawals.push(withdrawal);
        }
        
        await withdrawal.save();
        
        // Send notification to user
        const mailOptions = {
          from: 'no-reply@bithash.com',
          to: withdrawal.user.email,
          subject: `Your withdrawal has been ${status}`,
          html: `<p>Your withdrawal of $${withdrawal.amount} has been ${status}.</p>
                 <p>Transaction ID: ${withdrawal.reference}</p>`
        };
        
        await transporter.sendMail(mailOptions);
      } catch (err) {
        console.error(`Error processing withdrawal ${withdrawal._id}:`, err);
      }
    }

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'process_withdrawal_batch',
      ip: req.ip,
      metadata: {
        status,
        processedCount: processedWithdrawals.length,
        failedCount: failedWithdrawals.length
      }
    });

    res.status(200).json({
      status: 'success',
      data: {
        processed: processedWithdrawals.length,
        failed: failedWithdrawals.length,
        total: withdrawals.length
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/loans', protect, isAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    let query = {};
    
    if (status) {
      query.status = status;
    }

    const loans = await Loan.find(query)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName')
      .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      results: loans.length,
      data: loans
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/admin/loans', protect, isAdmin, async (req, res) => {
  try {
    const { userId, amount, collateralAmount, duration, interestRate } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }

    if (user.balances.savings < collateralAmount) {
      return res.status(400).json({
        status: 'fail',
        message: 'User does not have enough savings for collateral'
      });
    }

    const repaymentAmount = amount + (amount * (interestRate / 100));
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + parseInt(duration));

    const loan = await Loan.create({
      user: userId,
      amount,
      collateralAmount,
      collateralCurrency: 'BTC',
      interestRate,
      duration,
      repaymentAmount,
      endDate,
      status: 'approved',
      approvedBy: req.user._id,
      approvedAt: new Date()
    });

    // Deduct collateral from user's savings
    user.balances.savings -= collateralAmount;
    await user.save();

    // Add loan amount to user's main balance
    user.balances.main += amount;
    await user.save();

    // Create transaction for the loan disbursement
    await Transaction.create({
      user: userId,
      type: 'loan',
      amount,
      status: 'completed',
      method: 'internal',
      reference: generateReference(),
      description: `Loan disbursement - ${loan._id}`
    });

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'create_loan',
      target: 'Loan',
      targetId: loan._id,
      ip: req.ip,
      metadata: req.body
    });

    res.status(201).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/admin/loans/:id', protect, isAdmin, async (req, res) => {
  try {
    const loan = await Loan.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName')
      .populate('repaymentHistory.transaction');

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.put('/api/admin/loans/:id', protect, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['approved', 'rejected', 'active', 'repaid', 'defaulted'].includes(status)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid status value'
      });
    }

    const loan = await Loan.findById(req.params.id);
    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }

    if (loan.status === 'repaid' || loan.status === 'defaulted') {
      return res.status(400).json({
        status: 'fail',
        message: 'Cannot modify a loan that has already been repaid or defaulted'
      });
    }

    // Handle loan approval
    if (status === 'approved' && loan.status === 'pending') {
      const user = await User.findById(loan.user);
      
      // Deduct collateral from user's savings
      user.balances.savings -= loan.collateralAmount;
      await user.save();

      // Add loan amount to user's main balance
      user.balances.main += loan.amount;
      await user.save();

      // Create transaction for the loan disbursement
      await Transaction.create({
        user: loan.user,
        type: 'loan',
        amount: loan.amount,
        status: 'completed',
        method: 'internal',
        reference: generateReference(),
        description: `Loan disbursement - ${loan._id}`
      });

      loan.status = 'approved';
      loan.approvedBy = req.user._id;
      loan.approvedAt = new Date();
    } 
    // Handle loan rejection
    else if (status === 'rejected' && loan.status === 'pending') {
      loan.status = 'rejected';
      loan.approvedBy = req.user._id;
      loan.approvedAt = new Date();
    }
    // Handle other status changes
    else {
      loan.status = status;
    }

    await loan.save();

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'update_loan',
      target: 'Loan',
      targetId: loan._id,
      ip: req.ip,
      metadata: { status }
    });

    res.status(200).json({
      status: 'success',
      data: loan
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.delete('/api/admin/loans/:id', protect, isAdmin, async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'No loan found with that ID'
      });
    }

    // Log admin activity
    await AdminActivity.create({
      admin: req.user._id,
      action: 'delete_loan',
      target: 'Loan',
      targetId: loan._id,
      ip: req.ip
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

app.get('/api/admin/profile', protect, isAdmin, async (req, res) => {
  try {
    const admin = await User.findById(req.user._id)
      .select('-password -twoFactorSecret -passwordResetToken -passwordResetExpires');

    res.status(200).json({
      status: 'success',
      data: admin
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Dashboard Routes
app.get('/api/plans', protect, async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true });

    res.status(200).json({
      status: 'success',
      results: plans.length,
      data: plans
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, status, limit = 10 } = req.query;
    let query = { user: req.user._id };
    
    if (type) {
      query.type = type;
    }
    if (status) {
      query.status = status;
    }

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: transactions
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.get('/api/mining/stats', protect, async (req, res) => {
  try {
    // Get user's active investments
    const investments = await Investment.find({
      user: req.user._id,
      status: 'active'
    }).populate('plan');

    // Calculate mining stats
    const stats = {
      activeInvestments: investments.length,
      totalInvested: investments.reduce((sum, inv) => sum + inv.amount, 0),
      estimatedDailyEarnings: investments.reduce((sum, inv) => {
        const dailyRate = inv.plan.percentage / inv.plan.duration;
        return sum + (inv.amount * dailyRate / 100);
      }, 0),
      estimatedMonthlyEarnings: investments.reduce((sum, inv) => {
        const dailyRate = inv.plan.percentage / inv.plan.duration;
        return sum + (inv.amount * dailyRate * 30 / 100);
      }, 0)
    };

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

app.post('/api/transactions/deposit', protect, async (req, res) => {
  try {
    const { amount, method } = req.body;
    
    if (!['btc', 'bank', 'card'].includes(method)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit method'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }

    const reference = generateReference();
    let description = `Deposit of $${amount}`;
    let metadata = { method };

    // For BTC deposits, include the deposit address
    if (method === 'btc') {
      metadata.btcAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
      description += ' via BTC';
    } else if (method === 'card') {
      description += ' via Credit/Debit Card';
    } else {
      description += ' via Bank Transfer';
    }

    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'deposit',
      amount,
      status: 'pending',
      method,
      reference,
      description,
      metadata
    });

    res.status(201).json({
      status: 'success',
      data: transaction
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
    const { amount, method, address } = req.body;
    
    if (!['btc', 'bank'].includes(method)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid withdrawal method'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }

    // Deduct amount from user's balance (will be refunded if withdrawal fails)
    user.balances.main -= amount;
    await user.save();

    const reference = generateReference();
    let description = `Withdrawal of $${amount}`;
    let metadata = { method };

    if (method === 'btc') {
      if (!address) {
        return res.status(400).json({
          status: 'fail',
          message: 'BTC address is required'
        });
      }
      metadata.btcAddress = address;
      description += ' to BTC address';
    } else {
      description += ' via Bank Transfer';
    }

    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      method,
      reference,
      description,
      metadata
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

app.post('/api/transactions/transfer', protect, async (req, res) => {
  try {
    const { amount, toUserId } = req.body;
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be greater than 0'
      });
    }

    // Check if recipient exists
    const recipient = await User.findById(toUserId);
    if (!recipient) {
      return res.status(404).json({
        status: 'fail',
        message: 'Recipient not found'
      });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }

    // Perform transfer
    user.balances.main -= amount;
    recipient.balances.main += amount;
    
    await Promise.all([user.save(), recipient.save()]);

    const reference = generateReference();
    const description = `Transfer of $${amount} to ${recipient.email}`;

    // Create transaction for sender
    await Transaction.create({
      user: req.user._id,
      type: 'transfer',
      amount,
      status: 'completed',
      method: 'internal',
      reference,
      description,
      metadata: {
        recipient: recipient._id,
        recipientEmail: recipient.email
      }
    });

    // Create transaction for recipient
    await Transaction.create({
      user: toUserId,
      type: 'transfer',
      amount,
      status: 'completed',
      method: 'internal',
      reference,
      description: `Received $${amount} from ${user.email}`,
      metadata: {
        sender: req.user._id,
        senderEmail: user.email
      }
    });

    res.status(201).json({
      status: 'success',
      message: 'Transfer completed successfully'
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
    
    // Check if plan exists and is active
    const plan = await Plan.findById(planId);
    if (!plan || !plan.isActive) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found or inactive'
      });
    }

    // Check amount is within plan limits
    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }

    // Deduct amount from user's main balance
    user.balances.main -= amount;
    await user.save();

    // Calculate expected return
    const expectedReturn = amount + (amount * plan.percentage / 100);
    const endDate = new Date();
    endDate.setHours(endDate.getHours() + plan.duration);

    // Create investment
    const investment = await Investment.create({
      user: req.user._id,
      plan: planId,
      amount,
      expectedReturn,
      endDate
    });

    // Create transaction
    await Transaction.create({
      user: req.user._id,
      type: 'investment',
      amount,
      status: 'completed',
      method: 'internal',
      reference: generateReference(),
      description: `Investment in ${plan.name}`
    });

    // Check if user was referred and pay referral bonus if applicable
    if (user.referredBy && !investment.referralBonusPaid) {
      const referrer = await User.findById(user.referredBy);
      if (referrer) {
        const referralBonus = amount * (plan.referralBonus / 100);
        
        referrer.balances.bonus += referralBonus;
        referrer.referralEarnings += referralBonus;
        await referrer.save();
        
        investment.referralBonusPaid = true;
        investment.referralBonusAmount = referralBonus;
        await investment.save();
        
        // Create transaction for referrer
        await Transaction.create({
          user: referrer._id,
          type: 'referral',
          amount: referralBonus,
          status: 'completed',
          method: 'internal',
          reference: generateReference(),
          description: `Referral bonus from ${user.email}`
        });
      }
    }

    res.status(201).json({
      status: 'success',
      data: investment
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Process investment earnings (cron job)
const processInvestmentEarnings = async () => {
  try {
    const now = new Date();
    const completedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan');

    for (const investment of completedInvestments) {
      const user = investment.user;
      const earnings = investment.expectedReturn - investment.amount;
      
      // Add earnings to user's balance
      user.balances.main += investment.expectedReturn;
      await user.save();
      
      // Mark investment as completed
      investment.status = 'completed';
      investment.earnings = earnings;
      await investment.save();
      
      // Create transaction
      await Transaction.create({
        user: user._id,
        type: 'earning',
        amount: investment.expectedReturn,
        status: 'completed',
        method: 'internal',
        reference: generateReference(),
        description: `Earnings from ${investment.plan.name} investment`
      });
    }
    
    console.log(`Processed ${completedInvestments.length} investment earnings`);
  } catch (err) {
    console.error('Error processing investment earnings:', err);
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await seedInitialData();
  
  // Schedule investment earnings processing every hour
  setInterval(processInvestmentEarnings, 60 * 60 * 1000);
});
