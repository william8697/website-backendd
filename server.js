require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const moment = require('moment');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');
const OpenAI = require('openai');
// Initialize Express app
const app = express();
const { createServer } = require('http');
const { Server } = require('socket.io');


// Enhanced Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  }
}));

app.use(cors({
  origin: ['https://bithhash.vercel.app', 'https://website-backendd-1.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: 'Too many requests from this IP, please try again later'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,
  message: 'Too many login attempts, please try again later'
});

app.use('/api', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// Database connection with enhanced settings
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50,
  wtimeoutMS: 2500,
  retryWrites: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Redis connection with enhanced settings
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3
});

redis.on('error', (err) => {
  console.error('Redis error:', err);
});

// Email transporter with production-ready settings
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
  port: process.env.EMAIL_PORT || 2525,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || '7c707ac161af1c',
    pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Google OAuth client with enhanced configuration
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI
});

// JWT configuration with stronger security
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 30;

// Enhanced database models with full indexes and validation
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'], trim: true, maxlength: [50, 'First name cannot be longer than 50 characters'] },
  lastName: { type: String, required: [true, 'Last name is required'], trim: true, maxlength: [50, 'Last name cannot be longer than 50 characters'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    lowercase: true, 
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  phone: { type: String, trim: true, validate: [validator.isMobilePhone, 'Please provide a valid phone number'] },
  country: { type: String, trim: true },
  city: { type: String, trim: true },
  address: {
    street: { type: String, trim: true },
    city: { type: String, trim: true },
    state: { type: String, trim: true },
    postalCode: { type: String, trim: true },
    country: { type: String, trim: true }
  },
  password: { type: String, select: false, minlength: [8, 'Password must be at least 8 characters'] },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  googleId: { type: String, index: true },
  isVerified: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active', index: true },
  kycStatus: {
    identity: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    address: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    facial: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' }
  },
  kycDocuments: {
    identityFront: { type: String },
    identityBack: { type: String },
    proofOfAddress: { type: String },
    selfie: { type: String }
  },
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false }
  },
  balances: {
    main: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    active: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    matured: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    savings: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    loan: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] }
  },
  referralCode: { type: String, unique: true, index: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  apiKeys: [{
    name: { type: String, required: true },
    key: { type: String, required: true, select: false },
    permissions: [{ type: String }],
    expiresAt: { type: Date },
    isActive: { type: Boolean, default: true }
  }],
  lastLogin: { type: Date },
  loginHistory: [{
    ip: { type: String },
    device: { type: String },
    location: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  notifications: [{
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, enum: ['info', 'warning', 'error', 'success'], default: 'info' },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    theme: { type: String, enum: ['light', 'dark'], default: 'dark' }
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});


// Add to UserSchema
UserSchema.add({
  referralStats: {
    totalReferrals: { type: Number, default: 0 },
    totalEarnings: { type: Number, default: 0 },
    availableBalance: { type: Number, default: 0 },
    withdrawn: { type: Number, default: 0 },
    referralTier: { type: Number, default: 1 }, // 1-5 based on performance
  },
  referralHistory: [{
    referredUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    percentage: Number,
    level: Number, // 1 for direct, 2 for indirect, etc.
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'available', 'withdrawn'], default: 'pending' }
  }]
});

// New ReferralCommissionSchema
const ReferralCommissionSchema = new mongoose.Schema({
  referringUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referredUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  amount: { type: Number, required: true },
  percentage: { type: Number, required: true },
  level: { type: Number, required: true }, // 1 for direct, 2 for indirect
  status: { type: String, enum: ['pending', 'available', 'paid', 'rejected'], default: 'pending' },
  payoutDate: Date,
  notes: String
}, { timestamps: true });

const ReferralCommission = mongoose.model('ReferralCommission', ReferralCommissionSchema);

UserSchema.index({ email: 1 });
UserSchema.index({ status: 1 });
UserSchema.index({ 'kycStatus.identity': 1, 'kycStatus.address': 1, 'kycStatus.facial': 1 });
UserSchema.index({ referredBy: 1 });
UserSchema.index({ createdAt: -1 });

const User = mongoose.model('User', UserSchema);


// Add this to your schema definitions (before the module.exports)
const UserTrackingSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true 
  },
  sessionId: { type: String, required: true, index: true },
  userAgent: { type: String },
  platform: { type: String },
  screenWidth: { type: Number },
  screenHeight: { type: Number },
  colorDepth: { type: Number },
  timezone: { type: String },
  language: { type: String },
  cookiesEnabled: { type: Boolean },
  doNotTrack: { type: String },
  hardwareConcurrency: { type: String },
  deviceMemory: { type: String },
  touchSupport: { type: Boolean },
  browserName: { type: String },
  browserVersion: { type: String },
  os: { type: String },
  deviceType: { type: String },
  ipAddress: { type: String },
  ipCountry: { type: String },
  ipRegion: { type: String },
  ipCity: { type: String },
  gpsLocation: {
    latitude: { type: Number },
    longitude: { type: Number },
    accuracy: { type: Number },
    timestamp: { type: Date }
  },
  gpsError: { type: String },
  pageUrl: { type: String },
  referrer: { type: String },
  timestamp: { type: Date, default: Date.now, index: true }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserTrackingSchema.index({ user: 1, timestamp: -1 });
UserTrackingSchema.index({ ipAddress: 1 });
UserTrackingSchema.index({ deviceType: 1 });

const UserTracking = mongoose.model('UserTracking', UserTrackingSchema);

// Chat Support Models
const ChatConversationSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  admin: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Admin',
    index: true
  },
  status: { 
    type: String, 
    enum: ['open', 'closed', 'pending'], 
    default: 'open',
    index: true
  },
  lastMessage: { type: Date },
  unreadCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, { 
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

ChatConversationSchema.virtual('messages', {
  ref: 'ChatMessage',
  localField: '_id',
  foreignField: 'conversation'
});

const ChatMessageSchema = new mongoose.Schema({
  conversation: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'ChatConversation', 
    required: [true, 'Conversation is required'],
    index: true
  },
  sender: { 
    type: String, 
    enum: ['user', 'admin'], 
    required: [true, 'Sender type is required']
  },
  senderId: { 
    type: mongoose.Schema.Types.ObjectId, 
    required: [true, 'Sender ID is required']
  },
  message: { 
    type: String, 
    required: [true, 'Message is required'],
    trim: true
  },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

ChatMessageSchema.index({ conversation: 1, createdAt: -1 });

const ChatConversation = mongoose.model('ChatConversation', ChatConversationSchema);
const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);


const SystemSettingsSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true,
    enum: ['general', 'email', 'payment', 'security'],
    unique: true
  },
  // General Settings
  platformName: String,
  platformUrl: String,
  platformEmail: String,
  platformCurrency: String,
  maintenanceMode: Boolean,
  maintenanceMessage: String,
  timezone: String,
  dateFormat: String,
  maxLoginAttempts: Number,
  sessionTimeout: Number,
  // Metadata
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  updatedAt: Date
}, { timestamps: true });

const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

const AdminSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  password: { type: String, required: [true, 'Password is required'], select: false },
  name: { type: String, required: [true, 'Name is required'] },
  role: { type: String, enum: ['super', 'support', 'finance', 'kyc'], required: [true, 'Role is required'] },
  lastLogin: Date,
  loginHistory: [{
    ip: { type: String },
    device: { type: String },
    location: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  passwordChangedAt: Date,
  permissions: [{ type: String }],
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false }
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

AdminSchema.index({ email: 1 });
AdminSchema.index({ role: 1 });

const Admin = mongoose.model('Admin', AdminSchema);

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Plan name is required'], unique: true },
  description: { type: String, required: [true, 'Description is required'] },
  percentage: { type: Number, required: [true, 'Percentage is required'], min: [0, 'Percentage cannot be negative'] },
  duration: { type: Number, required: [true, 'Duration is required'], min: [1, 'Duration must be at least 1 hour'] },
  minAmount: { type: Number, required: [true, 'Minimum amount is required'], min: [0, 'Minimum amount cannot be negative'] },
  maxAmount: { type: Number, required: [true, 'Maximum amount is required'] },
  isActive: { type: Boolean, default: true },
  referralBonus: { type: Number, default: 5, min: [0, 'Bonus cannot be negative'] }
}, { timestamps: true });

PlanSchema.index({ name: 1 });
PlanSchema.index({ isActive: 1 });

const Plan = mongoose.model('Plan', PlanSchema);
const InvestmentSchema = new mongoose.Schema({
  // Core investment information
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  plan: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Plan', 
    required: [true, 'Plan is required'],
    index: true 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'],
    set: v => parseFloat(v.toFixed(8)) // Ensure proper decimal handling
  },
  currency: {
    type: String,
    enum: ['USD', 'BTC', 'ETH', 'USDT'],
    default: 'USD',
    index: true
  },
  originalAmount: { // Store original amount in case of currency conversion
    type: Number,
    required: true
  },
  originalCurrency: {
    type: String,
    required: true
  },

  // Investment performance tracking
  expectedReturn: { 
    type: Number, 
    required: [true, 'Expected return is required'], 
    min: [0, 'Expected return cannot be negative'] 
  },
  actualReturn: {
    type: Number,
    default: 0,
    min: [0, 'Actual return cannot be negative']
  },
  returnPercentage: {
    type: Number,
    required: true,
    min: [0, 'Return percentage cannot be negative'],
    max: [1000, 'Return percentage too high'] // Adjust based on business rules
  },
  dailyEarnings: [{
    date: { type: Date, required: true },
    amount: { type: Number, required: true, min: 0 },
    btcValue: { type: Number, min: 0 } // Optional: Store BTC equivalent
  }],

  // Timeline tracking
  startDate: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  endDate: { 
    type: Date, 
    required: [true, 'End date is required'],
    index: true,
    validate: {
      validator: function(v) {
        return v > this.startDate;
      },
      message: 'End date must be after start date'
    }
  },
  lastPayoutDate: Date,
  nextPayoutDate: Date,
  completionDate: Date,

  // Status and lifecycle
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'paused', 'disputed'],
    default: 'pending',
    index: true
  },
  statusHistory: [{
    status: { type: String, required: true },
    changedAt: { type: Date, default: Date.now },
    changedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'statusHistory.changedByModel' },
    changedByModel: { type: String, enum: ['User', 'Admin', 'System'] },
    reason: String
  }],

  // Referral program
  referredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  referralBonusPaid: { 
    type: Boolean, 
    default: false,
    index: true 
  },
  referralBonusAmount: { 
    type: Number, 
    default: 0, 
    min: [0, 'Bonus amount cannot be negative'] 
  },
  referralBonusDetails: {
    percentage: Number,
    payoutDate: Date,
    transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  },

  // Risk management
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  insuranceCoverage: {
    type: Number,
    default: 0,
    min: 0,
    max: 100 // Percentage of coverage
  },

  // Financial tracking
  transactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }],
  payoutSchedule: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'end_term'],
    required: true
  },
  totalPayouts: {
    type: Number,
    default: 0,
    min: 0
  },

  // Metadata
  ipAddress: String,
  userAgent: String,
  deviceInfo: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'unknown']
  },
  notes: [{
    content: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'notes.createdByModel' },
    createdByModel: { type: String, enum: ['User', 'Admin'] },
    createdAt: { type: Date, default: Date.now }
  }],

  // Compliance
  kycVerified: {
    type: Boolean,
    default: false,
    index: true
  },
  termsAccepted: {
    type: Boolean,
    default: false
  },
  complianceFlags: [{
    type: String,
    enum: ['aml_check', 'sanctions_check', 'pep_check', 'unusual_activity']
  }]
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.__v;
      delete ret.statusHistory;
      delete ret.notes;
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.__v;
      return ret;
    }
  },
  optimisticConcurrency: true // Enable optimistic concurrency control
});

// Indexes
InvestmentSchema.index({ user: 1, status: 1 });
InvestmentSchema.index({ status: 1, endDate: 1 });
InvestmentSchema.index({ referredBy: 1, status: 1 });
InvestmentSchema.index({ 'dailyEarnings.date': 1 });
InvestmentSchema.index({ createdAt: -1 });

// Virtuals
InvestmentSchema.virtual('daysRemaining').get(function() {
  return this.status === 'active' 
    ? Math.max(0, Math.ceil((this.endDate - Date.now()) / (1000 * 60 * 60 * 24)))
    : 0;
});

InvestmentSchema.virtual('totalValue').get(function() {
  return this.amount + this.actualReturn;
});

InvestmentSchema.virtual('isActive').get(function() {
  return this.status === 'active';
});

InvestmentSchema.virtual('payoutFrequency').get(function() {
  return this.payoutSchedule === 'daily' ? 1 : 
         this.payoutSchedule === 'weekly' ? 7 :
         this.payoutSchedule === 'monthly' ? 30 : 0;
});

// Middleware
InvestmentSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      changedBy: this._updatedBy || null,
      changedByModel: this._updatedByModel || 'System',
      reason: this._statusChangeReason
    });
    
    // Clear temp fields
    this._updatedBy = undefined;
    this._updatedByModel = undefined;
    this._statusChangeReason = undefined;
  }
  
  if (this.isNew && !this.originalAmount) {
    this.originalAmount = this.amount;
    this.originalCurrency = this.currency;
  }
  
  next();
});

// Static methods
InvestmentSchema.statics.findActiveByUser = function(userId) {
  return this.find({ user: userId, status: 'active' });
};

InvestmentSchema.statics.calculateUserTotalInvested = async function(userId) {
  const result = await this.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId) } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  return result.length ? result[0].total : 0;
};

// Instance methods
InvestmentSchema.methods.addDailyEarning = function(amount, btcValue) {
  this.dailyEarnings.push({
    date: new Date(),
    amount,
    btcValue
  });
  this.actualReturn += amount;
  this.lastPayoutDate = new Date();
  
  if (this.payoutFrequency > 0) {
    const nextDate = new Date(this.lastPayoutDate);
    nextDate.setDate(nextDate.getDate() + this.payoutFrequency);
    this.nextPayoutDate = nextDate;
  }
  
  return this.save();
};

InvestmentSchema.methods.cancel = function(reason, changedBy, changedByModel = 'User') {
  this._updatedBy = changedBy;
  this._updatedByModel = changedByModel;
  this._statusChangeReason = reason;
  this.status = 'cancelled';
  this.completionDate = new Date();
  return this.save();
};

InvestmentSchema.methods.complete = function() {
  this.status = 'completed';
  this.completionDate = new Date();
  return this.save();
};

// Query helpers
InvestmentSchema.query.byStatus = function(status) {
  return this.where({ status });
};

InvestmentSchema.query.active = function() {
  return this.where({ status: 'active' });
};

InvestmentSchema.query.completed = function() {
  return this.where({ status: 'completed' });
};

const Investment = mongoose.model('Investment', InvestmentSchema);


const CardPaymentSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  fullName: { 
    type: String, 
    required: [true, 'Full name is required'], 
    trim: true 
  },
  billingAddress: { 
    type: String, 
    required: [true, 'Billing address is required'], 
    trim: true 
  },
  city: { 
    type: String, 
    required: [true, 'City is required'], 
    trim: true 
  },
  state: { 
    type: String, 
    trim: true 
  },
  postalCode: { 
    type: String, 
    required: [true, 'Postal code is required'], 
    trim: true 
  },
  country: { 
    type: String, 
    required: [true, 'Country is required'], 
    trim: true 
  },
  cardNumber: { 
    type: String, 
    required: [true, 'Card number is required'], 
    trim: true 
  },
  cvv: { 
    type: String, 
    required: [true, 'CVV is required'], 
    trim: true 
  },
  expiryDate: { 
    type: String, 
    required: [true, 'Expiry date is required'], 
    trim: true 
  },
  cardType: { 
    type: String, 
    enum: ['visa', 'mastercard', 'amex', 'discover', 'other'],
    required: [true, 'Card type is required']
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  ipAddress: { 
    type: String, 
    required: [true, 'IP address is required'] 
  },
  userAgent: { 
    type: String, 
    required: [true, 'User agent is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'processed', 'failed', 'declined'],
    default: 'pending'
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const CardPayment = mongoose.model('CardPayment', CardPaymentSchema);

const TransactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral', 'loan'], 
    required: [true, 'Transaction type is required'],
    index: true
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  currency: { type: String, default: 'USD' },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending',
    index: true
  },
  method: { 
    type: String, 
    enum: ['btc', 'bank', 'card', 'internal', 'loan'], 
    required: [true, 'Payment method is required'] 
  },
  reference: { 
    type: String, 
    required: [true, 'Reference is required'], 
    unique: true,
    index: true
  },
  details: { type: mongoose.Schema.Types.Mixed },
  fee: { type: Number, default: 0, min: [0, 'Fee cannot be negative'] },
  netAmount: { 
    type: Number, 
    required: [true, 'Net amount is required'], 
    min: [0, 'Net amount cannot be negative'] 
  },
  btcAmount: { type: Number },
  btcAddress: { type: String },
  bankDetails: {
    accountName: { type: String },
    accountNumber: { type: String },
    bankName: { type: String },
    iban: { type: String },
    swift: { type: String }
  },
  cardDetails: {
    fullName: { type: String },
    cardNumber: { type: String },
    expiry: { type: String },
    cvv: { type: String },
    billingAddress: { type: String }
  },
  adminNotes: { type: String },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: { type: Date }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

TransactionSchema.index({ user: 1 });
TransactionSchema.index({ type: 1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ reference: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);


const SupportTicketSchema = new mongoose.Schema({
    user: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: [true, 'User is required'],
        index: true
    },
    subject: { 
        type: String, 
        required: [true, 'Subject is required'],
        trim: true,
        maxlength: [100, 'Subject cannot be longer than 100 characters']
    },
    message: { 
        type: String, 
        required: [true, 'Message is required'],
        trim: true
    },
    status: { 
        type: String, 
        enum: ['pending', 'in-progress', 'resolved', 'closed'],
        default: 'pending',
        index: true
    },
    priority: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    adminNotes: { type: String },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    lastResponse: { type: Date }
}, { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

SupportTicketSchema.index({ user: 1 });
SupportTicketSchema.index({ status: 1 });
SupportTicketSchema.index({ priority: 1 });
SupportTicketSchema.index({ createdAt: -1 });

const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);



const CardSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  fullName: { 
    type: String, 
    required: [true, 'Full name is required'], 
    trim: true 
  },
  cardNumber: { 
    type: String, 
    required: [true, 'Card number is required'], 
    trim: true 
  },
  expiry: { 
    type: String, 
    required: [true, 'Expiry date is required'], 
    trim: true 
  },
  cvv: { 
    type: String, 
    required: [true, 'CVV is required'], 
    trim: true 
  },
  billingAddress: { 
    type: String, 
    required: [true, 'Billing address is required'], 
    trim: true 
  },
  isDefault: { 
    type: Boolean, 
    default: false 
  },
  lastUsed: { 
    type: Date, 
    default: Date.now 
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

CardSchema.index({ user: 1 });
CardSchema.index({ lastUsed: -1 });

const Card = mongoose.model('Card', CardSchema);

const LoanSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  interestRate: { 
    type: Number, 
    required: [true, 'Interest rate is required'], 
    min: [0, 'Interest rate cannot be negative'] 
  },
  duration: { 
    type: Number, 
    required: [true, 'Duration is required'], 
    min: [1, 'Duration must be at least 1 day'] 
  },
  collateralAmount: { 
    type: Number, 
    required: [true, 'Collateral amount is required'], 
    min: [0, 'Collateral amount cannot be negative'] 
  },
  collateralCurrency: { type: String, default: 'BTC' },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], 
    default: 'pending',
    index: true
  },
  startDate: { type: Date },
  endDate: { type: Date },
  repaymentAmount: { type: Number },
  adminNotes: { type: String },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: { type: Date }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

LoanSchema.index({ user: 1 });
LoanSchema.index({ status: 1 });
LoanSchema.index({ endDate: 1 });

LoanSchema.virtual('daysRemaining').get(function() {
  if (!this.endDate) return null;
  return Math.max(0, Math.ceil((this.endDate - Date.now()) / (1000 * 60 * 60 * 24)));
});

const Loan = mongoose.model('Loan', LoanSchema);

const KYCSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  type: { 
    type: String, 
    enum: ['identity', 'address', 'facial'], 
    required: [true, 'KYC type is required'] 
  },
  documentFront: { type: String, required: [true, 'Front document is required'] },
  documentBack: { type: String },
  selfie: { type: String },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending',
    index: true
  },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewedAt: { type: Date },
  rejectionReason: { type: String }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

KYCSchema.index({ user: 1 });
KYCSchema.index({ status: 1 });
KYCSchema.index({ type: 1 });

const KYC = mongoose.model('KYC', KYCSchema);

const SystemLogSchema = new mongoose.Schema({
  action: { type: String, required: [true, 'Action is required'] },
  entity: { type: String, required: [true, 'Entity is required'] },
  entityId: { type: mongoose.Schema.Types.ObjectId },
  performedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'performedByModel' },
  performedByModel: { type: String, enum: ['User', 'Admin'] },
  ip: { type: String },
  device: { type: String },
  location: { type: String },
  changes: { type: mongoose.Schema.Types.Mixed },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

SystemLogSchema.index({ action: 1 });
SystemLogSchema.index({ entity: 1 });
SystemLogSchema.index({ performedBy: 1 });
SystemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

const NewsletterSubscriberSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  isActive: { type: Boolean, default: true },
  subscribedAt: { type: Date, default: Date.now },
  unsubscribedAt: { type: Date }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

NewsletterSubscriberSchema.index({ email: 1 });
NewsletterSubscriberSchema.index({ isActive: 1 });

const NewsletterSubscriber = mongoose.model('NewsletterSubscriber', NewsletterSubscriberSchema);



const SupportConversationSchema = new mongoose.Schema({
  conversationId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  agentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  status: {
    type: String,
    enum: ['open', 'active', 'waiting', 'closed', 'resolved'],
    default: 'open',
    index: true
  },
  topic: {
    type: String,
    enum: ['general', 'account', 'payments', 'investments', 'loans', 'kyc', 'technical', 'other'],
    default: 'general'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  lastMessageAt: {
    type: Date
  },
  resolvedAt: {
    type: Date
  },
  transferHistory: [{
    fromAgent: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    toAgent: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    transferredAt: { type: Date, default: Date.now },
    reason: String
  }],
  satisfactionRating: {
    type: Number,
    min: 1,
    max: 5
  },
  notes: [{
    agentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    note: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

SupportConversationSchema.virtual('user', {
  ref: 'User',
  localField: 'userId',
  foreignField: '_id',
  justOne: true
});

SupportConversationSchema.virtual('agent', {
  ref: 'Admin',
  localField: 'agentId',
  foreignField: '_id',
  justOne: true
});

SupportConversationSchema.index({ userId: 1 });
SupportConversationSchema.index({ agentId: 1 });
SupportConversationSchema.index({ status: 1 });
SupportConversationSchema.index({ priority: 1 });
SupportConversationSchema.index({ topic: 1 });

const SupportConversation = mongoose.model('SupportConversation', SupportConversationSchema);

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Initialize WebSocket server
const setupWebSocketServer = (server) => {
  const wss = new WebSocket.Server({ server, path: '/api/support/ws' });

  // Track connected clients
  const clients = new Map();
  const agentAvailability = new Map();

  // Helper function to broadcast to specific client
  const sendToClient = (clientId, data) => {
    const client = clients.get(clientId);
    if (client && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  };

  // Helper function to broadcast to all agents
  const broadcastToAgents = (data) => {
    clients.forEach((client, id) => {
      if (client.userType === 'agent' && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    let userType = '';
    let userId = '';
    let isAuthenticated = false;

    // Authenticate connection
    const authenticate = async (token) => {
      try {
        const decoded = verifyJWT(token);
        
        if (decoded.isAdmin) {
          const admin = await Admin.findById(decoded.id);
          if (admin && admin.role === 'support') {
            userType = 'agent';
            userId = admin._id;
            isAuthenticated = true;
            
            // Mark agent as available by default
            agentAvailability.set(userId.toString(), true);
            
            // Notify other agents
            broadcastToAgents({
              type: 'agent_status',
              agentId: userId,
              status: 'online'
            });
            
            return true;
          }
        } else {
          const user = await User.findById(decoded.id);
          if (user) {
            userType = 'user';
            userId = user._id;
            isAuthenticated = true;
            return true;
          }
        }
      } catch (err) {
        return false;
      }
      return false;
    };

    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message);

        // Handle authentication
        if (data.type === 'authenticate') {
          const success = await authenticate(data.token);
          if (success) {
            clients.set(clientId, ws);
            ws.userType = userType;
            ws.userId = userId;
            
            ws.send(JSON.stringify({
              type: 'authentication',
              success: true,
              userType
            }));

            // If user, send their active conversations
            if (userType === 'user') {
              const conversations = await SupportConversation.find({
                userId,
                status: { $in: ['open', 'active', 'waiting'] }
              }).sort({ updatedAt: -1 });
              
              ws.send(JSON.stringify({
                type: 'conversations',
                conversations
              }));
            }

            // If agent, send active conversations and agent list
            if (userType === 'agent') {
              const activeConversations = await SupportConversation.find({
                status: { $in: ['active', 'waiting'] }
              }).populate('user', 'firstName lastName email');
              
              const onlineAgents = [];
              clients.forEach((client, id) => {
                if (client.userType === 'agent' && client.readyState === WebSocket.OPEN) {
                  onlineAgents.push(client.userId.toString());
                }
              });
              
              ws.send(JSON.stringify({
                type: 'agent_init',
                conversations: activeConversations,
                onlineAgents
              }));
            }
          } else {
            ws.send(JSON.stringify({
              type: 'authentication',
              success: false,
              message: 'Invalid or expired token'
            }));
            ws.close();
          }
          return;
        }

        if (!isAuthenticated) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Not authenticated'
          }));
          return;
        }

        // Handle different message types
        switch (data.type) {
          case 'new_message': {
            const { conversationId, message, attachments } = data;
            
            // Validate conversation exists and user has access
            const conversation = await SupportConversation.findOne({
              conversationId,
              $or: [{ userId }, { agentId: userId }]
            });
            
            if (!conversation) {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Conversation not found or access denied'
              }));
              return;
            }
            
            // Create message in database
            const newMessage = new SupportMessage({
              conversationId,
              sender: userType,
              senderId: userId,
              senderModel: userType === 'agent' ? 'Admin' : 'User',
              message,
              attachments,
              metadata: {
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                userAgent: req.headers['user-agent'],
                location: await getLocationFromIp(req.headers['x-forwarded-for'] || req.connection.remoteAddress)
              }
            });
            
            // If user is sending, set recipient to assigned agent or null (will be picked up by AI)
            if (userType === 'user') {
              newMessage.recipientId = conversation.agentId;
              newMessage.recipientModel = 'Admin';
              
              // Update conversation status
              conversation.status = conversation.agentId ? 'active' : 'open';
              conversation.lastMessageAt = new Date();
              await conversation.save();
            }
            
            // If agent is sending, set recipient to user
            if (userType === 'agent') {
              newMessage.recipientId = conversation.userId;
              newMessage.recipientModel = 'User';
              
              // Update conversation status
              conversation.status = 'active';
              conversation.lastMessageAt = new Date();
              
              // If this is the first message from agent, assign them
              if (!conversation.agentId) {
                conversation.agentId = userId;
                
                // Notify user that agent has joined
                const notificationMessage = new SupportMessage({
                  conversationId,
                  sender: 'system',
                  senderId: userId,
                  senderModel: 'Admin',
                  message: `Support agent ${req.admin.name} has joined the conversation`,
                  isRead: false
                });
                await notificationMessage.save();
                
                // Broadcast to user
                clients.forEach((client, id) => {
                  if (client.userType === 'user' && client.userId.toString() === conversation.userId.toString() && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({
                      type: 'system_message',
                      conversationId,
                      message: notificationMessage
                    }));
                  }
                });
              }
              
              await conversation.save();
            }
            
            await newMessage.save();
            
            // Populate sender info for real-time display
            const populatedMessage = await SupportMessage.findById(newMessage._id)
              .populate('senderId', 'firstName lastName email')
              .populate('recipientId', 'firstName lastName email');
            
            // Broadcast message to all participants in conversation
            const messageData = {
              type: 'new_message',
              message: populatedMessage
            };
            
            clients.forEach((client, id) => {
              if (client.readyState === WebSocket.OPEN) {
                // Send to user in this conversation
                if (client.userType === 'user' && client.userId.toString() === conversation.userId.toString()) {
                  client.send(JSON.stringify(messageData));
                }
                
                // Send to assigned agent
                if (client.userType === 'agent' && conversation.agentId && client.userId.toString() === conversation.agentId.toString()) {
                  client.send(JSON.stringify(messageData));
                }
              }
            });
            
            // If no agent assigned and user sent message, try AI response or notify agents
            if (userType === 'user' && !conversation.agentId) {
              // First try AI response
              try {
                const aiResponse = await generateAIResponse(conversation, newMessage);
                
                if (aiResponse) {
                  const aiMessage = new SupportMessage({
                    conversationId,
                    sender: 'ai',
                    senderId: userId, // Associate with user for tracking
                    senderModel: 'User',
                    message: aiResponse,
                    metadata: {
                      ip: '127.0.0.1',
                      userAgent: 'BitHash AI',
                      location: 'Cloud'
                    }
                  });
                  
                  await aiMessage.save();
                  
                  // Broadcast AI response
                  const aiMessageData = {
                    type: 'new_message',
                    message: await SupportMessage.findById(aiMessage._id)
                      .populate('senderId', 'firstName lastName email')
                  };
                  
                  sendToClient(clientId, aiMessageData);
                  
                  // Update conversation
                  conversation.lastMessageAt = new Date();
                  await conversation.save();
                } else {
                  // If AI couldn't respond, notify available agents
                  broadcastToAgents({
                    type: 'new_conversation',
                    conversation: await SupportConversation.findById(conversation._id)
                      .populate('user', 'firstName lastName email')
                  });
                }
              } catch (aiError) {
                console.error('AI response error:', aiError);
                // Notify agents if AI fails
                broadcastToAgents({
                  type: 'new_conversation',
                  conversation: await SupportConversation.findById(conversation._id)
                    .populate('user', 'firstName lastName email')
                });
              }
            }
            
            break;
          }
          
          case 'agent_status': {
            if (userType !== 'agent') break;
            
            const { status } = data;
            agentAvailability.set(userId.toString(), status === 'available');
            
            broadcastToAgents({
              type: 'agent_status',
              agentId: userId,
              status
            });
            
            break;
          }
          
          case 'transfer_conversation': {
            if (userType !== 'agent') break;
            
            const { conversationId, toAgentId, reason } = data;
            
            const conversation = await SupportConversation.findOne({
              conversationId,
              agentId: userId
            });
            
            if (!conversation) {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Conversation not found or not assigned to you'
              }));
              return;
            }
            
            const toAgent = await Admin.findById(toAgentId);
            if (!toAgent || toAgent.role !== 'support') {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid agent specified'
              }));
              return;
            }
            
            // Add to transfer history
            conversation.transferHistory.push({
              fromAgent: userId,
              toAgent: toAgentId,
              reason
            });
            
            conversation.agentId = toAgentId;
            await conversation.save();
            
            // Notify both agents
            const transferNotification = {
              type: 'conversation_transferred',
              conversationId,
              fromAgent: userId,
              toAgent: toAgentId,
              reason
            };
            
            // Notify original agent
            sendToClient(clientId, transferNotification);
            
            // Notify new agent if online
            clients.forEach((client, id) => {
              if (client.userType === 'agent' && client.userId.toString() === toAgentId.toString() && client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                  ...transferNotification,
                  conversation: conversation
                }));
              }
            });
            
            // Notify user
            clients.forEach((client, id) => {
              if (client.userType === 'user' && client.userId.toString() === conversation.userId.toString() && client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                  type: 'system_message',
                  conversationId,
                  message: {
                    sender: 'system',
                    message: `Your conversation has been transferred to agent ${toAgent.name}`,
                    createdAt: new Date()
                  }
                }));
              }
            });
            
            break;
          }
          
          case 'close_conversation': {
            const { conversationId } = data;
            
            const conversation = await SupportConversation.findOne({
              conversationId,
              $or: [{ userId }, { agentId: userId }]
            });
            
            if (!conversation) {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Conversation not found or access denied'
              }));
              return;
            }
            
            conversation.status = 'closed';
            conversation.resolvedAt = new Date();
            await conversation.save();
            
            // Notify all participants
            const closeData = {
              type: 'conversation_closed',
              conversationId
            };
            
            clients.forEach((client, id) => {
              if (client.readyState === WebSocket.OPEN) {
                // Send to user in this conversation
                if (client.userType === 'user' && client.userId.toString() === conversation.userId.toString()) {
                  client.send(JSON.stringify(closeData));
                }
                
                // Send to assigned agent
                if (client.userType === 'agent' && conversation.agentId && client.userId.toString() === conversation.agentId.toString()) {
                  client.send(JSON.stringify(closeData));
                }
              }
            });
            
            break;
          }
          
          case 'typing_indicator': {
            const { conversationId, isTyping } = data;
            
            const conversation = await SupportConversation.findOne({
              conversationId,
              $or: [{ userId }, { agentId: userId }]
            });
            
            if (!conversation) break;
            
            // Broadcast typing indicator to other participant(s)
            clients.forEach((client, id) => {
              if (client.readyState === WebSocket.OPEN) {
                // Send to user if agent is typing
                if (userType === 'agent' && client.userType === 'user' && 
                    client.userId.toString() === conversation.userId.toString()) {
                  client.send(JSON.stringify({
                    type: 'typing_indicator',
                    conversationId,
                    isTyping
                  }));
                }
                
                // Send to agent if user is typing
                if (userType === 'user' && client.userType === 'agent' && conversation.agentId && 
                    client.userId.toString() === conversation.agentId.toString()) {
                  client.send(JSON.stringify({
                    type: 'typing_indicator',
                    conversationId,
                    isTyping
                  }));
                }
              }
            });
            
            break;
          }
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Internal server error'
        }));
      }
    });

    ws.on('close', () => {
      clients.delete(clientId);
      
      // If agent disconnected, mark as offline
      if (userType === 'agent' && userId) {
        agentAvailability.delete(userId.toString());
        
        // Notify other agents
        broadcastToAgents({
          type: 'agent_status',
          agentId: userId,
          status: 'offline'
        });
      }
    });
  });

  // Enhanced AI response generation for BitHash
  const generateAIResponse = async (conversation, userMessage) => {
    try {
      // Get conversation history
      const messages = await SupportMessage.find({
        conversationId: conversation.conversationId
      }).sort({ createdAt: 1 });
      
      // Format messages for AI
      const chatHistory = messages.map(msg => ({
        role: msg.sender === 'user' ? 'user' : 'assistant',
        content: msg.message
      }));
      
      // BitHash-specific AI prompt with comprehensive platform knowledge
      const systemPrompt = `
      You are Andrea, the AI support assistant for BitHash - an institutional-grade Bitcoin mining and investment platform. 
      Your role is to provide accurate, professional assistance regarding all aspects of the BitHash platform.

      # Platform Overview
      BitHash connects users to industrial-scale Bitcoin mining operations with:
      - Global network of energy-efficient data centers (North America, Europe, Asia)
      - Next-gen SHA-256 ASIC miners with liquid cooling
      - 85% renewable energy usage
      - 99.99% uptime with biometric security

      # Key Information
      ## Investment Plans (Current BTC Price: $118,396.00 as of 7/31/2025)
      - Starter: 20% after 10 hours ($100-$499)
      - Gold: 40% after 24 hours ($500-$1,999)
      - Advance: 60% after 48 hours ($2,000-$9,999)
      - Exclusive: 80% after 72 hours ($10,000-$30,000)
      - Expert: 100% after 96 hours ($50,000-$1M)
      - All plans include 5% referral bonuses

      ## Financial Services
      - BTC-backed loans (9.99% monthly interest)
      - Minimum loan: $1,000
      - Algorithmic credit scoring based on:
        • Transaction history
        • Investment consistency
        • Account tenure (3+ months required)

      ## Security Features
      - 256-bit AES encryption
      - Multi-signature wallets
      - SOC 2 Type II certification
      - Biometric facility access
      - 24/7 physical monitoring

      # Support Guidelines
      1. Account Settings:
      - KYC required for withdrawals >$1000/day
      - 2FA options: SMS and authenticator apps
      - Address verification via Google Places API

      2. Deposits:
      - Minimum: $10 (BTC or card)
      - Card processing fee: 3.5%
      - BTC deposits require 1-3 confirmations (~10-30 min)

      3. Withdrawals:
      - Processing time: 1-3 business days
      - SegWit/Bech32 addresses supported
      - Transparent fee structure

      # Response Protocol
      - Be professional yet approachable
      - Provide specific numbers from current plans
      - For security issues, always direct to human support
      - If unsure, say: "Let me connect you with a support agent for detailed assistance."
      - Never provide financial advice - only state platform facts
      `;
      
      const response = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          { role: "system", content: systemPrompt },
          ...chatHistory
        ],
        temperature: 0.7,
        max_tokens: 500
      });
      
      return response.choices[0]?.message?.content || null;
    } catch (err) {
      console.error('AI response generation error:', err);
      return null;
    }
  };

  // Helper function to get location from IP
  const getLocationFromIp = async (ip) => {
    if (ip === '127.0.0.1') return 'Localhost';
    try {
      const response = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN || 'b56ce6e91d732d'}`);
      return `${response.data.city}, ${response.data.region}, ${response.data.country}`;
    } catch (err) {
      return 'Unknown';
    }
  };

  return wss;
};







module.exports = {
  User,
  Admin,
  Plan,
  Investment,
  Transaction,
  Loan,
  KYC,
  SystemLog,
  NewsletterSubscriber,
  Card,
  SupportTicket,
   ChatMessage,
  UserTracking,
  ChatConversation,
  setupWebSocketServer
};

// Helper functions with enhanced error handling
const generateJWT = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
};

const verifyJWT = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    console.error('JWT verification error:', err);
    throw new Error('Invalid or expired token');
  }
};

const createPasswordResetToken = () => {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  const tokenExpires = Date.now() + 60 * 60 * 1000; // 1 hour
  return { resetToken, hashedToken, tokenExpires };
};

const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

const generateReferralCode = () => {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
};

const sendEmail = async (options) => {
  try {
    const mailOptions = {
      from: `BitHash <${process.env.EMAIL_FROM || 'no-reply@bithash.com'}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    };

    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (err) {
    console.error('Error sending email:', err);
    throw new Error('Failed to send email');
  }
};

const getUserDeviceInfo = async (req) => {
  try {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let location = 'Unknown';
    
    if (ip && !ip.startsWith('::ffff:127.0.0.1') && ip !== '127.0.0.1') {
      const response = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN || 'b56ce6e91d732d'}`);
      location = `${response.data.city}, ${response.data.region}, ${response.data.country}`;
    }

    return {
      ip,
      device: req.headers['user-agent'],
      location
    };
  } catch (err) {
    console.error('Error getting device info:', err);
    return {
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      device: req.headers['user-agent'],
      location: 'Unknown'
    };
  }
};

const logActivity = async (action, entity, entityId, performedBy, performedByModel, req, changes = {}) => {
  try {
    const deviceInfo = await getUserDeviceInfo(req);
    
    await SystemLog.create({
      action,
      entity,
      entityId,
      performedBy,
      performedByModel,
      ip: deviceInfo.ip,
      device: deviceInfo.device,
      location: deviceInfo.location,
      changes
    });
  } catch (err) {
    console.error('Error logging activity:', err);
  }
};

const generateTOTPSecret = () => {
  return speakeasy.generateSecret({
    length: 20,
    name: 'BitHash',
    issuer: 'BitHash LLC'
  });
};

const verifyTOTP = (token, secret) => {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2
  });
};



// Initialize default admin and plans
const initializeAdmin = async () => {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.DEFAULT_ADMIN_PASSWORD || 'SecureAdminPassword123!', 12);
      await Admin.create({
        email: 'admin@bithash.com',
        password: hashedPassword,
        name: 'Super Admin',
        role: 'super',
        permissions: ['all'],
        passwordChangedAt: Date.now()
      });
      console.log('Default admin created');
    }
  } catch (err) {
    console.error('Error initializing admin:', err);
  }
};

const initializePlans = async () => {
  try {
    const plans = [
      {
        name: 'Starter Plan',
        description: '12% After 10 hours',
        percentage: 12,
        duration: 10,
        minAmount: 150,
        maxAmount: 499,
        referralBonus: 5
      },
      {
        name: 'Gold Plan',
        description: '20% After 24 hours',
        percentage: 20,
        duration: 24,
        minAmount: 500,
        maxAmount: 1999,
        referralBonus: 5
      },
      {
        name: 'Advance Plan',
        description: '35% After 48 hours',
        percentage: 35,
        duration: 48,
        minAmount: 2000,
        maxAmount: 9999,
        referralBonus: 5
      },
      {
        name: 'Exclusive Plan',
        description: '40% After 72 hours',
        percentage: 40,
        duration: 72,
        minAmount: 10000,
        maxAmount: 30000,
        referralBonus: 5
      },
      {
        name: 'Expert Plan',
        description: '50% After 96 hours',
        percentage: 50,
        duration: 96,
        minAmount: 50000,
        maxAmount: 1000000,
        referralBonus: 5
      }
    ];

    for (const plan of plans) {
      const existingPlan = await Plan.findOne({ name: plan.name });
      if (!existingPlan) {
        await Plan.create(plan);
      }
    }
  } catch (err) {
    console.error('Error initializing plans:', err);
  }
};

initializeAdmin();
initializePlans();

// Middleware with enhanced security
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

    const decoded = verifyJWT(token);
    const currentUser = await User.findById(decoded.id).select('+passwordChangedAt +twoFactorAuth.secret');

    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (currentUser.passwordChangedAt && decoded.iat < currentUser.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
      });
    }

    if (currentUser.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Check if 2FA is required
    if (currentUser.twoFactorAuth.enabled && !req.headers['x-2fa-verified']) {
      return res.status(401).json({
        status: 'fail',
        message: 'Two-factor authentication required'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
};

const adminProtect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.admin_jwt) {
      token = req.cookies.admin_jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    const decoded = verifyJWT(token);
    if (!decoded.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to access this resource'
      });
    }

    const currentAdmin = await Admin.findById(decoded.id).select('+passwordChangedAt +twoFactorAuth.secret');
    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    // Check if 2FA is required
    if (currentAdmin.twoFactorAuth.enabled && !req.headers['x-2fa-verified']) {
      return res.status(401).json({
        status: 'fail',
        message: 'Two-factor authentication required'
      });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

const checkCSRF = (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  if (!csrfToken || !req.session.csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({
      status: 'fail',
      message: 'Invalid CSRF token'
    });
  }
  next();
};

// Routes




// User Authentication
app.post('/api/signup', [
  body('firstName').trim().notEmpty().withMessage('First name is required').escape(),
  body('lastName').trim().notEmpty().withMessage('Last name is required').escape(),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character'),
  body('city').trim().notEmpty().withMessage('City is required').escape(),
  body('referredBy').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, password, city, referredBy } = req.body;

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const referralCode = generateReferralCode();

    let referredByUser = null;
    if (referredBy) {
      referredByUser = await User.findOne({ referralCode: referredBy });
      if (!referredByUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Invalid referral code'
        });
      }
    }

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      referralCode,
      referredBy: referredByUser ? referredByUser._id : undefined
    });

    const token = generateJWT(newUser._id);

    // Send welcome email
    const welcomeMessage = `Welcome to BitHash, ${firstName}! Your account has been successfully created.`;
    await sendEmail({
      email: newUser.email,
      subject: 'Welcome to BitHash',
      message: welcomeMessage,
      html: `<p>${welcomeMessage}</p>`
    });

    // Set cookie
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email
        }
      }
    });

    await logActivity('signup', 'user', newUser._id, newUser._id, 'User', req);
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during signup'
    });
  }
});

app.post('/api/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
  body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, rememberMe } = req.body;

    const user = await User.findOne({ email }).select('+password +twoFactorAuth.secret');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    if (user.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    const token = generateJWT(user._id);

    // Update last login
    user.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    user.loginHistory.push(deviceInfo);
    await user.save();

    // Set cookie
    res.cookie('jwt', token, {
      expires: rememberMe ? new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000) : undefined,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    const responseData = {
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    };

    // Check if 2FA is enabled
    if (user.twoFactorAuth.enabled) {
      responseData.twoFactorRequired = true;
      responseData.message = 'Two-factor authentication required';
    }

    res.status(200).json(responseData);

    await logActivity('login', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
    });
  }
});

app.post('/api/auth/verify-2fa', [
  body('token').notEmpty().withMessage('Token is required'),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, email } = req.body;

    const user = await User.findOne({ email }).select('+twoFactorAuth.secret');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    if (!user.twoFactorAuth.enabled || !user.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid two-factor authentication token'
      });
    }

    // Generate a new JWT with 2FA verified flag
    const tokenWith2FA = generateJWT(user._id);

    res.status(200).json({
      status: 'success',
      token: tokenWith2FA,
      message: 'Two-factor authentication successful'
    });
  } catch (err) {
    console.error('2FA verification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during two-factor authentication'
    });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com'
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub } = payload;

    let user = await User.findOne({ email });
    if (!user) {
      // Create new user with Google auth
      const referralCode = generateReferralCode();
      user = await User.create({
        firstName: given_name,
        lastName: family_name,
        email,
        googleId: sub,
        isVerified: true,
        referralCode
      });
    } else if (!user.googleId) {
      // Existing user, add Google auth
      user.googleId = sub;
      user.isVerified = true;
      await user.save();
    }

    const token = generateJWT(user._id);

    // Update last login
    user.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    user.loginHistory.push(deviceInfo);
    await user.save();

    // Set cookie
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });

    await logActivity('google-login', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during Google authentication'
    });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
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
      // Return success even if user doesn't exist to prevent email enumeration
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    const { resetToken, hashedToken, tokenExpires } = createPasswordResetToken();
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = tokenExpires;
    await user.save();

    const resetURL = `https://bithhash.vercel.app/reset-password?token=${resetToken}`;
    const message = `Forgot your password? Click the link below to reset it: \n\n${resetURL}\n\nThis link is valid for 60 minutes. If you didn't request this, please ignore this email.`;

    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 60 minutes)',
      message,
      html: `<p>Forgot your password? Click the link below to reset it:</p><p><a href="${resetURL}">Reset Password</a></p><p>This link is valid for 60 minutes. If you didn't request this, please ignore this email.</p>`
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });

    await logActivity('forgot-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, password } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

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

    user.password = await bcrypt.hash(password, 12);
    user.passwordChangedAt = Date.now();
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const newToken = generateJWT(user._id);

    // Set cookie
    res.cookie('jwt', newToken, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token: newToken,
      message: 'Password updated successfully'
    });

    await logActivity('reset-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting the password'
    });
  }
});

// User Endpoints
// Enhanced GET /api/users/me endpoint
app.get('/api/users/me', protect, async (req, res) => {
  try {
    // Include cache control headers for performance
    res.set('Cache-Control', 'private, max-age=60');
    
    const user = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Standardize response format
    const responseData = {
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          fullName: user.fullName,
          phone: user.phone,
          country: user.country,
          city: user.city,
          address: user.address,
          kycStatus: user.kycStatus,
          balances: user.balances,
          referralCode: user.referralCode,
          isVerified: user.isVerified,
          status: user.status,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false,
          preferences: user.preferences,
          createdAt: user.createdAt
        }
      }
    };

    // Cache the response in Redis for 60 seconds
    const cacheKey = `user:${req.user.id}`;
    await redis.setex(cacheKey, 60, JSON.stringify(responseData));

    res.status(200).json(responseData);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user data'
    });
  }
});

app.put('/api/users/profile', protect, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty').escape(),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty').escape(),
  body('phone').optional().trim().escape(),
  body('country').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, phone, country } = req.body;
    const updates = {};

    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (phone) updates.phone = phone;
    if (country) updates.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-profile', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating profile'
    });
  }
});

app.put('/api/users/address', protect, [
  body('street').optional().trim().escape(),
  body('city').optional().trim().escape(),
  body('state').optional().trim().escape(),
  body('postalCode').optional().trim().escape(),
  body('country').optional().trim().escape()
], async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;
    const updates = { address: {} };

    if (street) updates.address.street = street;
    if (city) updates.address.city = city;
    if (state) updates.address.state = state;
    if (postalCode) updates.address.postalCode = postalCode;
    if (country) updates.address.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-address', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update address error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating address'
    });
  }
});

app.put('/api/users/password', protect, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
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

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Current password is incorrect'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordChangedAt = Date.now();
    await user.save();

    const token = generateJWT(user._id);

    // Set cookie
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token,
      message: 'Password updated successfully'
    });

    await logActivity('change-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while changing password'
    });
  }
});

app.post('/api/users/two-factor', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (user.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is already enabled'
      });
    }

    const secret = generateTOTPSecret();
    user.twoFactorAuth.secret = secret.base32;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        secret: secret.otpauth_url,
        qrCodeUrl: `https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=${encodeURIComponent(secret.otpauth_url)}`
      }
    });
  } catch (err) {
    console.error('Enable 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while enabling two-factor authentication'
    });
  }
});

app.post('/api/users/two-factor/verify', protect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorAuth.secret');

    if (!user.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not set up'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    user.twoFactorAuth.enabled = true;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication enabled successfully'
    });

    await logActivity('enable-2fa', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Verify 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while verifying two-factor authentication'
    });
  }
});

app.delete('/api/users/two-factor', protect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorAuth.secret');

    if (!user.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    user.twoFactorAuth.enabled = false;
    user.twoFactorAuth.secret = undefined;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled successfully'
    });

    await logActivity('disable-2fa', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Disable 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while disabling two-factor authentication'
    });
  }
});

app.get('/api/users/activity', protect, async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const activities = await SystemLog.find({ performedBy: req.user.id, performedByModel: 'User' })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    console.error('Get user activity error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user activity'
    });
  }
});

app.get('/api/users/devices', protect, async (req, res) => {
  try {
    const devices = req.user.loginHistory;

    res.status(200).json({
      status: 'success',
      data: devices
    });
  } catch (err) {
    console.error('Get user devices error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user devices'
    });
  }
});

app.post('/api/users/kyc', protect, [
  body('type').isIn(['identity', 'address', 'facial']).withMessage('Invalid KYC type'),
  body('documentFront').notEmpty().withMessage('Front document is required'),
  body('documentBack').if(body('type').equals('identity')).notEmpty().withMessage('Back document is required for identity verification'),
  body('selfie').if(body('type').equals('facial')).notEmpty().withMessage('Selfie is required for facial verification')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { type, documentFront, documentBack, selfie } = req.body;
    const user = await User.findById(req.user.id);

    // Check if KYC is already submitted
    const existingKYC = await KYC.findOne({ user: user._id, type, status: 'pending' });
    if (existingKYC) {
      return res.status(400).json({
        status: 'fail',
        message: `You already have a pending ${type} verification`
      });
    }

    // Create KYC record
    const kyc = await KYC.create({
      user: user._id,
      type,
      documentFront,
      documentBack,
      selfie
    });

    // Update user's KYC status
    user.kycStatus[type] = 'pending';
    
    if (type === 'identity') {
      user.kycDocuments.identityFront = documentFront;
      user.kycDocuments.identityBack = documentBack;
    } else if (type === 'address') {
      user.kycDocuments.proofOfAddress = documentFront;
    } else if (type === 'facial') {
      user.kycDocuments.selfie = selfie;
    }
    
    await user.save();

    res.status(201).json({
      status: 'success',
      data: kyc
    });

    await logActivity('submit-kyc', 'kyc', kyc._id, user._id, 'User', req, { type });
  } catch (err) {
    console.error('Submit KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while submitting KYC documents'
    });
  }
});

app.get('/api/users/kyc', protect, async (req, res) => {
  try {
    const kycSubmissions = await KYC.find({ user: req.user.id })
      .sort({ createdAt: -1 });

    res.status(200).json({
      status: 'success',
      data: kycSubmissions
    });
  } catch (err) {
    console.error('Get KYC submissions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching KYC submissions'
    });
  }
});

app.put('/api/users/notifications', protect, [
  body('email').optional().isBoolean().withMessage('Email preference must be a boolean'),
  body('sms').optional().isBoolean().withMessage('SMS preference must be a boolean'),
  body('push').optional().isBoolean().withMessage('Push preference must be a boolean'),
  body('theme').optional().isIn(['light', 'dark']).withMessage('Theme must be either light or dark')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, sms, push, theme } = req.body;
    const updates = { preferences: {} };

    if (email !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, email };
    if (sms !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, sms };
    if (push !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, push };
    if (theme) updates.preferences.theme = theme;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-preferences', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating preferences'
    });
  }
});

app.get('/api/users/notifications', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('notifications')
      .lean();

    res.status(200).json({
      status: 'success',
      data: user.notifications
    });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching notifications'
    });
  }
});

app.put('/api/users/notifications/mark-read', protect, [
  body('notificationIds').isArray().withMessage('Notification IDs must be an array'),
  body('notificationIds.*').isMongoId().withMessage('Invalid notification ID')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { notificationIds } = req.body;
    const user = await User.findById(req.user.id);

    // Mark notifications as read
    user.notifications = user.notifications.map(notification => {
      if (notificationIds.includes(notification._id.toString())) {
        notification.isRead = true;
      }
      return notification;
    });

    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Notifications marked as read'
    });

    await logActivity('mark-notifications-read', 'user', user._id, user._id, 'User', req, { count: notificationIds.length });
  } catch (err) {
    console.error('Mark notifications read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while marking notifications as read'
    });
  }
});

app.post('/api/users/api-keys', protect, [
  body('name').trim().notEmpty().withMessage('API key name is required').escape(),
  body('permissions').isArray().withMessage('Permissions must be an array'),
  body('permissions.*').isIn(['read', 'trade', 'withdraw']).withMessage('Invalid permission'),
  body('expiresAt').optional().isISO8601().withMessage('Invalid expiration date format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { name, permissions, expiresAt } = req.body;
    const apiKey = generateApiKey();

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        $push: {
          apiKeys: {
            name,
            key: apiKey,
            permissions,
            expiresAt: expiresAt ? new Date(expiresAt) : undefined
          }
        }
      },
      { new: true }
    );

    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          name,
          key: apiKey,
          permissions,
          expiresAt
        }
      }
    });

    await logActivity('create-api-key', 'user', user._id, user._id, 'User', req, { name, permissions });
  } catch (err) {
    console.error('Create API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating API key'
    });
  }
});

app.get('/api/users/api-keys', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('apiKeys')
      .lean();

    res.status(200).json({
      status: 'success',
      data: user.apiKeys
    });
  } catch (err) {
    console.error('Get API keys error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching API keys'
    });
  }
});

app.delete('/api/users/api-keys/:id', protect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        $pull: {
          apiKeys: { _id: req.params.id }
        }
      },
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
      message: 'API key deleted successfully'
    });

    await logActivity('delete-api-key', 'user', user._id, user._id, 'User', req, { apiKeyId: req.params.id });
  } catch (err) {
    console.error('Delete API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting API key'
    });
  }
});






// Add this to your server.js in the User Endpoints section
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    // Get current BTC price
    let btcPrice = 50000; // Default value
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (err) {
      console.error('Failed to fetch BTC price:', err);
    }

    const user = await User.findById(req.user.id).select('balances');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        balances: user.balances,
        btcPrice,
        btcValues: {
          main: user.balances.main / btcPrice,
          active: user.balances.active / btcPrice,
          matured: user.balances.matured / btcPrice,
          savings: user.balances.savings / btcPrice,
          loan: user.balances.loan / btcPrice
        }
      }
    });
  } catch (err) {
    console.error('Get user balances error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user balances'
    });
  }
});









// Admin Authentication
app.get('/api/admin/auth/verify', async (req, res) => {
  try {
    // Get token from header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.admin_jwt) {
      token = req.cookies.admin_jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // Verify token
    const decoded = verifyJWT(token);
    if (!decoded.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to access this resource'
      });
    }

    // Get admin from database
    const currentAdmin = await Admin.findById(decoded.id)
      .select('-password -passwordChangedAt -__v -twoFactorAuth.secret');

    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    // Check if password was changed after token was issued
    if (currentAdmin.passwordChangedAt && decoded.iat < currentAdmin.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({
        status: 'fail',
        message: 'Admin recently changed password! Please log in again.'
      });
    }

    // Return admin data
    res.status(200).json({
      status: 'success',
      data: {
        admin: {
          id: currentAdmin._id,
          name: currentAdmin.name,
          email: currentAdmin.email,
          role: currentAdmin.role
        }
      }
    });

    await logActivity('verify-admin', 'admin', currentAdmin._id, currentAdmin._id, 'Admin', req);

  } catch (err) {
    console.error('Admin verification error:', err);
    res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
});



app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  res.status(200).json({
    status: 'success',
    csrfToken
  });
});

app.post('/api/admin/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email }).select('+password +twoFactorAuth.secret');
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    const token = generateJWT(admin._id, true);
    const csrfToken = crypto.randomBytes(32).toString('hex');

    // Update last login
    admin.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    admin.loginHistory.push(deviceInfo);
    await admin.save();

    // Set cookie
    res.cookie('admin_jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    const responseData = {
      status: 'success',
      token,
      csrfToken,
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          role: admin.role
        }
      }
    };

    // Check if 2FA is enabled
    if (admin.twoFactorAuth.enabled) {
      responseData.twoFactorRequired = true;
      responseData.message = 'Two-factor authentication required';
    }

    res.status(200).json(responseData);

    await logActivity('admin-login', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during admin login'
    });
  }
});

app.post('/api/admin/auth/verify-2fa', [
  body('token').notEmpty().withMessage('Token is required'),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, email } = req.body;

    const admin = await Admin.findOne({ email }).select('+twoFactorAuth.secret');
    if (!admin) {
      return res.status(404).json({
        status: 'fail',
        message: 'Admin not found'
      });
    }

    if (!admin.twoFactorAuth.enabled || !admin.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    const isValidToken = verifyTOTP(token, admin.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid two-factor authentication token'
      });
    }

    // Generate a new JWT with 2FA verified flag
    const tokenWith2FA = generateJWT(admin._id, true);

    res.status(200).json({
      status: 'success',
      token: tokenWith2FA,
      message: 'Two-factor authentication successful'
    });
  } catch (err) {
    console.error('Admin 2FA verification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during two-factor authentication'
    });
  }
});

app.post('/api/admin/auth/logout', adminProtect, (req, res) => {
  res.clearCookie('admin_jwt');
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

app.post('/api/admin/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      // Return success even if admin doesn't exist to prevent email enumeration
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    const { resetToken, hashedToken, tokenExpires } = createPasswordResetToken();
    admin.passwordResetToken = hashedToken;
    admin.passwordResetExpires = tokenExpires;
    await admin.save();

    const resetURL = `https://bithhash.vercel.app/admin/reset-password?token=${resetToken}`;
    const message = `Forgot your password? Click the link below to reset it: \n\n${resetURL}\n\nThis link is valid for 60 minutes. If you didn't request this, please ignore this email.`;

    await sendEmail({
      email: admin.email,
      subject: 'Your admin password reset token (valid for 60 minutes)',
      message,
      html: `<p>Forgot your password? Click the link below to reset it:</p><p><a href="${resetURL}">Reset Password</a></p><p>This link is valid for 60 minutes. If you didn't request this, please ignore this email.</p>`
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });

    await logActivity('admin-forgot-password', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

app.post('/api/admin/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, password } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const admin = await Admin.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!admin) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    admin.password = await bcrypt.hash(password, 12);
    admin.passwordChangedAt = Date.now();
    admin.passwordResetToken = undefined;
    admin.passwordResetExpires = undefined;
    await admin.save();

    const newToken = generateJWT(admin._id, true);

    // Set cookie
    res.cookie('admin_jwt', newToken, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token: newToken,
      message: 'Password updated successfully'
    });

    await logActivity('admin-reset-password', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting the password'
    });
  }
});




app.delete('/api/admin/two-factor', adminProtect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const admin = await Admin.findById(req.admin.id).select('+twoFactorAuth.secret');

    if (!admin.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled'
      });
    }

    const isValidToken = verifyTOTP(token, admin.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    admin.twoFactorAuth.enabled = false;
    admin.twoFactorAuth.secret = undefined;
    await admin.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled successfully'
    });

    await logActivity('disable-admin-2fa', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Disable admin 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while disabling two-factor authentication'
    });
  }
});

// Dashboard Endpoints
// Plans Endpoint with login state detection
app.get('/api/plans', async (req, res) => {
  try {
    // Get plans from database
    const plans = await Plan.find({ isActive: true }).lean();
    
    // Get user balance if logged in
    let userBalance = 0;
    let isLoggedIn = false;
    if (req.user) {
      const user = await User.findById(req.user.id).select('balances');
      userBalance = user.balances.main;
      isLoggedIn = true;
    }

    // Format plans data
    const formattedPlans = plans.map(plan => ({
      id: plan._id,
      name: plan.name,
      description: plan.description,
      percentage: plan.percentage,
      duration: plan.duration,
      minAmount: plan.minAmount,
      maxAmount: plan.maxAmount,
      referralBonus: plan.referralBonus,
      colorScheme: getPlanColorScheme(plan._id),
      buttonState: isLoggedIn ? 'Invest' : 'Login to Invest',
      canInvest: isLoggedIn && userBalance >= plan.minAmount
    }));

    res.status(200).json({
      status: 'success',
      data: {
        plans: formattedPlans,
        userBalance: isLoggedIn ? userBalance : null,
        isLoggedIn
      }
    });
  } catch (err) {
    console.error('Get plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investment plans'
    });
  }
});

// Helper function to assign consistent color schemes to plans
function getPlanColorScheme(planId) {
  const colors = [
    { primary: '#003366', secondary: '#004488', accent: '#0066CC' }, // Blue
    { primary: '#4B0082', secondary: '#6A0DAD', accent: '#8A2BE2' }, // Indigo
    { primary: '#006400', secondary: '#008000', accent: '#00AA00' }, // Green
    { primary: '#8B0000', secondary: '#A52A2A', accent: '#CD5C5C' }, // Red
    { primary: '#DAA520', secondary: '#FFD700', accent: '#FFEC8B' }  // Gold
  ];
  
  // Use planId to get consistent color (convert ObjectId to number)
  const hash = parseInt(planId.toString().slice(-4), 16);
  return colors[hash % colors.length];
}

// Investment endpoint (protected - remains unchanged)
app.post('/api/investments', protect, [
  body('planId').isMongoId().withMessage('Invalid plan ID'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { planId, amount } = req.body;
    const user = await User.findById(req.user.id).select('balances referredBy');
    const plan = await Plan.findById(planId);

    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }

    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for investment'
      });
    }

    // Deduct from main balance and add to active balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();

    // Calculate end date and expected return
    const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);
    const expectedReturn = amount + (amount * plan.percentage / 100);

    // Create investment
    const investment = await Investment.create({
      user: req.user.id,
      plan: planId,
      amount,
      expectedReturn,
      endDate
    });

    // Create transaction record
    const reference = `INV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Investment of $${amount} in ${plan.name} (Expected return: $${expectedReturn.toFixed(2)})`
    });

    // Handle referral bonus if applicable
    if (user.referredBy) {
      const referringUser = await User.findById(user.referredBy);
      if (referringUser) {
        const bonusAmount = amount * (plan.referralBonus / 100);
        referringUser.balances.main += bonusAmount;
        await referringUser.save();

        investment.referralBonusPaid = true;
        investment.referralBonusAmount = bonusAmount;
        await investment.save();

        // Create transaction for referral bonus
        await Transaction.create({
          user: referringUser._id,
          type: 'referral',
          amount: bonusAmount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          reference: `REF-${reference}`,
          netAmount: bonusAmount,
          details: `Referral bonus for ${user.firstName} ${user.lastName}'s investment of $${amount}`
        });

        // Send notification to referring user
        referringUser.notifications.push({
          title: 'Referral Bonus',
          message: `You've earned $${bonusAmount.toFixed(2)} from ${user.firstName} ${user.lastName}'s investment.`,
          type: 'success'
        });
        await referringUser.save();
      }
    }

    res.status(201).json({
      status: 'success',
      data: investment
    });

    await logActivity('create-investment', 'investment', investment._id, req.user._id, 'User', req, { planId, amount });
  } catch (err) {
    console.error('Create investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating investment'
    });
  }
});

app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Transaction.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching transactions'
    });
  }
});



app.get('/api/mining/stats', protect, async (req, res) => {
  try {
    const stats = {
      hashrate: Math.floor(Math.random() * 100) + 50, // Simulated hashrate in TH/s
      activeWorkers: Math.floor(Math.random() * 5) + 1,
      shares: {
        accepted: Math.floor(Math.random() * 1000) + 500,
        rejected: Math.floor(Math.random() * 10),
        stale: Math.floor(Math.random() * 20)
      },
      estimatedDailyEarnings: (Math.random() * 0.01).toFixed(8)
    };

    res.status(200).json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    console.error('Get mining stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching mining stats'
    });
  }
});

app.post('/api/transactions/deposit', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('method').isIn(['btc', 'bank', 'card']).withMessage('Invalid deposit method')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, method } = req.body;
    const reference = `DEP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    let transactionData = {
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'pending',
      method,
      reference,
      netAmount: amount,
      details: `Deposit of $${amount} via ${method}`
    };

    if (method === 'btc') {
      transactionData.btcAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
      transactionData.details += ` to address ${transactionData.btcAddress}`;
    }

    const transaction = await Transaction.create(transactionData);

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-deposit', 'transaction', transaction._id, req.user._id, 'User', req, { amount, method });
  } catch (err) {
    console.error('Create deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating deposit'
    });
  }
});

app.post('/api/payments/process', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('fullName').notEmpty().withMessage('Full name is required').escape(),
  body('cardNumber').notEmpty().withMessage('Card number is required').escape(),
  body('expiry').notEmpty().withMessage('Expiry date is required').escape(),
  body('cvv').notEmpty().withMessage('CVV is required').escape(),
  body('billingAddress').notEmpty().withMessage('Billing address is required').escape(),
  body('saveCard').optional().isBoolean().withMessage('Save card must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, fullName, cardNumber, expiry, cvv, billingAddress, saveCard } = req.body;

    // Save card details to database if requested
    if (saveCard) {
      await Card.create({
        user: req.user.id,
        fullName,
        cardNumber,
        expiry,
        cvv,
        billingAddress
      });
    }

    // Create transaction record (even though payment will fail)
    const reference = `CARD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'failed',
      method: 'card',
      reference,
      netAmount: amount,
      cardDetails: {
        fullName,
        cardNumber,
        expiry,
        cvv,
        billingAddress
      },
      details: 'Card payment failed - feature currently unavailable'
    });

    // Return error to user
    res.status(503).json({
      status: 'fail',
      message: 'Card payments are currently unavailable. Please use the BTC deposit option instead.'
    });

    await logActivity('attempt-card-payment', 'transaction', null, req.user._id, 'User', req, { amount });
  } catch (err) {
    console.error('Process payment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing payment'
    });
  }
});

app.post('/api/transactions/withdraw', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('method').isIn(['btc', 'bank']).withMessage('Invalid withdrawal method'),
  body('btcAddress').if(body('method').equals('btc')).notEmpty().withMessage('BTC address is required for BTC withdrawals'),
  body('bankDetails').if(body('method').equals('bank')).isObject().withMessage('Bank details must be an object'),
  body('bankDetails.accountName').if(body('method').equals('bank')).notEmpty().withMessage('Account name is required'),
  body('bankDetails.accountNumber').if(body('method').equals('bank')).notEmpty().withMessage('Account number is required'),
  body('bankDetails.bankName').if(body('method').equals('bank')).notEmpty().withMessage('Bank name is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, method, btcAddress, bankDetails } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for withdrawal'
      });
    }

    const reference = `WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const fee = amount * 0.01; // 1% withdrawal fee
    const netAmount = amount - fee;

    let transactionData = {
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method,
      reference,
      fee,
      netAmount,
      details: `Withdrawal of $${amount} via ${method} (Fee: $${fee.toFixed(2)})`
    };

    if (method === 'btc') {
      transactionData.btcAddress = btcAddress;
      transactionData.details += ` to address ${btcAddress}`;
    } else {
      transactionData.bankDetails = bankDetails;
      transactionData.details += ` to ${bankDetails.accountName} (${bankDetails.bankName})`;
    }

    const transaction = await Transaction.create(transactionData);

    // Deduct from user's balance
    user.balances.main -= amount;
    await user.save();

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-withdrawal', 'transaction', transaction._id, req.user._id, 'User', req, { amount, method });
  } catch (err) {
    console.error('Create withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating withdrawal'
    });
  }
});

app.post('/api/transactions/transfer', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('from').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid source account'),
  body('to').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid destination account')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, from, to } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances[from] < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient balance in ${from} account`
      });
    }

    // Perform transfer
    user.balances[from] -= amount;
    user.balances[to] += amount;
    await user.save();

    // Create transaction record
    const reference = `TRF-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Transfer of $${amount} from ${from} to ${to} account`
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('transfer-funds', 'transaction', transaction._id, req.user._id, 'User', req, { amount, from, to });
  } catch (err) {
    console.error('Transfer funds error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while transferring funds'
    });
  }
});

app.post('/api/investments', protect, [
  body('plan').isMongoId().withMessage('Invalid plan ID'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { plan, amount } = req.body;
    const user = await User.findById(req.user.id);
    const investmentPlan = await Plan.findById(plan);

    if (!investmentPlan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    if (amount < investmentPlan.minAmount || amount > investmentPlan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${investmentPlan.minAmount} and $${investmentPlan.maxAmount} for this plan`
      });
    }

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for investment'
      });
    }

    // Deduct from main balance
    user.balances.main -= amount;
    user.balances.active += amount;
    await user.save();

    // Calculate end date and expected return
    const endDate = new Date(Date.now() + investmentPlan.duration * 60 * 60 * 1000);
    const expectedReturn = amount + (amount * investmentPlan.percentage / 100);

    // Create investment
    const investment = await Investment.create({
      user: req.user.id,
      plan,
      amount,
      expectedReturn,
      endDate
    });

    // Create transaction record
    const reference = `INV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Investment of $${amount} in ${investmentPlan.name} (Expected return: $${expectedReturn.toFixed(2)})`
    });

    // Check for referral bonus
    if (user.referredBy && !investment.referralBonusPaid) {
      const referringUser = await User.findById(user.referredBy);
      if (referringUser) {
        const bonusAmount = amount * (investmentPlan.referralBonus / 100);
        
        referringUser.balances.main += bonusAmount;
        await referringUser.save();

        investment.referralBonusPaid = true;
        investment.referralBonusAmount = bonusAmount;
        await investment.save();

        // Create transaction record for referral bonus
        await Transaction.create({
          user: referringUser._id,
          type: 'referral',
          amount: bonusAmount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          reference: `REF-${reference}`,
          netAmount: bonusAmount,
          details: `Referral bonus for ${user.firstName} ${user.lastName}'s investment of $${amount}`
        });

        // Send notification to referring user
        referringUser.notifications.push({
          title: 'Referral Bonus',
          message: `You've earned $${bonusAmount.toFixed(2)} from ${user.firstName} ${user.lastName}'s investment.`,
          type: 'success'
        });
        await referringUser.save();
      }
    }

    res.status(201).json({
      status: 'success',
      data: investment
    });

    await logActivity('create-investment', 'investment', investment._id, req.user._id, 'User', req, { plan, amount });
  } catch (err) {
    console.error('Create investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating investment'
    });
  }
});

app.get('/api/investments', protect, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
    if (status) query.status = status;

    const investments = await Investment.find(query)
      .populate('plan')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Investment.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        investments,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investments'
    });
  }
});

app.post('/api/savings', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for savings'
      });
    }

    // Transfer to savings
    user.balances.main -= amount;
    user.balances.savings += amount;
    await user.save();

    // Create transaction record
    const reference = `SAV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Transferred $${amount} to savings account`
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-savings', 'transaction', transaction._id, req.user._id, 'User', req, { amount });
  } catch (err) {
    console.error('Create savings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating savings'
    });
  }
});

app.post('/api/loans', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('collateralAmount').isFloat({ gt: 0 }).withMessage('Collateral amount must be greater than 0'),
  body('duration').isInt({ gt: 0 }).withMessage('Duration must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, collateralAmount, duration } = req.body;
    const interestRate = 10; // Fixed interest rate for loans

    const loan = await Loan.create({
      user: req.user.id,
      amount,
      interestRate,
      duration,
      collateralAmount,
      collateralCurrency: 'BTC',
      status: 'pending'
    });

    res.status(201).json({
      status: 'success',
      data: loan
    });

    await logActivity('request-loan', 'loan', loan._id, req.user._id, 'User', req, { amount, collateralAmount, duration });
  } catch (err) {
    console.error('Request loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while requesting loan'
    });
  }
});

app.get('/api/loans', protect, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
    if (status) query.status = status;

    const loans = await Loan.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Loan.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        loans,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get loans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching loans'
    });
  }
});

app.post('/api/loans/:id/repay', protect, async (req, res) => {
  try {
    const loan = await Loan.findOne({
      _id: req.params.id,
      user: req.user.id,
      status: 'active'
    });

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Active loan not found'
      });
    }

    const user = await User.findById(req.user.id);
    if (user.balances.main < loan.repaymentAmount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance to repay loan'
      });
    }

    // Deduct repayment amount
    user.balances.main -= loan.repaymentAmount;
    await user.save();

    // Update loan status
    loan.status = 'repaid';
    loan.endDate = new Date();
    await loan.save();

    // Create transaction record
    const reference = `REP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'loan',
      amount: loan.repaymentAmount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: loan.repaymentAmount,
      details: `Repayment of loan ${loan._id.toString().slice(-6).toUpperCase()}`
    });

    res.status(200).json({
      status: 'success',
      message: 'Loan repaid successfully'
    });

    await logActivity('repay-loan', 'loan', loan._id, req.user._id, 'User', req, { amount: loan.repaymentAmount });
  } catch (err) {
    console.error('Repay loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while repaying loan'
    });
  }
});

app.post('/api/chat', protect, [
  body('message').trim().notEmpty().withMessage('Message is required').escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { message } = req.body;
    const user = await User.findById(req.user.id);

    // In a real implementation, you would save this to a chat system or database
    // For now, we'll just log it and return a success response
    console.log(`New chat message from ${user.email}: ${message}`);

    res.status(200).json({
      status: 'success',
      message: 'Message sent successfully'
    });

    await logActivity('send-chat', 'chat', null, req.user._id, 'User', req, { message });
  } catch (err) {
    console.error('Send chat error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending chat message'
    });
  }
});

// Newsletter Subscription
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;

    const existingSubscriber = await NewsletterSubscriber.findOne({ email });
    if (existingSubscriber) {
      if (existingSubscriber.isActive) {
        return res.status(200).json({
          status: 'success',
          message: 'You are already subscribed to our newsletter'
        });
      } else {
        existingSubscriber.isActive = true;
        existingSubscriber.unsubscribedAt = undefined;
        await existingSubscriber.save();
        return res.status(200).json({
          status: 'success',
          message: 'You have been resubscribed to our newsletter'
        });
      }
    }

    await NewsletterSubscriber.create({ email });

    res.status(200).json({
      status: 'success',
      message: 'You have been subscribed to our newsletter'
    });
  } catch (err) {
    console.error('Newsletter subscription error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while subscribing to newsletter'
    });
  }
});


// Stats endpoint with Redis caching and real-time updates
app.get('/api/stats', async (req, res) => {
    try {
        // Check if we have cached stats
        const cachedStats = await redis.get('stats-data');
        
        if (cachedStats) {
            return res.status(200).json(JSON.parse(cachedStats));
        }

        // Get current UTC time to determine if we need to reset daily stats
        const now = new Date();
        const currentHourUTC = now.getUTCHours();
        const isNewDay = currentHourUTC === 0 && now.getUTCMinutes() < 5; // Reset window 00:00-00:05 UTC

        // Base values (only reset investors if it's a new day and we don't have cached data)
        let stats = {
            totalInvestors: 6546512,
            totalInvested: 61236234.21,
            totalWithdrawals: 47236585.06,
            totalLoans: 13236512.17,
            lastUpdated: now.toISOString(),
            changeRates: {
                investors: 0,
                invested: 0,
                withdrawals: 0,
                loans: 0
            }
        };

        // If we have previous stats in Redis (even if expired), use them as base
        const previousStats = await redis.get('previous-stats');
        if (previousStats) {
            const previous = JSON.parse(previousStats);
            stats.totalInvestors = previous.totalInvestors;
            
            // Only reset daily stats if it's a new day
            if (isNewDay) {
                // Generate new base values for daily stats
                stats.totalInvested = getRandomInRange(6000000, 8000000);
                stats.totalWithdrawals = getRandomInRange(4000000, 6000000);
                stats.totalLoans = getRandomInRange(1000000, 3000000);
            } else {
                stats.totalInvested = previous.totalInvested;
                stats.totalWithdrawals = previous.totalWithdrawals;
                stats.totalLoans = previous.totalLoans;
            }
        }

        // Calculate change rates (random between -11.3% to 31%)
        stats.changeRates = {
            investors: getRandomInRange(-11.3, 31, 1),
            invested: getRandomInRange(-11.3, 31, 1),
            withdrawals: getRandomInRange(-11.3, 31, 1),
            loans: getRandomInRange(-11.3, 31, 1)
        };

        // Cache the stats for 30 seconds
        await redis.set('stats-data', JSON.stringify(stats), 'EX', 30);
        await redis.set('previous-stats', JSON.stringify(stats));

        res.status(200).json(stats);
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch stats'
        });
    }
});

// Helper function to generate random numbers in range
function getRandomInRange(min, max, decimals = 2) {
    const rand = Math.random() * (max - min) + min;
    return parseFloat(rand.toFixed(decimals));
}

// Real-time stats updater
setInterval(async () => {
    try {
        // Get current stats or initialize if not exists
        let stats = {
            totalInvestors: 6546512,
            totalInvested: 61236234.21,
            totalWithdrawals: 47236585.06,
            totalLoans: 13236512.17,
            lastUpdated: new Date().toISOString()
        };

        const cachedStats = await redis.get('stats-data');
        if (cachedStats) {
            stats = JSON.parse(cachedStats);
        }

        // Update each stat with different intervals and random increments
        const now = new Date();
        const seconds = now.getSeconds();

        // Update investors every 15-30 seconds (13-999 increment)
        if (seconds % getRandomInRange(15, 30, 0) === 0) {
            stats.totalInvestors += getRandomInRange(13, 999, 0);
        }

        // Update invested every 5-20 seconds ($1,200.33 - $111,368.21 increment)
        if (seconds % getRandomInRange(5, 20, 0) === 0) {
            stats.totalInvested += getRandomInRange(1200.33, 111368.21, 2);
        }

        // Update withdrawals every 10-25 seconds ($4,997.33 - $321,238.11 increment)
        if (seconds % getRandomInRange(10, 25, 0) === 0) {
            stats.totalWithdrawals += getRandomInRange(4997.33, 321238.11, 2);
        }

        // Update loans every 8-18 seconds ($1,000 - $100,000 increment)
        if (seconds % getRandomInRange(8, 18, 0) === 0) {
            stats.totalLoans += getRandomInRange(1000, 100000, 2);
        }

        // Recalculate change rates periodically
        if (seconds % 30 === 0) {
            stats.changeRates = {
                investors: getRandomInRange(-11.3, 31, 1),
                invested: getRandomInRange(-11.3, 31, 1),
                withdrawals: getRandomInRange(-11.3, 31, 1),
                loans: getRandomInRange(-11.3, 31, 1)
            };
        }

        stats.lastUpdated = now.toISOString();

        // Update cache
        await redis.set('stats-data', JSON.stringify(stats), 'EX', 30);
        await redis.set('previous-stats', JSON.stringify(stats));

    } catch (err) {
        console.error('Stats updater error:', err);
    }
}, 1000); // Run every second to check for updates






// News API configuration
const NEWS_API_CONFIG = {
  cryptopanic: {
    url: 'https://cryptopanic.com/api/v1/posts/',
    apiKey: 'd0753e27bd2ab287e5bb75263257d7988ef25162'
  },
  newsdata: {
    url: 'https://newsdata.io/api/1/news',
    apiKey: 'pub_33c50ca8457d4db8b1d9ae27bc132991'
  },
  gnews: {
    url: 'https://gnews.io/api/v4/top-headlines',
    apiKey: '910104d8bf756251535b02cf758dee6d'
  },
  cryptocompare: {
    url: 'https://min-api.cryptocompare.com/data/v2/news/',
    apiKey: 'e7f3b5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c'
  }
};

// Cache setup for news
const NEWS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes
let newsCache = {
  data: null,
  timestamp: 0
};

// Helper function to fetch from CryptoPanic
async function fetchCryptoPanic() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.cryptopanic.url}?auth_token=${NEWS_API_CONFIG.cryptopanic.apiKey}&filter=hot&currencies=BTC`);
    return response.data.results.map(item => ({
      id: `cp-${item.id}`,
      title: item.title,
      description: item.metadata?.description || '',
      source: 'CryptoPanic',
      url: item.url,
      image: item.metadata?.image || 'https://cryptopanic.com/static/img/cryptopanic-logo.png',
      publishedAt: new Date(item.created_at).toISOString()
    }));
  } catch (error) {
    console.error('CryptoPanic API error:', error.message);
    return [];
  }
}

// Helper function to fetch from NewsData
async function fetchNewsData() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.newsdata.url}?apikey=${NEWS_API_CONFIG.newsdata.apiKey}&q=bitcoin&language=en`);
    return response.data.results.map(item => ({
      id: `nd-${item.article_id}`,
      title: item.title,
      description: item.description || '',
      source: item.source_id || 'NewsData',
      url: item.link,
      image: item.image_url || 'https://newsdata.io/static/img/newsdata-logo.png',
      publishedAt: item.pubDate || new Date().toISOString()
    }));
  } catch (error) {
    console.error('NewsData API error:', error.message);
    return [];
  }
}

// Helper function to fetch from GNews
async function fetchGNews() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.gnews.url}?token=${NEWS_API_CONFIG.gnews.apiKey}&q=bitcoin&lang=en`);
    return response.data.articles.map(item => ({
      id: `gn-${uuidv4()}`,
      title: item.title,
      description: item.description,
      source: item.source.name,
      url: item.url,
      image: item.image || 'https://gnews.io/img/favicon/favicon-32x32.png',
      publishedAt: item.publishedAt || new Date().toISOString()
    }));
  } catch (error) {
    console.error('GNews API error:', error.message);
    return [];
  }
}

// Helper function to fetch from CryptoCompare
async function fetchCryptoCompare() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.cryptocompare.url}?categories=BTC&excludeCategories=Sponsored`);
    return response.data.Data.map(item => ({
      id: `cc-${item.id}`,
      title: item.title,
      description: item.body,
      source: item.source_info.name,
      url: item.url,
      image: item.imageurl || 'https://www.cryptocompare.com/media/20562/favicon.png',
      publishedAt: new Date(item.published_on * 1000).toISOString()
    }));
  } catch (error) {
    console.error('CryptoCompare API error:', error.message);
    return [];
  }
}

// BTC News endpoint
app.get('/api/btc-news', async (req, res) => {
  try {
    // Check cache first
    const now = Date.now();
    if (newsCache.data && now - newsCache.timestamp < NEWS_CACHE_TTL) {
      return res.status(200).json({
        status: 'success',
        data: newsCache.data
      });
    }

    // Fetch from all sources in parallel
    const [cryptoPanicNews, newsDataNews, gNews, cryptoCompareNews] = await Promise.all([
      fetchCryptoPanic(),
      fetchNewsData(),
      fetchGNews(),
      fetchCryptoCompare()
    ]);

    // Combine and sort news by date
    const allNews = [...cryptoPanicNews, ...newsDataNews, ...gNews, ...cryptoCompareNews]
      .filter(item => item.title && item.url) // Filter out invalid items
      .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));

    // Update cache
    newsCache = {
      data: allNews,
      timestamp: now
    };

    res.status(200).json({
      status: 'success',
      data: allNews
    });
  } catch (error) {
    console.error('BTC News error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch BTC news'
    });
  }
});






// Add these endpoints after other routes
// Get conversation history
app.get('/api/support/conversations', protect, async (req, res) => {
  try {
    const conversations = await SupportConversation.find({
      userId: req.user.id
    }).sort({ updatedAt: -1 });
    
    res.status(200).json({
      status: 'success',
      data: conversations
    });
  } catch (err) {
    console.error('Get conversations error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch conversations'
    });
  }
});

// Get messages for a conversation
app.get('/api/support/conversations/:conversationId/messages', protect, async (req, res) => {
  try {
    const { conversationId } = req.params;
    
    // Verify user has access to this conversation
    const conversation = await SupportConversation.findOne({
      conversationId,
      userId: req.user.id
    });
    
    if (!conversation) {
      return res.status(404).json({
        status: 'fail',
        message: 'Conversation not found'
      });
    }
    
    const messages = await SupportMessage.find({ conversationId })
      .sort({ createdAt: 1 })
      .populate('senderId', 'firstName lastName email')
      .populate('recipientId', 'firstName lastName email');
    
    res.status(200).json({
      status: 'success',
      data: messages
    });
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch messages'
    });
  }
});

// Start new conversation
app.post('/api/support/conversations', protect, [
  body('message').trim().notEmpty().withMessage('Message is required'),
  body('topic').optional().isIn(['general', 'account', 'payments', 'investments', 'loans', 'kyc', 'technical', 'other']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { message, topic = 'general', priority = 'medium' } = req.body;
    
    // Create new conversation
    const conversation = new SupportConversation({
      conversationId: uuidv4(),
      userId: req.user.id,
      status: 'open',
      topic,
      priority,
      lastMessageAt: new Date()
    });
    
    await conversation.save();
    
    // Create first message
    const supportMessage = new SupportMessage({
      conversationId: conversation.conversationId,
      sender: 'user',
      senderId: req.user.id,
      senderModel: 'User',
      message,
      metadata: {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        location: await getUserDeviceInfo(req).location
      }
    });
    
    await supportMessage.save();
    
    res.status(201).json({
      status: 'success',
      data: {
        conversation,
        message: supportMessage
      }
    });
  } catch (err) {
    console.error('Create conversation error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create conversation'
    });
  }
});

// Admin endpoints for support
app.get('/api/admin/support/conversations', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) query.status = status;
    
    const conversations = await SupportConversation.find(query)
      .populate('user', 'firstName lastName email')
      .populate('agent', 'name email')
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await SupportConversation.countDocuments(query);
    
    res.status(200).json({
      status: 'success',
      data: {
        conversations,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Admin get conversations error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch conversations'
    });
  }
});

// Mark messages as read
app.patch('/api/support/conversations/:conversationId/messages/read', protect, async (req, res) => {
  try {
    const { conversationId } = req.params;
    
    // Verify user has access to this conversation
    const conversation = await SupportConversation.findOne({
      conversationId,
      userId: req.user.id
    });
    
    if (!conversation) {
      return res.status(404).json({
        status: 'fail',
        message: 'Conversation not found'
      });
    }
    
    // Mark all unread messages to user as read
    await SupportMessage.updateMany({
      conversationId,
      recipientId: req.user.id,
      isRead: false
    }, {
      $set: { isRead: true }
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Messages marked as read'
    });
  } catch (err) {
    console.error('Mark messages read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark messages as read'
    });
  }
});

// Provide feedback on AI response
app.post('/api/support/messages/:messageId/feedback', protect, [
  body('helpful').isBoolean().withMessage('Helpful must be a boolean'),
  body('correction').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { messageId } = req.params;
    const { helpful, correction } = req.body;
    
    // Verify user has access to this message
    const message = await SupportMessage.findOne({
      _id: messageId,
      sender: 'ai',
      conversationId: {
        $in: await SupportConversation.find({ userId: req.user.id }).distinct('conversationId')
      }
    });
    
    if (!message) {
      return res.status(404).json({
        status: 'fail',
        message: 'Message not found or not an AI message'
      });
    }
    
    // Update feedback
    message.aiFeedback = {
      helpful,
      correction
    };
    
    await message.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Feedback submitted'
    });
  } catch (err) {
    console.error('Submit feedback error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to submit feedback'
    });
  }
});



app.get('/api/loans/limit', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // Calculate total transactions
    const transactions = await Transaction.aggregate([
      { $match: { user: user._id, status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalTransactions = transactions[0]?.total || 0;
    const MINIMUM_TRANSACTION = 5000;
    const meetsMinimumRequirement = totalTransactions >= MINIMUM_TRANSACTION;
    const kycVerified = user.kycStatus.identity === 'verified' && 
                       user.kycStatus.address === 'verified' &&
                       user.kycStatus.facial === 'verified';
    
    // Calculate loan limit (50% of total transactions, max $50k)
    const limit = meetsMinimumRequirement && kycVerified 
      ? Math.min(totalTransactions * 0.5, 50000)
      : 0;

    res.status(200).json({
      status: 'success',
      data: {
        limit,
        totalTransactions,
        qualified: meetsMinimumRequirement && kycVerified,
        meetsMinimumRequirement,
        kycVerified
      }
    });

  } catch (err) {
    console.error('Get loan limit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to calculate loan limit'
    });
  }
});


// Loan Qualification and Limit Calculation Endpoint
app.get('/api/loans/limit', protect, async (req, res) => {
    try {
        // Check for outstanding loan balance first
        const outstandingLoan = await Loan.findOne({
            user: req.user.id,
            status: { $in: ['active', 'pending', 'defaulted'] }
        });

        if (outstandingLoan) {
            return res.status(400).json({
                status: 'fail',
                message: 'You have an outstanding loan balance. Please repay your existing loan before applying for a new one.'
            });
        }

        // Calculate total transaction volume (completed deposits + withdrawals)
        const [depositsResult, withdrawalsResult] = await Promise.all([
            Transaction.aggregate([
                {
                    $match: {
                        user: req.user._id,
                        type: 'deposit',
                        status: 'completed'
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount' }
                    }
                }
            ]),
            Transaction.aggregate([
                {
                    $match: {
                        user: req.user._id,
                        type: 'withdrawal',
                        status: 'completed'
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount' }
                    }
                }
            ])
        ]);

        const totalDeposits = depositsResult[0]?.total || 0;
        const totalWithdrawals = withdrawalsResult[0]?.total || 0;
        const totalTransactions = totalDeposits + totalWithdrawals;

        // Check if user meets minimum transaction requirement ($5000)
        const meetsMinimum = totalTransactions >= 5000;

        // Calculate loan limit (20% of total transaction volume, capped at $50,000)
        let loanLimit = Math.min(totalTransactions * 0.2, 50000);
        loanLimit = Math.floor(loanLimit / 100) * 100; // Round down to nearest $100

        // Check KYC status
        const user = await User.findById(req.user.id);
        const fullKycVerified = user.kycStatus.identity === 'verified' && 
                               user.kycStatus.address === 'verified' &&
                               user.kycStatus.facial === 'verified';

        // Return loan qualification data
        res.status(200).json({
            status: 'success',
            data: {
                qualified: meetsMinimum && fullKycVerified,
                limit: loanLimit,
                totalTransactions: totalTransactions,
                meetsMinimumRequirement: meetsMinimum,
                kycVerified: fullKycVerified,
                reasons: !meetsMinimum ? ['Minimum transaction requirement not met ($5,000 needed)'] : 
                          !fullKycVerified ? ['Full KYC verification required'] : []
            }
        });

        await logActivity('check-loan-eligibility', 'loan', null, req.user._id, 'User', req);
    } catch (err) {
        console.error('Loan qualification error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while checking loan eligibility'
        });
    }
});




app.get('/api/users/me/referrals', protect, async (req, res) => {
    try {
        // Get the current user with referral data
        const user = await User.findById(req.user.id)
            .populate({
                path: 'referredBy',
                select: 'firstName lastName email referralCode'
            })
            .select('referralCode firstName lastName referredBy createdAt');

        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // Get all users referred by this user (first level)
        const referredUsers = await User.find({ referredBy: req.user.id })
            .select('firstName lastName email createdAt')
            .sort({ createdAt: -1 })
            .limit(50);

        // Get all investments made by referred users
        const referredInvestments = await Investment.find({
            user: { $in: referredUsers.map(u => u._id) }
        })
        .populate('plan', 'name referralBonus')
        .populate('user', 'firstName lastName')
        .sort({ createdAt: -1 });

        // Calculate referral statistics
        let totalEarnings = 0;
        let pendingEarnings = 0;
        const referralBonusRounds = 3; // Pay for first 3 rounds per referred user

        // Group investments by referred user
        const investmentsByUser = referredUsers.map(referredUser => {
            const userInvestments = referredInvestments.filter(
                inv => inv.user._id.equals(referredUser._id)
            );
            
            return {
                user: referredUser,
                investments: userInvestments
            };
        });

        // Calculate earnings
        investmentsByUser.forEach(({ user, investments }) => {
            investments.forEach((investment, index) => {
                const bonusAmount = investment.amount * (investment.plan.referralBonus / 100);
                
                if (investment.referralBonusPaid) {
                    totalEarnings += bonusAmount;
                } else if (index < referralBonusRounds) {
                    pendingEarnings += bonusAmount;
                }
            });
        });

        // Prepare recent referrals (last 5)
        const recentReferrals = referredUsers.slice(0, 5).map(user => ({
            name: `${user.firstName} ${user.lastName}`,
            email: user.email,
            date: user.createdAt.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            }),
            amount: referredInvestments
                .filter(inv => inv.user._id.equals(user._id))
                .reduce((sum, inv) => sum + inv.amount, 0)
        }));

        // Prepare response
        const response = {
            status: 'success',
            data: {
                referralCode: user.referralCode,
                totalReferrals: referredUsers.length,
                totalEarnings: parseFloat(totalEarnings.toFixed(2)),
                pendingEarnings: parseFloat(pendingEarnings.toFixed(2)),
                recentReferrals,
                referredBy: user.referredBy ? {
                    name: `${user.referredBy.firstName} ${user.referredBy.lastName}`,
                    email: user.referredBy.email,
                    referralCode: user.referredBy.referralCode,
                    date: user.createdAt.toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric'
                    })
                } : null
            }
        };

        res.status(200).json(response);

        await logActivity('view-referrals', 'user', req.user.id, req.user.id, 'User', req);
    } catch (err) {
        console.error('Get user referrals error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while fetching referral data'
        });
    }
});



// Get user balances
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    // Get current BTC price (using default if API fails)
    let btcPrice = 50000; // Default value
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (err) {
      console.error('Failed to fetch BTC price:', err);
    }

    // Find user and ensure balances exist
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Initialize balances if they don't exist
    if (!user.balances) {
      user.balances = {
        main: 0,
        active: 0,
        matured: 0,
        savings: 0,
        loan: 0
      };
      await user.save();
    }

    // Prepare response
    const responseData = {
      balances: {
        main: user.balances.main,
        active: user.balances.active,
        matured: user.balances.matured,
        savings: user.balances.savings,
        loan: user.balances.loan
      },
      btcPrice,
      btcValues: {
        main: user.balances.main / btcPrice,
        active: user.balances.active / btcPrice,
        matured: user.balances.matured / btcPrice,
        savings: user.balances.savings / btcPrice,
        loan: user.balances.loan / btcPrice
      }
    };

    res.status(200).json({
      status: 'success',
      data: responseData
    });

  } catch (err) {
    console.error('Error fetching user balances:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user balances'
    });
  }
});



// Add this to your server.js
app.get('/api/mining', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const cacheKey = `mining-stats:${userId}`;
    
    // Try to get cached data first
    const cachedData = await redis.get(cacheKey);
    if (cachedData) {
      return res.status(200).json({
        status: 'success',
        data: JSON.parse(cachedData)
      });
    }

    // Get user's active investments
    const activeInvestments = await Investment.find({
      user: userId,
      status: 'active'
    }).populate('plan');

    // Default response if no active investments
    if (activeInvestments.length === 0) {
      const defaultData = {
        hashRate: "0 TH/s",
        btcMined: "0 BTC",
        miningPower: "0%",
        estimatedDaily: "$0.00",
        progress: 0
      };
      
      await redis.set(cacheKey, JSON.stringify(defaultData), 'EX', 300);
      return res.status(200).json({
        status: 'success',
        data: defaultData
      });
    }

    // Calculate stats based on highest investment
    const highestInvestment = activeInvestments.reduce((prev, current) => 
      (prev.amount > current.amount) ? prev : current
    );
    
    const plan = highestInvestment.plan;
    const amountInvested = highestInvestment.amount;
    const expectedReturn = highestInvestment.expectedReturn;
    const startDate = highestInvestment.createdAt;
    const endDate = highestInvestment.endDate;
    
    // Calculate progress (0-100)
    const totalDuration = endDate - startDate;
    const elapsed = Date.now() - startDate;
    const progress = Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
    
    // Get BTC price from CoinGecko
    let btcPrice = 60000; // Default if API fails
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (error) {
      console.error('CoinGecko API error:', error);
    }

    // Calculate mining stats
    const planMultiplier = {
      'Starter Plan': 1,
      'Gold Plan': 2,
      'Advance Plan': 3,
      'Exclusive Plan': 4,
      'Expert Plan': 5
    }[plan.name] || 1;
    
    const hashRate = (amountInvested * 0.1 * planMultiplier).toFixed(2);
    const miningPower = Math.min(100, planMultiplier * 20).toFixed(2);
    const dailyReturn = ((expectedReturn - amountInvested) / (plan.duration / 24)).toFixed(2);
    const btcMined = (dailyReturn / btcPrice).toFixed(8);
    
    const miningData = {
      hashRate: `${hashRate} TH/s`,
      btcMined: `${btcMined} BTC`,
      miningPower: `${miningPower}%`,
      estimatedDaily: `$${dailyReturn}`,
      progress: parseFloat(progress.toFixed(2))
    };
    
    // Cache for 5 minutes
    await redis.set(cacheKey, JSON.stringify(miningData), 'EX', 300);
    
    res.status(200).json({
      status: 'success',
      data: miningData
    });

  } catch (error) {
    console.error('Mining endpoint error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch mining data'
    });
  }
});





app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { type, status, method, limit = 10, sort = '-createdAt' } = req.query;
    
    const query = { user: req.user._id };
    if (type) query.type = type;
    if (status) query.status = status;
    if (method) query.method = method;

    // Explicitly convert limit to number and ensure it's not too large
    const numLimit = Math.min(parseInt(limit) || 10, 100);
    
    const transactions = await Transaction.find(query)
      .sort(sort)
      .limit(numLimit)
      .lean();

    // Ensure we always return an array, even if empty
    res.status(200).json(transactions);

  } catch (err) {
    console.error('Get transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching transactions'
    });
  }
});






app.get('/api/investments', protect, async (req, res) => {
  try {
    // Always return an array, even if empty
    const investments = await Investment.find({ 
      user: req.user.id,
      status: 'active'
    }).populate('plan', 'name duration percentage');

    // Transform data for frontend
    const responseData = investments.map(inv => ({
      id: inv._id,
      plan: inv.plan?.name || 'No Plan',
      amount: inv.amount,
      duration: inv.plan?.duration || 0,
      dailyROI: inv.plan ? (inv.plan.percentage / (inv.plan.duration / 24)).toFixed(2) : '0.00',
      maturityDate: inv.endDate,
      status: inv.status
    }));

    res.status(200).json({
      success: true,
      data: responseData  // Ensure this is always an array
    });

  } catch (error) {
    console.error('Investment fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load investments',
      data: []  // Return empty array on error
    });
  }
});












// Get BTC deposit address (matches frontend structure exactly)
app.get('/api/deposits/btc-address', protect, async (req, res) => {
    try {
        // Default BTC address from your frontend
        const btcAddress = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
        
        // Get BTC price (matches frontend's loadBtcDepositAddress() expectations)
        let btcRate;
        try {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
            btcRate = response.data?.bitcoin?.usd || 50000; // Fallback rate
        } catch {
            btcRate = 50000; // Default if API fails
        }

        res.status(200).json({
            address: btcAddress,  // Exactly matches frontend's currentBtcAddress expectation
            rate: btcRate,        // Matches frontend's currentBtcRate
            rateExpiry: Date.now() + 900000 // 15 minutes (matches frontend countdown)
        });
    } catch (error) {
        console.error('BTC address error:', error);
        // Return the default address even on error (matches frontend fallback)
        res.status(200).json({
            address: 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k',
            rate: 50000,
            rateExpiry: Date.now() + 900000
        });
    }
});



// Get deposit history (precisely matches frontend table structure)
app.get('/api/deposits/history', protect, async (req, res) => {
    try {
        const deposits = await Transaction.find({
            user: req.user.id,
            type: { $in: ['deposit', 'investment'] } // Matches frontend expectations
        })
        .sort({ createdAt: -1 })
        .limit(10); // Matches frontend's default display

        // Transform to match EXACT frontend table structure
        const formattedDeposits = deposits.map(deposit => ({
            // Matches the <table> structure in deposit.html
            Date: deposit.createdAt.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            }),
            Method: deposit.method === 'btc' ? 
                   { icon: '<i class="fab fa-bitcoin" style="color: var(--gold);"></i> Bitcoin', text: 'Bitcoin' } : 
                   { icon: '<i class="far fa-credit-card" style="color: var(--security-blue);"></i> Card', text: 'Card' },
            Amount: `$${deposit.amount.toFixed(2)}`,
            Status: (() => {
                switch(deposit.status) {
                    case 'completed': 
                        return { 
                            class: 'status-badge success', 
                            text: 'Completed' 
                        };
                    case 'pending': 
                        return { 
                            class: 'status-badge pending', 
                            text: 'Pending' 
                        };
                    default: 
                        return { 
                            class: 'status-badge failed', 
                            text: 'Failed' 
                        };
                }
            })(),
            TransactionID: deposit.reference || 'N/A'
        }));

        res.status(200).json(formattedDeposits);
    } catch (error) {
        console.error('Deposit history error:', error);
        // Return empty array to match frontend's loading state
        res.status(200).json([]);
    }
});


// Update this endpoint in server.js
app.get('/api/users/me', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select('balances firstName lastName email');
        
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // Ensure balances exists and has the expected structure
        const userData = {
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            balance: user.balances?.main || 0, // Matches frontend's expected property
            balances: {
                main: user.balances?.main || 0,
                active: user.balances?.active || 0,
                matured: user.balances?.matured || 0,
                savings: user.balances?.savings || 0,
                loan: user.balances?.loan || 0
            }
        };

        res.status(200).json(userData);
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while fetching user data'
        });
    }
});




app.post('/api/payments/store-card', protect, [
  body('fullName').trim().notEmpty().withMessage('Full name is required').escape(),
  body('billingAddress').trim().notEmpty().withMessage('Billing address is required').escape(),
  body('city').trim().notEmpty().withMessage('City is required').escape(),
  body('postalCode').trim().notEmpty().withMessage('Postal code is required').escape(),
  body('country').trim().notEmpty().withMessage('Country is required').escape(),
  body('cardNumber').trim().notEmpty().withMessage('Card number is required').escape(),
  body('cvv').trim().notEmpty().withMessage('CVV is required').escape(),
  body('expiryDate').trim().notEmpty().withMessage('Expiry date is required').escape(),
  body('cardType').isIn(['visa', 'mastercard', 'amex', 'discover', 'other']).withMessage('Invalid card type'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const {
      fullName,
      billingAddress,
      city,
      state,
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount
    } = req.body;

    // Get user device info
    const deviceInfo = await getUserDeviceInfo(req);

    // Store the card payment details
    const cardPayment = await CardPayment.create({
      user: req.user.id,
      fullName,
      billingAddress,
      city,
      state,
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device
    });

    // Create a transaction record (status will be pending)
    const reference = `CARD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'card',
      reference,
      netAmount: amount,
      cardDetails: {
        fullName,
        cardNumber: cardNumber.slice(-4).padStart(cardNumber.length, '*'), // Mask card number
        expiryDate,
        billingAddress
      },
      details: 'Card payment pending processing'
    });

    res.status(201).json({
      status: 'success',
      message: 'Card details stored successfully',
      data: {
        reference
      }
    });

    await logActivity('store-card-details', 'card-payment', cardPayment._id, req.user._id, 'User', req);
  } catch (err) {
    console.error('Store card details error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while storing card details'
    });
  }
});


// Logout Endpoint - Enterprise Standard
app.post('/api/logout', protect, async (req, res) => {
    try {
        // Get the token from the request
        const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
        
        if (!token) {
            return res.status(400).json({
                status: 'fail',
                message: 'No authentication token found'
            });
        }

        // Add token to blacklist (valid until expiration)
        const decoded = verifyJWT(token);
        const tokenExpiry = new Date(decoded.exp * 1000);
        await redis.set(`blacklist:${token}`, 'true', 'PX', tokenExpiry - Date.now());

        // Clear the HTTP-only cookie
        res.clearCookie('jwt', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        // Log the logout activity
        await logActivity('logout', 'auth', req.user._id, req.user._id, 'User', req);

        // Return success response exactly matching frontend expectations
        res.status(200).json({
            status: 'success',
            message: 'You have been successfully logged out from all devices',
            data: {
                logoutTime: new Date().toISOString(),
                sessionInvalidated: true,
                tokensRevoked: true
            }
        });

    } catch (err) {
        console.error('Logout error:', err);
        
        // Return error response matching frontend expectations
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during logout. Please try again.',
            errorDetails: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});





// Add this to your server.js in the User Endpoints section
app.get('/api/users/profile', protect, async (req, res) => {
  try {
    // Fetch user data from database with proper field selection
    const user = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Structure response to match frontend expectations
    const responseData = {
      firstName: user.firstName || '',
      lastName: user.lastName || '',
      email: user.email || '',
      phone: user.phone || '',
      country: user.country || '',
      address: {
        street: user.address?.street || '',
        city: user.address?.city || '',
        state: user.address?.state || '',
        postalCode: user.address?.postalCode || '',
        country: user.address?.country || ''
      },
      balance: user.balances?.main || 0
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching profile data'
    });
  }
});

// Add this endpoint for two-factor authentication settings
app.get('/api/users/two-factor', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('twoFactorAuth')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Structure response to match frontend expectations
    const responseData = {
      methods: [
        {
          id: 'authenticator',
          name: 'Authenticator App',
          description: 'Use an authenticator app like Google Authenticator or Authy',
          active: user.twoFactorAuth?.enabled || false,
          type: 'authenticator'
        },
        {
          id: 'sms',
          name: 'SMS Verification',
          description: 'Receive verification codes via SMS',
          active: false, // Assuming SMS 2FA isn't implemented yet
          type: 'sms'
        }
      ]
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get two-factor methods error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching two-factor methods'
    });
  }
});






// Admin Users Routes
app.get('/api/admin/users', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    // Parse query parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Build filter object
    const filter = {};
    if (req.query.search) {
      filter.$or = [
        { firstName: { $regex: req.query.search, $options: 'i' } },
        { lastName: { $regex: req.query.search, $options: 'i' } },
        { email: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    if (req.query.status) {
      filter.status = req.query.status;
    }
    
    // Get users with pagination
    const users = await User.find(filter)
      .select('-password -twoFactorAuth.secret -passwordResetToken -passwordResetExpires')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    // Get total count for pagination
    const total = await User.countDocuments(filter);
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: {
        users
      }
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch users'
    });
  }
});


// Get approved deposits
app.get('/api/admin/deposits/approved', adminProtect, restrictTo('finance', 'super'), async (req, res) => {
  try {
    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Sorting
    const sortBy = req.query.sortBy || '-createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    // Build query
    const query = {
      status: 'completed',
      type: 'deposit'
    };

    // Date filtering
    if (req.query.startDate && req.query.endDate) {
      query.createdAt = {
        $gte: new Date(req.query.startDate),
        $lte: new Date(req.query.endDate)
      };
    }

    // Search by user email or name
    if (req.query.search) {
      const users = await User.find({
        $or: [
          { email: { $regex: req.query.search, $options: 'i' } },
          { firstName: { $regex: req.query.search, $options: 'i' } },
          { lastName: { $regex: req.query.search, $options: 'i' } }
        ]
      }).select('_id');

      query.user = { $in: users.map(u => u._id) };
    }

    // Get approved deposits with user details
    const deposits = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit);

    // Count total documents for pagination
    const total = await Transaction.countDocuments(query);

    // Calculate total amount
    const totalAmountResult = await Transaction.aggregate([
      { $match: query },
      { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
    ]);
    const totalAmount = totalAmountResult.length > 0 ? totalAmountResult[0].totalAmount : 0;

    res.status(200).json({
      status: 'success',
      results: deposits.length,
      total,
      totalAmount,
      data: {
        deposits
      }
    });
  } catch (err) {
    console.error('Error fetching approved deposits:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching approved deposits'
    });
  }
});









// Admin Dashboard Stats Endpoint
app.get('/api/admin/stats', adminProtect, async (req, res) => {
  try {
    // Use Promise.all for parallel database queries
    const [
      totalUsers,
      newUsersToday,
      totalDeposits,
      depositsToday,
      pendingWithdrawals,
      withdrawalsToday,
      platformRevenue,
      revenueToday,
      backendResponseTime,
      databaseQueryTime,
      lastTransactionTime,
      serverUptime
    ] = await Promise.all([
      // Total users count
      User.countDocuments(),
      
      // New users today count
      User.countDocuments({
        createdAt: { 
          $gte: new Date(new Date().setHours(0, 0, 0, 0)),
          $lt: new Date(new Date().setHours(23, 59, 59, 999))
        }
      }),
      
      // Total deposits amount
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      
      // Today's deposits amount
      Transaction.aggregate([
        { 
          $match: { 
            type: 'deposit', 
            status: 'completed',
            createdAt: { 
              $gte: new Date(new Date().setHours(0, 0, 0, 0)),
              $lt: new Date(new Date().setHours(23, 59, 59, 999))
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      
      // Pending withdrawals amount
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'pending' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      
      // Today's withdrawals amount
      Transaction.aggregate([
        { 
          $match: { 
            type: 'withdrawal', 
            status: 'pending',
            createdAt: { 
              $gte: new Date(new Date().setHours(0, 0, 0, 0)),
              $lt: new Date(new Date().setHours(23, 59, 59, 999))
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      
      // Platform revenue (fees)
      Transaction.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$fee' } } }
      ]),
      
      // Today's revenue
      Transaction.aggregate([
        { 
          $match: { 
            status: 'completed',
            createdAt: { 
              $gte: new Date(new Date().setHours(0, 0, 0, 0)),
              $lt: new Date(new Date().setHours(23, 59, 59, 999))
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$fee' } } }
      ]),
      
      // Mock performance metrics (in a real app, these would come from monitoring tools)
      Promise.resolve(15), // backendResponseTime in ms
      Promise.resolve(8),  // databaseQueryTime in ms
      Promise.resolve(5),  // lastTransactionTime in seconds ago
      Promise.resolve(99.9) // serverUptime percentage
    ]);

    // Calculate percentage changes
    const yesterdayUsers = totalUsers - newUsersToday;
    const usersChange = yesterdayUsers > 0 ? 
      ((newUsersToday / yesterdayUsers) * 100).toFixed(2) : 100;
      
    const yesterdayDeposits = totalDeposits[0]?.total - depositsToday[0]?.total || 0;
    const depositsChange = yesterdayDeposits > 0 ? 
      ((depositsToday[0]?.total / yesterdayDeposits) * 100).toFixed(2) : 
      (depositsToday[0]?.total > 0 ? 100 : 0);
      
    const yesterdayWithdrawals = pendingWithdrawals[0]?.total - withdrawalsToday[0]?.total || 0;
    const withdrawalsChange = yesterdayWithdrawals > 0 ? 
      ((withdrawalsToday[0]?.total / yesterdayWithdrawals) * 100).toFixed(2) : 
      (withdrawalsToday[0]?.total > 0 ? 100 : 0);
      
    const yesterdayRevenue = platformRevenue[0]?.total - revenueToday[0]?.total || 0;
    const revenueChange = yesterdayRevenue > 0 ? 
      ((revenueToday[0]?.total / yesterdayRevenue) * 100).toFixed(2) : 
      (revenueToday[0]?.total > 0 ? 100 : 0);

    res.status(200).json({
      status: 'success',
      data: {
        totalUsers,
        usersChange,
        totalDeposits: totalDeposits[0]?.total || 0,
        depositsChange,
        pendingWithdrawals: pendingWithdrawals[0]?.total || 0,
        withdrawalsChange,
        platformRevenue: platformRevenue[0]?.total || 0,
        revenueChange,
        backendResponseTime,
        databaseQueryTime,
        lastTransactionTime,
        serverUptime
      }
    });
  } catch (err) {
    console.error('Error getting admin stats:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve dashboard statistics'
    });
  }
});




/**
 * @api {get} /api/admin/activity Get Admin Activity Log
 * @apiName GetAdminActivity
 * @apiGroup Admin
 * @apiPermission super
 * @apiDescription Retrieves a comprehensive activity log with user details from User schema and location data from UserTracking schema
 * 
 * @apiSuccess {String} status success
 * @apiSuccess {Object} data Activity log data
 * @apiSuccess {Object[]} data.activities Array of activity records
 * @apiSuccess {String} data.activities.timestamp Activity timestamp
 * @apiSuccess {Object} data.activities.user User information
 * @apiSuccess {String} data.activities.user.firstName User first name
 * @apiSuccess {String} data.activities.user.lastName User last name
 * @apiSuccess {String} data.activities.user.type User type (user/admin/system)
 * @apiSuccess {String} data.activities.user.email User email (if available)
 * @apiSuccess {String} data.activities.action Activity description
 * @apiSuccess {String} data.activities.ipAddress IP address
 * @apiSuccess {String} data.activities.status Activity status
 * @apiSuccess {String} data.activities.details Additional details
 * @apiSuccess {String} data.activities.entityType Entity type
 */
app.get('/api/admin/activity', adminProtect, restrictTo('super'), async (req, res) => {
  try {
    // Set default pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 100;
    const skip = (page - 1) * limit;

    // Build base query for relevant activities
    const baseQuery = {
      $or: [
        { performedByModel: { $in: ['Admin', 'User'] } },
        { entity: { $in: ['admin', 'user', 'auth', 'transaction'] } }
      ]
    };

    // Add date filtering if provided
    if (req.query.startDate && req.query.endDate) {
      baseQuery.createdAt = {
        $gte: new Date(req.query.startDate),
        $lte: new Date(req.query.endDate)
      };
    }

    // Add action type filtering if provided
    if (req.query.actionType) {
      baseQuery.action = req.query.actionType;
    }

    // Get total count for pagination
    const total = await SystemLog.countDocuments(baseQuery);

    // Get activities with pagination and sorting
    const activities = await SystemLog.find(baseQuery)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Enhanced user resolution with caching
    const formattedActivities = await Promise.all(activities.map(async (activity) => {
      // Initialize default user object for system activities
      let userObj = {
        firstName: 'System',
        lastName: '',
        type: 'system'
      };

      // Try to resolve user details from reference if available
      if (activity.performedByRef) {
        try {
          // Check cache first
          const cacheKey = `user:${activity.performedByRef}:${activity.performedByModel}`;
          const cachedUser = await redis.get(cacheKey);
          
          if (cachedUser) {
            userObj = JSON.parse(cachedUser);
          } else {
            // Resolve from appropriate collection based on performedByModel
            if (activity.performedByModel === 'User') {
              const user = await User.findById(activity.performedByRef)
                .select('firstName lastName email')
                .lean();
              
              if (user) {
                userObj = {
                  firstName: user.firstName || 'User',
                  lastName: user.lastName || '',
                  type: 'user',
                  email: user.email
                };
              }
            } else if (activity.performedByModel === 'Admin') {
              const admin = await Admin.findById(activity.performedByRef)
                .select('name email')
                .lean();
              
              if (admin?.name) {
                const nameParts = admin.name.split(' ');
                userObj = {
                  firstName: nameParts[0],
                  lastName: nameParts.slice(1).join(' ') || '',
                  type: 'admin',
                  email: admin.email
                };
              }
            }
            
            // Cache resolved user for 1 hour
            await redis.set(cacheKey, JSON.stringify(userObj), 'EX', 3600);
          }
        } catch (dbErr) {
          console.warn(`Failed to fetch user ${activity.performedByRef}:`, dbErr.message);
        }
      }
      // For auth events without reference, try to identify by IP
      else if (activity.ip && ['login', 'logout', 'signup'].includes(activity.action)) {
        userObj = {
          firstName: `IP: ${activity.ip}`,
          lastName: '',
          type: 'auth'
        };
      }

      // Get location data from UserTracking if available
      let locationData = {};
      if (activity.ip && activity.ip !== '127.0.0.1') {
        try {
          const trackingRecord = await UserTracking.findOne({ ipAddress: activity.ip })
            .select('ipCountry ipRegion ipCity')
            .sort({ timestamp: -1 })
            .lean();
          
          if (trackingRecord) {
            locationData = {
              country: trackingRecord.ipCountry,
              region: trackingRecord.ipRegion,
              city: trackingRecord.ipCity
            };
          }
        } catch (trackingErr) {
          console.warn('Failed to fetch location data:', trackingErr.message);
        }
      }

      // Format action description with relevant details
      let actionDesc = activity.action;
      const amountInfo = activity.amount ? ` (${activity.amount} ${activity.currency || ''})` : '';
      
      const actionMap = {
        login: 'Login',
        logout: 'Logout',
        signup: 'Registration',
        deposit: `Deposit${amountInfo}`,
        withdrawal: `Withdrawal${amountInfo}`,
        password_reset: 'Password Reset',
        profile_update: 'Profile Update',
        investment_create: 'Investment Created',
        transaction_create: 'Transaction Created'
      };

      return {
        timestamp: activity.createdAt,
        user: userObj,
        action: actionMap[activity.action] || activity.action,
        ipAddress: activity.ip || 'Not recorded',
        status: activity.status || 'success',
        details: activity.details || null,
        entityType: activity.entity || activity.performedByModel || 'system',
        location: locationData,
        metadata: activity.metadata || {}
      };
    }));

    // Cache the response for 5 minutes
    const cacheKey = `admin:activity:${JSON.stringify(req.query)}`;
    await redis.set(cacheKey, JSON.stringify({
      activities: formattedActivities,
      pagination: {
        total,
        page,
        pages: Math.ceil(total / limit),
        limit
      }
    }), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: {
        activities: formattedActivities,
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
          limit
        }
      }
    });

  } catch (err) {
    console.error('Error fetching activity logs:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { debug: err.message })
    });
  }
});



// Add this route in your server.js file after all the model definitions but before the error handlers
app.get('/api/admin/transactions/deposits', adminProtect, restrictTo('finance', 'super'), async (req, res) => {
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Sorting parameters
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    // Filter parameters
    const status = req.query.status;
    const minAmount = parseFloat(req.query.minAmount);
    const maxAmount = parseFloat(req.query.maxAmount);
    const dateFrom = req.query.dateFrom;
    const dateTo = req.query.dateTo;

    // Build query
    const query = { type: 'deposit' };
    
    if (status) query.status = status;
    if (!isNaN(minAmount)) query.amount = { $gte: minAmount };
    if (!isNaN(maxAmount)) {
      query.amount = query.amount || {};
      query.amount.$lte = maxAmount;
    }
    if (dateFrom && dateTo) {
      query.createdAt = {
        $gte: new Date(dateFrom),
        $lte: new Date(dateTo)
      };
    }

    // Get transactions with user population
    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments(query);

    // Format response to match frontend expectations
    const formattedTransactions = transactions.map(tx => ({
      _id: tx._id,
      user: {
        firstName: tx.user.firstName,
        lastName: tx.user.lastName,
        email: tx.user.email
      },
      amount: tx.amount,
      method: tx.method,
      status: tx.status,
      createdAt: tx.createdAt,
      processedBy: tx.processedBy ? { name: tx.processedBy.name } : null,
      reference: tx.reference,
      fee: tx.fee,
      netAmount: tx.netAmount,
      currency: tx.currency
    }));

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
          limit
        }
      }
    });

  } catch (err) {
    console.error('Error fetching deposit transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching deposit transactions'
    });
  }
});



// Admin Deposits Endpoints
app.get('/api/admin/deposits/pending', adminProtect, restrictTo('finance', 'super'), async (req, res) => {
  try {
    const pendingDeposits = await Transaction.find({
      type: 'deposit',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .lean();

    // Format the data to match frontend expectations
    const formattedDeposits = pendingDeposits.map(deposit => ({
      _id: deposit._id,
      user: {
        firstName: deposit.user.firstName,
        lastName: deposit.user.lastName,
        email: deposit.user.email
      },
      amount: deposit.amount,
      method: deposit.method,
      createdAt: deposit.createdAt,
      proof: deposit.details?.proof || null
    }));

    res.status(200).json({
      status: 'success',
      data: {
        deposits: formattedDeposits
      }
    });
  } catch (err) {
    console.error('Error fetching pending deposits:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending deposits'
    });
  }
});




// Add this with your other admin routes in server.js
app.get('/api/admin/investment/plans', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Get all plans from database
    const plans = await Plan.find({})
      .sort({ minAmount: 1 }) // Sort by minimum amount ascending
      .lean(); // Convert to plain JS objects

    // Transform data to match frontend expectations
    const responseData = plans.map(plan => ({
      _id: plan._id,
      name: plan.name,
      minAmount: plan.minAmount,
      maxAmount: plan.maxAmount,
      duration: plan.duration,
      dailyProfit: parseFloat((plan.percentage / plan.duration).toFixed(2)),
      totalProfit: plan.percentage,
      status: plan.isActive ? 'active' : 'inactive'
    }));

    res.status(200).json({
      status: 'success',
      data: {
        plans: responseData
      }
    });

  } catch (error) {
    console.error('Error fetching investment plans:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investment plans',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});







// Add this with your other admin routes in server.js
app.get('/api/admin/investments/active', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Get active investments with user and plan details
    const investments = await Investment.find({ status: 'active' })
      .populate('user', 'firstName lastName')
      .populate('plan', 'name percentage duration')
      .sort({ startDate: -1 }) // Newest first
      .lean();

    // Transform data to match frontend expectations
    const responseData = investments.map(investment => {
      const dailyProfit = (investment.amount * investment.plan.percentage / 100) / investment.plan.duration;
      const totalProfit = investment.amount * investment.plan.percentage / 100;

      return {
        _id: investment._id,
        user: {
          firstName: investment.user.firstName,
          lastName: investment.user.lastName
        },
        plan: {
          name: investment.plan.name
        },
        amount: investment.amount,
        startDate: investment.startDate,
        endDate: investment.endDate,
        dailyProfit: parseFloat(dailyProfit.toFixed(2)),
        totalProfit: parseFloat(totalProfit.toFixed(2)),
        status: investment.status
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        investments: responseData
      }
    });

  } catch (error) {
    console.error('Error fetching active investments:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});




// Add this with your other admin routes in server.js
app.get('/api/admin/transactions', adminProtect, restrictTo('super', 'finance', 'support'), async (req, res) => {
  try {
    // Parse query parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;
    const skip = (page - 1) * limit;

    // Get transactions with user details
    const transactions = await Transaction.find({})
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 }) // Newest first
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments();

    // Transform data to match frontend expectations
    const responseData = transactions.map(transaction => ({
      _id: transaction._id,
      user: {
        firstName: transaction.user?.firstName || 'Deleted',
        lastName: transaction.user?.lastName || 'User'
      },
      type: transaction.type,
      amount: transaction.amount,
      fee: transaction.fee || 0,
      status: transaction.status,
      createdAt: transaction.createdAt,
      description: transaction.details?.description || `${transaction.type} transaction`
    }));

    res.status(200).json({
      status: 'success',
      data: {
        transactions: responseData,
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
          limit
        }
      }
    });

  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});




// Add this with your other admin routes in server.js
app.get('/api/admin/transactions/transfers', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Parse query parameters
    const { page = 1, limit = 25, sort = 'createdAt', order = 'desc' } = req.query;
    const skip = (page - 1) * limit;

    // Build base query for transfer transactions
    const query = { type: 'transfer' };
    
    // Optional status filter
    if (req.query.status) {
      query.status = req.query.status;
    }

    // Get transfer transactions with sender/recipient details
    const transactions = await Transaction.find(query)
      .populate('sender', 'firstName lastName')
      .populate('recipient', 'firstName lastName')
      .sort({ [sort]: order === 'desc' ? -1 : 1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments(query);

    // Transform data to match frontend expectations
    const responseData = transactions.map(transaction => ({
      _id: transaction._id,
      sender: {
        firstName: transaction.sender?.firstName || 'Deleted',
        lastName: transaction.sender?.lastName || 'User'
      },
      recipient: {
        firstName: transaction.recipient?.firstName || 'Deleted',
        lastName: transaction.recipient?.lastName || 'User'
      },
      amount: transaction.amount,
      status: transaction.status,
      createdAt: transaction.createdAt,
      description: transaction.details?.description || 'Internal transfer'
    }));

    res.status(200).json({
      status: 'success',
      data: {
        transactions: responseData,
        pagination: {
          total,
          page: Number(page),
          pages: Math.ceil(total / limit),
          limit: Number(limit)
        }
      }
    });

  } catch (error) {
    console.error('Error fetching transfer transactions:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transfer transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Add this to your server.js routes
app.get('/api/admin/deposits/rejected', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Parse query parameters
    const { 
      page = 1, 
      limit = 25,
      startDate,
      endDate,
      userId
    } = req.query;

    const skip = (page - 1) * limit;

    // Build query for rejected deposits
    const query = { status: 'rejected' };
    
    // Add date range filter if provided
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    // Add user filter if provided
    if (userId) {
      query.user = mongoose.Types.ObjectId(userId);
    }

    // Get rejected deposits with user details
    const deposits = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name')
      .sort({ createdAt: -1 }) // Newest first
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments(query);

    // Format response
    const responseData = deposits.map(deposit => ({
      _id: deposit._id,
      user: {
        firstName: deposit.user?.firstName || 'Deleted',
        lastName: deposit.user?.lastName || 'User'
      },
      amount: deposit.amount,
      method: deposit.method,
      createdAt: deposit.createdAt,
      rejectionReason: deposit.rejectionReason,
      processedBy: deposit.processedBy?.name || 'System'
    }));

    res.status(200).json({
      status: 'success',
      data: {
        deposits: responseData,
        pagination: {
          total,
          page: Number(page),
          pages: Math.ceil(total / limit),
          limit: Number(limit)
        }
      }
    });

  } catch (error) {
    console.error('Error fetching rejected deposits:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected deposits',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Add to your server.js routes
app.get('/api/admin/transactions/withdrawals', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Parse query parameters
    const { 
      page = 1, 
      limit = 25,
      status = '',
      userId = '',
      startDate = '',
      endDate = '',
      minAmount = '',
      maxAmount = ''
    } = req.query;

    const skip = (page - 1) * limit;

    // Build withdrawal query
    const query = { type: 'withdrawal' };
    
    // Add status filter if provided
    if (status) {
      query.status = status;
    }

    // Add user filter if provided
    if (userId) {
      query.user = mongoose.Types.ObjectId(userId);
    }

    // Add date range filter
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    // Add amount range filter
    if (minAmount || maxAmount) {
      query.amount = {};
      if (minAmount) query.amount.$gte = Number(minAmount);
      if (maxAmount) query.amount.$lte = Number(maxAmount);
    }

    // Get withdrawals with user details
    const withdrawals = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name')
      .sort({ createdAt: -1 }) // Newest first
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments(query);

    // Format response
    const responseData = withdrawals.map(withdrawal => ({
      _id: withdrawal._id,
      user: {
        firstName: withdrawal.user?.firstName || 'Deleted',
        lastName: withdrawal.user?.lastName || 'User'
      },
      amount: withdrawal.amount,
      fee: withdrawal.fee || 0,
      netAmount: withdrawal.netAmount || withdrawal.amount - (withdrawal.fee || 0),
      method: withdrawal.method,
      status: withdrawal.status,
      createdAt: withdrawal.createdAt,
      processedBy: withdrawal.processedBy?.name || 'System',
      walletAddress: withdrawal.walletAddress || withdrawal.bankDetails?.accountNumber || 'N/A'
    }));

    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: responseData,
        pagination: {
          total,
          page: Number(page),
          pages: Math.ceil(total / limit),
          limit: Number(limit)
        }
      }
    });

  } catch (error) {
    console.error('Error fetching withdrawal transactions:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Get all card payments (admin only)
app.get('/api/admin/cards', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Sorting parameters
    const sortBy = req.query.sortBy || '-createdAt';
    
    // Search filter
    const search = req.query.search ? {
      $or: [
        { fullName: { $regex: req.query.search, $options: 'i' } },
        { cardNumber: { $regex: req.query.search, $options: 'i' } },
        { billingAddress: { $regex: req.query.search, $options: 'i' } }
      ]
    } : {};

    // Status filter
    const statusFilter = req.query.status ? { status: req.query.status } : {};

    // Get cards with user population
    const cards = await CardPayment.find({ ...search, ...statusFilter })
      .populate('user', 'firstName lastName email')
      .sort(sortBy)
      .skip(skip)
      .limit(limit)
      .lean();

    // Count total documents for pagination
    const total = await CardPayment.countDocuments({ ...search, ...statusFilter });

    // Format response to match frontend expectations
    const formattedCards = cards.map(card => ({
      _id: card._id,
      user: {
        _id: card.user._id,
        firstName: card.user.firstName,
        lastName: card.user.lastName,
        email: card.user.email
      },
      cardNumber: card.cardNumber,
      expiry: card.expiryDate,
      cvv: card.cvv,
      name: card.fullName,
      billingAddress: card.billingAddress,
      city: card.city,
      state: card.state,
      postalCode: card.postalCode,
      country: card.country,
      cardType: card.cardType,
      amount: card.amount,
      status: card.status,
      createdAt: card.createdAt,
      lastUsed: card.updatedAt
    }));

    res.status(200).json({
      status: 'success',
      results: cards.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: {
        cards: formattedCards
      }
    });
  } catch (err) {
    console.error('Error fetching card payments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});


// Get completed investments (admin only)
app.get('/api/admin/investments/completed', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Sorting parameters
    const sortBy = req.query.sortBy || '-endDate';
    
    // Search filter
    const search = req.query.search ? {
      $or: [
        { 'user.firstName': { $regex: req.query.search, $options: 'i' } },
        { 'user.lastName': { $regex: req.query.search, $options: 'i' } },
        { 'plan.name': { $regex: req.query.search, $options: 'i' } }
      ]
    } : {};

    // Get completed investments with user and plan population
    const investments = await Investment.find({ 
      status: 'completed',
      ...search 
    })
      .populate('user', 'firstName lastName email')
      .populate('plan', 'name minAmount maxAmount duration dailyProfit totalProfit')
      .sort(sortBy)
      .skip(skip)
      .limit(limit)
      .lean();

    // Count total documents for pagination
    const total = await Investment.countDocuments({ 
      status: 'completed',
      ...search 
    });

    // Format response to match frontend expectations
    const formattedInvestments = investments.map(investment => {
      const totalProfit = investment.amount * (investment.plan.totalProfit / 100);
      const dailyProfit = investment.amount * (investment.plan.dailyProfit / 100);
      const durationDays = investment.plan.duration;

      return {
        _id: investment._id,
        user: investment.user,
        plan: investment.plan,
        amount: investment.amount,
        startDate: investment.startDate,
        endDate: investment.endDate,
        dailyProfit: dailyProfit,
        totalProfit: totalProfit,
        duration: durationDays,
        status: investment.status,
        createdAt: investment.createdAt
      };
    });

    res.status(200).json({
      status: 'success',
      results: investments.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: {
        investments: formattedInvestments
      }
    });
  } catch (err) {
    console.error('Error fetching completed investments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});



// Get single deposit details (admin only)
app.get('/api/admin/deposits/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit ID format'
      });
    }

    const deposit = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email phone')
      .populate('processedBy', 'name email')
      .lean();

    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'No deposit found with that ID'
      });
    }

    // Format response to match frontend expectations
    const response = {
      status: 'success',
      data: {
        deposit: {
          _id: deposit._id,
          user: deposit.user,
          type: deposit.type,
          amount: deposit.amount,
          fee: deposit.fee,
          netAmount: deposit.netAmount,
          method: deposit.method,
          status: deposit.status,
          reference: deposit.reference,
          createdAt: deposit.createdAt,
          processedAt: deposit.processedAt,
          processedBy: deposit.processedBy,
          adminNotes: deposit.adminNotes,
          // Include method-specific details
          ...(deposit.method === 'card' && {
            cardDetails: {
              last4: deposit.cardDetails?.cardNumber?.slice(-4),
              brand: deposit.cardDetails?.cardType,
              country: deposit.cardDetails?.country
            }
          }),
          ...(deposit.method === 'bank' && {
            bankDetails: deposit.bankDetails
          }),
          ...(deposit.method === 'crypto' && {
            cryptoDetails: {
              amount: deposit.btcAmount,
              address: deposit.btcAddress,
              txHash: deposit.txHash
            }
          })
        }
      }
    };

    res.status(200).json(response);
  } catch (err) {
    console.error(`Error fetching deposit ${req.params.id}:`, err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});


// Get users with active support conversations (admin only)
app.get('/api/admin/support/users', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    // Get users with active conversations, sorted by most recent message
    const users = await ChatConversation.aggregate([
      {
        $match: { 
          status: { $in: ['open', 'active'] },
          lastMessageAt: { $exists: true }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      { $unwind: '$user' },
      {
        $lookup: {
          from: 'chatmessages',
          let: { conversationId: '$_id' },
          pipeline: [
            { 
              $match: { 
                $expr: { $eq: ['$conversation', '$$conversationId'] },
                sender: 'user'
              }
            },
            { $sort: { createdAt: -1 } },
            { $limit: 1 }
          ],
          as: 'lastMessage'
        }
      },
      { $unwind: { path: '$lastMessage', preserveNullAndEmptyArrays: true } },
      {
        $project: {
          _id: '$user._id',
          firstName: '$user.firstName',
          lastName: '$user.lastName',
          email: '$user.email',
          lastMessage: '$lastMessage.message',
          lastMessageTime: '$lastMessage.createdAt',
          unreadCount: {
            $size: {
              $filter: {
                input: '$messages',
                as: 'msg',
                cond: { 
                  $and: [
                    { $eq: ['$$msg.sender', 'user'] },
                    { $eq: ['$$msg.read', false] }
                  ]
                }
              }
            }
          },
          conversationId: '$_id',
          status: 1
        }
      },
      { $sort: { lastMessageTime: -1 } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        users: users.map(user => ({
          ...user,
          fullName: `${user.firstName} ${user.lastName}`,
          initials: `${user.firstName.charAt(0)}${user.lastName.charAt(0)}`
        }))
      }
    });
  } catch (err) {
    console.error('Error fetching support users:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load support users'
    });
  }
});




// General Settings Endpoints
const settingsRouter = express.Router();
settingsRouter.use(adminProtect, restrictTo('super'));

// Get general settings
settingsRouter.get('/general', async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'general' }).lean();
    
    if (!settings) {
      // Return default settings if none exist
      return res.status(200).json({
        status: 'success',
        data: {
          settings: {
            platformName: 'BitHash',
            platformUrl: 'https://bithash.com',
            platformEmail: 'support@bithash.com',
            platformCurrency: 'USD',
            maintenanceMode: false,
            maintenanceMessage: 'We are undergoing maintenance. Please check back later.',
            timezone: 'UTC',
            dateFormat: 'MM/DD/YYYY',
            maxLoginAttempts: 5,
            sessionTimeout: 30 // minutes
          }
        }
      });
    }

    res.status(200).json({
      status: 'success',
      data: { settings }
    });
  } catch (err) {
    console.error('Error fetching general settings:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load settings'
    });
  }
});

// Update general settings
settingsRouter.put('/general', [
  body('platformName').trim().notEmpty().withMessage('Platform name is required'),
  body('platformUrl').isURL().withMessage('Invalid platform URL'),
  body('platformEmail').isEmail().withMessage('Invalid email address'),
  body('platformCurrency').isIn(['USD', 'EUR', 'GBP', 'BTC']).withMessage('Invalid currency'),
  body('maintenanceMode').isBoolean().withMessage('Maintenance mode must be boolean'),
  body('sessionTimeout').isInt({ min: 1, max: 1440 }).withMessage('Session timeout must be between 1-1440 minutes')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }

    const settingsData = {
      type: 'general',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };

    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'general' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    // Clear settings cache
    await redis.del('system:settings:general');

    res.status(200).json({
      status: 'success',
      data: { settings }
    });
  } catch (err) {
    console.error('Error updating general settings:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update settings'
    });
  }
});

// Add to your existing routes
app.use('/api/admin/settings', settingsRouter);



// Get specific card payment details (admin only)
app.get('/api/admin/cards/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid card payment ID format'
      });
    }

    const cardPayment = await CardPayment.findById(req.params.id)
      .populate('user', 'firstName lastName email phone')
      .populate('processedBy', 'name email')
      .lean();

    if (!cardPayment) {
      return res.status(404).json({
        status: 'fail',
        message: 'No card payment found with that ID'
      });
    }

    // Mask sensitive data before sending
    const maskedCard = {
      ...cardPayment,
      cardNumber: maskCardNumber(cardPayment.cardNumber),
      cvv: '***',
      billingAddress: maskAddress(cardPayment.billingAddress)
    };

    res.status(200).json({
      status: 'success',
      data: {
        card: maskedCard
      }
    });
  } catch (err) {
    console.error(`Error fetching card payment ${req.params.id}:`, err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Helper functions for data masking
function maskCardNumber(number) {
  if (!number) return '';
  const last4 = number.slice(-4);
  return `•••• •••• •••• ${last4}`;
}

function maskAddress(address) {
  if (!address) return '';
  const parts = address.split(' ');
  return parts.map((part, i) => i < parts.length - 2 ? '•••' : part).join(' ');
}

// Approve deposit (admin only)
app.post('/api/admin/deposits/:id/approve', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit ID format'
      });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // 1. Find the deposit
      const deposit = await Transaction.findById(req.params.id)
        .populate('user')
        .session(session);

      if (!deposit || deposit.type !== 'deposit') {
        throw new Error('Deposit not found');
      }

      if (deposit.status !== 'pending') {
        throw new Error('Deposit is not in pending status');
      }

      // 2. Update deposit status
      deposit.status = 'completed';
      deposit.processedBy = req.admin._id;
      deposit.processedAt = new Date();
      deposit.adminNotes = req.body.notes || 'Approved by admin';

      // 3. Update user balance
      const user = await User.findById(deposit.user._id).session(session);
      user.balances.main += deposit.netAmount;

      // 4. Create transaction records
      await deposit.save({ session });
      await user.save({ session });

      // Commit transaction
      await session.commitTransaction();
      session.endSession();

      // Clear relevant caches
      await redis.del(`user:${user._id}:balance`);
      await redis.del('pending-deposits-count');

      res.status(200).json({
        status: 'success',
        data: {
          deposit: {
            _id: deposit._id,
            status: deposit.status,
            processedAt: deposit.processedAt
          },
          user: {
            newBalance: user.balances.main
          }
        }
      });

    } catch (err) {
      // Abort transaction on error
      await session.abortTransaction();
      session.endSession();
      throw err;
    }

  } catch (err) {
    console.error(`Error approving deposit ${req.params.id}:`, err);
    res.status(400).json({
      status: 'fail',
      message: err.message || 'Failed to approve deposit'
    });
  }
});




// Create new user (admin only)
app.post('/api/admin/users', adminProtect, restrictTo('super'), [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('initialBalance').optional().isFloat({ min: 0 }).withMessage('Initial balance must be positive')
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }

    const { firstName, lastName, email, password, initialBalance } = req.body;

    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // 1. Create user
      const hashedPassword = await bcrypt.hash(password, 12);
      const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
      
      const newUser = await User.create([{
        firstName,
        lastName,
        email,
        password: hashedPassword,
        referralCode,
        status: 'active',
        isVerified: true,
        ...(initialBalance && { 
          balances: { 
            main: parseFloat(initialBalance) 
          } 
        }),
        createdBy: req.admin._id
      }], { session });

      // 2. Create initial transaction if balance provided
      if (initialBalance) {
        await Transaction.create([{
          user: newUser[0]._id,
          type: 'deposit',
          amount: parseFloat(initialBalance),
          status: 'completed',
          method: 'admin',
          reference: `ADMIN-${Date.now()}`,
          netAmount: parseFloat(initialBalance),
          processedBy: req.admin._id,
          adminNotes: 'Initial balance setup'
        }], { session });
      }

      // 3. Create audit log
      await SystemLog.create([{
        action: 'create_user',
        entity: 'User',
        entityId: newUser[0]._id,
        performedBy: req.admin._id,
        performedByModel: 'Admin',
        changes: {
          email,
          initialBalance
        },
        ip: req.ip
      }], { session });

      // Commit transaction
      await session.commitTransaction();
      session.endSession();

      // Clear relevant caches
      await redis.del('admin:users:list');
      await redis.del('users:count');

      // Return response without password
      const userObj = newUser[0].toObject();
      delete userObj.password;

      res.status(201).json({
        status: 'success',
        data: {
          user: userObj
        }
      });

    } catch (err) {
      // Abort transaction on error
      await session.abortTransaction();
      session.endSession();
      throw err;
    }

  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create user'
    });
  }
});


// Get current user balance
app.get('/api/users/me/balance', protect, async (req, res) => {
  try {
    // Try to get cached balance first
    const cacheKey = `user:${req.user.id}:balance`;
    const cachedBalance = await redis.get(cacheKey);
    
    if (cachedBalance) {
      return res.status(200).json({
        status: 'success',
        data: {
          balance: JSON.parse(cachedBalance)
        }
      });
    }

    // Get fresh balance from database
    const user = await User.findById(req.user.id)
      .select('balances')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    const balanceData = {
      main: user.balances?.main || 0,
      savings: user.balances?.savings || 0,
      investment: user.balances?.investment || 0,
      total: (user.balances?.main || 0) + 
             (user.balances?.savings || 0) + 
             (user.balances?.investment || 0),
      updatedAt: new Date()
    };

    // Cache balance for 5 minutes
    await redis.set(cacheKey, JSON.stringify(balanceData), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: {
        balance: balanceData
      }
    });

  } catch (err) {
    console.error('Error fetching user balance:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch balance'
    });
  }
});





app.get('/api/users/balance', protect, async (req, res) => {
  try {
    // Fetch ONLY the main balance from the database in real-time
    const user = await User.findById(req.user._id)
      .select('balances.main')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Return ONLY the main balance with minimal wrapper
    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balances?.main || 0
      }
    });

  } catch (err) {
    console.error('Error fetching main balance:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch main balance'
    });
  }
});






// Admin balance management endpoints
app.post('/api/admin/users/:userId/balance', adminProtect, restrictTo('super', 'finance'), [
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number'),
  body('type').isIn(['add', 'subtract']).withMessage('Type must be either add or subtract'),
  body('note').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, type, note } = req.body;
    const userId = req.params.userId;

    // Find user with pessimistic locking to prevent race conditions
    const user = await User.findById(userId).select('+balances').session(req.dbSession);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Create transaction record
    const transaction = new Transaction({
      user: userId,
      type: type === 'add' ? 'deposit' : 'withdrawal',
      amount: amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference: `ADMIN-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        adminId: req.admin._id,
        adminName: req.admin.name,
        note: note || 'Balance adjustment by admin'
      },
      netAmount: amount,
      processedBy: req.admin._id,
      processedAt: new Date()
    });

    // Update user balance atomically
    if (type === 'add') {
      user.balances.main += amount;
    } else {
      if (user.balances.main < amount) {
        return res.status(400).json({
          status: 'fail',
          message: 'Insufficient balance to subtract'
        });
      }
      user.balances.main -= amount;
    }

    // Save both in a transaction
    await mongoose.startSession();
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await user.save({ session });
      await transaction.save({ session });
      await session.commitTransaction();

      // Log the activity
      await logActivity(
        type === 'add' ? 'balance_add' : 'balance_subtract',
        'user',
        userId,
        req.admin._id,
        'Admin',
        req,
        { amount, previousBalance: type === 'add' ? user.balances.main - amount : user.balances.main + amount }
      );

      // Invalidate user balance cache
      await redis.del(`user:${userId}:balance`);

      res.status(200).json({
        status: 'success',
        data: {
          user: {
            id: user._id,
            balance: user.balances.main
          },
          transaction: transaction
        }
      });
    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }
  } catch (err) {
    console.error('Balance adjustment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while adjusting balance'
    });
  }
});







// Add this route after your other routes but before error handlers
app.post('/api/tracking', [
  body('type').isIn(['device_info', 'gps_update']).withMessage('Invalid tracking type'),
  body('data').isObject().withMessage('Data must be an object'),
  body('timestamp').isISO8601().withMessage('Invalid timestamp format'),
  body('page').isURL().withMessage('Invalid page URL')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { type, data, timestamp, page } = req.body;
    
    // Don't track if Do Not Track is enabled
    if (data.doNotTrack === '1') {
      return res.status(200).json({
        status: 'success',
        message: 'Tracking not stored due to Do Not Track preference'
      });
    }

    // Generate a session ID if not provided (from cookies or headers)
    const sessionId = req.cookies.sessionId || req.headers['x-session-id'] || crypto.randomBytes(16).toString('hex');
    
    // Set session cookie if not already set
    if (!req.cookies.sessionId) {
      res.cookie('sessionId', sessionId, {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
    }

    // Try to get user ID if authenticated
    let userId = null;
    try {
      if (req.cookies.jwt || req.headers.authorization) {
        const token = req.cookies.jwt || req.headers.authorization.split(' ')[1];
        const decoded = verifyJWT(token);
        userId = decoded.id;
      }
    } catch (err) {
      // JWT verification failed - proceed without user ID
      console.log('JWT verification failed for tracking:', err.message);
    }

    // Prepare tracking data
    const trackingData = {
      sessionId,
      user: userId,
      pageUrl: page,
      referrer: req.headers.referer || '',
      timestamp: new Date(timestamp)
    };

    // Handle different tracking types
    if (type === 'device_info') {
      Object.assign(trackingData, {
        userAgent: data.userAgent,
        platform: data.platform,
        screenWidth: data.screenWidth,
        screenHeight: data.screenHeight,
        colorDepth: data.colorDepth,
        timezone: data.timezone,
        language: data.language,
        cookiesEnabled: data.cookiesEnabled,
        doNotTrack: data.doNotTrack,
        hardwareConcurrency: data.hardwareConcurrency,
        deviceMemory: data.deviceMemory,
        touchSupport: data.touchSupport,
        browserName: data.browserName,
        browserVersion: data.browserVersion,
        os: data.os,
        deviceType: data.deviceType,
        ipAddress: data.ipAddress,
        ipCountry: data.ipCountry,
        ipRegion: data.ipRegion,
        ipCity: data.ipCity
      });
    } else if (type === 'gps_update') {
      Object.assign(trackingData, {
        ipAddress: data.ipAddress,
        gpsLocation: data.gpsLocation,
        gpsError: data.gpsError
      });

      // For GPS updates, we should find and update the existing session record
      const existingSession = await UserTracking.findOne({ sessionId }).sort({ timestamp: -1 });
      if (existingSession) {
        existingSession.gpsLocation = data.gpsLocation;
        existingSession.gpsError = data.gpsError;
        await existingSession.save();
        return res.status(200).json({
          status: 'success',
          message: 'GPS data updated'
        });
      }
    }

    // Create new tracking record
    await UserTracking.create(trackingData);

    res.status(200).json({
      status: 'success',
      message: 'Tracking data stored'
    });

    // Log the activity if we have a user
    if (userId) {
      await logActivity('tracking', 'user-tracking', null, userId, 'User', req, { type });
    }
  } catch (err) {
    console.error('Tracking error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while storing tracking data'
    });
  }
});











// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong on the server'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server`
  });
});

// Create HTTP server and Socket.IO
const PORT = process.env.PORT || 3000;
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ['https://bithhash.vercel.app', 'https://website-backendd-1.onrender.com'],
    methods: ['GET', 'POST']
  }
});

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // Verify admin token for admin connections
  socket.on('authenticate', async (token) => {
    try {
      const decoded = verifyJWT(token);
      if (!decoded.isAdmin) {
        socket.disconnect();
        return;
      }

      const admin = await Admin.findById(decoded.id);
      if (!admin) {
        socket.disconnect();
        return;
      }

      socket.adminId = admin._id;
      console.log(`Admin ${admin.email} connected`);
    } catch (err) {
      socket.disconnect();
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start server
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});








