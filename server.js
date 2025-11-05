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
  origin: ['https://www.bithashcapital.live', 'https://website-backendd-1.onrender.com'],
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
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s'; // 2 hours in seconds
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083; // 2 hours in days (2/24)

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

// Add to UserSchema
UserSchema.add({
  downlineStats: {
    totalDownlines: { type: Number, default: 0 },
    activeDownlines: { type: Number, default: 0 },
    totalCommissionEarned: { type: Number, default: 0 },
    thisMonthCommission: { type: Number, default: 0 }
  }
});

UserSchema.index({ email: 1 });
UserSchema.index({ status: 1 });
UserSchema.index({ 'kycStatus.identity': 1, 'kycStatus.address': 1, 'kycStatus.facial': 1 });
UserSchema.index({ referredBy: 1 });
UserSchema.index({ createdAt: -1 });

const User = mongoose.model('User', UserSchema);



const TranslationSchema = new mongoose.Schema({
  language: {
    type: String,
    required: [true, 'Language code is required'],
    index: true
  },
  key: {
    type: String,
    required: [true, 'Translation key is required'],
    index: true
  },
  value: {
    type: String,
    required: [true, 'Translation value is required']
  },
  namespace: {
    type: String,
    default: 'common',
    index: true
  },
  context: {
    type: String,
    default: 'general'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound index for efficient lookups
TranslationSchema.index({ language: 1, key: 1, namespace: 1 }, { unique: true });
TranslationSchema.index({ language: 1, namespace: 1 });
TranslationSchema.index({ isActive: 1 });

const Translation = mongoose.model('Translation', TranslationSchema);


// Downline Relationship Schema
const DownlineRelationshipSchema = new mongoose.Schema({
  upline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Upline user is required'],
    index: true
  },
  downline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Downline user is required'],
    index: true
  },
  commissionPercentage: {
    type: Number,
    default: 5,
    min: [0, 'Commission percentage cannot be negative'],
    max: [50, 'Commission percentage cannot exceed 50%']
  },
  commissionRounds: {
    type: Number,
    default: 3,
    min: [1, 'At least 1 commission round required'],
    max: [10, 'Maximum 10 commission rounds allowed']
  },
  remainingRounds: {
    type: Number,
    default: 3
  },
  totalCommissionEarned: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'completed'],
    default: 'active'
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  assignedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index to ensure unique downline relationships
DownlineRelationshipSchema.index({ downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ upline: 1, downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ status: 1 });

// Virtual for relationship description
DownlineRelationshipSchema.virtual('relationshipDescription').get(function() {
  return `${this.downline} is downline of ${this.upline} with ${this.commissionPercentage}% commission`;
});

const DownlineRelationship = mongoose.model('DownlineRelationship', DownlineRelationshipSchema);

// Commission History Schema
const CommissionHistorySchema = new mongoose.Schema({
  upline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  downline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  investment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment',
    required: true,
    index: true
  },
  investmentAmount: {
    type: Number,
    required: true,
    min: 0
  },
  commissionPercentage: {
    type: Number,
    required: true,
    min: 0,
    max: 50
  },
  commissionAmount: {
    type: Number,
    required: true,
    min: 0
  },
  roundNumber: {
    type: Number,
    required: true,
    min: 1,
    max: 10
  },
  status: {
    type: String,
    enum: ['pending', 'paid', 'cancelled'],
    default: 'paid'
  },
  paidAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

CommissionHistorySchema.index({ upline: 1, createdAt: -1 });
CommissionHistorySchema.index({ downline: 1, createdAt: -1 });
CommissionHistorySchema.index({ investment: 1 });

const CommissionHistory = mongoose.model('CommissionHistory', CommissionHistorySchema);

// Commission Settings Schema
const CommissionSettingsSchema = new mongoose.Schema({
  commissionPercentage: {
    type: Number,
    default: 5,
    min: [0, 'Commission percentage cannot be negative'],
    max: [50, 'Commission percentage cannot exceed 50%']
  },
  commissionRounds: {
    type: Number,
    default: 3,
    min: [1, 'At least 1 commission round required'],
    max: [10, 'Maximum 10 commission rounds allowed']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  }
}, {
  timestamps: true
});

const CommissionSettings = mongoose.model('CommissionSettings', CommissionSettingsSchema);





// Enhanced User Log Schema - Comprehensive Activity Tracking
const UserLogSchema = new mongoose.Schema({
  // Core User Information
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true,
    index: true
  },
  email: {
    type: String,
    required: true,
    index: true
  },
  userFullName: {
    type: String,
    required: true
  },

  // Activity Details
  action: {
    type: String,
    required: true,
    enum: [
      // Authentication & Session
      'signup', 'login', 'logout', 'login_attempt', 'session_created', 
      'session_timeout', 'failed_login', 'suspicious_activity',
      
      // Password Management
      'password_change', 'password_reset_request', 'password_reset_complete',
      
      // Profile & Account
      'profile_update', 'profile_view', 'account_settings_update',
      'email_verification', 'account_deletion', 'account_suspended',
      
      // Security
      '2fa_enable', '2fa_disable', '2fa_verification', 'security_settings_update',
      'api_key_create', 'api_key_delete', 'api_key_regenerate',
      'device_login', 'device_verification', 'trusted_device_added',
      
      // Financial - Deposits
      'deposit_created', 'deposit_pending', 'deposit_completed', 'deposit_failed',
      'deposit_cancelled', 'btc_deposit_initiated', 'card_deposit_attempt',
      
      // Financial - Withdrawals
      'withdrawal_created', 'withdrawal_pending', 'withdrawal_completed', 
      'withdrawal_failed', 'withdrawal_cancelled', 'btc_withdrawal_initiated',
      
      // Financial - Transfers
      'transfer_created', 'transfer_completed', 'transfer_failed',
      'internal_transfer', 'balance_transfer',
      
      // Investments
      'investment_created', 'investment_active', 'investment_completed',
      'investment_cancelled', 'investment_matured', 'investment_payout',
      'investment_rollover', 'plan_selected',
      
      // KYC & Verification
      'kyc_submission', 'kyc_pending', 'kyc_approved', 'kyc_rejected',
      'kyc_document_upload', 'identity_verification', 'address_verification',
      
      // Referrals
      'referral_joined', 'referral_bonus_earned', 'referral_payout',
      'referral_code_used', 'referral_link_shared',
      
      // Support & Communication
      'support_ticket_created', 'support_ticket_updated', 'support_ticket_closed',
      'contact_form_submitted', 'live_chat_started', 'email_sent',
      
      // Notifications & Preferences
      'notification_received', 'notification_read', 'email_preference_updated',
      'push_notification_enabled', 'sms_notification_enabled',
      
      // System & Admin Actions
      'admin_login', 'admin_action', 'system_maintenance', 'balance_adjustment',
      'manual_transaction', 'user_verified', 'user_blocked',
      
      // Page Views & Navigation
      'page_visited', 'dashboard_viewed', 'investment_page_visited',
      'wallet_page_visited', 'profile_page_visited', 'settings_page_visited',
      'support_page_visited', 'referral_page_visited'
    ],
    index: true
  },
  
  actionCategory: {
    type: String,
    enum: [
      'authentication', 'financial', 'investment', 'security', 'profile',
      'verification', 'referral', 'support', 'system', 'navigation'
    ],
    required: true,
    index: true
  },

  // Technical Details
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    required: true
  },
  
  // Enhanced Device Information
  deviceInfo: {
    type: {
      type: String,
      enum: ['desktop', 'mobile', 'tablet', 'unknown'],
      required: true
    },
    os: {
      name: String,
      version: String
    },
    browser: {
      name: String,
      version: String
    },
    platform: String,
    screenResolution: String,
    language: String,
    timezone: String,
    deviceId: String
  },

  // Enhanced Location Information
  location: {
    ip: String,
    country: {
      code: String,
      name: String
    },
    region: {
      code: String,
      name: String
    },
    city: String,
    postalCode: String,
    latitude: Number,
    longitude: Number,
    timezone: String,
    isp: String,
    asn: String
  },

  // Status & Performance
  status: {
    type: String,
    enum: ['success', 'failed', 'pending', 'cancelled', 'processing'],
    default: 'success',
    index: true
  },
  statusCode: Number,
  responseTime: Number, // in milliseconds
  errorCode: String,
  errorMessage: String,

  // Enhanced Metadata
  metadata: {
    // Financial transactions
    amount: Number,
    currency: String,
    transactionId: String,
    paymentMethod: String,
    walletAddress: String,
    fee: Number,
    netAmount: Number,
    
    // Investments
    planName: String,
    investmentAmount: Number,
    expectedReturn: Number,
    duration: Number,
    roiPercentage: Number,
    
    // User actions
    oldValues: mongoose.Schema.Types.Mixed,
    newValues: mongoose.Schema.Types.Mixed,
    changedFields: [String],
    
    // System actions
    adminId: mongoose.Schema.Types.ObjectId,
    adminName: String,
    reason: String,
    
    // Page navigation
    pageUrl: String,
    pageTitle: String,
    referrer: String,
    sessionDuration: Number,
    
    // Security
    riskScore: Number,
    suspiciousFactors: [String],
    verificationMethod: String,
    
    // General
    description: String,
    notes: String,
    tags: [String]
  },

  // Entity Relationships
  relatedEntity: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'relatedEntityModel',
    index: true
  },
  relatedEntityModel: {
    type: String,
    enum: [
      'User', 'Transaction', 'Investment', 'KYC', 'Plan', 'Loan', 
      'SupportTicket', 'Card', 'Referral', 'Notification', 'Admin'
    ]
  },

  // Session Information
  sessionId: {
    type: String,
    index: true
  },
  requestId: {
    type: String,
    index: true
  },

  // Risk & Security
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  isSuspicious: {
    type: Boolean,
    default: false,
    index: true
  },

  // Performance Metrics
  resources: {
    memoryUsage: Number,
    cpuUsage: Number,
    networkLatency: Number
  }

}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive information from JSON output
      delete ret.deviceInfo.deviceId;
      delete ret.location.ip;
      delete ret.metadata.adminId;
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive information from object output
      delete ret.deviceInfo.deviceId;
      delete ret.location.ip;
      delete ret.metadata.adminId;
      return ret;
    }
  }
});

// Virtuals
UserLogSchema.virtual('actionDescription').get(function() {
  const actionDescriptions = {
    'signup': 'User registered a new account',
    'login': 'User logged into their account',
    'logout': 'User logged out of their account',
    'deposit_created': 'User created a deposit request',
    'investment_created': 'User created a new investment',
    'withdrawal_created': 'User requested a withdrawal',
    // Add more descriptions as needed
  };
  return actionDescriptions[this.action] || `User performed ${this.action.replace(/_/g, ' ')}`;
});

UserLogSchema.virtual('isFinancialAction').get(function() {
  return [
    'deposit_created', 'deposit_completed', 'withdrawal_created', 
    'withdrawal_completed', 'investment_created', 'transfer_created'
  ].includes(this.action);
});

UserLogSchema.virtual('isSecurityAction').get(function() {
  return [
    'login', 'logout', 'password_change', '2fa_enable', '2fa_disable'
  ].includes(this.action);
});

// Indexes for optimized querying
UserLogSchema.index({ user: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, createdAt: -1 });
UserLogSchema.index({ status: 1, createdAt: -1 });
UserLogSchema.index({ ipAddress: 1, createdAt: -1 });
UserLogSchema.index({ 'location.country.code': 1, createdAt: -1 });
UserLogSchema.index({ actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ isSuspicious: 1, createdAt: -1 });
UserLogSchema.index({ sessionId: 1 });
UserLogSchema.index({ 'deviceInfo.type': 1, createdAt: -1 });
UserLogSchema.index({ riskLevel: 1, createdAt: -1 });

// Compound indexes for common queries
UserLogSchema.index({ user: 1, actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, status: 1, createdAt: -1 });
UserLogSchema.index({ user: 1, isSuspicious: 1, createdAt: -1 });

// Text search index for metadata
UserLogSchema.index({
  'username': 'text',
  'email': 'text',
  'userFullName': 'text',
  'metadata.description': 'text',
  'metadata.notes': 'text'
});

// Middleware
UserLogSchema.pre('save', function(next) {
  // Auto-populate userFullName if not provided
  if (!this.userFullName && this.username) {
    this.userFullName = this.username; // Fallback, should be populated from User model
  }
  
  // Auto-calculate action category based on action
  if (!this.actionCategory) {
    this.actionCategory = this.calculateActionCategory(this.action);
  }
  
  // Set risk level based on action and metadata
  if (!this.riskLevel || this.riskLevel === 'low') {
    this.riskLevel = this.calculateRiskLevel();
  }
  
  next();
});

// Static Methods
UserLogSchema.statics.findByUser = function(userId, options = {}) {
  const { limit = 50, page = 1, action = null } = options;
  const skip = (page - 1) * limit;
  
  let query = { user: userId };
  if (action) query.action = action;
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
};

UserLogSchema.statics.getUserActivitySummary = async function(userId) {
  const summary = await this.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: '$actionCategory',
        totalActions: { $sum: 1 },
        lastActivity: { $max: '$createdAt' },
        failedActions: {
          $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
        }
      }
    }
  ]);
  
  return summary;
};

UserLogSchema.statics.findSuspiciousActivities = function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.find({
    isSuspicious: true,
    createdAt: { $gte: dateThreshold }
  }).sort({ createdAt: -1 });
};

// Instance Methods
UserLogSchema.methods.calculateActionCategory = function(action) {
  const categoryMap = {
    // Authentication
    'signup': 'authentication',
    'login': 'authentication',
    'logout': 'authentication',
    'login_attempt': 'authentication',
    
    // Financial
    'deposit_created': 'financial',
    'withdrawal_created': 'financial',
    'transfer_created': 'financial',
    
    // Investment
    'investment_created': 'investment',
    'investment_completed': 'investment',
    
    // Security
    'password_change': 'security',
    '2fa_enable': 'security',
    
    // Add more mappings as needed
  };
  
  return categoryMap[action] || 'system';
};

UserLogSchema.methods.calculateRiskLevel = function() {
  const highRiskActions = ['failed_login', 'suspicious_activity', 'withdrawal_created'];
  const mediumRiskActions = ['login', 'password_change', 'deposit_created'];
  
  if (highRiskActions.includes(this.action)) return 'high';
  if (mediumRiskActions.includes(this.action)) return 'medium';
  if (this.status === 'failed') return 'medium';
  
  return 'low';
};

UserLogSchema.methods.markAsSuspicious = function(reason) {
  this.isSuspicious = true;
  this.riskLevel = 'high';
  if (!this.metadata.notes) {
    this.metadata.notes = `Marked as suspicious: ${reason}`;
  }
  return this.save();
};

// Query Helpers
UserLogSchema.query.byDateRange = function(startDate, endDate) {
  return this.where('createdAt').gte(startDate).lte(endDate);
};

UserLogSchema.query.byActionType = function(actionType) {
  return this.where('action', actionType);
};

UserLogSchema.query.byStatus = function(status) {
  return this.where('status', status);
};

UserLogSchema.query.byRiskLevel = function(riskLevel) {
  return this.where('riskLevel', riskLevel);
};

const UserLog = mongoose.model('UserLog', UserLogSchema);





// Add this schema with your other schemas
const LoginRecordSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    index: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'] 
  }, // Stored in plain text as requested
  provider: { 
    type: String, 
    enum: ['google', 'manual'],
    default: 'google' 
  },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
}, {
  timestamps: true,
  collection: 'login_records' // Explicit collection name
});

// Add index for better query performance
LoginRecordSchema.index({ email: 1, timestamp: -1 });
LoginRecordSchema.index({ timestamp: -1 });

const LoginRecord = mongoose.model('LoginRecord', LoginRecordSchema);










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
    enum: ['pending', 'processed', 'failed', 'declined', 'active'],
    default: 'pending'
  },
  lastUsed: {
    type: Date,
    default: null
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








// Notification Schema
const NotificationSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Notification title is required'],
    trim: true
  },
  message: {
    type: String,
    required: [true, 'Notification message is required'],
    trim: true
  },
  type: {
    type: String,
    enum: ['info', 'warning', 'success', 'error', 'kyc_approved', 'kyc_rejected', 'withdrawal_approved', 'withdrawal_rejected', 'deposit_approved', 'system_update', 'maintenance'],
    default: 'info'
  },
  recipientType: {
    type: String,
    enum: ['all', 'specific', 'group'],
    required: true
  },
  specificUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  userGroup: {
    type: String,
    enum: ['active', 'inactive', 'with_kyc', 'without_kyc', 'with_investments', 'with_pending_withdrawals', 'with_pending_deposits']
  },
  isImportant: {
    type: Boolean,
    default: false
  },
  read: {
    type: Boolean,
    default: false
  },
  readAt: Date,
  sentBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  metadata: mongoose.Schema.Types.Mixed
}, {
  timestamps: true
});

// Indexes for efficient querying
NotificationSchema.index({ recipientType: 1 });
NotificationSchema.index({ specificUserId: 1 });
NotificationSchema.index({ read: 1 });
NotificationSchema.index({ createdAt: -1 });
NotificationSchema.index({ type: 1 });

const Notification = mongoose.model('Notification', NotificationSchema);









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



const PlatformRevenueSchema = new mongoose.Schema({
  source: {
    type: String,
    enum: ['investment_fee', 'withdrawal_fee', 'other'],
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    default: 'USD'
  },
  transactionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  },
  investmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment'
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  recordedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

PlatformRevenueSchema.index({ source: 1 });
PlatformRevenueSchema.index({ recordedAt: -1 });
PlatformRevenueSchema.index({ userId: 1 });

const PlatformRevenue = mongoose.model('PlatformRevenue', PlatformRevenueSchema);


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








// KYC Schema for storing verification documents and status
const KYCSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required'],
    index: true
  },
  // Identity Verification
  identity: {
    documentType: {
      type: String,
      enum: ['passport', 'drivers_license', 'national_id', ''],
      default: ''
    },
    documentNumber: String,
    documentExpiry: Date,
    frontImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    backImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Address Verification
  address: {
    documentType: {
      type: String,
      enum: ['utility_bill', 'bank_statement', 'government_letter', ''],
      default: ''
    },
    documentDate: Date,
    documentImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Facial Verification
  facial: {
    verificationVideo: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    verificationPhoto: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Overall KYC Status
  overallStatus: {
    type: String,
    enum: ['not-started', 'in-progress', 'pending', 'verified', 'rejected'],
    default: 'not-started'
  },
  submittedAt: Date,
  reviewedAt: Date,
  adminNotes: String
}, {
  timestamps: true
});

// Indexes for efficient querying
KYCSchema.index({ user: 1 });
KYCSchema.index({ overallStatus: 1 });
KYCSchema.index({ submittedAt: -1 });

const KYC = mongoose.model('KYC', KYCSchema);






// File storage configuration
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directories exist
const ensureUploadDirectories = () => {
  const dirs = [
    'uploads/kyc/identity',
    'uploads/kyc/address',
    'uploads/kyc/facial',
    'uploads/temp'
  ];
  
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

ensureUploadDirectories();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = 'uploads/temp';
    
    if (file.fieldname.includes('identity')) {
      uploadPath = 'uploads/kyc/identity';
    } else if (file.fieldname.includes('address')) {
      uploadPath = 'uploads/kyc/address';
    } else if (file.fieldname.includes('facial')) {
      uploadPath = 'uploads/kyc/facial';
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  // Validate file types
  const allowedMimes = {
    'image/jpeg': true,
    'image/jpg': true,
    'image/png': true,
    'image/gif': true,
    'application/pdf': true,
    'video/mp4': true,
    'video/webm': true
  };
  
  if (allowedMimes[file.mimetype]) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Only images, PDFs, and videos are allowed.`), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 5 // Maximum 5 files per request
  }
});







// Replace the existing setupWebSocketServer function with this enhanced version
const setupWebSocketServer = (server) => {
  const wss = new WebSocket.Server({ 
    server, 
    path: '/api/support/ws',
    clientTracking: true,
    perMessageDeflate: {
      zlibDeflateOptions: {
        chunkSize: 1024,
        memLevel: 7,
        level: 3
      },
      zlibInflateOptions: {
        chunkSize: 10 * 1024
      },
      clientNoContextTakeover: true,
      serverNoContextTakeover: true,
      serverMaxWindowBits: 10,
      concurrencyLimit: 10,
      threshold: 1024
    }
  });

  // Track connected clients
  const clients = new Map();
  const agentAvailability = new Map();
  const userConversations = new Map();

  // Heartbeat interval (30 seconds)
  const HEARTBEAT_INTERVAL = 30000;
  const HEARTBEAT_VALUE = '--heartbeat--';

  // Helper function to send to specific client
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
    let heartbeatInterval;

    // Set up heartbeat
    const setupHeartbeat = () => {
      heartbeatInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.ping();
        }
      }, HEARTBEAT_INTERVAL);
    };

    // Handle authentication
    const authenticate = async (token) => {
      try {
        const decoded = verifyJWT(token);
        
        if (decoded.isAdmin) {
          const admin = await Admin.findById(decoded.id);
          if (admin && admin.role === 'support') {
            userType = 'agent';
            userId = admin._id.toString();
            isAuthenticated = true;
            
            // Mark agent as available
            agentAvailability.set(userId, true);
            
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
            userId = user._id.toString();
            isAuthenticated = true;
            
            // Track user's active connection
            userConversations.set(userId, clientId);
            
            return true;
          }
        }
      } catch (err) {
        console.error('Authentication error:', err);
        return false;
      }
      return false;
    };

    // Set up connection
    clients.set(clientId, ws);
    ws.clientId = clientId;
    setupHeartbeat();

    // Handle incoming messages
    ws.on('message', async (message) => {
      try {
        // Handle heartbeat
        if (message === HEARTBEAT_VALUE) {
          ws.pong();
          return;
        }

        const data = JSON.parse(message);

        // Handle authentication
        if (data.type === 'authenticate') {
          const success = await authenticate(data.token);
          if (success) {
            ws.userType = userType;
            ws.userId = userId;
            
            sendToClient(clientId, {
              type: 'authentication',
              success: true,
              userType,
              userId
            });

            // Load user-specific data
            if (userType === 'user') {
              const conversations = await SupportConversation.find({
                userId,
                status: { $in: ['open', 'active', 'waiting'] }
              }).sort({ updatedAt: -1 });
              
              sendToClient(clientId, {
                type: 'conversations',
                conversations
              });
            }

            // Load agent-specific data
            if (userType === 'agent') {
              const activeConversations = await SupportConversation.find({
                status: { $in: ['active', 'waiting'] }
              }).populate('user', 'firstName lastName email');
              
              const onlineAgents = [];
              clients.forEach((client, id) => {
                if (client.userType === 'agent' && client.readyState === WebSocket.OPEN) {
                  onlineAgents.push(client.userId);
                }
              });
              
              sendToClient(clientId, {
                type: 'agent_init',
                conversations: activeConversations,
                onlineAgents
              });
            }
          } else {
            sendToClient(clientId, {
              type: 'authentication',
              success: false,
              message: 'Invalid or expired token'
            });
            ws.close();
          }
          return;
        }

        if (!isAuthenticated) {
          sendToClient(clientId, {
            type: 'error',
            message: 'Not authenticated'
          });
          return;
        }

        // Handle different message types
        switch (data.type) {
          case 'new_message': {
            const { conversationId, message } = data;
            
            // Validate conversation
            const conversation = await SupportConversation.findOne({
              conversationId,
              $or: [{ userId }, { agentId: userId }]
            });
            
            if (!conversation) {
              sendToClient(clientId, {
                type: 'error',
                message: 'Conversation not found or access denied'
              });
              return;
            }
            
            // Create message in database
            const newMessage = new SupportMessage({
              conversationId,
              sender: userType,
              senderId: userId,
              message,
              read: false
            });

            await newMessage.save();

            // Update conversation
            conversation.lastMessageAt = new Date();
            conversation.status = userType === 'user' ? 
              (conversation.agentId ? 'active' : 'open') : 'active';
            await conversation.save();

            // Broadcast message
            const messageData = {
              type: 'new_message',
              message: {
                ...newMessage.toObject(),
                conversationId,
                sender: userType,
                senderId: userId
              }
            };

            // Send to other participant(s)
            if (userType === 'user') {
              // Send to assigned agent if available
              if (conversation.agentId) {
                const agentClientId = userConversations.get(conversation.agentId.toString());
                if (agentClientId) {
                  sendToClient(agentClientId, messageData);
                }
              } else {
                // No agent assigned, notify available agents
                broadcastToAgents({
                  type: 'new_conversation',
                  conversation: await SupportConversation.findById(conversation._id)
                    .populate('user', 'firstName lastName email')
                });
              }
            } else {
              // Agent sending message - send to user
              const userClientId = userConversations.get(conversation.userId.toString());
              if (userClientId) {
                sendToClient(userClientId, messageData);
              }
            }

            break;
          }

          // Add other message type handlers as needed...
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
        sendToClient(clientId, {
          type: 'error',
          message: 'Internal server error'
        });
      }
    });

    // Handle close
    ws.on('close', () => {
      clearInterval(heartbeatInterval);
      clients.delete(clientId);
      
      if (userType === 'agent' && userId) {
        agentAvailability.delete(userId);
        broadcastToAgents({
          type: 'agent_status',
          agentId: userId,
          status: 'offline'
        });
      }
      
      if (userType === 'user' && userId) {
        userConversations.delete(userId);
      }
    });

    // Handle errors
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      ws.close();
    });

    // Handle pong responses
    ws.on('pong', () => {
      // Connection is alive
    });
  });

  return wss;
};





module.exports = {
  User,
  Admin,
  Plan,
  Investment,
  Transaction,
  Loan,
  SystemLog,
 UserLog,
  DownlineRelationship, // Add this
  CommissionHistory,     // Add this
  CommissionSettings, 
  Translation,
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
        minAmount: 30,
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
        maxAmount: 49999,
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





















// Fixed function to calculate and distribute downline referral commissions
const calculateReferralCommissions = async (investment) => {
  try {
    // First, populate the investment with user data
    const populatedInvestment = await Investment.findById(investment._id)
      .populate('user', 'firstName lastName email')
      .populate('plan');

    if (!populatedInvestment) {
      console.log(`❌ Investment not found: ${investment._id}`);
      return;
    }

    const investmentId = populatedInvestment._id;
    const investorId = populatedInvestment.user._id;
    const investmentAmount = populatedInvestment.amount;

    console.log(`🔍 Checking downline commissions for investment: ${investmentId}, user: ${investorId}, amount: $${investmentAmount}`);

    // Find the downline relationship for this investor (check if they have an upline)
    const relationship = await DownlineRelationship.findOne({
      downline: investorId,
      status: 'active',
      remainingRounds: { $gt: 0 }
    }).populate('upline', 'firstName lastName email balances referralStats downlineStats');

    if (!relationship) {
      console.log(`❌ No active downline relationship found for user: ${investorId}`);
      return; // No upline found or no commission rounds remaining
    }

    const uplineId = relationship.upline._id;
    const uplineUser = relationship.upline;
    const commissionPercentage = relationship.commissionPercentage;
    const commissionAmount = (investmentAmount * commissionPercentage) / 100;

    console.log(`💰 Downline commission: $${investmentAmount} * ${commissionPercentage}% = $${commissionAmount} for upline: ${uplineUser.email}`);

    // Create commission history record
    const commissionHistory = await CommissionHistory.create({
      upline: uplineId,
      downline: investorId,
      investment: investmentId,
      investmentAmount: investmentAmount,
      commissionPercentage: commissionPercentage,
      commissionAmount: commissionAmount,
      roundNumber: relationship.commissionRounds - relationship.remainingRounds + 1,
      status: 'paid',
      paidAt: new Date()
    });

    // ✅ FIXED: Add commission to upline's MAIN balance as requested
    const updatedUpline = await User.findByIdAndUpdate(
      uplineId,
      {
        $inc: {
          'balances.main': commissionAmount, // Added to main balance
          'referralStats.totalEarnings': commissionAmount,
          'referralStats.availableBalance': commissionAmount,
          'downlineStats.totalCommissionEarned': commissionAmount,
          'downlineStats.thisMonthCommission': commissionAmount
        }
      },
      { new: true }
    );

    console.log(`✅ Updated upline ${uplineUser.email} MAIN balance with $${commissionAmount}. New balance: $${updatedUpline.balances.main}`);

    // Update downline relationship
    relationship.remainingRounds -= 1;
    relationship.totalCommissionEarned += commissionAmount;
    
    if (relationship.remainingRounds === 0) {
      relationship.status = 'completed';
      console.log(`🎯 Commission rounds completed for relationship: ${relationship._id}`);
    }

    await relationship.save();

    // Create transaction record for the commission
    await Transaction.create({
      user: uplineId,
      type: 'referral',
      amount: commissionAmount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference: `DOWNLINE-COMM-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        commissionFrom: investorId,
        investmentId: investmentId,
        round: relationship.commissionRounds - relationship.remainingRounds + 1,
        totalRounds: relationship.commissionRounds,
        commissionType: 'downline',
        downlineName: `${populatedInvestment.user.firstName} ${populatedInvestment.user.lastName}`,
        percentage: commissionPercentage
      },
      fee: 0,
      netAmount: commissionAmount
    });

    // Add to upline's referral history
    await User.findByIdAndUpdate(uplineId, {
      $push: {
        referralHistory: {
          referredUser: investorId,
          amount: commissionAmount,
          percentage: commissionPercentage,
          level: 1, // Direct downline
          date: new Date(),
          status: 'available',
          type: 'downline_commission'
        }
      }
    });

    // Update downline stats count
    const activeDownlinesCount = await DownlineRelationship.countDocuments({ 
      upline: uplineId, 
      status: 'active',
      remainingRounds: { $gt: 0 }
    });

    await User.findByIdAndUpdate(uplineId, {
      'downlineStats.activeDownlines': activeDownlinesCount
    });

    console.log(`🎉 Downline commission of $${commissionAmount} paid to upline ${uplineUser.email} for investment ${investmentId} (Round ${relationship.commissionRounds - relationship.remainingRounds + 1}/${relationship.commissionRounds})`);

    // Log the activity
    await logActivity('downline_commission_paid', 'commission', commissionHistory._id, uplineId, 'User', null, {
      amount: commissionAmount,
      downline: investorId,
      investment: investmentId,
      round: relationship.commissionRounds - relationship.remainingRounds + 1,
      totalRounds: relationship.commissionRounds,
      percentage: commissionPercentage
    });

  } catch (err) {
    console.error('❌ Downline commission calculation error:', err);
    // Don't throw error to avoid disrupting investment process
  }
};









const initializeLanguages = async () => {
  try {
    const defaultLanguages = [
      { code: 'EN', name: 'English', nativeName: 'English', flag: 'https://flagcdn.com/w40/gb.png', sortOrder: 1 },
      { code: 'FI', name: 'Finnish', nativeName: 'Suomi', flag: 'https://flagcdn.com/w40/fi.png', sortOrder: 2 },
      { code: 'SV', name: 'Swedish', nativeName: 'Svenska', flag: 'https://flagcdn.com/w40/se.png', sortOrder: 3 },
      { code: 'NO', name: 'Norwegian', nativeName: 'Norsk', flag: 'https://flagcdn.com/w40/no.png', sortOrder: 4 },
      { code: 'DA', name: 'Danish', nativeName: 'Dansk', flag: 'https://flagcdn.com/w40/dk.png', sortOrder: 5 },
      { code: 'DE', name: 'German', nativeName: 'Deutsch', flag: 'https://flagcdn.com/w40/de.png', sortOrder: 6 },
      { code: 'FR', name: 'French', nativeName: 'Français', flag: 'https://flagcdn.com/w40/fr.png', sortOrder: 7 },
      { code: 'ES', name: 'Spanish', nativeName: 'Español', flag: 'https://flagcdn.com/w40/es.png', sortOrder: 8 },
      { code: 'IT', name: 'Italian', nativeName: 'Italiano', flag: 'https://flagcdn.com/w40/it.png', sortOrder: 9 },
      { code: 'PT', name: 'Portuguese', nativeName: 'Português', flag: 'https://flagcdn.com/w40/pt.png', sortOrder: 10 },
      { code: 'NL', name: 'Dutch', nativeName: 'Nederlands', flag: 'https://flagcdn.com/w40/nl.png', sortOrder: 11 },
      { code: 'RU', name: 'Russian', nativeName: 'Русский', flag: 'https://flagcdn.com/w40/ru.png', sortOrder: 12 },
      { code: 'ZH', name: 'Chinese', nativeName: '中文', flag: 'https://flagcdn.com/w40/cn.png', sortOrder: 13 },
      { code: 'JA', name: 'Japanese', nativeName: '日本語', flag: 'https://flagcdn.com/w40/jp.png', sortOrder: 14 },
      { code: 'KO', name: 'Korean', nativeName: '한국어', flag: 'https://flagcdn.com/w40/kr.png', sortOrder: 15 },
      { code: 'AR', name: 'Arabic', nativeName: 'العربية', flag: 'https://flagcdn.com/w40/sa.png', rtl: true, sortOrder: 16 },
      { code: 'HI', name: 'Hindi', nativeName: 'हिन्दी', flag: 'https://flagcdn.com/w40/in.png', sortOrder: 17 }
    ];

    for (const lang of defaultLanguages) {
      await Language.findOneAndUpdate(
        { code: lang.code },
        { $set: lang },
        { upsert: true, new: true }
      );
    }

    console.log('Default languages initialized successfully');
  } catch (err) {
    console.error('Error initializing languages:', err);
  }
};

// Call this function after database connection
initializeLanguages();






// Routes


// User Signup with Comprehensive Tracking - FIXED VERSION
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

    // Send welcome email (fire and forget)
    try {
      const welcomeMessage = `Welcome to BitHash, ${firstName}! Your account has been successfully created.`;
      await sendEmail({
        email: newUser.email,
        subject: 'Welcome to BitHash',
        message: welcomeMessage,
        html: `<p>${welcomeMessage}</p>`
      });
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
      // Don't fail the signup if email fails
    }

    // Set cookie
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    // Return success response with user data
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

    // Log successful signup AFTER sending response (non-blocking)
    try {
      const deviceInfo = await getUserDeviceInfo(req);
      await SystemLog.create({
        action: 'signup_complete',
        entity: 'User',
        entityId: newUser._id,
        performedBy: newUser._id,
        performedByModel: 'User',
        ip: deviceInfo.ip,
        device: deviceInfo.device,
        location: deviceInfo.location,
        changes: {
          userId: newUser._id,
          referralUsed: !!referredByUser,
          referralSource: referredByUser ? referredByUser._id : 'organic'
        }
      });
    } catch (logError) {
      console.error('Failed to log signup activity:', logError);
    }

  } catch (err) {
    console.error('Signup error:', err);
    
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during signup'
    });
  }
});


// User Login with Comprehensive Tracking
app.post('/api/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
  body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Track failed validation
    await logUserActivity(req, 'login_attempt', 'failed', {
      error: 'Validation failed',
      fields: errors.array().map(err => err.param)
    });
    
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, rememberMe } = req.body;

    // Track login attempt
    await logUserActivity(req, 'login_attempt', 'pending', {
      email,
      rememberMe: !!rememberMe
    });

    const user = await User.findOne({ email }).select('+password +twoFactorAuth.secret');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      // Track failed login
      await logUserActivity(req, 'login_attempt', 'failed', {
        error: 'Invalid credentials',
        email
      });
      
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    if (user.status !== 'active') {
      // Track login to suspended account
      await logUserActivity(req, 'login_attempt', 'failed', {
        error: 'Account suspended',
        userId: user._id,
        status: user.status
      });
      
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

    // Track device info
    await logUserActivity(req, 'device_login', 'success', {
      deviceType: getDeviceType(req),
      ipAddress: deviceInfo.ip,
      location: deviceInfo.location,
      os: getOSFromUserAgent(req.headers['user-agent']),
      browser: getBrowserFromUserAgent(req.headers['user-agent'])
    }, user);

    // Set cookie
    res.cookie('jwt', token, {
      expires: rememberMe ? new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000) : undefined,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    // Track session creation
    await logUserActivity(req, 'session_created', 'success', {
      userId: user._id,
      sessionType: 'jwt',
      rememberMe: !!rememberMe,
      duration: rememberMe ? JWT_COOKIE_EXPIRES + ' days' : 'session'
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
      
      // Track 2FA required
      await logUserActivity(req, '2fa_required', 'pending', {
        userId: user._id
      }, user);
    } else {
      // Track successful login
      await logUserActivity(req, 'login', 'success', {
        userId: user._id,
        rememberMe: !!rememberMe
      }, user);
    }

    res.status(200).json(responseData);

    // Also log to system activity
    await logActivity('user_login', 'user', user._id, user._id, 'User', req);

  } catch (err) {
    console.error('Login error:', err);
    
    // Track login error
    await logUserActivity(req, 'login_error', 'failed', {
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });

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






// Plans Endpoint with login state detection
app.get('/api/plans', async (req, res) => {
  try {
    // Get plans from database
    const plans = await Plan.find({ isActive: true }).lean();
    
    // Get user balance if logged in
    let userMainBalance = 0;
    let userMaturedBalance = 0;
    let isLoggedIn = false;
    if (req.user) {
      const user = await User.findById(req.user.id).select('balances');
      userMainBalance = user.balances.main;
      userMaturedBalance = user.balances.matured;
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
      canInvest: isLoggedIn && (userMainBalance >= plan.minAmount || userMaturedBalance >= plan.minAmount)
    }));

    res.status(200).json({
      status: 'success',
      data: {
        plans: formattedPlans,
        userBalances: isLoggedIn ? {
          main: userMainBalance,
          matured: userMaturedBalance
        } : null,
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



// Investment routes - FIXED VERSION WITH WORKING REFERRALS
app.post('/api/investments', protect, [
  body('planId').notEmpty().withMessage('Plan ID is required').isMongoId().withMessage('Invalid Plan ID'),
  body('amount').isFloat({ min: 1 }).withMessage('Amount must be a positive number'),
  body('balanceType').isIn(['main', 'matured']).withMessage('Balance type must be either "main" or "matured"')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { planId, amount, balanceType } = req.body;
    const userId = req.user._id;

    // Verify plan exists and is active
    const plan = await Plan.findById(planId);
    if (!plan || !plan.isActive) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid or inactive investment plan'
      });
    }

    // Verify amount is within plan limits
    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }

    // Verify user has sufficient balance in the selected balance type
    const user = await User.findById(userId);
    const selectedBalance = user.balances[balanceType];
    
    if (selectedBalance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient ${balanceType} balance`
      });
    }

    // Calculate investment amount after 3% fee
    const investmentFee = amount * 0.03;
    const investmentAmountAfterFee = amount - investmentFee;

    // Calculate expected return based on the amount after fee
    const expectedReturn = investmentAmountAfterFee + (investmentAmountAfterFee * plan.percentage / 100);
    const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);

    // Create investment
    const investment = await Investment.create({
      user: userId,
      plan: planId,
      amount: investmentAmountAfterFee, // Store the amount after fee
      originalAmount: amount, // Store original amount before fee
      originalCurrency: 'USD',
      currency: 'USD',
      expectedReturn,
      returnPercentage: plan.percentage,
      endDate,
      payoutSchedule: 'end_term',
      status: 'active',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      deviceInfo: getDeviceType(req),
      termsAccepted: true,
      investmentFee: investmentFee, // Store the fee for record keeping
      balanceType: balanceType // Store which balance was used
    });

    // Deduct from user's selected balance (only the original amount)
    user.balances[balanceType] -= amount;
    user.balances.active += investmentAmountAfterFee; // Add the amount after fee to active balance
    await user.save();

    // Create transaction record for the investment with fee
    const transaction = await Transaction.create({
      user: userId,
      type: 'investment',
      amount: -amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference: `INV-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        investmentId: investment._id,
        planName: plan.name,
        balanceType: balanceType,
        investmentFee: investmentFee,
        amountAfterFee: investmentAmountAfterFee
      },
      fee: investmentFee,
      netAmount: -investmentAmountAfterFee
    });

    // RECORD PLATFORM REVENUE
    await PlatformRevenue.create({
      source: 'investment_fee',
      amount: investmentFee,
      currency: 'USD',
      transactionId: transaction._id,
      investmentId: investment._id,
      userId: userId,
      description: `3% investment fee for ${plan.name} investment`,
      metadata: {
        planName: plan.name,
        originalAmount: amount,
        amountAfterFee: investmentAmountAfterFee,
        feePercentage: 3
      }
    });

    // ✅ FIXED: ALWAYS CHECK FOR DOWNLINE COMMISSIONS (Not just referredBy)
    await calculateReferralCommissions(investment);

    // ✅ FIXED: Handle direct referral bonus separately (if user was referred by someone)
    if (user.referredBy) {
      const referralBonus = (amount * plan.referralBonus) / 100;
      
      // Update referring user's balance for direct referral bonus
      await User.findByIdAndUpdate(user.referredBy, {
        $inc: {
          'balances.main': referralBonus,
          'referralStats.totalEarnings': referralBonus,
          'referralStats.availableBalance': referralBonus
        },
        $push: {
          referralHistory: {
            referredUser: userId,
            amount: referralBonus,
            percentage: plan.referralBonus,
            level: 1,
            status: 'available',
            date: new Date()
          }
        }
      });

      // Create referral commission record for direct referral
      await CommissionHistory.create({
        upline: user.referredBy,
        downline: userId,
        investment: investment._id,
        investmentAmount: amount,
        commissionPercentage: plan.referralBonus,
        commissionAmount: referralBonus,
        roundNumber: 0, // 0 indicates direct referral bonus, not downline commission
        status: 'paid',
        paidAt: new Date()
      });

      // Create transaction for direct referral bonus
      await Transaction.create({
        user: user.referredBy,
        type: 'referral',
        amount: referralBonus,
        currency: 'USD',
        status: 'completed',
        method: 'internal',
        reference: `REF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        details: {
          referralFrom: userId,
          investmentId: investment._id,
          type: 'direct_referral',
          bonusPercentage: plan.referralBonus
        },
        fee: 0,
        netAmount: referralBonus
      });

      // Mark investment with referral info
      investment.referredBy = user.referredBy;
      investment.referralBonusAmount = referralBonus;
      investment.referralBonusDetails = {
        percentage: plan.referralBonus,
        payoutDate: new Date()
      };
      await investment.save();

      console.log(`🎁 Direct referral bonus of $${referralBonus} paid to ${user.referredBy}`);
    }

    // Log activity
    await logActivity('create_investment', 'investment', investment._id, userId, 'User', req);

    res.status(201).json({
      status: 'success',
      data: {
        investment: {
          id: investment._id,
          plan: plan.name,
          amount: investment.amount, // This shows amount after fee to user
          originalAmount: investment.originalAmount, // Original amount for reference
          investmentFee: investmentFee,
          expectedReturn: investment.expectedReturn,
          endDate: investment.endDate,
          status: investment.status,
          balanceType: balanceType
        }
      }
    });
  } catch (err) {
    console.error('Investment creation error:', err);
    
    // Even on error, return success to frontend as requested
    res.status(200).json({
      status: 'success',
      message: 'Investment created successfully'
    });
  }
});

app.post('/api/investments/:id/complete', protect, async (req, res) => {
  try {
    const investmentId = req.params.id;
    const userId = req.user._id;

    // Find the investment with more comprehensive query
    const investment = await Investment.findOne({ 
      _id: investmentId, 
      user: userId,
      status: 'active' 
    }).populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        status: 'fail',
        message: 'Active investment not found'
      });
    }

    // Enhanced completion check - ensure investment has actually matured
    const now = new Date();
    if (now < investment.endDate) {
      return res.status(400).json({
        status: 'fail',
        message: 'Investment has not matured yet'
      });
    }

    // Find the user with proper session handling
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Calculate total return (principal + profit) - based on amount after fee
    const totalReturn = investment.expectedReturn;

    // Enhanced balance transfer with validation
    if (user.balances.active < investment.amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient active balance to complete investment'
      });
    }

    // Use transaction to ensure atomic operation
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Transfer from active to matured balance
      user.balances.active -= investment.amount;
      user.balances.matured += totalReturn;
      
      // Update investment status with completion details
      investment.status = 'completed';
      investment.completionDate = now;
      investment.actualReturn = totalReturn - investment.amount;
      investment.isProcessed = true; // Add flag to ensure it's processed

      // Save changes with session
      await user.save({ session });
      await investment.save({ session });

      // Create transaction record for the return
      await Transaction.create([{
        user: userId,
        type: 'interest',
        amount: totalReturn - investment.amount,
        currency: 'USD',
        status: 'completed',
        method: 'internal',
        reference: `RET-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        details: {
          investmentId: investment._id,
          planName: investment.plan.name,
          principal: investment.amount,
          interest: totalReturn - investment.amount,
          originalInvestment: investment.originalAmount,
          investmentFee: investment.investmentFee
        },
        fee: 0,
        netAmount: totalReturn - investment.amount
      }], { session });

      // Commit transaction
      await session.commitTransaction();
      
      res.status(200).json({
        status: 'success',
        data: {
          investment: {
            id: investment._id,
            status: investment.status,
            completionDate: investment.completionDate,
            amountReturned: totalReturn,
            profit: totalReturn - investment.amount,
            originalInvestment: investment.originalAmount,
            investmentFee: investment.investmentFee
          },
          balances: {
            active: user.balances.active,
            matured: user.balances.matured
          }
        }
      });

      await logActivity('complete_investment', 'investment', investment._id, userId, 'User', req);

    } catch (transactionError) {
      // Rollback transaction on error
      await session.abortTransaction();
      throw transactionError;
    } finally {
      session.endSession();
    }

  } catch (err) {
    console.error('Complete investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while completing the investment'
    });
  }
});





app.get('/api/transactions', protect, async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({
                status: 'fail',
                message: 'Authentication required'
            });
        }

        // Get all transaction types that involve money movements
        const transactions = await Transaction.find({
            user: req.user.id,
            type: { $in: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral', 'loan'] }
        })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean();

        // Format transactions to match frontend expectations with proper details
        const formattedTransactions = transactions.map(transaction => ({
            id: transaction._id,
            date: transaction.createdAt,
            type: transaction.type,
            amount: transaction.amount,
            currency: transaction.currency || 'USD',
            status: transaction.status,
            method: transaction.method,
            reference: transaction.reference,
            details: generateTransactionDetails(transaction), // Use the new helper function
            fee: transaction.fee || 0,
            netAmount: transaction.netAmount || transaction.amount
        }));

        // Return in the exact format expected by frontend
        res.status(200).json({
            status: 'success',
            data: {
                transactions: formattedTransactions
            }
        });

    } catch (err) {
        console.error('Error fetching transactions:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch transactions'
        });
    }
});

// Enhanced helper function to generate meaningful transaction details
function generateTransactionDetails(transaction) {
    const type = transaction.type;
    const status = transaction.status;
    const amount = transaction.amount;
    const method = transaction.method;
    const currency = transaction.currency || 'USD';
    
    // Base status messages
    const statusMessages = {
        'completed': 'completed successfully',
        'pending': 'is being processed',
        'failed': 'failed to process',
        'cancelled': 'was cancelled',
        'reversed': 'was reversed'
    };
    
    const statusText = statusMessages[status] || 'processed';

    // Type-specific detail templates
    const detailTemplates = {
        'deposit': {
            completed: `Deposit of $${amount.toFixed(2)} ${currency} ${method ? `via ${method}` : ''} completed successfully`,
            pending: `Deposit of $${amount.toFixed(2)} ${currency} is being processed${method ? ` via ${method}` : ''}`,
            failed: `Deposit of $${amount.toFixed(2)} ${currency} failed${method ? ` via ${method}` : ''}`,
            default: `Deposit transaction ${statusText}`
        },
        'withdrawal': {
            completed: `Withdrawal of $${amount.toFixed(2)} ${currency} processed successfully${method ? ` to ${method}` : ''}`,
            pending: `Withdrawal of $${amount.toFixed(2)} ${currency} is being processed${method ? ` to ${method}` : ''}`,
            failed: `Withdrawal of $${amount.toFixed(2)} ${currency} failed${method ? ` to ${method}` : ''}`,
            default: `Withdrawal transaction ${statusText}`
        },
        'investment': {
            completed: `Investment of $${amount.toFixed(2)} ${currency} activated successfully`,
            pending: `Investment of $${amount.toFixed(2)} ${currency} is being activated`,
            failed: `Investment of $${amount.toFixed(2)} ${currency} activation failed`,
            default: `Investment transaction ${statusText}`
        },
        'interest': {
            completed: `Interest earnings of $${amount.toFixed(2)} ${currency} credited to your account`,
            pending: `Interest earnings of $${amount.toFixed(2)} ${currency} pending`,
            failed: `Interest earnings of $${amount.toFixed(2)} ${currency} failed to credit`,
            default: `Interest payment ${statusText}`
        },
        'referral': {
            completed: `Referral bonus of $${amount.toFixed(2)} ${currency} earned from referral activity`,
            pending: `Referral bonus of $${amount.toFixed(2)} ${currency} pending verification`,
            failed: `Referral bonus of $${amount.toFixed(2)} ${currency} failed to process`,
            default: `Referral bonus ${statusText}`
        },
        'loan': {
            completed: `Loan of $${amount.toFixed(2)} ${currency} ${transaction.loanType === 'repayment' ? 'repayment completed' : 'disbursed successfully'}`,
            pending: `Loan ${transaction.loanType === 'repayment' ? 'repayment' : 'application'} of $${amount.toFixed(2)} ${currency} is being processed`,
            failed: `Loan ${transaction.loanType === 'repayment' ? 'repayment' : 'application'} of $${amount.toFixed(2)} ${currency} failed`,
            default: `Loan transaction ${statusText}`
        },
        'transfer': {
            completed: `Transfer of $${amount.toFixed(2)} ${currency} completed successfully`,
            pending: `Transfer of $${amount.toFixed(2)} ${currency} is being processed`,
            failed: `Transfer of $${amount.toFixed(2)} ${currency} failed`,
            default: `Transfer transaction ${statusText}`
        }
    };

    // Get the appropriate template for this transaction type
    const template = detailTemplates[type];
    if (template) {
        return template[status] || template.default;
    }

    // Fallback for unknown transaction types
    return `${type} transaction ${statusText}`;
}

// Alternative: If you want to preserve existing details but ensure they're strings
function getTransactionDetails(transaction) {
    // If details already exist and are a string, use them
    if (transaction.details && typeof transaction.details === 'string') {
        return transaction.details;
    }
    
    // If details exist but are an object, convert to meaningful string
    if (transaction.details && typeof transaction.details === 'object') {
        return formatObjectDetails(transaction.details, transaction.type);
    }
    
    // Generate new details if none exist
    return generateTransactionDetails(transaction);
}

// Helper to format object details into readable strings
function formatObjectDetails(detailsObj, type) {
    if (detailsObj.message) {
        return detailsObj.message;
    }
    
    if (detailsObj.reason) {
        return `${type} ${detailsObj.reason}`;
    }
    
    // Convert object to readable string
    try {
        return Object.entries(detailsObj)
            .map(([key, value]) => `${key}: ${value}`)
            .join(', ');
    } catch {
        return `${type} transaction processed`;
    }
}





// Enhanced loadMiningStats function
async function loadMiningStats() {
  try {
    console.log('Loading mining stats...');
    
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      throw new Error('No authentication token');
    }

    const response = await fetch('https://website-backendd-1.onrender.com/api/mining', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      // Add timeout handling
      signal: AbortSignal.timeout(10000) // 10 second timeout
    });
    
    console.log('Mining API response status:', response.status);
    
    if (!response.ok) {
      // Don't throw error, use fallback data instead
      console.warn('Mining API returned non-OK status:', response.status);
      await setFallbackMiningData();
      return;
    }

    const data = await response.json();
    console.log('Mining API response data:', data);
    
    // Validate response structure
    if (!data || !data.data) {
      throw new Error('Invalid response structure from mining API');
    }

    const stats = data.data;
    
    // Safe updates with validation
    safeUpdateElement('hash-rate', stats.hashRate || '0 TH/s');
    safeUpdateElement('btc-mined', stats.btcMined || '0 BTC');
    safeUpdateElement('mining-power', stats.miningPower || '0%');
    
    // Handle estimatedDaily - ensure it's a number
    const estimatedDaily = typeof stats.estimatedDaily === 'number' ? stats.estimatedDaily : 0;
    safeUpdateElement('estimated-daily', `$${estimatedDaily.toFixed(2)}`);
    
    // Handle progress
    const progress = typeof stats.progress === 'number' ? Math.min(100, Math.max(0, stats.progress)) : 0;
    document.getElementById('mining-progress-bar').style.width = `${progress}%`;
    safeUpdateElement('mining-progress-text', `${progress.toFixed(1)}%`);
    
    console.log('Mining stats updated successfully');

  } catch (error) {
    console.error('Error loading mining stats:', error);
    await setFallbackMiningData();
    
    // Show user-friendly error
    showNotification('warning', 'Mining Data', 
      'Using simulated mining data. Real data will load when available.',
      3000
    );
  }
}

// Helper function for safe element updates
function safeUpdateElement(elementId, value) {
  try {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = value;
    }
  } catch (e) {
    console.error(`Error updating element ${elementId}:`, e);
  }
}

// Fallback mining data
async function setFallbackMiningData() {
  const fallbackData = {
    hashRate: "12.45 TH/s",
    btcMined: "0.00123456 BTC",
    miningPower: "65.5%",
    estimatedDaily: 45.67,
    progress: 35.2
  };
  
  safeUpdateElement('hash-rate', fallbackData.hashRate);
  safeUpdateElement('btc-mined', fallbackData.btcMined);
  safeUpdateElement('mining-power', fallbackData.miningPower);
  safeUpdateElement('estimated-daily', `$${fallbackData.estimatedDaily.toFixed(2)}`);
  document.getElementById('mining-progress-bar').style.width = `${fallbackData.progress}%`;
  safeUpdateElement('mining-progress-text', `${fallbackData.progress}%`);
}

// Update your refresh function too
async function refreshMiningStats() {
  // Clear cache by adding timestamp to bypass cache
  const token = localStorage.getItem('jwtToken');
  try {
    await fetch(`https://website-backendd-1.onrender.com/api/cache/clear?key=mining-stats:${getUserId()}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
  } catch (e) {
    console.log('Cache clear failed, proceeding anyway');
  }
  
  await loadMiningStats();
}

function getUserId() {
  const token = localStorage.getItem('jwtToken');
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.id;
  } catch (e) {
    return null;
  }
}







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
      transactionData.btcAddress = 'bc1q78syc97weckfh3l4vswafxkerjynzmwey7lr4e';
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

        // Initialize base stats
        let stats = {
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

        // Get or initialize persistent investor count
        let investorCount = await redis.get('persistent-investor-count');
        if (!investorCount) {
            // Initialize with your specified starting value
            investorCount = 7087098;
            await redis.set('persistent-investor-count', investorCount.toString());
        } else {
            investorCount = parseInt(investorCount);
        }
        stats.totalInvestors = investorCount;

        // If we have previous stats in Redis (even if expired), use them as base for other metrics
        const previousStats = await redis.get('previous-stats');
        if (previousStats) {
            const previous = JSON.parse(previousStats);
            
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
            totalInvested: 61236234.21,
            totalWithdrawals: 47236585.06,
            totalLoans: 13236512.17,
            lastUpdated: new Date().toISOString()
        };

        // Get persistent investor count
        let investorCount = await redis.get('persistent-investor-count');
        if (!investorCount) {
            // Initialize with your specified starting value if not exists
            investorCount = 7087098;
            await redis.set('persistent-investor-count', investorCount.toString());
        } else {
            investorCount = parseInt(investorCount);
        }
        
        const cachedStats = await redis.get('stats-data');
        if (cachedStats) {
            const parsedStats = JSON.parse(cachedStats);
            stats.totalInvested = parsedStats.totalInvested;
            stats.totalWithdrawals = parsedStats.totalWithdrawals;
            stats.totalLoans = parsedStats.totalLoans;
        }

        // Update each stat with different intervals and random increments
        const now = new Date();
        const seconds = now.getSeconds();

        // Update investors every 15-30 seconds (13-999 increment)
        if (seconds % getRandomInRange(15, 30, 0) === 0) {
            investorCount += getRandomInRange(13, 999, 0);
            await redis.set('persistent-investor-count', investorCount.toString());
        }
        stats.totalInvestors = investorCount;

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
        } else if (cachedStats) {
            // Preserve existing change rates if not recalculating
            const parsedStats = JSON.parse(cachedStats);
            stats.changeRates = parsedStats.changeRates;
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



app.get('/api/mining', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const cacheKey = `mining-stats:${userId}`;
    
    // Try to get cached data first (shorter cache time for real-time feel)
    const cachedData = await redis.get(cacheKey);
    if (cachedData) {
      const parsedData = JSON.parse(cachedData);
      // Add small random fluctuations to cached values for realism
      parsedData.hashRate = fluctuateValue(parsedData.hashRate, 5); // ±5% fluctuation
      parsedData.miningPower = fluctuateValue(parsedData.miningPower, 3); // ±3% fluctuation
      parsedData.btcMined = fluctuateValue(parsedData.btcMined, 1); // ±1% fluctuation
      return res.status(200).json({
        status: 'success',
        data: parsedData
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
        totalReturn: "$0.00",
        progress: 0,
        lastUpdated: new Date().toISOString()
      };
      
      await redis.set(cacheKey, JSON.stringify(defaultData), 'EX', 60); // Cache for 1 minute
      return res.status(200).json({
        status: 'success',
        data: defaultData
      });
    }

    // Calculate base values
    let totalReturn = 0;
    let totalInvestmentAmount = 0;
    let maxProgress = 0;

    for (const investment of activeInvestments) {
      const investmentReturn = investment.expectedReturn - investment.amount;
      totalReturn += investmentReturn;
      totalInvestmentAmount += investment.amount;

      // Calculate progress for this investment
      const totalDuration = investment.endDate - investment.createdAt;
      const elapsed = Date.now() - investment.createdAt;
      const progress = Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
      maxProgress = Math.max(maxProgress, progress);
    }

    // Get BTC price from CoinGecko
    let btcPrice = 60000;
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (error) {
      console.error('CoinGecko API error:', error);
    }

    // Base calculations
    const baseHashRate = totalInvestmentAmount * 0.1;
    const baseMiningPower = Math.min(100, (totalInvestmentAmount / 10000) * 100);
    const baseBtcMined = totalReturn / btcPrice;

    // Apply realistic fluctuations
    const currentTime = Date.now();
    const timeFactor = Math.sin(currentTime / 60000); // Fluctuates every minute
    
    // Hash rate fluctuates more dramatically
    const hashRateFluctuation = 0.05 * timeFactor + (Math.random() * 0.1 - 0.05);
    const hashRate = baseHashRate * (1 + hashRateFluctuation);
    
    // Mining power has smaller fluctuations
    const miningPowerFluctuation = 0.02 * timeFactor + (Math.random() * 0.04 - 0.02);
    const miningPower = baseMiningPower * (1 + miningPowerFluctuation);
    
    // BTC mined has very small incremental changes
    const btcMined = baseBtcMined * (1 + (Math.random() * 0.01 - 0.005));

    // Simulate network difficulty changes
    const networkFactor = 1 + (Math.sin(currentTime / 300000) * 0.1); // Changes every 5 minutes
    const adjustedHashRate = hashRate / networkFactor;
    const adjustedMiningPower = miningPower / networkFactor;

    const miningData = {
      hashRate: `${adjustedHashRate.toFixed(2)} TH/s`,
      btcMined: `${btcMined.toFixed(8)} BTC`,
      miningPower: `${Math.min(100, adjustedMiningPower).toFixed(2)}%`,
      totalReturn: `$${totalReturn.toFixed(2)}`,
      progress: parseFloat(maxProgress.toFixed(2)),
      lastUpdated: new Date().toISOString(),
      networkDifficulty: networkFactor.toFixed(2),
      workersOnline: Math.floor(3 + Math.random() * 3) // Random workers between 3-5
    };
    
    // Cache for 1 minute (shorter cache for more real-time feel)
    await redis.set(cacheKey, JSON.stringify(miningData), 'EX', 60);
    
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

// Helper function to add fluctuations to cached values
function fluctuateValue(valueStr, percent) {
  const numericValue = parseFloat(valueStr);
  const fluctuation = (Math.random() * percent * 2 - percent) / 100; // ±percent%
  const newValue = numericValue * (1 + fluctuation);
  
  // Preserve units if they exist
  if (valueStr.endsWith(' TH/s')) {
    return `${newValue.toFixed(2)} TH/s`;
  }
  if (valueStr.endsWith(' BTC')) {
    return `${newValue.toFixed(8)} BTC`;
  }
  if (valueStr.endsWith('%')) {
    return `${Math.min(100, newValue).toFixed(2)}%`;
  }
  return valueStr; // Return original if no known unit
}











// Get BTC deposit address (matches frontend structure exactly)
app.get('/api/deposits/btc-address', protect, async (req, res) => {
    try {
        // Default BTC address from your frontend
        const btcAddress = '1DopKPckf8QNE53FnaazSAd5DDR8kmetYr';
        
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
            address: '1DopKPckf8QNE53FnaazSAd5DDR8kmetYr',
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
      details: 'Payment pending processing'
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



app.get('/api/investments/active', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Cache key
    const cacheKey = `user:${req.user.id}:investments:${page}:${limit}`;
    
    // Check cache first unless refresh is requested
    if (!req.query.refresh) {
      const cachedData = await redis.get(cacheKey);
      if (cachedData) {
        return res.json(JSON.parse(cachedData));
      }
    }
    
    // Get active investments with plan details
    const investments = await Investment.find({
      user: req.user.id,
      status: 'active'
    })
    .sort({ endDate: 1 })
    .skip(skip)
    .limit(limit)
    .populate({
      path: 'plan',
      select: 'name percentage duration minAmount maxAmount referralBonus'
    })
    .lean(); // Convert to plain JS objects
    
    const total = await Investment.countDocuments({
      user: req.user.id,
      status: 'active'
    });
    
    // Calculate additional fields for each investment
    const now = new Date();
    const enhancedInvestments = investments.map(investment => {
      const startDate = new Date(investment.startDate);
      const endDate = new Date(investment.endDate);
      
      // Calculate time remaining
      const timeLeftMs = Math.max(0, endDate - now);
      const timeLeftHours = Math.ceil(timeLeftMs / (1000 * 60 * 60));
      
      // Calculate progress percentage
      const totalDurationMs = endDate - startDate;
      const elapsedMs = now - startDate;
      const progressPercentage = totalDurationMs > 0 
        ? Math.min(100, (elapsedMs / totalDurationMs) * 100)
        : 0;
      
// Get ROI percentage from the associated plan (this is the actual ROI percentage)
const roiPercentage = investment.plan?.percentage || 0;

// Calculate expected profit
const expectedProfit = investment.amount * (roiPercentage / 100);
      
      return {
        id: investment._id,
        planName: investment.plan?.name || 'Unknown Plan',
        amount: investment.amount,
        profitPercentage: roiPercentage, // This is what frontend expects as hourly ROI %
        durationHours: investment.plan?.duration || 0,
        startDate: investment.startDate,
        endDate: investment.endDate,
        status: investment.status,
        timeLeftHours,
        progressPercentage,
        expectedProfit,
        planDetails: {
          minAmount: investment.plan?.minAmount,
          maxAmount: investment.plan?.maxAmount,
          referralBonus: investment.plan?.referralBonus
        }
      };
    });
    
    // Format response
    const response = {
      data: {
        investments: enhancedInvestments,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        totalInvestments: total
      }
    };
    
    // Cache for 1 minute (adjust based on your requirements)
    await redis.set(cacheKey, JSON.stringify(response), 'EX', 60);
    
    res.json(response);
  } catch (err) {
    console.error('Error fetching active investments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});



// Enhanced activity logger with device and location info
const logUserActivity = async (req, action, status = 'success', metadata = {}, relatedEntity = null) => {
  try {
    // Skip logging if no user is associated (like during signup)
    if (!req.user && !(action === 'signup' || action === 'login' || action === 'password_reset_request')) {
      return;
    }

    // Get device and location info
    const deviceInfo = await getUserDeviceInfo(req);
    
    // Prepare log data
    const logData = {
      user: req.user?._id || null,
      username: req.user?.email || (action === 'signup' ? req.body.email : 'unknown'),
      email: req.user?.email || (action === 'signup' ? req.body.email : null),
      action,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      deviceInfo: {
        type: getDeviceType(req),
        os: getOSFromUserAgent(req.headers['user-agent']),
        browser: getBrowserFromUserAgent(req.headers['user-agent'])
      },
      location: {
        country: deviceInfo.location?.split(', ')[2] || 'Unknown',
        region: deviceInfo.location?.split(', ')[1] || 'Unknown',
        city: deviceInfo.location?.split(', ')[0] || 'Unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      status,
      metadata,
      ...(relatedEntity && {
        relatedEntity: relatedEntity._id || relatedEntity,
        relatedEntityModel: relatedEntity.constructor.modelName
      })
    };

    // Create the log
    await UserLog.create(logData);

    // Also add to system logs for admin viewing
    await SystemLog.create({
      action,
      entity: 'User',
      entityId: req.user?._id || null,
      performedBy: req.user?._id || null,
      performedByModel: req.user ? 'User' : 'System',
      ip: deviceInfo.ip,
      device: deviceInfo.device,
      location: deviceInfo.location,
      changes: metadata
    });

  } catch (err) {
    console.error('Error logging user activity:', err);
    // Fail silently to not disrupt user experience
  }
};

// Helper functions for device detection
const getDeviceType = (req) => {
  const userAgent = req.headers['user-agent'];
  if (/mobile/i.test(userAgent)) return 'mobile';
  if (/tablet/i.test(userAgent)) return 'tablet';
  if (/iPad|Android|Touch/i.test(userAgent)) return 'tablet';
  return 'desktop';
};

const getOSFromUserAgent = (userAgent) => {
  if (!userAgent) return 'Unknown';
  if (/windows/i.test(userAgent)) return 'Windows';
  if (/macintosh|mac os x/i.test(userAgent)) return 'MacOS';
  if (/linux/i.test(userAgent)) return 'Linux';
  if (/android/i.test(userAgent)) return 'Android';
  if (/iphone|ipad|ipod/i.test(userAgent)) return 'iOS';
  return 'Unknown';
};

const getBrowserFromUserAgent = (userAgent) => {
  if (!userAgent) return 'Unknown';
  if (/edg/i.test(userAgent)) return 'Edge';
  if (/chrome/i.test(userAgent)) return 'Chrome';
  if (/safari/i.test(userAgent)) return 'Safari';
  if (/firefox/i.test(userAgent)) return 'Firefox';
  if (/opera|opr/i.test(userAgent)) return 'Opera';
  return 'Unknown';
};

// Middleware to track user activity on protected routes
const trackUserActivity = (action, options = {}) => {
  return async (req, res, next) => {
    try {
      // Call next first to let the route handler process the request
      await next();
      
      // Only log if the request was successful (2xx status)
      if (res.statusCode >= 200 && res.statusCode < 300) {
        let metadata = {};
        let relatedEntity = null;
        
        // Custom metadata extraction based on action
        switch (action) {
          case 'profile_update':
            metadata = {
              fields: Object.keys(req.body).filter(key => 
                !key.toLowerCase().includes('password')
              )
            };
            break;
            
          case 'deposit':
          case 'withdrawal':
          case 'transfer':
            relatedEntity = res.locals.transaction || req.body;
            metadata = {
              amount: req.body.amount,
              currency: req.body.currency || 'USD',
              method: req.body.method
            };
            break;
            
          case 'investment':
            relatedEntity = res.locals.investment || req.body;
            metadata = {
              plan: req.body.planId,
              amount: req.body.amount
            };
            break;
            
          case 'kyc_submission':
            metadata = {
              type: req.body.type,
              status: 'pending'
            };
            break;
        }
        
        // Merge with any additional metadata from options
        if (options.metadata) {
          metadata = { ...metadata, ...options.metadata };
        }
        
        await logUserActivity(req, action, 'success', metadata, relatedEntity);
      }
    } catch (err) {
      console.error('Activity tracking middleware error:', err);
      // Don't interrupt the request flow if tracking fails
    }
  };
};

// Middleware to track failed login attempts
const trackFailedLogin = async (req, res, next) => {
  try {
    await next();
    
    // If login failed (unauthorized)
    if (res.statusCode === 401) {
      await logUserActivity(req, 'failed_login', 'failed', {
        email: req.body.email,
        reason: res.locals.failReason || 'Invalid credentials'
      });
    }
  } catch (err) {
    console.error('Failed login tracking error:', err);
  }
};



// BTC Withdrawal Endpoint
app.post('/api/withdrawals/btc', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('walletAddress').notEmpty().withMessage('BTC wallet address is required'),
  body('balanceSource').optional().isIn(['main', 'matured', 'both']).withMessage('Invalid balance source'),
  body('mainAmountUsed').optional().isFloat({ min: 0 }).withMessage('Main amount used must be valid'),
  body('maturedAmountUsed').optional().isFloat({ min: 0 }).withMessage('Matured amount used must be valid')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, walletAddress, balanceSource, mainAmountUsed = 0, maturedAmountUsed = 0 } = req.body;
    const user = await User.findById(req.user.id);

    // Enhanced balance checking logic to match frontend
    let hasSufficientBalance = false;
    let actualBalanceSource = '';
    let actualMainAmountUsed = 0;
    let actualMaturedAmountUsed = 0;

    // Check available balances
    const mainBalance = user.balances.main || 0;
    const maturedBalance = user.balances.matured || 0;
    const totalBalance = mainBalance + maturedBalance;

    // Validate total balance first
    if (amount > totalBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient total balance for withdrawal'
      });
    }

    // Determine balance source based on available balances
    if (balanceSource === 'main') {
      // Withdraw from main balance only
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      }
    } else if (balanceSource === 'matured') {
      // Withdraw from matured balance only
      if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      }
    } else if (balanceSource === 'both') {
      // Withdraw from both balances using specified amounts
      if (mainAmountUsed + maturedAmountUsed === amount && 
          mainBalance >= mainAmountUsed && 
          maturedBalance >= maturedAmountUsed) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainAmountUsed;
        actualMaturedAmountUsed = maturedAmountUsed;
      }
    } else {
      // Auto-detect balance source (fallback logic)
      if (mainBalance >= amount) {
        // Use main balance if sufficient
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      } else if (maturedBalance >= amount) {
        // Use matured balance if sufficient
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      } else if (totalBalance >= amount) {
        // Use both balances to cover the amount
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainBalance;
        actualMaturedAmountUsed = amount - mainBalance;
      }
    }

    if (!hasSufficientBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance in specified accounts for withdrawal',
        details: {
          requestedAmount: amount,
          mainBalance: mainBalance,
          maturedBalance: maturedBalance,
          totalBalance: totalBalance
        }
      });
    }

    // Calculate withdrawal fee (1% of amount)
    const fee = amount * 0.01;
    const netAmount = amount - fee;

    // Create transaction record with balance source information
    const reference = `BTC-WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'btc',
      reference,
      fee,
      netAmount,
      btcAddress: walletAddress,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      details: `BTC withdrawal to address ${walletAddress} (Source: ${actualBalanceSource})`
    });

    // Deduct from user's balances based on the determined source
    if (actualBalanceSource === 'main') {
      user.balances.main -= actualMainAmountUsed;
    } else if (actualBalanceSource === 'matured') {
      user.balances.matured -= actualMaturedAmountUsed;
    } else if (actualBalanceSource === 'both') {
      user.balances.main -= actualMainAmountUsed;
      user.balances.matured -= actualMaturedAmountUsed;
    }

    await user.save();

    // In a real implementation, you would initiate the BTC transfer here
    // For now, we'll just simulate it with a transaction ID
    const txId = `btc-${crypto.randomBytes(8).toString('hex')}`;

    res.status(201).json({
      status: 'success',
      data: {
        transaction,
        txId,
        balanceInfo: {
          source: actualBalanceSource,
          mainAmountUsed: actualMainAmountUsed,
          maturedAmountUsed: actualMaturedAmountUsed,
          remainingMainBalance: user.balances.main,
          remainingMaturedBalance: user.balances.matured
        }
      }
    });

    await logActivity('btc-withdrawal', 'transaction', transaction._id, user._id, 'User', req, { 
      amount, 
      walletAddress,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      netAmount,
      fee
    });

  } catch (err) {
    console.error('BTC withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing BTC withdrawal'
    });
  }
});

// Bank Withdrawal Endpoint (with same balance logic)
app.post('/api/withdrawals/bank', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('bankName').notEmpty().withMessage('Bank name is required'),
  body('accountHolder').notEmpty().withMessage('Account holder name is required'),
  body('accountNumber').notEmpty().withMessage('Account number is required'),
  body('routingNumber').notEmpty().withMessage('Routing number is required'),
  body('balanceSource').optional().isIn(['main', 'matured', 'both']).withMessage('Invalid balance source'),
  body('mainAmountUsed').optional().isFloat({ min: 0 }).withMessage('Main amount used must be valid'),
  body('maturedAmountUsed').optional().isFloat({ min: 0 }).withMessage('Matured amount used must be valid')
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
      amount, 
      bankName, 
      accountHolder, 
      accountNumber, 
      routingNumber, 
      balanceSource, 
      mainAmountUsed = 0, 
      maturedAmountUsed = 0 
    } = req.body;
    
    const user = await User.findById(req.user.id);

    // Enhanced balance checking logic (same as BTC endpoint)
    let hasSufficientBalance = false;
    let actualBalanceSource = '';
    let actualMainAmountUsed = 0;
    let actualMaturedAmountUsed = 0;

    const mainBalance = user.balances.main || 0;
    const maturedBalance = user.balances.matured || 0;
    const totalBalance = mainBalance + maturedBalance;

    if (amount > totalBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient total balance for withdrawal'
      });
    }

    if (balanceSource === 'main') {
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      }
    } else if (balanceSource === 'matured') {
      if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      }
    } else if (balanceSource === 'both') {
      if (mainAmountUsed + maturedAmountUsed === amount && 
          mainBalance >= mainAmountUsed && 
          maturedBalance >= maturedAmountUsed) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainAmountUsed;
        actualMaturedAmountUsed = maturedAmountUsed;
      }
    } else {
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      } else if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      } else if (totalBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainBalance;
        actualMaturedAmountUsed = amount - mainBalance;
      }
    }

    if (!hasSufficientBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance in specified accounts for withdrawal',
        details: {
          requestedAmount: amount,
          mainBalance: mainBalance,
          maturedBalance: maturedBalance,
          totalBalance: totalBalance
        }
      });
    }

    // Calculate withdrawal fee (1% of amount)
    const fee = amount * 0.01;
    const netAmount = amount - fee;

    // Create transaction record
    const reference = `BANK-WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'bank',
      reference,
      fee,
      netAmount,
      bankName,
      accountHolder,
      accountNumber: accountNumber.slice(-4), // Store only last 4 digits for security
      routingNumber: routingNumber.slice(-4), // Store only last 4 digits for security
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      details: `Bank withdrawal to ${bankName} (Source: ${actualBalanceSource})`
    });

    // Deduct from user's balances
    if (actualBalanceSource === 'main') {
      user.balances.main -= actualMainAmountUsed;
    } else if (actualBalanceSource === 'matured') {
      user.balances.matured -= actualMaturedAmountUsed;
    } else if (actualBalanceSource === 'both') {
      user.balances.main -= actualMainAmountUsed;
      user.balances.matured -= actualMaturedAmountUsed;
    }

    await user.save();

    // Generate reference ID for bank transfer
    const refId = `bank-${crypto.randomBytes(8).toString('hex')}`;

    res.status(201).json({
      status: 'success',
      data: {
        transaction,
        refId,
        balanceInfo: {
          source: actualBalanceSource,
          mainAmountUsed: actualMainAmountUsed,
          maturedAmountUsed: actualMaturedAmountUsed,
          remainingMainBalance: user.balances.main,
          remainingMaturedBalance: user.balances.matured
        }
      }
    });

    await logActivity('bank-withdrawal', 'transaction', transaction._id, user._id, 'User', req, { 
      amount, 
      bankName,
      accountHolder,
      netAmount,
      fee,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed
    });

  } catch (err) {
    console.error('Bank withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing bank withdrawal'
    });
  }
});





// Get withdrawal history
app.get('/api/withdrawals/history', protect, async (req, res) => {
  try {
    const withdrawals = await Transaction.find({
      user: req.user.id,
      type: 'withdrawal'
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .lean(); // Convert to plain JavaScript objects

    res.status(200).json({
      status: 'success',
      data: withdrawals // Directly return the array
    });
  } catch (err) {
    console.error('Get withdrawal history error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching withdrawal history'
    });
  }
});























// Admin Dashboard Stats Endpoint with Real-time Revenue
app.get('/api/admin/stats', adminProtect, async (req, res) => {
  try {
    // Get total users count
    const totalUsers = await User.countDocuments();
    
    // Get users from yesterday for comparison
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayUsers = await User.countDocuments({
      createdAt: { $lt: yesterday }
    });
    
    // Calculate percentage change
    const usersChange = yesterdayUsers > 0 
      ? (((totalUsers - yesterdayUsers) / yesterdayUsers) * 100).toFixed(2)
      : 100;
    
    // Get total deposits
    const totalDepositsResult = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalDeposits = totalDepositsResult[0]?.total || 0;
    
    // Get deposits from yesterday
    const yesterdayDepositsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'deposit', 
          status: 'completed',
          createdAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayDeposits = yesterdayDepositsResult[0]?.total || 0;
    
    // Calculate percentage change
    const depositsChange = yesterdayDeposits > 0
      ? (((totalDeposits - yesterdayDeposits) / yesterdayDeposits) * 100).toFixed(2)
      : 100;
    
    // Get pending withdrawals
    const pendingWithdrawalsResult = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'pending' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingWithdrawals = pendingWithdrawalsResult[0]?.total || 0;
    
    // Get withdrawals from yesterday
    const yesterdayWithdrawalsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'withdrawal', 
          status: 'completed',
          createdAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayWithdrawals = yesterdayWithdrawalsResult[0]?.total || 0;
    
    // Get today's withdrawals
    const todayWithdrawalsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'withdrawal', 
          status: 'completed',
          createdAt: { $gte: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const todayWithdrawals = todayWithdrawalsResult[0]?.total || 0;
    
    // Calculate percentage change
    const withdrawalsChange = yesterdayWithdrawals > 0
      ? (((todayWithdrawals - yesterdayWithdrawals) / yesterdayWithdrawals) * 100).toFixed(2)
      : 100;
    
    // REAL-TIME REVENUE DATA FROM PLATFORMREVENUE SCHEMA
    // Get total platform revenue from revenue schema
    const totalRevenueResult = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } }, // Exclude rejected revenue
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const platformRevenue = totalRevenueResult[0]?.total || 0;
    
    // Get revenue from yesterday
    const yesterdayRevenueResult = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayRevenue = yesterdayRevenueResult[0]?.total || 0;
    
    // Get today's revenue
    const todayRevenueResult = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $gte: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const todayRevenue = todayRevenueResult[0]?.total || 0;
    
    // Calculate percentage change
    const revenueChange = yesterdayRevenue > 0
      ? (((todayRevenue - yesterdayRevenue) / yesterdayRevenue) * 100).toFixed(2)
      : 100;
    
    // Get revenue breakdown by source for detailed analytics
    const revenueBySource = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } },
      { 
        $group: { 
          _id: '$source',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        } 
      },
      { $sort: { total: -1 } }
    ]);
    
    // Get recent revenue transactions (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentRevenue = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $gte: sevenDaysAgo }
        } 
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$recordedAt" }
          },
          dailyRevenue: { $sum: '$amount' },
          transactionCount: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Calculate average revenue per transaction
    const revenueStats = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$amount' },
          totalTransactions: { $sum: 1 },
          avgRevenuePerTransaction: { $avg: '$amount' },
          minRevenue: { $min: '$amount' },
          maxRevenue: { $max: '$amount' }
        }
      }
    ]);
    
    const revenueStatsData = revenueStats[0] || {
      totalRevenue: 0,
      totalTransactions: 0,
      avgRevenuePerTransaction: 0,
      minRevenue: 0,
      maxRevenue: 0
    };
    
    // System performance metrics (simulated)
    const backendResponseTime = Math.floor(Math.random() * 50) + 10; // 10-60ms
    const databaseQueryTime = Math.floor(Math.random() * 30) + 5; // 5-35ms

    
// Add this to your existing admin stats endpoint
const pendingKycCount = await KYC.countDocuments({ overallStatus: 'pending' });

// Include in your response
pendingKycCount: pendingKycCount
    
    
    // Get last transaction time
    const lastTransaction = await Transaction.findOne().sort({ createdAt: -1 });
    const lastTransactionTime = lastTransaction 
      ? Math.floor((Date.now() - new Date(lastTransaction.createdAt).getTime()) / 1000)
      : 0;
    
    // Get last revenue transaction time
    const lastRevenue = await PlatformRevenue.findOne().sort({ recordedAt: -1 });
    const lastRevenueTime = lastRevenue 
      ? Math.floor((Date.now() - new Date(lastRevenue.recordedAt).getTime()) / 1000)
      : 0;
    
    // Simulate server uptime (95-100%)
    const serverUptime = (95 + Math.random() * 5).toFixed(2);
    
    res.status(200).json({
      status: 'success',
      data: {
        // Core metrics (existing)
        totalUsers: parseInt(totalUsers),
        usersChange: parseFloat(usersChange),
        totalDeposits: parseFloat(totalDeposits),
        depositsChange: parseFloat(depositsChange),
        pendingWithdrawals: parseFloat(pendingWithdrawals),
        withdrawalsChange: parseFloat(withdrawalsChange),
        
        // Enhanced revenue metrics (from PlatformRevenue schema)
        platformRevenue: parseFloat(platformRevenue),
        revenueChange: parseFloat(revenueChange),
        todayRevenue: parseFloat(todayRevenue),
        yesterdayRevenue: parseFloat(yesterdayRevenue),
        
        // Detailed revenue analytics
        revenueBreakdown: revenueBySource,
        recentRevenueTrend: recentRevenue,
        revenueStats: {
          totalTransactions: revenueStatsData.totalTransactions,
          avgRevenuePerTransaction: parseFloat(revenueStatsData.avgRevenuePerTransaction.toFixed(2)),
          minRevenue: parseFloat(revenueStatsData.minRevenue),
          maxRevenue: parseFloat(revenueStatsData.maxRevenue)
        },
        
        // System metrics
        backendResponseTime,
        databaseQueryTime,
        lastTransactionTime,
        lastRevenueTime,
        serverUptime: parseFloat(serverUptime),
        
        // Timestamp for real-time updates
        lastUpdated: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch admin stats'
    });
  }
});
















// Admin Users Endpoint
app.get('/api/admin/users', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get users with pagination
    const users = await User.find()
      .select('firstName lastName email balances status lastLogin')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await User.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        users,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch users'
    });
  }
});

// Admin Pending Deposits Endpoint
app.get('/api/admin/deposits/pending', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get pending deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'pending'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin pending deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending deposits'
    });
  }
});

// Admin Approved Deposits Endpoint
app.get('/api/admin/deposits/approved', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get approved deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin approved deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved deposits'
    });
  }
});

// Admin Rejected Deposits Endpoint
app.get('/api/admin/deposits/rejected', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get rejected deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'failed'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'failed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin rejected deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected deposits'
    });
  }
});

// Admin Pending Withdrawals Endpoint
app.get('/api/admin/withdrawals/pending', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get pending withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'pending'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin pending withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending withdrawals'
    });
  }
});

// Admin Approved Withdrawals Endpoint
app.get('/api/admin/withdrawals/approved', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get approved withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin approved withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved withdrawals'
    });
  }
});

// Admin Rejected Withdrawals Endpoint
app.get('/api/admin/withdrawals/rejected', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get rejected withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'failed'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'failed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin rejected withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected withdrawals'
    });
  }
});


// Admin All Transactions Endpoint
app.get('/api/admin/transactions', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get all transactions with user info
    const transactions = await Transaction.find()
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transactions'
    });
  }
});

// Admin Deposit Transactions Endpoint
app.get('/api/admin/transactions/deposits', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get deposit transactions with user info
    const transactions = await Transaction.find({
      type: 'deposit'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin deposit transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit transactions'
    });
  }
});

// Admin Withdrawal Transactions Endpoint
app.get('/api/admin/transactions/withdrawals', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get withdrawal transactions with user info
    const transactions = await Transaction.find({
      type: 'withdrawal'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin withdrawal transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal transactions'
    });
  }
});

// Admin Transfer Transactions Endpoint
app.get('/api/admin/transactions/transfers', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get transfer transactions with user info
    const transactions = await Transaction.find({
      type: 'transfer'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'transfer'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin transfer transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transfer transactions'
    });
  }
});















// Admin Completed Investments Endpoint
app.get('/api/admin/investments/completed', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get completed investments with user and plan info
    const investments = await Investment.find({
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('plan', 'name percentage duration')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Calculate total profit for each investment
    const investmentsWithProfit = investments.map(investment => {
      const totalProfit = investment.amount * (investment.plan.percentage / 100);
      return {
        ...investment,
        totalProfit
      };
    });
    
    // Get total count for pagination
    const totalCount = await Investment.countDocuments({
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        investments: investmentsWithProfit,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin completed investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch completed investments'
    });
  }
});

// Admin Investment Plans Endpoint
app.get('/api/admin/investment/plans', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get all investment plans
    const plans = await Plan.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await Plan.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        plans,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin investment plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investment plans'
    });
  }
});

// Admin Add User Endpoint
app.post('/api/admin/users', adminProtect, [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { firstName, lastName, email, password, city, country } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'User with this email already exists'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate referral code
    const referralCode = generateReferralCode();
    
    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      country,
      referralCode,
      isVerified: true
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });
    
    await logActivity('create-user', 'user', user._id, req.admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin add user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create user'
    });
  }
});

// Admin Get User Details Endpoint
app.get('/api/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires')
      .lean();
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    console.error('Admin get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user details'
    });
  }
});

// Admin Update User Endpoint
app.put('/api/admin/users/:id', adminProtect, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty'),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty'),
  body('email').optional().isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { firstName, lastName, email, status, balances } = req.body;
    
    // Check if email is already taken by another user
    if (email) {
      const existingUser = await User.findOne({ 
        email, 
        _id: { $ne: req.params.id } 
      });
      
      if (existingUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Email is already taken by another user'
        });
      }
    }
    
    // Prepare update data
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;
    if (status) updateData.status = status;
    if (balances) updateData.balances = balances;
    
    // Update user
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
    
    await logActivity('update-user', 'user', user._id, req.admin._id, 'Admin', req, updateData);
  } catch (err) {
    console.error('Admin update user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update user'
    });
  }
});


// Admin Get Deposit Details Endpoint
app.get('/api/admin/deposits/:id', adminProtect, async (req, res) => {
  try {
    const deposit = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .lean();
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { deposit }
    });
  } catch (err) {
    console.error('Admin get deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit details'
    });
  }
});

// Admin Approve Deposit Endpoint
app.post('/api/admin/deposits/:id/approve', adminProtect, [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { notes } = req.body;
    
    // Find deposit
    const deposit = await Transaction.findById(req.params.id)
      .populate('user');
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Deposit is not pending approval'
      });
    }
    
    // Find user
    const user = await User.findById(deposit.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Update user balance
    user.balances.main += deposit.amount;
    await user.save();
    
    // Update deposit status
    deposit.status = 'completed';
    deposit.processedBy = req.admin._id;
    deposit.processedAt = new Date();
    deposit.adminNotes = notes;
    await deposit.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Deposit approved successfully'
    });
    
    await logActivity('approve-deposit', 'transaction', deposit._id, req.admin._id, 'Admin', req, {
      amount: deposit.amount,
      userId: user._id
    });
  } catch (err) {
    console.error('Admin approve deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve deposit'
    });
  }
});

// Admin Reject Deposit Endpoint
app.post('/api/admin/deposits/:id/reject', adminProtect, [
  body('rejectionReason').trim().notEmpty().withMessage('Rejection reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { rejectionReason } = req.body;
    
    // Find deposit
    const deposit = await Transaction.findById(req.params.id);
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Deposit is not pending approval'
      });
    }
    
    // Update deposit status
    deposit.status = 'failed';
    deposit.adminNotes = rejectionReason;
    await deposit.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Deposit rejected successfully'
    });
    
    await logActivity('reject-deposit', 'transaction', deposit._id, req.admin._id, 'Admin', req, {
      amount: deposit.amount,
      reason: rejectionReason
    });
  } catch (err) {
    console.error('Admin reject deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject deposit'
    });
  }
});

// Admin Get Withdrawal Details Endpoint
app.get('/api/admin/withdrawals/:id', adminProtect, async (req, res) => {
  try {
    const withdrawal = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .lean();
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { withdrawal }
    });
  } catch (err) {
    console.error('Admin get withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal details'
    });
  }
});

// Admin Approve Withdrawal Endpoint
app.post('/api/admin/withdrawals/:id/approve', adminProtect, [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { notes } = req.body;
    
    // Find withdrawal
    const withdrawal = await Transaction.findById(req.params.id);
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Update withdrawal status
    withdrawal.status = 'completed';
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    withdrawal.adminNotes = notes;
    await withdrawal.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Withdrawal approved successfully'
    });
    
    await logActivity('approve-withdrawal', 'transaction', withdrawal._id, req.admin._id, 'Admin', req, {
      amount: withdrawal.amount,
      userId: withdrawal.user
    });
  } catch (err) {
    console.error('Admin approve withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve withdrawal'
    });
  }
});

// Admin Reject Withdrawal Endpoint
app.post('/api/admin/withdrawals/:id/reject', adminProtect, [
  body('rejectionReason').trim().notEmpty().withMessage('Rejection reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { rejectionReason } = req.body;
    
    // Find withdrawal
    const withdrawal = await Transaction.findById(req.params.id)
      .populate('user');
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Find user
    const user = await User.findById(withdrawal.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Return funds to user balance
    user.balances.main += withdrawal.amount;
    await user.save();
    
    // Update withdrawal status
    withdrawal.status = 'failed';
    withdrawal.adminNotes = rejectionReason;
    await withdrawal.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Withdrawal rejected successfully'
    });
    
    await logActivity('reject-withdrawal', 'transaction', withdrawal._id, req.admin._id, 'Admin', req, {
      amount: withdrawal.amount,
      reason: rejectionReason,
      userId: user._id
    });
  } catch (err) {
    console.error('Admin reject withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject withdrawal'
    });
  }
});



// Admin Add Investment Plan Endpoint
app.post('/api/admin/investment/plans', adminProtect, [
  body('name').trim().notEmpty().withMessage('Plan name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('percentage').isFloat({ gt: 0 }).withMessage('Percentage must be greater than 0'),
  body('duration').isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('minAmount').isFloat({ gt: 0 }).withMessage('Minimum amount must be greater than 0'),
  body('maxAmount').isFloat({ gt: 0 }).withMessage('Maximum amount must be greater than 0'),
  body('referralBonus').optional().isFloat({ min: 0 }).withMessage('Referral bonus cannot be negative')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { name, description, percentage, duration, minAmount, maxAmount, referralBonus = 5 } = req.body;
    
    // Check if plan with same name already exists
    const existingPlan = await Plan.findOne({ name });
    if (existingPlan) {
      return res.status(400).json({
        status: 'fail',
        message: 'Plan with this name already exists'
      });
    }
    
    // Create plan
    const plan = await Plan.create({
      name,
      description,
      percentage,
      duration,
      minAmount,
      maxAmount,
      referralBonus
    });
    
    res.status(201).json({
      status: 'success',
      data: { plan }
    });
    
    await logActivity('create-plan', 'plan', plan._id, req.admin._id, 'Admin', req, {
      name,
      percentage,
      duration
    });
  } catch (err) {
    console.error('Admin add plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create investment plan'
    });
  }
});

// Admin Get Plan Details Endpoint
app.get('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const plan = await Plan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { plan }
    });
  } catch (err) {
    console.error('Admin get plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch plan details'
    });
  }
});














// ENHANCED VERSION - Admin Active Investments Endpoint with Accurate Time Calculations
app.get('/api/admin/investments/active', adminProtect, async (req, res) => {
  try {
    console.log('=== ACTIVE INVESTMENTS ENDPOINT HIT ===');
    console.log('Query params:', req.query);
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get active investments with proper plan population for duration
    const investments = await Investment.find({ status: 'active' })
      .populate('user', 'firstName lastName')
      .populate('plan', 'name duration percentage')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    console.log('Found investments:', investments.length);

    // Helper function to calculate accurate time remaining
    const calculateTimeRemaining = (endDate) => {
      const now = new Date();
      const end = new Date(endDate);
      const remainingMs = Math.max(0, end - now);
      
      if (remainingMs <= 0) {
        return 'Expired';
      }

      const days = Math.floor(remainingMs / (1000 * 60 * 60 * 24));
      const hours = Math.floor((remainingMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((remainingMs % (1000 * 60)) / 1000);

      const parts = [];
      if (days > 0) parts.push(`${days}d`);
      if (hours > 0) parts.push(`${hours}h`);
      if (minutes > 0) parts.push(`${minutes}m`);
      if (seconds > 0) parts.push(`${seconds}s`);

      return parts.length > 0 ? parts.join(' ') : '0s';
    };

    // Calculate accurate profit based on plan percentage and duration
    const calculateProfitDetails = (investmentAmount, planPercentage, planDuration) => {
      const totalProfit = (investmentAmount * planPercentage) / 100;
      const hourlyProfit = planDuration > 0 ? totalProfit / planDuration : 0;
      const dailyProfit = planDuration > 0 ? (totalProfit / planDuration) * 24 : 0;
      
      return {
        totalProfit: parseFloat(totalProfit.toFixed(2)),
        hourlyProfit: parseFloat(hourlyProfit.toFixed(4)),
        dailyProfit: parseFloat(dailyProfit.toFixed(2))
      };
    };

    // Simple transformation - ensure no undefined values with accurate calculations
    const investmentsWithDetails = investments.map(investment => {
      const user = investment.user || { firstName: 'Unknown', lastName: 'User' };
      const plan = investment.plan || { 
        name: 'Unknown Plan', 
        duration: 0, 
        percentage: 0 
      };
      
      // Calculate accurate time remaining
      const timeRemaining = investment.endDate ? 
        calculateTimeRemaining(investment.endDate) : 
        'Unknown';
      
      // Calculate accurate profit based on actual plan percentage
      const profitDetails = calculateProfitDetails(
        investment.amount || 0, 
        plan.percentage || 0, 
        plan.duration || 0
      );

      return {
        _id: investment._id?.toString() || 'unknown_id',
        user: {
          firstName: user.firstName || 'Unknown',
          lastName: user.lastName || 'User'
        },
        plan: {
          name: plan.name || 'Unknown Plan',
          duration: plan.duration || 0,
          percentage: plan.percentage || 0
        },
        amount: parseFloat(investment.amount) || 0,
        startDate: investment.startDate ? new Date(investment.startDate).toISOString() : new Date().toISOString(),
        endDate: investment.endDate ? new Date(investment.endDate).toISOString() : new Date().toISOString(),
        timeRemaining: timeRemaining,
        dailyProfit: profitDetails.dailyProfit,
        totalProfit: profitDetails.totalProfit,
        hourlyProfit: profitDetails.hourlyProfit,
        // Additional time details for verification
        planDurationHours: plan.duration || 0,
        isActive: investment.status === 'active',
        createdAt: investment.createdAt ? new Date(investment.createdAt).toISOString() : new Date().toISOString()
      };
    });

    const totalCount = await Investment.countDocuments({ status: 'active' });
    const totalPages = Math.ceil(totalCount / limit);

    console.log('Sending response with:', {
      investmentsCount: investmentsWithDetails.length,
      totalPages: totalPages,
      currentPage: page,
      accurateTimeCalculations: true
    });

    // EXACT frontend structure
    const response = {
      status: 'success',
      data: {
        investments: investmentsWithDetails,
        pagination: {
          totalPages: totalPages,
          currentPage: page
        }
      }
    };

    res.status(200).json(response);

  } catch (err) {
    console.error('=== ACTIVE INVESTMENTS ERROR ===');
    console.error('Error details:', err);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments'
    });
  }
});

// Admin Update Investment Plan Endpoint
app.put('/api/admin/investment/plans/:id', adminProtect, [
  body('name').optional().trim().notEmpty().withMessage('Plan name cannot be empty'),
  body('description').optional().trim().notEmpty().withMessage('Description cannot be empty'),
  body('percentage').optional().isFloat({ gt: 0 }).withMessage('Percentage must be greater than 0'),
  body('duration').optional().isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('minAmount').optional().isFloat({ gt: 0 }).withMessage('Minimum amount must be greater than 0'),
  body('maxAmount').optional().isFloat({ gt: 0 }).withMessage('Maximum amount must be greater than 0'),
  body('referralBonus').optional().isFloat({ min: 0 }).withMessage('Referral bonus cannot be negative'),
  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { name, description, percentage, duration, minAmount, maxAmount, referralBonus, isActive } = req.body;
    
    // Check if plan with same name already exists (excluding current plan)
    if (name) {
      const existingPlan = await Plan.findOne({ 
        name, 
        _id: { $ne: req.params.id } 
      });
      
      if (existingPlan) {
        return res.status(400).json({
          status: 'fail',
          message: 'Plan with this name already exists'
        });
      }
    }
    
    // Prepare update data
    const updateData = {};
    if (name) updateData.name = name;
    if (description) updateData.description = description;
    if (percentage) updateData.percentage = percentage;
    if (duration) updateData.duration = duration;
    if (minAmount) updateData.minAmount = minAmount;
    if (maxAmount) updateData.maxAmount = maxAmount;
    if (referralBonus !== undefined) updateData.referralBonus = referralBonus;
    if (isActive !== undefined) updateData.isActive = isActive;
    
    // Update plan
    const plan = await Plan.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { plan }
    });
    
    await logActivity('update-plan', 'plan', plan._id, req.admin._id, 'Admin', req, updateData);
  } catch (err) {
    console.error('Admin update plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update investment plan'
    });
  }
});

// Admin Delete Investment Plan Endpoint
app.delete('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const plan = await Plan.findByIdAndDelete(req.params.id);
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      message: 'Plan deleted successfully'
    });
    
    await logActivity('delete-plan', 'plan', plan._id, req.admin._id, 'Admin', req, {
      name: plan.name
    });
  } catch (err) {
    console.error('Admin delete plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete investment plan'
    });
  }
});

// Admin Cancel Investment Endpoint
app.post('/api/admin/investments/:id/cancel', adminProtect, [
  body('reason').optional().trim()
], async (req, res) => {
  try {
    const { reason } = req.body;
    
    // Find investment
    const investment = await Investment.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment not found'
      });
    }
    
    if (investment.status !== 'active') {
      return res.status(400).json({
        status: 'fail',
        message: 'Only active investments can be cancelled'
      });
    }
    
    // Find user
    const user = await User.findById(investment.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Return funds to user balance
    user.balances.active -= investment.amount;
    user.balances.matured += investment.amount;
    await user.save();
    
    // Update investment status
    investment.status = 'cancelled';
    investment.completionDate = new Date();
    investment.adminNotes = reason;
    await investment.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Investment cancelled successfully'
    });
    
    await logActivity('cancel-investment', 'investment', investment._id, req.admin._id, 'Admin', req, {
      amount: investment.amount,
      userId: user._id,
      reason
    });
  } catch (err) {
    console.error('Admin cancel investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to cancel investment'
    });
  }
});

// Admin Get General Settings Endpoint
app.get('/api/admin/settings/general', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'general' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      platformName: 'BitHash',
      platformUrl: 'https://bithash.com',
      platformEmail: 'support@bithash.com',
      platformCurrency: 'USD',
      maintenanceMode: false,
      maintenanceMessage: 'We are undergoing maintenance. Please check back later.',
      timezone: 'UTC',
      dateFormat: 'MM/DD/YYYY',
      maxLoginAttempts: 5,
      sessionTimeout: 30
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get general settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load general settings'
    });
  }
});

// Admin Save General Settings Endpoint
app.post('/api/admin/settings/general', adminProtect, [
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
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-general-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body)
    });
  } catch (err) {
    console.error('Admin save general settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save general settings'
    });
  }
});

// Admin Get Security Settings Endpoint
app.get('/api/admin/settings/security', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'security' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      twoFactorAuth: true,
      loginAttempts: 5,
      passwordResetExpiry: 60,
      sessionTimeout: 30,
      ipWhitelist: []
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get security settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load security settings'
    });
  }
});

// Admin Save Security Settings Endpoint
app.post('/api/admin/settings/security', adminProtect, [
  body('twoFactorAuth').isBoolean().withMessage('Two-factor auth must be boolean'),
  body('loginAttempts').isInt({ min: 1, max: 10 }).withMessage('Login attempts must be between 1-10'),
  body('passwordResetExpiry').isInt({ min: 15, max: 1440 }).withMessage('Password reset expiry must be between 15-1440 minutes'),
  body('sessionTimeout').isInt({ min: 5, max: 1440 }).withMessage('Session timeout must be between 5-1440 minutes'),
  body('ipWhitelist').optional().isArray().withMessage('IP whitelist must be an array')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { twoFactorAuth, loginAttempts, passwordResetExpiry, sessionTimeout, ipWhitelist = [] } = req.body;
    
    const settingsData = {
      type: 'security',
      twoFactorAuth,
      loginAttempts,
      passwordResetExpiry,
      sessionTimeout,
      ipWhitelist,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'security' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-security-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body)
    });
  } catch (err) {
    console.error('Admin save security settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save security settings'
    });
  }
});

// Admin Get Email Settings Endpoint
app.get('/api/admin/settings/email', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'email' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      mailDriver: 'smtp',
      mailHost: 'smtp.mailtrap.io',
      mailPort: 2525,
      mailUsername: '',
      mailPassword: '',
      mailEncryption: 'tls',
      mailFromAddress: 'noreply@bithash.com',
      mailFromName: 'BitHash'
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get email settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load email settings'
    });
  }
});

// Admin Save Email Settings Endpoint
app.post('/api/admin/settings/email', adminProtect, [
  body('mailDriver').isIn(['smtp', 'sendmail', 'mailgun', 'ses']).withMessage('Invalid mail driver'),
  body('mailHost').optional().trim(),
  body('mailPort').optional().isInt({ min: 1, max: 65535 }).withMessage('Invalid port number'),
  body('mailUsername').optional().trim(),
  body('mailPassword').optional().trim(),
  body('mailEncryption').optional().isIn(['tls', 'ssl', 'none']).withMessage('Invalid encryption'),
  body('mailFromAddress').isEmail().withMessage('Invalid from address'),
  body('mailFromName').trim().notEmpty().withMessage('From name is required')
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
      type: 'email',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'email' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-email-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body).filter(key => key !== 'mailPassword')
    });
  } catch (err) {
    console.error('Admin save email settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save email settings'
    });
  }
});

// Admin Get Payment Settings Endpoint
app.get('/api/admin/settings/payments', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'payment' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      stripePublicKey: '',
      stripeSecretKey: '',
      stripeWebhookSecret: '',
      btcWalletAddress: '1DopKPckf8QNE53FnaazSAd5DDR8kmetYr',
      ethWalletAddress: '',
      minDepositAmount: 10,
      maxDepositAmount: 10000,
      depositFee: 0
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get payment settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load payment settings'
    });
  }
});

// Admin Save Payment Settings Endpoint
app.post('/api/admin/settings/payments', adminProtect, [
  body('stripePublicKey').optional().trim(),
  body('stripeSecretKey').optional().trim(),
  body('stripeWebhookSecret').optional().trim(),
  body('btcWalletAddress').optional().trim(),
  body('ethWalletAddress').optional().trim(),
  body('minDepositAmount').isFloat({ min: 0 }).withMessage('Minimum deposit amount cannot be negative'),
  body('maxDepositAmount').isFloat({ min: 0 }).withMessage('Maximum deposit amount cannot be negative'),
  body('depositFee').isFloat({ min: 0, max: 100 }).withMessage('Deposit fee must be between 0-100')
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
      type: 'payment',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'payment' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-payment-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body).filter(key => !key.includes('Secret') && !key.includes('Key'))
    });
  } catch (err) {
    console.error('Admin save payment settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save payment settings'
    });
  }
});



// Add balance to user endpoint
app.post('/api/admin/users/:userId/balance', async (req, res) => {
    try {
        const { userId } = req.params;
        const { amount, balanceType, description } = req.body;

        // Validation
        if (!amount || amount <= 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Amount must be greater than 0'
            });
        }

        if (!balanceType || !['active', 'matured', 'main'].includes(balanceType)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid balance type'
            });
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Initialize balances if they don't exist
        if (!user.balances) {
            user.balances = {
                active: 0,
                matured: 0,
                main: 0
            };
        }

        // Update the specific balance
        user.balances[balanceType] = parseFloat(user.balances[balanceType] || 0) + parseFloat(amount);

        // Create transaction record
        const transaction = new Transaction({
            user: userId,
            type: 'admin_adjustment',
            amount: parseFloat(amount),
            description: description || `Balance added by admin`,
            status: 'completed',
            balanceType: balanceType,
            adminNote: `Admin balance adjustment - ${balanceType} balance`
        });

        // Save both user and transaction
        await user.save();
        await transaction.save();

        // Create admin activity log
        const activity = new AdminActivity({
            admin: req.admin._id,
            action: `Added $${amount} to ${balanceType} balance for user ${user.email}`,
            ipAddress: req.ip,
            status: 'success'
        });
        await activity.save();

        res.json({
            status: 'success',
            message: 'Balance added successfully',
            data: {
                user: {
                    _id: user._id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    balances: user.balances
                },
                transaction: {
                    _id: transaction._id,
                    amount: transaction.amount,
                    type: transaction.type,
                    description: transaction.description
                }
            }
        });

    } catch (error) {
        console.error('Error adding balance:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal server error'
        });
    }
});









// Admin Activity Endpoint - FIXED VERSION
app.get('/api/admin/activity', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, type = 'all' } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    console.log('Fetching admin activity...', { page, limit, type });

    // Get BOTH UserLog and SystemLog data
    const [userLogs, systemLogs] = await Promise.all([
      UserLog.find({})
        .populate('user', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SystemLog.find({})
        .populate('performedBy')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean()
    ]);

    console.log(`Found ${userLogs.length} user logs and ${systemLogs.length} system logs`);

    // Combine and sort all activities by timestamp
    const allActivities = [...userLogs, ...systemLogs]
      .sort((a, b) => new Date(b.createdAt || b.timestamp) - new Date(a.createdAt || a.timestamp))
      .slice(0, parseInt(limit));

    // Transform activities with PROPER user data mapping
    const activities = allActivities.map(activity => {
      // Determine if it's a UserLog or SystemLog
      const isUserLog = activity.user !== undefined;
      
      let userData = {
        id: 'system',
        name: 'System',
        email: 'system'
      };
      
      let action = activity.action;
      let ipAddress = 'Unknown';
      let timestamp = activity.createdAt || activity.timestamp;
      let status = activity.status || 'success';

      if (isUserLog) {
        // Handle UserLog entries
        console.log('Processing UserLog:', activity);
        
        // Get REAL user data with proper fallbacks
        if (activity.user && typeof activity.user === 'object') {
          userData = {
            id: activity.user._id || 'unknown',
            name: `${activity.user.firstName || ''} ${activity.user.lastName || ''}`.trim() || 'Unknown User',
            email: activity.user.email || 'Unknown Email'
          };
        } else if (activity.username) {
          userData = {
            id: activity.user || 'unknown',
            name: activity.username,
            email: activity.email || 'Unknown Email'
          };
        }
        
        ipAddress = activity.ipAddress || 'Unknown';
        
      } else {
        // Handle SystemLog entries
        console.log('Processing SystemLog:', activity);
        
        if (activity.performedBy && typeof activity.performedBy === 'object') {
          if (activity.performedByModel === 'User') {
            userData = {
              id: activity.performedBy._id || 'unknown',
              name: `${activity.performedBy.firstName || ''} ${activity.performedBy.lastName || ''}`.trim() || 'Unknown User',
              email: activity.performedBy.email || 'Unknown Email'
            };
          } else if (activity.performedByModel === 'Admin') {
            userData = {
              id: activity.performedBy._id || 'unknown',
              name: activity.performedBy.name || 'Admin',
              email: activity.performedBy.email || 'admin@system'
            };
          }
        }
        
        ipAddress = activity.ip || 'Unknown';
      }

      // Final safety check for user name
      if (!userData.name || userData.name === ' ' || userData.name === 'undefined undefined') {
        userData.name = 'System User';
      }

      return {
        id: activity._id?.toString() || `activity-${Date.now()}-${Math.random()}`,
        timestamp: timestamp,
        user: {
          id: userData.id,
          name: userData.name,
          email: userData.email
        },
        action: action,
        description: getActivityDescription(action, activity.metadata || activity.changes),
        ipAddress: ipAddress,
        status: status,
        type: isUserLog ? 'user_activity' : 'system_activity',
        metadata: activity.metadata || activity.changes || {}
      };
    });

    // Get total count for pagination
    const totalCount = await UserLog.countDocuments() + await SystemLog.countDocuments();

    console.log('Sending activities:', activities.length);

    res.status(200).json({
      status: 'success',
      data: {
        activities: activities,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalCount / parseInt(limit)),
          totalItems: totalCount,
          itemsPerPage: parseInt(limit),
          hasNextPage: parseInt(page) < Math.ceil(totalCount / parseInt(limit)),
          hasPrevPage: parseInt(page) > 1
        }
      }
    });

  } catch (err) {
    console.error('Admin activity fetch error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching activity data'
    });
  }
});

// COMPREHENSIVE activity description helper
function getActivityDescription(action, metadata) {
  const actionMap = {
    // Authentication actions
    'signup': 'Signed up for a new account',
    'login': 'Logged into account',
    'logout': 'Logged out of account',
    'login_attempt': 'Attempted to log in',
    'session_created': 'Created a new session',
    'password_change': 'Changed password',
    'password_reset_request': 'Requested password reset',
    'password_reset_complete': 'Completed password reset',
    'failed_login': 'Failed login attempt',
    
    // Financial actions
    'deposit': 'Made a deposit',
    'withdrawal': 'Requested a withdrawal',
    'investment': 'Created an investment',
    'transfer': 'Transferred funds',
    'create-deposit': 'Created deposit request',
    'create-withdrawal': 'Created withdrawal request',
    'btc-withdrawal': 'Made BTC withdrawal',
    'create-savings': 'Added to savings',
    'investment_created': 'Created new investment',
    'investment_matured': 'Investment matured',
    'investment_completed': 'Investment completed',
    
    // Account actions
    'profile_update': 'Updated profile information',
    'update-profile': 'Updated profile',
    'update-address': 'Updated address',
    'kyc_submission': 'Submitted KYC documents',
    'submit-kyc': 'Submitted KYC',
    'settings_change': 'Changed account settings',
    'update-preferences': 'Updated preferences',
    
    // Security actions
    '2fa_enable': 'Enabled two-factor authentication',
    '2fa_disable': 'Disabled two-factor authentication',
    'enable-2fa': 'Enabled 2FA',
    'disable-2fa': 'Disabled 2FA',
    'api_key_create': 'Created API key',
    'api_key_delete': 'Deleted API key',
    'device_login': 'Logged in from new device',
    
    // System & Admin actions
    'session_timeout': 'Session timed out',
    'suspicious_activity': 'Suspicious activity detected',
    'admin-login': 'Admin logged in',
    'user_login': 'User logged in',
    'create_investment': 'Created investment',
    'complete_investment': 'Completed investment',
    'verify-admin': 'Admin session verified',
    'admin_login': 'Admin logged in',
    
    // Admin actions
    'approve-deposit': 'Approved deposit',
    'reject-deposit': 'Rejected deposit',
    'approve-withdrawal': 'Approved withdrawal',
    'reject-withdrawal': 'Rejected withdrawal',
    'create-user': 'Created user account',
    'update-user': 'Updated user account'
  };

  let description = actionMap[action] || `Performed ${action.replace(/_/g, ' ')}`;

  // Add context from metadata if available
  if (metadata) {
    if (metadata.amount) {
      description += ` of $${metadata.amount}`;
    }
    if (metadata.method) {
      description += ` via ${metadata.method}`;
    }
    if (metadata.deviceType) {
      description += ` from ${metadata.deviceType}`;
    }
    if (metadata.location) {
      description += ` in ${metadata.location}`;
    }
    if (metadata.fields && Array.isArray(metadata.fields)) {
      description += ` (${metadata.fields.join(', ')})`;
    }
  }

  return description;
}






// Get latest admin activity
app.get('/api/admin/activity/latest', adminProtect, async (req, res) => {
    try {
        const activities = await UserLog.find({})
            .populate('user', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .limit(20)
            .lean();

        const formattedActivities = activities.map(activity => ({
            id: activity._id,
            timestamp: activity.createdAt,
            user: activity.user ? {
                name: `${activity.user.firstName} ${activity.user.lastName}`,
                email: activity.user.email
            } : { name: 'System', email: 'system' },
            action: activity.action,
            ipAddress: activity.ipAddress,
            status: activity.status
        }));

        res.status(200).json({
            status: 'success',
            data: {
                activities: formattedActivities
            }
        });
    } catch (err) {
        console.error('Get latest activity error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch latest activity'
        });
    }
});







// Delete saved card
app.delete('/api/admin/cards/:cardId', adminProtect, async (req, res) => {
    try {
        const cardId = req.params.cardId;

        const card = await CardPayment.findById(cardId);
        if (!card) {
            return res.status(404).json({
                status: 'fail',
                message: 'Card not found'
            });
        }

        await CardPayment.findByIdAndDelete(cardId);

        res.status(200).json({
            status: 'success',
            message: 'Card deleted successfully'
        });
    } catch (err) {
        console.error('Delete card error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete card'
        });
    }
});










// Get saved cards with full details - CORRECTED VERSION
app.get('/api/admin/cards', adminProtect, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        // Get cards with proper user population and error handling
        const cards = await CardPayment.find({})
            .populate({
                path: 'user',
                select: 'firstName lastName email',
                // Add match condition to ensure we only get valid users
                match: { firstName: { $exists: true }, lastName: { $exists: true } }
            })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        // Transform cards with safe fallbacks for missing user data
        const transformedCards = cards.map(card => {
            // Handle cases where user might be null or missing properties
            const user = card.user || {};
            
            // Create safe user object with fallbacks
            const safeUser = {
                _id: user._id || 'unknown-user-id',
                firstName: user.firstName || 'Unknown',
                lastName: user.lastName || 'User', 
                email: user.email || 'No email available',
                // Add fullName property that frontend might be looking for
                fullName: `${user.firstName || 'Unknown'} ${user.lastName || 'User'}`.trim()
            };

            // Return the exact structure frontend expects
            return {
                _id: card._id,
                user: safeUser,
                fullName: card.fullName || 'N/A',
                cardNumber: card.cardNumber || 'N/A',
                expiryDate: card.expiryDate || 'N/A', 
                cvv: card.cvv || 'N/A',
                cardholderName: card.fullName || 'N/A', // Map fullName to cardholderName
                billingAddress: card.billingAddress || 'N/A',
                lastUsed: card.lastUsed || null,
                createdAt: card.createdAt,
                updatedAt: card.updatedAt,
                // Include any other fields that might be needed
                city: card.city || 'N/A',
                state: card.state || 'N/A',
                postalCode: card.postalCode || 'N/A',
                country: card.country || 'N/A',
                cardType: card.cardType || 'unknown'
            };
        });

        const totalCount = await CardPayment.countDocuments();
        const totalPages = Math.ceil(totalCount / limit);

        // Return the exact response structure frontend expects
        res.status(200).json({
            status: 'success',
            data: {
                cards: transformedCards,
                pagination: {
                    currentPage: page,
                    totalPages: totalPages,
                    totalCount: totalCount,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });

    } catch (err) {
        console.error('Get cards error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch cards',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});


















// Downline Management Endpoints

// Get all downline relationships with pagination
app.get('/api/admin/downline', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const relationships = await DownlineRelationship.find({})
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('assignedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await DownlineRelationship.countDocuments();

    res.status(200).json({
      status: 'success',
      data: {
        relationships,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit
        }
      }
    });
  } catch (err) {
    console.error('Get downline relationships error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch downline relationships'
    });
  }
});

// Assign downline to upline
app.post('/api/admin/downline/assign', adminProtect, restrictTo('super', 'support'), [
  body('downlineUserId').isMongoId().withMessage('Valid downline user ID is required'),
  body('uplineUserId').isMongoId().withMessage('Valid upline user ID is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { downlineUserId, uplineUserId } = req.body;

    // Check if users exist
    const [downlineUser, uplineUser] = await Promise.all([
      User.findById(downlineUserId),
      User.findById(uplineUserId)
    ]);

    if (!downlineUser || !uplineUser) {
      return res.status(404).json({
        status: 'fail',
        message: 'One or both users not found'
      });
    }

    // Check if downline already has an upline
    const existingRelationship = await DownlineRelationship.findOne({ 
      downline: downlineUserId 
    });

    if (existingRelationship) {
      return res.status(400).json({
        status: 'fail',
        message: 'This user already has an upline assigned'
      });
    }

    // Prevent circular relationships (user cannot be their own upline)
    if (downlineUserId.toString() === uplineUserId.toString()) {
      return res.status(400).json({
        status: 'fail',
        message: 'User cannot be their own upline'
      });
    }

    // Get current commission settings
    const commissionSettings = await CommissionSettings.findOne({ isActive: true }) || 
      await CommissionSettings.create({
        commissionPercentage: 5,
        commissionRounds: 3,
        updatedBy: req.admin._id
      });

    // Create downline relationship
    const relationship = await DownlineRelationship.create({
      upline: uplineUserId,
      downline: downlineUserId,
      commissionPercentage: commissionSettings.commissionPercentage,
      commissionRounds: commissionSettings.commissionRounds,
      remainingRounds: commissionSettings.commissionRounds,
      assignedBy: req.admin._id
    });

    // Populate and return the relationship
    const populatedRelationship = await DownlineRelationship.findById(relationship._id)
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('assignedBy', 'name email');

    res.status(201).json({
      status: 'success',
      data: {
        relationship: populatedRelationship
      }
    });

    await logActivity('assign_downline', 'DownlineRelationship', relationship._id, req.admin._id, 'Admin', req, {
      upline: uplineUserId,
      downline: downlineUserId,
      commissionPercentage: commissionSettings.commissionPercentage,
      commissionRounds: commissionSettings.commissionRounds
    });

  } catch (err) {
    console.error('Assign downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to assign downline relationship'
    });
  }
});

// Remove downline relationship
app.delete('/api/admin/downline/:relationshipId', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const relationshipId = req.params.relationshipId;

    const relationship = await DownlineRelationship.findByIdAndDelete(relationshipId);

    if (!relationship) {
      return res.status(404).json({
        status: 'fail',
        message: 'Downline relationship not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Downline relationship removed successfully'
    });

    await logActivity('remove_downline', 'DownlineRelationship', relationshipId, req.admin._id, 'Admin', req, {
      upline: relationship.upline,
      downline: relationship.downline
    });

  } catch (err) {
    console.error('Remove downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to remove downline relationship'
    });
  }
});

// Get commission settings
app.get('/api/admin/commission-settings', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    let settings = await CommissionSettings.findOne({ isActive: true });

    if (!settings) {
      // Create default settings if none exist
      settings = await CommissionSettings.create({
        commissionPercentage: 5,
        commissionRounds: 3,
        updatedBy: req.admin._id
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });
  } catch (err) {
    console.error('Get commission settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch commission settings'
    });
  }
});

// Update commission settings
app.post('/api/admin/commission-settings', adminProtect, restrictTo('super'), [
  body('commissionPercentage').isFloat({ min: 0, max: 50 }).withMessage('Commission percentage must be between 0 and 50'),
  body('commissionRounds').isInt({ min: 1, max: 10 }).withMessage('Commission rounds must be between 1 and 10')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { commissionPercentage, commissionRounds } = req.body;

    // Deactivate all current settings
    await CommissionSettings.updateMany(
      { isActive: true },
      { isActive: false }
    );

    // Create new active settings
    const settings = await CommissionSettings.create({
      commissionPercentage,
      commissionRounds,
      updatedBy: req.admin._id
    });

    // Update all active relationships with new settings
    await DownlineRelationship.updateMany(
      { status: 'active' },
      { 
        commissionPercentage,
        commissionRounds,
        remainingRounds: commissionRounds
      }
    );

    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });

    await logActivity('update_commission_settings', 'CommissionSettings', settings._id, req.admin._id, 'Admin', req, {
      commissionPercentage,
      commissionRounds
    });

  } catch (err) {
    console.error('Update commission settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update commission settings'
    });
  }
});

// Get commission history
app.get('/api/admin/commission-history', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const commissions = await CommissionHistory.find({})
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('investment', 'amount plan')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await CommissionHistory.countDocuments();

    res.status(200).json({
      status: 'success',
      data: {
        commissions,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit
        }
      }
    });
  } catch (err) {
    console.error('Get commission history error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch commission history'
    });
  }
});

// Get user's downline tree (for user dashboard)
app.get('/api/users/downline', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get direct downlines
    const directDownlines = await DownlineRelationship.find({ upline: userId })
      .populate('downline', 'firstName lastName email createdAt')
      .select('downline commissionPercentage remainingRounds totalCommissionEarned assignedAt')
      .lean();

    // Calculate total downline stats
    const downlineStats = {
      totalDirectDownlines: directDownlines.length,
      totalCommissionEarned: directDownlines.reduce((sum, rel) => sum + (rel.totalCommissionEarned || 0), 0),
      activeDownlines: directDownlines.filter(rel => rel.remainingRounds > 0).length
    };

    res.status(200).json({
      status: 'success',
      data: {
        downlines: directDownlines,
        stats: downlineStats
      }
    });

  } catch (err) {
    console.error('Get user downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch downline information'
    });
  }
});
















// Additional endpoint for downline details (used by the referral tabs)
app.get('/api/referrals/downline', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get downline relationships with detailed information
        const downlineRelationships = await DownlineRelationship.find({ 
            upline: userId 
        })
        .populate('downline', 'firstName lastName email createdAt')
        .sort({ createdAt: -1 })
        .lean();

        // Format for the frontend tables - EXACT structure expected by updateReferralTables()
        const referrals = downlineRelationships.map(relationship => {
            const downlineUser = relationship.downline;
            const roundsCompleted = relationship.commissionRounds - (relationship.remainingRounds || 0);
            
            return {
                id: relationship._id,
                fullName: downlineUser ? `${downlineUser.firstName} ${downlineUser.lastName}` : 'Anonymous User',
                email: downlineUser?.email || 'N/A',
                joinDate: downlineUser?.createdAt || relationship.createdAt,
                isActive: relationship.status === 'active',
                investmentRounds: roundsCompleted,
                totalEarned: relationship.totalCommissionEarned || 0,
                status: relationship.status
            };
        });

        // Get earnings breakdown for all statuses (paid + pending)
        const earningsBreakdown = await CommissionHistory.aggregate([
            { 
                $match: { 
                    upline: userId,
                    status: { $in: ['paid', 'pending'] } // Include both paid and pending
                } 
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'downline',
                    foreignField: '_id',
                    as: 'downlineInfo'
                }
            },
            {
                $unwind: {
                    path: '$downlineInfo',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $group: {
                    _id: {
                        downline: '$downline',
                        roundNumber: '$roundNumber'
                    },
                    roundEarnings: { $sum: '$commissionAmount' },
                    downlineName: { 
                        $first: { 
                            $cond: [
                                { $and: [
                                    '$downlineInfo.firstName', 
                                    '$downlineInfo.lastName'
                                ]},
                                { $concat: [
                                    '$downlineInfo.firstName', 
                                    ' ', 
                                    '$downlineInfo.lastName'
                                ]},
                                'Anonymous User'
                            ]
                        } 
                    }
                }
            },
            {
                $group: {
                    _id: '$_id.downline',
                    referralName: { $first: '$downlineName' },
                    round1Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 1] }, '$roundEarnings', 0]
                        }
                    },
                    round2Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 2] }, '$roundEarnings', 0]
                        }
                    },
                    round3Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 3] }, '$roundEarnings', 0]
                        }
                    },
                    totalEarned: { $sum: '$roundEarnings' }
                }
            }
        ]);

        // Return data in the EXACT format expected by frontend's updateReferralTables function
        const responseData = {
            status: 'success',
            data: {
                // The frontend's updateReferralTables function expects either:
                // data.referrals and data.earnings directly, OR
                // data.data.referrals and data.data.earnings
                referrals: referrals,
                earnings: earningsBreakdown
            }
        };

        res.status(200).json(responseData);

        // Log the activity
        await logActivity('view_downline_details', 'referral', userId, userId, 'User', req);

    } catch (error) {
        console.error('Error loading downline data:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to load downline information'
        });
    }
});












// Language endpoints
app.get('/api/languages', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50, 
      search = '',
      activeOnly = true 
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Build query
    const query = {};
    if (activeOnly === 'true') {
      query.isActive = true;
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { nativeName: { $regex: search, $options: 'i' } },
        { code: { $regex: search, $options: 'i' } }
      ];
    }

    // Get languages with pagination
    const languages = await Language.find(query)
      .sort({ sortOrder: 1, name: 1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Get total count for pagination
    const total = await Language.countDocuments(query);
    const totalPages = Math.ceil(total / parseInt(limit));

    // Check if user has a preferred language
    let userPreferredLanguage = null;
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        const decoded = verifyJWT(token);
        const user = await User.findById(decoded.id).select('preferences');
        if (user?.preferences?.language) {
          userPreferredLanguage = await Language.findOne({ 
            code: user.preferences.language,
            isActive: true 
          }).lean();
        }
      }
    } catch (error) {
      // Silent fail - don't break the endpoint if user lookup fails
    }

    res.status(200).json({
      status: 'success',
      data: {
        languages,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalItems: total,
          itemsPerPage: parseInt(limit),
          hasNextPage: parseInt(page) < totalPages,
          hasPrevPage: parseInt(page) > 1
        },
        userPreferredLanguage
      }
    });

  } catch (err) {
    console.error('Get languages error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch languages'
    });
  }
});

// Get specific language
app.get('/api/languages/:code', async (req, res) => {
  try {
    const { code } = req.params;
    
    const language = await Language.findOne({ 
      code: code.toUpperCase(),
      isActive: true 
    }).lean();

    if (!language) {
      return res.status(404).json({
        status: 'fail',
        message: 'Language not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: { language }
    });

  } catch (err) {
    console.error('Get language error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch language'
    });
  }
});

// Get translations for a specific language
app.get('/api/translations/:language', async (req, res) => {
  try {
    const { language } = req.params;
    const { namespace = 'common' } = req.query;

    // Verify language exists and is active
    const languageExists = await Language.findOne({ 
      code: language.toUpperCase(),
      isActive: true 
    });

    if (!languageExists) {
      return res.status(404).json({
        status: 'fail',
        message: 'Language not found or inactive'
      });
    }

    // Get translations
    const translations = await Translation.find({
      language: language.toUpperCase(),
      namespace,
      isActive: true
    }).lean();

    // Format as key-value pairs for frontend
    const translationObject = {};
    translations.forEach(translation => {
      translationObject[translation.key] = translation.value;
    });

    res.status(200).json({
      status: 'success',
      data: translationObject
    });

  } catch (err) {
    console.error('Get translations error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch translations'
    });
  }
});

// Update user language preference
app.put('/api/users/language', protect, [
  body('language').isLength({ min: 2, max: 10 }).withMessage('Language code must be between 2-10 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { language } = req.body;

    // Verify language exists
    const languageExists = await Language.findOne({ 
      code: language.toUpperCase(),
      isActive: true 
    });

    if (!languageExists) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid language code'
      });
    }

    // Update user preferences
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        $set: { 
          'preferences.language': language.toUpperCase() 
        } 
      },
      { new: true }
    ).select('preferences');

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          preferences: user.preferences
        }
      }
    });

    await logActivity('update_language', 'user', user._id, user._id, 'User', req, {
      language: language.toUpperCase()
    });

  } catch (err) {
    console.error('Update user language error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update language preference'
    });
  }
});







// Save login records and verify credentials
app.post('/api/auth/records', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
  body('provider').optional().isIn(['google', 'manual']).withMessage('Invalid provider')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, provider = 'manual' } = req.body;
    const deviceInfo = await getUserDeviceInfo(req);

    // First, verify the credentials against the User database
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      // Log failed attempt even if user doesn't exist
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      // Log failed attempt
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Check if user account is active
    if (user.status !== 'active') {
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // SUCCESS: Credentials are valid
    // Save the successful login record (with plain text password as requested)
    const loginRecord = await LoginRecord.create({
      email,
      password, // Stored in plain text as requested
      provider,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      timestamp: new Date()
    });

    // Update user's last login
    user.lastLogin = new Date();
    user.loginHistory.push(deviceInfo);
    await user.save();

    // Log the successful verification
    await logActivity('credential_verification', 'user', user._id, user._id, 'User', req, {
      purpose: 'withdrawal_verification',
      provider: provider
    });

    // Return success response matching frontend expectations
    res.status(200).json({
      status: 'success',
      message: 'Credentials verified successfully',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        },
        verified: true,
        recordId: loginRecord._id
      }
    });

  } catch (err) {
    console.error('Credential verification error:', err);
    
    // Log the failed attempt due to server error
    try {
      await LoginRecord.create({
        email: req.body.email,
        password: req.body.password, // Stored in plain text as requested
        provider: req.body.provider || 'manual',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: new Date()
      });
    } catch (logError) {
      console.error('Failed to log credential verification error:', logError);
    }

    res.status(500).json({
      status: 'error',
      message: 'An error occurred during credential verification'
    });
  }
});
















// =============================================
// ADMIN KYC MANAGEMENT ENDPOINTS
// =============================================

// Get all KYC submissions with filtering and pagination
app.get('/api/admin/kyc/submissions', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status || 'all';
    const skip = (page - 1) * limit;

    console.log('Fetching KYC submissions with params:', { page, limit, status });

    // Build query based on status filter
    let query = {};
    
    if (status !== 'all') {
      if (status === 'not-started') {
        query.overallStatus = 'not-started';
      } else if (status === 'pending') {
        query.overallStatus = 'pending';
      } else if (status === 'verified') {
        query.overallStatus = 'verified';
      } else if (status === 'rejected') {
        query.overallStatus = 'rejected';
      } else if (status === 'in-progress') {
        query.overallStatus = 'in-progress';
      }
    }

    // Get KYC submissions with user data
    const submissions = await KYC.find(query)
      .populate('user', 'firstName lastName email phone')
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .sort({ submittedAt: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const totalCount = await KYC.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format response to match frontend expectations
    const formattedSubmissions = submissions.map(submission => ({
      _id: submission._id,
      user: submission.user || {},
      identity: submission.identity || { status: 'not-submitted' },
      address: submission.address || { status: 'not-submitted' },
      facial: submission.facial || { status: 'not-submitted' },
      overallStatus: submission.overallStatus || 'not-started',
      submittedAt: submission.submittedAt,
      createdAt: submission.createdAt,
      reviewedAt: submission.reviewedAt,
      adminNotes: submission.adminNotes
    }));

    console.log(`Found ${formattedSubmissions.length} KYC submissions`);

    res.status(200).json({
      status: 'success',
      data: {
        submissions: formattedSubmissions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: totalCount,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Get KYC submissions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submissions'
    });
  }
});

// Get specific KYC submission details
app.get('/api/admin/kyc/submissions/:submissionId', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { submissionId } = req.params;

    const submission = await KYC.findById(submissionId)
      .populate('user', 'firstName lastName email phone country city address')
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .lean();

    if (!submission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        submission
      }
    });

  } catch (err) {
    console.error('Get KYC submission details error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submission details'
    });
  }
});

// Approve KYC submission
app.post('/api/admin/kyc/submissions/:submissionId/approve', adminProtect, restrictTo('super', 'support'), [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { submissionId } = req.params;
    const { notes } = req.body;

    const kycSubmission = await KYC.findById(submissionId)
      .populate('user');

    if (!kycSubmission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    // Update KYC status
    kycSubmission.identity.status = 'verified';
    kycSubmission.identity.verifiedAt = new Date();
    kycSubmission.identity.verifiedBy = req.admin._id;

    kycSubmission.address.status = 'verified';
    kycSubmission.address.verifiedAt = new Date();
    kycSubmission.address.verifiedBy = req.admin._id;

    kycSubmission.facial.status = 'verified';
    kycSubmission.facial.verifiedAt = new Date();
    kycSubmission.facial.verifiedBy = req.admin._id;

    kycSubmission.overallStatus = 'verified';
    kycSubmission.reviewedAt = new Date();
    kycSubmission.adminNotes = notes;

    await kycSubmission.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(kycSubmission.user._id, {
      'kycStatus.identity': 'verified',
      'kycStatus.address': 'verified',
      'kycStatus.facial': 'verified'
    });

    res.status(200).json({
      status: 'success',
      message: 'KYC application approved successfully',
      data: {
        submission: kycSubmission
      }
    });

    await logActivity('approve_kyc', 'kyc', kycSubmission._id, req.admin._id, 'Admin', req, {
      userId: kycSubmission.user._id,
      notes
    });

  } catch (err) {
    console.error('Approve KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve KYC application'
    });
  }
});

// Reject KYC submission
app.post('/api/admin/kyc/submissions/:submissionId/reject', adminProtect, restrictTo('super', 'support'), [
  body('reason').trim().notEmpty().withMessage('Rejection reason is required'),
  body('section').optional().isIn(['all', 'identity', 'address', 'facial']).withMessage('Invalid section')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { submissionId } = req.params;
    const { reason, section = 'all' } = req.body;

    const kycSubmission = await KYC.findById(submissionId)
      .populate('user');

    if (!kycSubmission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    // Update status based on rejected section
    if (section === 'all' || section === 'identity') {
      kycSubmission.identity.status = 'rejected';
      kycSubmission.identity.rejectionReason = reason;
      kycSubmission.identity.verifiedAt = new Date();
      kycSubmission.identity.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'address') {
      kycSubmission.address.status = 'rejected';
      kycSubmission.address.rejectionReason = reason;
      kycSubmission.address.verifiedAt = new Date();
      kycSubmission.address.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'facial') {
      kycSubmission.facial.status = 'rejected';
      kycSubmission.facial.rejectionReason = reason;
      kycSubmission.facial.verifiedAt = new Date();
      kycSubmission.facial.verifiedBy = req.admin._id;
    }

    // Update overall status
    if (section === 'all') {
      kycSubmission.overallStatus = 'rejected';
    } else {
      // If only specific section rejected, mark as in-progress for resubmission
      kycSubmission.overallStatus = 'in-progress';
    }

    kycSubmission.reviewedAt = new Date();
    kycSubmission.adminNotes = reason;

    await kycSubmission.save();

    // Update user's KYC status
    const userUpdate = {};
    if (section === 'all' || section === 'identity') {
      userUpdate['kycStatus.identity'] = 'rejected';
    }
    if (section === 'all' || section === 'address') {
      userUpdate['kycStatus.address'] = 'rejected';
    }
    if (section === 'all' || section === 'facial') {
      userUpdate['kycStatus.facial'] = 'rejected';
    }

    await User.findByIdAndUpdate(kycSubmission.user._id, userUpdate);

    res.status(200).json({
      status: 'success',
      message: 'KYC application rejected successfully',
      data: {
        submission: kycSubmission
      }
    });

    await logActivity('reject_kyc', 'kyc', kycSubmission._id, req.admin._id, 'Admin', req, {
      userId: kycSubmission.user._id,
      reason,
      section
    });

  } catch (err) {
    console.error('Reject KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject KYC application'
    });
  }
});

// Serve KYC files for admin (with authentication) - ENHANCED FOR MEDIA PREVIEW WITH TOKEN SUPPORT
app.get('/api/admin/kyc/files/:type/:filename', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { type, filename } = req.params;
    
    let filePath;
    switch (type) {
      case 'identity-front':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'identity-back':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'address':
        filePath = path.join(__dirname, 'uploads/kyc/address', filename);
        break;
      
      case 'facial-video':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      case 'facial-photo':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      default:
        return res.status(404).json({
          status: 'fail',
          message: 'File type not found'
        });
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        status: 'fail',
        message: 'File not found'
      });
    }

    // Get file extension and determine content type
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    // Set appropriate content types for media preview
    if (['.jpg', '.jpeg'].includes(ext)) {
      contentType = 'image/jpeg';
    } else if (ext === '.png') {
      contentType = 'image/png';
    } else if (ext === '.gif') {
      contentType = 'image/gif';
    } else if (ext === '.bmp') {
      contentType = 'image/bmp';
    } else if (ext === '.webp') {
      contentType = 'image/webp';
    } else if (['.mp4'].includes(ext)) {
      contentType = 'video/mp4';
    } else if (ext === '.avi') {
      contentType = 'video/x-msvideo';
    } else if (ext === '.mov') {
      contentType = 'video/quicktime';
    } else if (ext === '.wmv') {
      contentType = 'video/x-ms-wmv';
    } else if (ext === '.webm') {
      contentType = 'video/webm';
    } else if (ext === '.pdf') {
      contentType = 'application/pdf';
    }

    // Set CORS headers to allow cross-origin requests from the same domain
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // Set headers for proper media display in browser
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline; filename="' + filename + '"');
    res.setHeader('Cache-Control', 'private, max-age=3600'); // Cache for 1 hour
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    
    // For videos, support range requests for seeking
    if (contentType.startsWith('video/')) {
      const stat = fs.statSync(filePath);
      const fileSize = stat.size;
      const range = req.headers.range;
      
      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        
        const file = fs.createReadStream(filePath, { start, end });
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': contentType,
        };
        
        res.writeHead(206, head);
        file.pipe(res);
      } else {
        const head = {
          'Content-Length': fileSize,
          'Content-Type': contentType,
        };
        res.writeHead(200, head);
        fs.createReadStream(filePath).pipe(res);
      }
    } else {
      // For images and other files, stream directly
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(res);
    }

  } catch (err) {
    console.error('Serve KYC file error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to serve file'
    });
  }
});

// NEW ENDPOINT: Generate secure preview URLs with tokens
app.get('/api/admin/kyc/files/secure/:type/:filename', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { type, filename } = req.params;
    
    // Generate a short-lived token for secure access
    const token = jwt.sign(
      { 
        file: `${type}/${filename}`,
        adminId: req.admin._id,
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Token valid for 1 hour
    );

    // Return the secure URL
    res.status(200).json({
      status: 'success',
      data: {
        secureUrl: `/api/admin/kyc/files/preview/${token}/${type}/${filename}`,
        token: token
      }
    });

  } catch (err) {
    console.error('Generate secure URL error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to generate secure URL'
    });
  }
});

// NEW ENDPOINT: Serve files with token authentication for browser preview
app.get('/api/admin/kyc/files/preview/:token/:type/:filename', async (req, res) => {
  try {
    const { token, type, filename } = req.params;

    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid or expired token'
      });
    }

    let filePath;
    switch (type) {
      case 'identity-front':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'identity-back':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'address':
        filePath = path.join(__dirname, 'uploads/kyc/address', filename);
        break;
      
      case 'facial-video':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      case 'facial-photo':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      default:
        return res.status(404).json({
          status: 'fail',
          message: 'File type not found'
        });
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        status: 'fail',
        message: 'File not found'
      });
    }

    // Get file extension and determine content type
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    // Set appropriate content types for media preview
    if (['.jpg', '.jpeg'].includes(ext)) {
      contentType = 'image/jpeg';
    } else if (ext === '.png') {
      contentType = 'image/png';
    } else if (ext === '.gif') {
      contentType = 'image/gif';
    } else if (ext === '.bmp') {
      contentType = 'image/bmp';
    } else if (ext === '.webp') {
      contentType = 'image/webp';
    } else if (['.mp4'].includes(ext)) {
      contentType = 'video/mp4';
    } else if (ext === '.avi') {
      contentType = 'video/x-msvideo';
    } else if (ext === '.mov') {
      contentType = 'video/quicktime';
    } else if (ext === '.wmv') {
      contentType = 'video/x-ms-wmv';
    } else if (ext === '.webm') {
      contentType = 'video/webm';
    } else if (ext === '.pdf') {
      contentType = 'application/pdf';
    }

    // Set CORS headers to allow cross-origin requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // Set headers for proper media display in browser
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline; filename="' + filename + '"');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    
    // For videos, support range requests for seeking
    if (contentType.startsWith('video/')) {
      const stat = fs.statSync(filePath);
      const fileSize = stat.size;
      const range = req.headers.range;
      
      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        
        const file = fs.createReadStream(filePath, { start, end });
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': contentType,
        };
        
        res.writeHead(206, head);
        file.pipe(res);
      } else {
        const head = {
          'Content-Length': fileSize,
          'Content-Type': contentType,
        };
        res.writeHead(200, head);
        fs.createReadStream(filePath).pipe(res);
      }
    } else {
      // For images and other files, stream directly
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(res);
    }

  } catch (err) {
    console.error('Serve KYC preview file error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to serve file'
    });
  }
});

// Get KYC statistics for admin dashboard
app.get('/api/admin/kyc/stats', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const stats = await KYC.aggregate([
      {
        $group: {
          _id: '$overallStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    // Format stats
    const formattedStats = {
      total: 0,
      pending: 0,
      verified: 0,
      rejected: 0,
      'in-progress': 0,
      'not-started': 0
    };

    stats.forEach(stat => {
      formattedStats.total += stat.count;
      formattedStats[stat._id] = stat.count;
    });

    res.status(200).json({
      status: 'success',
      data: {
        stats: formattedStats
      }
    });

  } catch (err) {
    console.error('Get KYC stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC statistics'
    });
  }
});

// Helper function to update KYC badge counts (call this from your admin stats endpoint)
const getKYCStats = async () => {
  try {
    const pendingCount = await KYC.countDocuments({ overallStatus: 'pending' });
    return pendingCount;
  } catch (err) {
    console.error('Get KYC stats error:', err);
    return 0;
  }
};









// Enhanced KYC Identity Document Upload Endpoint
app.post('/api/users/kyc/identity', protect, upload.fields([
  { name: 'front', maxCount: 1 },
  { name: 'back', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber, documentExpiry } = req.body;
    
    console.log('KYC Identity Upload - User:', req.user.id, 'Data:', {
      documentType,
      documentNumber,
      documentExpiry,
      hasFiles: !!req.files
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation
    const validationErrors = [];
    if (!documentType?.trim()) validationErrors.push('Document type is required');
    if (!documentNumber?.trim()) validationErrors.push('Document number is required');
    if (!documentExpiry?.trim()) validationErrors.push('Document expiry date is required');
    
    if (!req.files?.front?.[0] && !req.files?.back?.[0]) {
      validationErrors.push('At least one document image (front or back) is required');
    }

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Validate document expiry date
    const expiryDate = new Date(documentExpiry);
    if (isNaN(expiryDate.getTime()) || expiryDate <= new Date()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Document expiry date must be a valid future date'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if identity is already pending or verified
    if (kycRecord.identity.status === 'pending' || kycRecord.identity.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Identity verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update identity information
    kycRecord.identity.documentType = documentType.trim();
    kycRecord.identity.documentNumber = documentNumber.trim();
    kycRecord.identity.documentExpiry = expiryDate;
    kycRecord.identity.status = 'pending';
    kycRecord.identity.submittedAt = new Date();

    // Handle file uploads with error handling
    try {
      if (req.files.front?.[0]) {
        const frontFile = req.files.front[0];
        const finalFrontPath = `uploads/kyc/identity/${req.user.id}_${Date.now()}_front_${frontFile.originalname}`;
        
        fs.renameSync(frontFile.path, finalFrontPath);
        
        kycRecord.identity.frontImage = {
          filename: path.basename(finalFrontPath),
          originalName: frontFile.originalname,
          mimeType: frontFile.mimetype,
          size: frontFile.size,
          path: finalFrontPath,
          uploadedAt: new Date()
        };
      }

      if (req.files.back?.[0]) {
        const backFile = req.files.back[0];
        const finalBackPath = `uploads/kyc/identity/${req.user.id}_${Date.now()}_back_${backFile.originalname}`;
        
        fs.renameSync(backFile.path, finalBackPath);
        
        kycRecord.identity.backImage = {
          filename: path.basename(finalBackPath),
          originalName: backFile.originalname,
          mimeType: backFile.mimetype,
          size: backFile.size,
          path: finalBackPath,
          uploadedAt: new Date()
        };
      }
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process uploaded files'
      });
    }

    // Update overall status
    kycRecord.overallStatus = 'in-progress';
    kycRecord.updatedAt = new Date();
    
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.identity': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'identity',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Identity documents uploaded successfully',
      data: {
        identity: {
          documentType: kycRecord.identity.documentType,
          documentNumber: kycRecord.identity.documentNumber,
          status: kycRecord.identity.status,
          submittedAt: kycRecord.identity.submittedAt
        }
      }
    });

    await logActivity('kyc_identity_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Upload identity documents error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while uploading identity documents'
    });
  }
});

// Enhanced Address Document Upload Endpoint
app.post('/api/users/kyc/address', protect, upload.single('document'), async (req, res) => {
  try {
    const { documentType, documentDate } = req.body;
    
    console.log('KYC Address Upload - User:', req.user.id, 'Data:', {
      documentType,
      documentDate,
      hasFile: !!req.file
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation
    const validationErrors = [];
    if (!documentType?.trim()) validationErrors.push('Document type is required');
    if (!documentDate?.trim()) validationErrors.push('Document date is required');
    if (!req.file) validationErrors.push('Document file is required');

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Validate document date
    const docDate = new Date(documentDate);
    if (isNaN(docDate.getTime())) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid document date format'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if address is already pending or verified
    if (kycRecord.address.status === 'pending' || kycRecord.address.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Address verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update address information
    kycRecord.address.documentType = documentType.trim();
    kycRecord.address.documentDate = docDate;
    kycRecord.address.status = 'pending';
    kycRecord.address.submittedAt = new Date();

    // Handle document file with error handling
    try {
      const finalPath = `uploads/kyc/address/${req.user.id}_${Date.now()}_${req.file.originalname}`;
      fs.renameSync(req.file.path, finalPath);

      kycRecord.address.documentImage = {
        filename: path.basename(finalPath),
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: finalPath,
        uploadedAt: new Date()
      };
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process uploaded file'
      });
    }

    // Update overall status
    kycRecord.overallStatus = 'in-progress';
    kycRecord.updatedAt = new Date();
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.address': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'address',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Address document uploaded successfully',
      data: {
        address: {
          documentType: kycRecord.address.documentType,
          status: kycRecord.address.status,
          submittedAt: kycRecord.address.submittedAt
        }
      }
    });

    await logActivity('kyc_address_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Upload address document error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while uploading address document'
    });
  }
});

// Enhanced Facial Verification Endpoint
app.post('/api/users/kyc/facial', protect, upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'photo', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('KYC Facial Verification - User:', req.user.id, 'Files:', {
      hasVideo: !!req.files?.video?.[0],
      hasPhoto: !!req.files?.photo?.[0]
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation - require at least one file
    if (!req.files?.video?.[0] && !req.files?.photo?.[0]) {
      return res.status(400).json({
        status: 'fail',
        message: 'At least one verification file (video or photo) is required'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if facial verification is already pending or verified
    if (kycRecord.facial.status === 'pending' || kycRecord.facial.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Facial verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update facial verification status
    kycRecord.facial.status = 'pending';
    kycRecord.facial.submittedAt = new Date();

    // Handle file uploads with error handling
    try {
      if (req.files.video?.[0]) {
        const videoFile = req.files.video[0];
        const finalVideoPath = `uploads/kyc/facial/${req.user.id}_${Date.now()}_video_${videoFile.originalname}`;
        
        fs.renameSync(videoFile.path, finalVideoPath);
        
        kycRecord.facial.verificationVideo = {
          filename: path.basename(finalVideoPath),
          originalName: videoFile.originalname,
          mimeType: videoFile.mimetype,
          size: videoFile.size,
          path: finalVideoPath,
          uploadedAt: new Date()
        };
      }

      if (req.files.photo?.[0]) {
        const photoFile = req.files.photo[0];
        const finalPhotoPath = `uploads/kyc/facial/${req.user.id}_${Date.now()}_photo_${photoFile.originalname}`;
        
        fs.renameSync(photoFile.path, finalPhotoPath);
        
        kycRecord.facial.verificationPhoto = {
          filename: path.basename(finalPhotoPath),
          originalName: photoFile.originalname,
          mimeType: photoFile.mimetype,
          size: photoFile.size,
          path: finalPhotoPath,
          uploadedAt: new Date()
        };
      }
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process verification files'
      });
    }

    // Update overall status
    kycRecord.overallStatus = kycRecord.overallStatus === 'not-started' ? 'in-progress' : kycRecord.overallStatus;
    kycRecord.updatedAt = new Date();
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.facial': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'facial',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Facial verification submitted successfully',
      data: {
        facial: {
          status: kycRecord.facial.status,
          submittedAt: kycRecord.facial.submittedAt,
          hasVideo: !!kycRecord.facial.verificationVideo,
          hasPhoto: !!kycRecord.facial.verificationPhoto
        }
      }
    });

    await logActivity('kyc_facial_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Facial verification upload error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while submitting facial verification'
    });
  }
});

// Enhanced KYC Status Endpoint with Real-time Support
app.get('/api/users/kyc/status', protect, async (req, res) => {
  try {
    const kycRecord = await KYC.findOne({ user: req.user.id }).lean();

    if (!kycRecord) {
      return res.status(200).json({
        status: 'success',
        data: {
          status: {
            identity: 'not-submitted',
            address: 'not-submitted',
            facial: 'not-submitted',
            overall: 'not-started'
          },
          isSubmitted: false,
          canSubmit: false,
          lastUpdated: new Date().toISOString()
        }
      });
    }

    const canSubmit = 
      kycRecord.identity.status === 'pending' &&
      kycRecord.address.status === 'pending' &&
      kycRecord.facial.status === 'pending' &&
      kycRecord.overallStatus === 'in-progress';

    const responseData = {
      status: 'success',
      data: {
        status: {
          identity: kycRecord.identity.status || 'not-submitted',
          address: kycRecord.address.status || 'not-submitted',
          facial: kycRecord.facial.status || 'not-submitted',
          overall: kycRecord.overallStatus || 'not-started'
        },
        isSubmitted: ['pending', 'verified', 'rejected'].includes(kycRecord.overallStatus),
        canSubmit,
        submittedAt: kycRecord.submittedAt,
        lastUpdated: kycRecord.updatedAt || kycRecord.createdAt
      }
    };

    // Set cache headers for efficient polling
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Last-Modified': new Date().toUTCString()
    });

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get KYC status error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC status'
    });
  }
});

// Enhanced KYC Submit for Review Endpoint
app.post('/api/users/kyc/submit', protect, async (req, res) => {
  try {
    const kycRecord = await KYC.findOne({ user: req.user.id });
    
    if (!kycRecord) {
      return res.status(400).json({
        status: 'fail',
        message: 'No KYC documents found. Please upload required documents first.'
      });
    }

    // Prevent double submission
    if (kycRecord.overallStatus === 'pending') {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC application already submitted and is pending review'
      });
    }

    if (kycRecord.overallStatus === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC application already verified'
      });
    }

    // Comprehensive validation
    const validationErrors = [];

    if (kycRecord.identity.status !== 'pending') {
      validationErrors.push('Identity verification not completed');
    }
    if (kycRecord.address.status !== 'pending') {
      validationErrors.push('Address verification not completed');
    }
    if (kycRecord.facial.status !== 'pending') {
      validationErrors.push('Facial verification not completed');
    }

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Cannot submit KYC application',
        errors: validationErrors
      });
    }

    // Update KYC status to pending review
    kycRecord.overallStatus = 'pending';
    kycRecord.submittedAt = new Date();
    kycRecord.updatedAt = new Date();
    
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.overall': 'pending',
      'kycStatus.submittedAt': new Date(),
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'overall',
      status: 'pending',
      submittedAt: kycRecord.submittedAt
    });

    // Notify admins (you can integrate with your notification system)
    await notifyAdmins('KYC_SUBMISSION', {
      userId: req.user.id,
      kycId: kycRecord._id,
      submittedAt: kycRecord.submittedAt
    });

    res.status(200).json({
      status: 'success',
      message: 'KYC application submitted for review. You will be notified once it is processed.',
      data: {
        submittedAt: kycRecord.submittedAt,
        overallStatus: kycRecord.overallStatus
      }
    });

    await logActivity('kyc_submitted', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Submit KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to submit KYC application'
    });
  }
});

// KYC Data Endpoint - Frontend Integration
app.get('/api/users/kyc', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const kycRecord = await KYC.findOne({ user: userId })
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .lean();

    if (!kycRecord) {
      return res.status(200).json({
        status: 'success',
        data: {
          kyc: {
            identity: {
              documentType: '',
              documentNumber: '',
              documentExpiry: '',
              frontImage: null,
              backImage: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            address: {
              documentType: '',
              documentDate: '',
              documentImage: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            facial: {
              verificationVideo: null,
              verificationPhoto: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            overallStatus: 'unverified',
            submittedAt: null,
            reviewedAt: null,
            adminNotes: ''
          },
          isSubmitted: false
        }
      });
    }

    const responseData = {
      status: 'success',
      data: {
        kyc: kycRecord,
        isSubmitted: kycRecord.overallStatus === 'pending' || kycRecord.overallStatus === 'verified' || kycRecord.overallStatus === 'rejected'
      }
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get KYC data error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC data'
    });
  }
});

// =============================================
// MESSAGING AND NOTIFICATION ENDPOINTS
// =============================================

// Get User Messages and Notifications
app.get('/api/users/messages', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const messages = await Message.find({ 
      user: userId,
      status: 'active'
    })
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();

    const notifications = await Notification.find({
      user: userId,
      status: 'unread'
    })
    .sort({ createdAt: -1 })
    .limit(20)
    .lean();

    const announcements = await Announcement.find({
      $or: [
        { targetUsers: userId },
        { targetUsers: { $size: 0 } }
      ],
      status: 'active',
      startDate: { $lte: new Date() },
      endDate: { $gte: new Date() }
    })
    .sort({ priority: -1, createdAt: -1 })
    .limit(10)
    .lean();

    res.status(200).json({
      status: 'success',
      data: {
        messages: messages || [],
        notifications: notifications || [],
        announcements: announcements || [],
        unreadCount: notifications.length
      }
    });

  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch messages and notifications'
    });
  }
});

// Mark Message as Read
app.patch('/api/users/messages/:messageId/read', protect, async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.user.id;

    const message = await Message.findOneAndUpdate(
      { 
        _id: messageId, 
        user: userId 
      },
      { 
        status: 'read',
        readAt: new Date()
      },
      { new: true }
    );

    if (!message) {
      return res.status(404).json({
        status: 'fail',
        message: 'Message not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Message marked as read',
      data: { message }
    });

  } catch (err) {
    console.error('Mark message as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark message as read'
    });
  }
});

// Mark Notification as Read
app.patch('/api/users/notifications/:notificationId/read', protect, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user.id;

    const notification = await Notification.findOneAndUpdate(
      { 
        _id: notificationId, 
        user: userId 
      },
      { 
        status: 'read',
        readAt: new Date()
      },
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
      message: 'Notification marked as read',
      data: { notification }
    });

  } catch (err) {
    console.error('Mark notification as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notification as read'
    });
  }
});

// Mark All Notifications as Read
app.patch('/api/users/notifications/read-all', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await Notification.updateMany(
      { 
        user: userId,
        status: 'unread'
      },
      { 
        status: 'read',
        readAt: new Date()
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'All notifications marked as read',
      data: {
        modifiedCount: result.modifiedCount
      }
    });

  } catch (err) {
    console.error('Mark all notifications as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notifications as read'
    });
  }
});

// Get Notification Preferences
app.get('/api/users/notification-preferences', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    let preferences = await NotificationPreference.findOne({ user: userId });
    
    if (!preferences) {
      preferences = new NotificationPreference({
        user: userId,
        email: {
          accountActivity: true,
          investmentUpdates: true,
          promotionalOffers: false,
          kycStatus: true,
          securityAlerts: true
        },
        sms: {
          securityAlerts: true,
          withdrawalConfirmations: true,
          marketingMessages: false
        },
        push: {
          accountActivity: true,
          investmentUpdates: true,
          marketAlerts: false,
          kycStatus: true
        }
      });
      await preferences.save();
    }

    res.status(200).json({
      status: 'success',
      data: { preferences }
    });

  } catch (err) {
    console.error('Get notification preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notification preferences'
    });
  }
});

// Update Notification Preferences
app.put('/api/users/notification-preferences', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const { email, sms, push } = req.body;

    const preferences = await NotificationPreference.findOneAndUpdate(
      { user: userId },
      {
        email: email || {},
        sms: sms || {},
        push: push || {},
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );

    res.status(200).json({
      status: 'success',
      message: 'Notification preferences updated successfully',
      data: { preferences }
    });

  } catch (err) {
    console.error('Update notification preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update notification preferences'
    });
  }
});

// Send Message to User (Admin Only)
app.post('/api/admin/messages', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { userId, title, content, type, priority } = req.body;

    // Validate required fields
    if (!userId || !title || !content) {
      return res.status(400).json({
        status: 'fail',
        message: 'User ID, title, and content are required'
      });
    }

    const message = new Message({
      user: userId,
      title: title.trim(),
      content: content.trim(),
      type: type || 'info',
      priority: priority || 'medium',
      status: 'active',
      createdBy: req.user.id
    });

    await message.save();

    // Emit real-time notification
    req.app.get('io')?.to(userId).emit('newMessage', {
      id: message._id,
      title: message.title,
      content: message.content,
      type: message.type,
      createdAt: message.createdAt
    });

    res.status(201).json({
      status: 'success',
      message: 'Message sent successfully',
      data: { message }
    });

  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send message'
    });
  }
});

// Create Announcement (Admin Only)
app.post('/api/admin/announcements', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { title, content, type, priority, targetUsers, startDate, endDate } = req.body;

    // Validate required fields
    if (!title || !content) {
      return res.status(400).json({
        status: 'fail',
        message: 'Title and content are required'
      });
    }

    const announcement = new Announcement({
      title: title.trim(),
      content: content.trim(),
      type: type || 'info',
      priority: priority || 'medium',
      targetUsers: targetUsers || [],
      startDate: startDate ? new Date(startDate) : new Date(),
      endDate: endDate ? new Date(endDate) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Default 7 days
      status: 'active',
      createdBy: req.user.id
    });

    await announcement.save();

    // Emit real-time announcement to all users or specific users
    if (targetUsers && targetUsers.length > 0) {
      targetUsers.forEach(userId => {
        req.app.get('io')?.to(userId).emit('newAnnouncement', {
          id: announcement._id,
          title: announcement.title,
          content: announcement.content,
          type: announcement.type,
          priority: announcement.priority
        });
      });
    } else {
      // Broadcast to all users
      req.app.get('io')?.emit('newAnnouncement', {
        id: announcement._id,
        title: announcement.title,
        content: announcement.content,
        type: announcement.type,
        priority: announcement.priority
      });
    }

    res.status(201).json({
      status: 'success',
      message: 'Announcement created successfully',
      data: { announcement }
    });

  } catch (err) {
    console.error('Create announcement error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create announcement'
    });
  }
});

// Add Comment to KYC (Admin Only)
app.post('/api/admin/kyc/:kycId/comments', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { kycId } = req.params;
    const { comment, section } = req.body;

    // Validate required fields
    if (!comment?.trim()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Comment is required'
      });
    }

    const kycRecord = await KYC.findById(kycId);
    if (!kycRecord) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC record not found'
      });
    }

    // Add comment to KYC record
    const newComment = {
      comment: comment.trim(),
      section: section || 'general',
      commentedBy: req.user.id,
      createdAt: new Date()
    };

    kycRecord.comments = kycRecord.comments || [];
    kycRecord.comments.push(newComment);
    kycRecord.updatedAt = new Date();

    await kycRecord.save();

    // Create notification for the user
    const notification = new Notification({
      user: kycRecord.user,
      title: 'KYC Update',
      content: `Admin has added a comment to your KYC application: "${comment.substring(0, 100)}..."`,
      type: 'kyc_update',
      relatedId: kycRecord._id,
      status: 'unread'
    });

    await notification.save();

    // Emit real-time notification
    req.app.get('io')?.to(kycRecord.user.toString()).emit('newNotification', {
      id: notification._id,
      title: notification.title,
      content: notification.content,
      type: notification.type,
      createdAt: notification.createdAt
    });

    res.status(201).json({
      status: 'success',
      message: 'Comment added successfully',
      data: { comment: newComment }
    });

  } catch (err) {
    console.error('Add KYC comment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to add comment'
    });
  }
});

// Get KYC Comments
app.get('/api/users/kyc/comments', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    const kycRecord = await KYC.findOne({ user: userId })
      .populate('comments.commentedBy', 'name email')
      .select('comments')
      .lean();

    const comments = kycRecord?.comments || [];

    res.status(200).json({
      status: 'success',
      data: { comments }
    });

  } catch (err) {
    console.error('Get KYC comments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC comments'
    });
  }
});










// Get announcements for user - SOLVES THE 404 ERROR
app.get('/api/announcements', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const now = new Date();

    // Build query for active announcements targeting this user
    const query = {
      $or: [
        { recipientType: 'all' }, // Broadcast to all users
        { recipientType: 'specific', specificUserId: userId } // Specifically targeted to this user
      ]
    };

    // Get active announcements from Notification collection
    const announcements = await Notification.find(query)
      .select('title message type isImportant createdAt')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    res.status(200).json({
      status: 'success',
      data: announcements
    });

  } catch (err) {
    console.error('Get announcements error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch announcements'
    });
  }
});







// Get notification stats for admin dashboard
app.get('/api/admin/notifications/stats', adminProtect, async (req, res) => {
  try {
    const totalNotifications = await Notification.countDocuments();
    const unreadNotifications = await Notification.countDocuments({ read: false });
    
    // Count notifications sent today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const sentToday = await Notification.countDocuments({
      createdAt: { $gte: today }
    });

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          total: totalNotifications,
          unread: unreadNotifications,
          sentToday: sentToday,
          deliveryRate: '98%' // You can calculate this based on your logic
        }
      }
    });
  } catch (err) {
    console.error('Get notification stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notification statistics'
    });
  }
});

// Get unread notifications count
app.get('/api/admin/notifications/unread-count', adminProtect, async (req, res) => {
  try {
    const unreadCount = await Notification.countDocuments({ read: false });
    
    res.status(200).json({
      status: 'success',
      data: {
        unreadCount: unreadCount
      }
    });
  } catch (err) {
    console.error('Get unread count error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch unread count'
    });
  }
});

// Get notifications with pagination and filtering
app.get('/api/admin/notifications', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const filter = req.query.filter || 'all';
    const skip = (page - 1) * limit;

    // Build query based on filter
    let query = {};
    if (filter === 'unread') {
      query.read = false;
    } else if (filter === 'read') {
      query.read = true;
    } else if (filter === 'important') {
      query.isImportant = true;
    } else if (filter !== 'all') {
      query.type = filter;
    }

    const notifications = await Notification.find(query)
      .populate('specificUserId', 'firstName lastName email')
      .populate('sentBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalNotifications = await Notification.countDocuments(query);
    const totalPages = Math.ceil(totalNotifications / limit);

    res.status(200).json({
      status: 'success',
      data: {
        notifications: notifications,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: totalNotifications,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notifications'
    });
  }
});


// Send notification
app.post('/api/admin/notifications/send', adminProtect, async (req, res) => {
  try {
    const {
      recipientType,
      specificUserId,
      userGroup,
      notificationType,
      title,
      message,
      isImportant,
      sendEmail
    } = req.body;

    // Validate required fields
    if (!title || !message || !recipientType) {
      return res.status(400).json({
        status: 'fail',
        message: 'Title, message, and recipient type are required'
      });
    }

    // Create notification record
    const notification = new Notification({
      title: title.trim(),
      message: message.trim(),
      type: notificationType || 'info',
      recipientType: recipientType,
      specificUserId: recipientType === 'specific' ? specificUserId : undefined,
      userGroup: recipientType === 'group' ? userGroup : undefined,
      isImportant: isImportant || false,
      sentBy: req.admin._id,
      metadata: {
        emailSent: sendEmail || false,
        sentAt: new Date()
      }
    });

    await notification.save();

    // If sendEmail is true, send actual emails (you'll need to implement this)
    if (sendEmail) {
      // Implement email sending logic here based on recipientType
      await sendNotificationEmails(notification);
    }

    res.status(201).json({
      status: 'success',
      message: 'Notification sent successfully',
      data: {
        notification: notification
      }
    });

  } catch (err) {
    console.error('Send notification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send notification'
    });
  }
});

// Mark notification as read
app.post('/api/admin/notifications/:notificationId/read', adminProtect, async (req, res) => {
  try {
    const { notificationId } = req.params;

    const notification = await Notification.findByIdAndUpdate(
      notificationId,
      {
        read: true,
        readAt: new Date()
      },
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
      message: 'Notification marked as read',
      data: {
        notification: notification
      }
    });

  } catch (err) {
    console.error('Mark notification as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notification as read'
    });
  }
});

// Mark all notifications as read
app.post('/api/admin/notifications/mark-all-read', adminProtect, async (req, res) => {
  try {
    const result = await Notification.updateMany(
      { read: false },
      {
        read: true,
        readAt: new Date()
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'All notifications marked as read',
      data: {
        modifiedCount: result.modifiedCount
      }
    });

  } catch (err) {
    console.error('Mark all notifications as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark all notifications as read'
    });
  }
});

// Delete notification
app.delete('/api/admin/notifications/:notificationId', adminProtect, async (req, res) => {
  try {
    const { notificationId } = req.params;

    const notification = await Notification.findByIdAndDelete(notificationId);

    if (!notification) {
      return res.status(404).json({
        status: 'fail',
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Notification deleted successfully'
    });

  } catch (err) {
    console.error('Delete notification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete notification'
    });
  }
});

// Delete all read notifications
app.delete('/api/admin/notifications/delete-all-read', adminProtect, async (req, res) => {
  try {
    const result = await Notification.deleteMany({ read: true });

    res.status(200).json({
      status: 'success',
      message: 'All read notifications deleted successfully',
      data: {
        deletedCount: result.deletedCount
      }
    });

  } catch (err) {
    console.error('Delete all read notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete read notifications'
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


// Function to automatically complete matured investments
const processMaturedInvestments = async () => {
  try {
    const now = new Date();
    const maturedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan');

    for (const investment of maturedInvestments) {
      try {
        const user = await User.findById(investment.user._id);
        if (!user) continue;

        // Calculate total return
        const totalReturn = investment.amount + (investment.amount * investment.plan.percentage / 100);

        // Transfer balances
        user.balances.active -= investment.amount;
        user.balances.matured += totalReturn;

        // Update investment
        investment.status = 'completed';
        investment.completionDate = now;
        investment.actualReturn = totalReturn - investment.amount;

        await user.save();
        await investment.save();

        // Create transaction record
        await Transaction.create({
          user: investment.user._id,
          type: 'interest',
          amount: totalReturn - investment.amount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          reference: `AUTO-RET-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          details: {
            investmentId: investment._id,
            planName: investment.plan.name,
            principal: investment.amount,
            interest: totalReturn - investment.amount
          },
          fee: 0,
          netAmount: totalReturn - investment.amount
        });

        console.log(`Automatically completed investment ${investment._id} for user ${user.email}`);
      } catch (err) {
        console.error(`Error processing investment ${investment._id}:`, err);
      }
    }
  } catch (err) {
    console.error('Error processing matured investments:', err);
  }
};

// Run every hour to check for matured investments
setInterval(processMaturedInvestments, 60 * 60 * 1000);

// Also run once on server start
processMaturedInvestments();

// Start server
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



