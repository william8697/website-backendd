require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const socketio = require('socket.io');
const http = require('http');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: ['https://bithhash.vercel.app'],
    methods: ['GET', 'POST']
  }
});

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://bithhash.vercel.app';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com';
const MAILTRAP_USER = process.env.MAILTRAP_USER || '7c707ac161af1c';
const MAILTRAP_PASS = process.env.MAILTRAP_PASS || '6c08aa4f2c679a';
const BTC_DEPOSIT_ADDRESS = process.env.BTC_DEPOSIT_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// Redis configuration
const redisClient = new Redis({
  host: 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: 14450,
  password: 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

// Connect to MongoDB with connection pooling
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  poolSize: 50, // Increased connection pool size
  socketTimeoutMS: 30000,
  connectTimeoutMS: 30000,
  serverSelectionTimeoutMS: 50000
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// MongoDB models
const User = require('./models/User');
const Transaction = require('./models/Transaction');
const Investment = require('./models/Investment');
const Plan = require('./models/Plan');
const KYC = require('./models/KYC');
const Referral = require('./models/Referral');
const ActivityLog = require('./models/ActivityLog');
const APIKey = require('./models/APIKey');
const SupportTicket = require('./models/SupportTicket');
const Loan = require('./models/Loan');
const Savings = require('./models/Savings');
const Admin = require('./models/Admin');

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(helmet());
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

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: MAILTRAP_USER,
    pass: MAILTRAP_PASS
  }
});

// Google OAuth client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Utility functions
const generateJWT = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

const createAndSendToken = (user, statusCode, res) => {
  const token = generateJWT(user._id);
  
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

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

const sendEmail = async (options) => {
  try {
    await transporter.sendMail(options);
  } catch (err) {
    console.error('Error sending email:', err);
  }
};

const cacheResponse = async (key, data, ttl = 3600) => {
  await redisClient.setex(key, ttl, JSON.stringify(data));
};

const getCachedData = async (key) => {
  const cachedData = await redisClient.get(key);
  return cachedData ? JSON.parse(cachedData) : null;
};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });
  
  socket.on('adminJoin', (adminId) => {
    socket.join(`admin-${adminId}`);
    console.log(`Admin ${adminId} joined their room`);
  });
  
  socket.on('sendMessage', async ({ senderId, receiverId, message }) => {
    try {
      const newMessage = await SupportTicket.create({
        sender: senderId,
        receiver: receiverId,
        message
      });
      
      io.to(receiverId).emit('receiveMessage', newMessage);
      socket.emit('messageSent', newMessage);
    } catch (err) {
      console.error('Error sending message:', err);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Routes

// 1. Authentication Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, city, referralCode } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      referralCode: referralCode || undefined
    });
    
    // Handle referral if code exists
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        await Referral.create({
          referrer: referrer._id,
          referee: newUser._id
        });
        
        // Update referrer's balance or give bonus
        referrer.referralBonus += 10; // Example bonus
        await referrer.save();
      }
    }
    
    // Generate referral code for new user if not exists
    if (!newUser.referralCode) {
      newUser.referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
      await newUser.save();
    }
    
    // Send welcome email
    const mailOptions = {
      from: 'Bithash <no-reply@bithash.com>',
      to: newUser.email,
      subject: 'Welcome to Bithash!',
      html: `<p>Hi ${newUser.firstName}, welcome to Bithash! Your account has been successfully created.</p>`
    };
    
    await sendEmail(mailOptions);
    
    // Create token and send response
    createAndSendToken(newUser, 201, res);
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during signup'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // 1) Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    // 3) Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      return res.status(202).json({
        status: 'success',
        twoFactorRequired: true,
        tempToken: generateJWT(user._id, '5m')
      });
    }
    
    // 4) If everything ok, send token to client
    createAndSendToken(user, 200, res);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
    });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { tokenId } = req.body;
    
    const ticket = await googleClient.verifyIdToken({
      idToken: tokenId,
      audience: GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { email, given_name, family_name, picture } = payload;
    
    // Check if user exists
    let user = await User.findOne({ email });
    
    if (!user) {
      // Create new user
      const randomPassword = crypto.randomBytes(16).toString('hex');
      const hashedPassword = await bcrypt.hash(randomPassword, 12);
      
      user = await User.create({
        firstName: given_name,
        lastName: family_name,
        email,
        password: hashedPassword,
        photo: picture,
        isVerified: true
      });
      
      // Generate referral code
      user.referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
      await user.save();
      
      // Send welcome email
      const mailOptions = {
        from: 'Bithash <no-reply@bithash.com>',
        to: user.email,
        subject: 'Welcome to Bithash!',
        html: `<p>Hi ${user.firstName}, welcome to Bithash! Your account has been successfully created via Google.</p>`
      };
      
      await sendEmail(mailOptions);
    }
    
    // Create token and send response
    createAndSendToken(user, 200, res);
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during Google authentication'
    });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // 1) Get user based on POSTed email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({
        status: 'success',
        message: 'If the email exists, a reset token will be sent'
      });
    }
    
    // 2) Generate the random reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();
    
    // 3) Send it to user's email
    const resetURL = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      from: 'Bithash <no-reply@bithash.com>',
      to: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      html: `<p>Hi ${user.firstName},</p>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <a href="${resetURL}">${resetURL}</a>
      <p>If you didn't request this, please ignore this email.</p>`
    };
    
    await sendEmail(mailOptions);
    
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing your request'
    });
  }
});

app.patch('/api/auth/reset-password/:token', async (req, res) => {
  try {
    // 1) Get user based on the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');
    
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });
    
    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }
    
    // 3) Update password and reset token fields
    user.password = await bcrypt.hash(req.body.password, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    
    // 4) Log the user in, send JWT
    createAndSendToken(user, 200, res);
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting your password'
    });
  }
});

// 2. User Routes
app.get('/api/users/me', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user still exists
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
    console.error('Get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user data'
    });
  }
});

app.put('/api/users/profile', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Filter out unwanted fields names that are not allowed to be updated
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email', 'city', 'country', 'phone');
    
    // Update user document
    const updatedUser = await User.findByIdAndUpdate(decoded.id, filteredBody, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating your profile'
    });
  }
});

app.put('/api/users/password', async (req, res) => {
  try {
    // 1) Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 2) Get user from collection
    const user = await User.findById(decoded.id).select('+password');
    
    // 3) Check if POSTed current password is correct
    if (!(await bcrypt.compare(req.body.currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is wrong.'
      });
    }
    
    // 4) If so, update password
    user.password = await bcrypt.hash(req.body.newPassword, 12);
    await user.save();
    
    // 5) Log user in, send JWT
    createAndSendToken(user, 200, res);
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating your password'
    });
  }
});

app.put('/api/users/theme', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Update theme preference
    await User.findByIdAndUpdate(decoded.id, { theme: req.body.theme });
    
    res.status(200).json({
      status: 'success',
      message: 'Theme preference updated'
    });
  } catch (err) {
    console.error('Update theme error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating your theme preference'
    });
  }
});

app.get('/api/users/balance', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user with balance
    const user = await User.findById(decoded.id).select('balance activeBalance maturedBalance savingsBalance');
    
    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balance,
        activeBalance: user.activeBalance,
        maturedBalance: user.maturedBalance,
        savingsBalance: user.savingsBalance
      }
    });
  } catch (err) {
    console.error('Get balance error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching your balance'
    });
  }
});

app.get('/api/users/activity', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get activity logs
    const activities = await ActivityLog.find({ user: decoded.id })
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
    console.error('Get activity error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching your activity'
    });
  }
});

app.get('/api/users/notifications', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user with notifications
    const user = await User.findById(decoded.id).select('notificationPreferences');
    
    res.status(200).json({
      status: 'success',
      data: {
        notifications: user.notificationPreferences
      }
    });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching your notifications'
    });
  }
});

app.put('/api/users/notifications', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Update notification preferences
    await User.findByIdAndUpdate(decoded.id, { notificationPreferences: req.body });
    
    res.status(200).json({
      status: 'success',
      message: 'Notification preferences updated'
    });
  } catch (err) {
    console.error('Update notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating your notification preferences'
    });
  }
});

app.post('/api/users/deactivate', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Deactivate account
    await User.findByIdAndUpdate(decoded.id, { active: false });
    
    res.status(200).json({
      status: 'success',
      message: 'Your account has been deactivated'
    });
  } catch (err) {
    console.error('Deactivate account error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deactivating your account'
    });
  }
});

// 3. Two-Factor Authentication Routes
app.get('/api/auth/2fa', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user
    const user = await User.findById(decoded.id).select('twoFactorEnabled twoFactorMethod');
    
    res.status(200).json({
      status: 'success',
      data: {
        twoFactorEnabled: user.twoFactorEnabled,
        twoFactorMethod: user.twoFactorMethod
      }
    });
  } catch (err) {
    console.error('Get 2FA status error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching 2FA status'
    });
  }
});

app.post('/api/auth/2fa/email', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Save code to user
    await User.findByIdAndUpdate(decoded.id, {
      twoFactorCode: code,
      twoFactorCodeExpires: Date.now() + 10 * 60 * 1000 // 10 minutes
    });
    
    // Get user email
    const user = await User.findById(decoded.id).select('email firstName');
    
    // Send email with code
    const mailOptions = {
      from: 'Bithash <no-reply@bithash.com>',
      to: user.email,
      subject: 'Your Two-Factor Authentication Code',
      html: `<p>Hi ${user.firstName},</p>
      <p>Your two-factor authentication code is: <strong>${code}</strong></p>
      <p>This code will expire in 10 minutes.</p>`
    };
    
    await sendEmail(mailOptions);
    
    res.status(200).json({
      status: 'success',
      message: '2FA code sent to your email'
    });
  } catch (err) {
    console.error('Send 2FA email error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the 2FA code'
    });
  }
});

app.post('/api/auth/2fa/email/verify', async (req, res) => {
  try {
    const { code } = req.body;
    
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user with 2FA code
    const user = await User.findOne({
      _id: decoded.id,
      twoFactorCode: code,
      twoFactorCodeExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid or expired code'
      });
    }
    
    // Clear the code
    user.twoFactorCode = undefined;
    user.twoFactorCodeExpires = undefined;
    user.twoFactorEnabled = true;
    user.twoFactorMethod = 'email';
    await user.save();
    
    // Generate new token
    const newToken = generateJWT(user._id);
    
    res.status(200).json({
      status: 'success',
      token: newToken,
      data: {
        user
      }
    });
  } catch (err) {
    console.error('Verify 2FA email error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while verifying the 2FA code'
    });
  }
});

app.get('/api/auth/2fa/totp/setup', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user email
    const user = await User.findById(decoded.id).select('email firstName');
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Bithash (${user.email})`
    });
    
    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    
    // Save secret temporarily (not enabling 2FA yet)
    await User.findByIdAndUpdate(decoded.id, {
      twoFactorTempSecret: secret.base32
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        secret: secret.base32,
        qrCode
      }
    });
  } catch (err) {
    console.error('Setup TOTP error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while setting up TOTP'
    });
  }
});

app.post('/api/auth/2fa/totp/verify', async (req, res) => {
  try {
    const { code } = req.body;
    
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user with temp secret
    const user = await User.findById(decoded.id).select('twoFactorTempSecret');
    
    if (!user.twoFactorTempSecret) {
      return res.status(400).json({
        status: 'fail',
        message: 'No TOTP setup in progress'
      });
    }
    
    // Verify code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorTempSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });
    
    if (!verified) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid code'
      });
    }
    
    // Enable TOTP
    user.twoFactorSecret = user.twoFactorTempSecret;
    user.twoFactorTempSecret = undefined;
    user.twoFactorEnabled = true;
    user.twoFactorMethod = 'totp';
    await user.save();
    
    // Generate recovery codes
    const recoveryCodes = Array.from({ length: 8 }, () => 
      crypto.randomBytes(5).toString('hex').toUpperCase()
    );
    
    // Hash and save recovery codes
    user.twoFactorRecoveryCodes = recoveryCodes.map(code => 
      crypto.createHash('sha256').update(code).digest('hex')
    );
    await user.save();
    
    // Generate new token
    const newToken = generateJWT(user._id);
    
    res.status(200).json({
      status: 'success',
      token: newToken,
      data: {
        recoveryCodes
      }
    });
  } catch (err) {
    console.error('Verify TOTP error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while verifying TOTP'
    });
  }
});

app.post('/api/auth/2fa/disable', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Disable 2FA
    await User.findByIdAndUpdate(decoded.id, {
      twoFactorEnabled: false,
      twoFactorMethod: undefined,
      twoFactorSecret: undefined,
      twoFactorRecoveryCodes: undefined
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled'
    });
  } catch (err) {
    console.error('Disable 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while disabling 2FA'
    });
  }
});

// 4. KYC Routes
app.get('/api/kyc', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get KYC status
    const kyc = await KYC.findOne({ user: decoded.id })
      .sort('-createdAt')
      .limit(1);
    
    res.status(200).json({
      status: 'success',
      data: {
        kyc: kyc || null
      }
    });
  } catch (err) {
    console.error('Get KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching KYC status'
    });
  }
});

// Configure multer for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = './uploads/kyc';
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const filename = `${uuidv4()}${ext}`;
      cb(null, filename);
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

app.post('/api/kyc', upload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 },
  { name: 'proofOfAddress', maxCount: 1 }
]), async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get files
    const files = req.files;
    if (!files || !files.idFront || !files.selfie) {
      return res.status(400).json({
        status: 'fail',
        message: 'ID front and selfie are required'
      });
    }
    
    // Create KYC submission
    const kycData = {
      user: decoded.id,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      dob: req.body.dob,
      address: req.body.address,
      city: req.body.city,
      country: req.body.country,
      postalCode: req.body.postalCode,
      idType: req.body.idType,
      idNumber: req.body.idNumber,
      idFront: files.idFront[0].path,
      idBack: files.idBack ? files.idBack[0].path : undefined,
      selfie: files.selfie[0].path,
      proofOfAddress: files.proofOfAddress ? files.proofOfAddress[0].path : undefined,
      status: 'pending'
    };
    
    const kyc = await KYC.create(kycData);
    
    res.status(201).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    console.error('Submit KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while submitting KYC'
    });
  }
});

// 5. Referral Routes
app.get('/api/referrals', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get referral stats
    const referrals = await Referral.find({ referrer: decoded.id })
      .populate('referee', 'firstName lastName email createdAt');
    
    // Get user's referral code
    const user = await User.findById(decoded.id).select('referralCode referralBonus');
    
    res.status(200).json({
      status: 'success',
      data: {
        referralCode: user.referralCode,
        referralBonus: user.referralBonus,
        referrals,
        referralLink: `${FRONTEND_URL}/signup?ref=${user.referralCode}`
      }
    });
  } catch (err) {
    console.error('Get referrals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching referral data'
    });
  }
});

// 6. Transaction Routes
app.get('/api/transactions', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get transactions
    const transactions = await Transaction.find({ user: decoded.id })
      .sort('-createdAt')
      .limit(50);
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
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

app.get('/api/transactions/deposits', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get deposit transactions
    const deposits = await Transaction.find({
      user: decoded.id,
      type: 'deposit'
    })
    .sort('-createdAt')
    .limit(50);
    
    res.status(200).json({
      status: 'success',
      results: deposits.length,
      data: {
        deposits
      }
    });
  } catch (err) {
    console.error('Get deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching deposits'
    });
  }
});

app.get('/api/transactions/withdrawals', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get withdrawal transactions
    const withdrawals = await Transaction.find({
      user: decoded.id,
      type: 'withdrawal'
    })
    .sort('-createdAt')
    .limit(50);
    
    res.status(200).json({
      status: 'success',
      results: withdrawals.length,
      data: {
        withdrawals
      }
    });
  } catch (err) {
    console.error('Get withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching withdrawals'
    });
  }
});

app.post('/api/transactions/deposit', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { amount, method } = req.body;
    
    // Create deposit transaction
    const transaction = await Transaction.create({
      user: decoded.id,
      type: 'deposit',
      amount,
      method,
      status: 'pending',
      btcAddress: method === 'bitcoin' ? BTC_DEPOSIT_ADDRESS : undefined
    });
    
    // If method is card, simulate instant approval (in production, this would wait for payment processor)
    if (method === 'card') {
      setTimeout(async () => {
        transaction.status = 'completed';
        await transaction.save();
        
        // Update user balance
        await User.findByIdAndUpdate(decoded.id, {
          $inc: { balance: amount }
        });
        
        // Notify user via socket
        io.to(decoded.id).emit('transactionUpdate', {
          type: 'deposit',
          amount,
          status: 'completed'
        });
      }, 3000);
    }
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    console.error('Create deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating deposit'
    });
  }
});

app.post('/api/transactions/withdraw', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { amount, method, address, notes } = req.body;
    
    // Check user balance
    const user = await User.findById(decoded.id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Create withdrawal transaction
    const transaction = await Transaction.create({
      user: decoded.id,
      type: 'withdrawal',
      amount,
      method,
      address,
      notes,
      status: 'pending'
    });
    
    // Deduct from user balance immediately
    user.balance -= amount;
    await user.save();
    
    // In production, this would be processed by admin approval
    // Here we simulate approval after 5 seconds
    setTimeout(async () => {
      transaction.status = 'completed';
      await transaction.save();
      
      // Notify user via socket
      io.to(decoded.id).emit('transactionUpdate', {
        type: 'withdrawal',
        amount,
        status: 'completed'
      });
    }, 5000);
    
    res.status(201).json({
      status: 'success',
      data: {
        transaction
      }
    });
  } catch (err) {
    console.error('Create withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating withdrawal'
    });
  }
});

// 7. Investment Routes
app.get('/api/plans', async (req, res) => {
  try {
    // Check cache first
    const cachedPlans = await getCachedData('investmentPlans');
    if (cachedPlans) {
      return res.status(200).json({
        status: 'success',
        data: {
          plans: cachedPlans
        }
      });
    }
    
    // Get plans from DB
    const plans = await Plan.find({ active: true });
    
    // Cache plans
    await cacheResponse('investmentPlans', plans);
    
    res.status(200).json({
      status: 'success',
      data: {
        plans
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

app.get('/api/investments', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get investments with plan details
    const investments = await Investment.find({ user: decoded.id })
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
    console.error('Get investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investments'
    });
  }
});

app.post('/api/investments', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { planId, amount } = req.body;
    
    // Get plan
    const plan = await Plan.findById(planId);
    if (!plan || !plan.active) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    // Check minimum investment
    if (amount < plan.minInvestment) {
      return res.status(400).json({
        status: 'fail',
        message: `Minimum investment is ${plan.minInvestment}`
      });
    }
    
    // Check user balance
    const user = await User.findById(decoded.id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct from balance
    user.balance -= amount;
    user.activeBalance += amount;
    await user.save();
    
    // Create investment
    const investment = await Investment.create({
      user: decoded.id,
      plan: planId,
      amount,
      startDate: new Date(),
      endDate: moment().add(plan.duration, 'days').toDate(),
      status: 'active'
    });
    
    // Create transaction
    await Transaction.create({
      user: decoded.id,
      type: 'investment',
      amount,
      status: 'completed'
    });
    
    // Schedule daily earnings
    const dailyEarning = (amount * plan.dailyReturn) / 100;
    const interval = setInterval(async () => {
      try {
        // Check if investment is still active
        const currentInvestment = await Investment.findById(investment._id);
        if (!currentInvestment || currentInvestment.status !== 'active') {
          clearInterval(interval);
          return;
        }
        
        // Check if investment period has ended
        if (new Date() > currentInvestment.endDate) {
          // Finalize investment
          currentInvestment.status = 'completed';
          await currentInvestment.save();
          
          // Move funds from active to matured balance
          await User.findByIdAndUpdate(decoded.id, {
            $inc: {
              activeBalance: -currentInvestment.amount,
              maturedBalance: currentInvestment.amount
            }
          });
          
          clearInterval(interval);
          return;
        }
        
        // Add daily earnings
        await User.findByIdAndUpdate(decoded.id, {
          $inc: { balance: dailyEarning }
        });
        
        // Record earning transaction
        await Transaction.create({
          user: decoded.id,
          type: 'earning',
          amount: dailyEarning,
          status: 'completed'
        });
        
        // Notify user
        io.to(decoded.id).emit('newEarning', {
          amount: dailyEarning,
          investmentId: investment._id
        });
      } catch (err) {
        console.error('Investment earning error:', err);
        clearInterval(interval);
      }
    }, 24 * 60 * 60 * 1000); // 24 hours
    
    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (err) {
    console.error('Create investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating investment'
    });
  }
});

// 8. Savings & Loans Routes
app.get('/api/savings', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get savings
    const savings = await Savings.find({ user: decoded.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: savings.length,
      data: {
        savings
      }
    });
  } catch (err) {
    console.error('Get savings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching savings'
    });
  }
});

app.post('/api/savings', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { amount, duration } = req.body;
    
    // Check user balance
    const user = await User.findById(decoded.id);
    if (user.balance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance'
      });
    }
    
    // Deduct from balance and add to savings
    user.balance -= amount;
    user.savingsBalance += amount;
    await user.save();
    
    // Create savings
    const savings = await Savings.create({
      user: decoded.id,
      amount,
      startDate: new Date(),
      endDate: moment().add(duration, 'days').toDate(),
      interestRate: 5, // 5% annual interest
      status: 'active'
    });
    
    // Create transaction
    await Transaction.create({
      user: decoded.id,
      type: 'savings',
      amount,
      status: 'completed'
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        savings
      }
    });
  } catch (err) {
    console.error('Create savings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating savings'
    });
  }
});

app.get('/api/loans', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get loans
    const loans = await Loan.find({ user: decoded.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: loans.length,
      data: {
        loans
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

app.post('/api/loans', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { amount, duration, purpose } = req.body;
    
    // Check savings balance (loan limit is 50% of savings)
    const user = await User.findById(decoded.id);
    const loanLimit = user.savingsBalance * 0.5;
    
    if (amount > loanLimit) {
      return res.status(400).json({
        status: 'fail',
        message: `Loan amount exceeds limit of ${loanLimit}`
      });
    }
    
    // Create loan (pending admin approval)
    const loan = await Loan.create({
      user: decoded.id,
      amount,
      duration,
      purpose,
      status: 'pending',
      interestRate: 10 // 10% interest
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        loan
      }
    });
  } catch (err) {
    console.error('Create loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating loan'
    });
  }
});

// 9. API Key Routes
app.get('/api/users/apikeys', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get API keys
    const apiKeys = await APIKey.find({ user: decoded.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: apiKeys.length,
      data: {
        apiKeys
      }
    });
  } catch (err) {
    console.error('Get API keys error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching API keys'
    });
  }
});

app.post('/api/users/apikeys', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { name, permissions } = req.body;
    
    // Generate API key
    const apiKey = crypto.randomBytes(32).toString('hex');
    const apiSecret = crypto.randomBytes(64).toString('hex');
    
    // Hash secrets before storing
    const hashedApiKey = crypto.createHash('sha256').update(apiKey).digest('hex');
    const hashedApiSecret = crypto.createHash('sha256').update(apiSecret).digest('hex');
    
    // Create API key record
    const newApiKey = await APIKey.create({
      user: decoded.id,
      name,
      permissions,
      apiKey: hashedApiKey,
      apiSecret: hashedApiSecret,
      lastUsed: null
    });
    
    // Return the unhashed keys only once
    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          id: newApiKey._id,
          name: newApiKey.name,
          key: apiKey,
          secret: apiSecret,
          createdAt: newApiKey.createdAt
        }
      }
    });
  } catch (err) {
    console.error('Create API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating API key'
    });
  }
});

app.delete('/api/users/apikeys/:id', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Delete API key
    await APIKey.findOneAndDelete({
      _id: req.params.id,
      user: decoded.id
    });
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    console.error('Delete API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting API key'
    });
  }
});

// 10. Admin Routes
app.post('/api/admin/auth/login', async (req, res) => {
  try {
    const { email, password, code } = req.body;
    
    // 1) Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }
    
    // 2) Check if admin exists && password is correct
    const admin = await Admin.findOne({ email }).select('+password');
    
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }
    
    // 3) Check if 2FA is enabled and code provided
    if (admin.twoFactorEnabled && !code) {
      return res.status(202).json({
        status: 'success',
        twoFactorRequired: true,
        tempToken: generateJWT(admin._id, '5m')
      });
    }
    
    // 4) Verify 2FA code if required
    if (admin.twoFactorEnabled && code) {
      const verified = speakeasy.totp.verify({
        secret: admin.twoFactorSecret,
        encoding: 'base32',
        token: code,
        window: 1
      });
      
      if (!verified) {
        return res.status(401).json({
          status: 'fail',
          message: 'Invalid 2FA code'
        });
      }
    }
    
    // 5) If everything ok, send token to client
    const token = generateJWT(admin._id);
    
    // Remove password from output
    admin.password = undefined;
    
    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
    });
  }
});

app.get('/api/admin/dashboard', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Get dashboard stats
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ active: true });
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: 'withdrawal',
      status: 'pending'
    });
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    
    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          totalUsers,
          activeUsers,
          pendingKYC,
          pendingWithdrawals,
          totalDeposits: totalDeposits[0]?.total || 0,
          totalWithdrawals: totalWithdrawals[0]?.total || 0,
          activeInvestments
        }
      }
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching dashboard data'
    });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Query
    let query = User.find();
    
    // Sorting
    if (req.query.sort) {
      const sortBy = req.query.sort.split(',').join(' ');
      query = query.sort(sortBy);
    } else {
      query = query.sort('-createdAt');
    }
    
    // Execute query
    const users = await query.skip(skip).limit(limit);
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
    console.error('Admin get users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching users'
    });
  }
});

app.get('/api/admin/users/:id', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Get user
    const user = await User.findById(req.params.id);
    
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
    console.error('Admin get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user'
    });
  }
});

app.patch('/api/admin/users/:id', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Filter out unwanted fields
    const filteredBody = filterObj(
      req.body,
      'firstName',
      'lastName',
      'email',
      'balance',
      'activeBalance',
      'maturedBalance',
      'savingsBalance',
      'referralBonus',
      'active',
      'role'
    );
    
    // Update user
    const updatedUser = await User.findByIdAndUpdate(req.params.id, filteredBody, {
      new: true,
      runValidators: true
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    console.error('Admin update user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating user'
    });
  }
});

app.get('/api/admin/kyc/pending', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Get pending KYC
    const pendingKYC = await KYC.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: pendingKYC.length,
      data: {
        kyc: pendingKYC
      }
    });
  } catch (err) {
    console.error('Admin get pending KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching pending KYC'
    });
  }
});

app.post('/api/admin/kyc/:id/review', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    const { status, reason } = req.body;
    
    // Update KYC status
    const kyc = await KYC.findByIdAndUpdate(
      req.params.id,
      { status, reason, reviewedBy: decoded.id, reviewedAt: new Date() },
      { new: true }
    ).populate('user', 'firstName lastName email');
    
    if (!kyc) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }
    
    // Update user verification status
    if (status === 'approved') {
      await User.findByIdAndUpdate(kyc.user._id, { isVerified: true });
    }
    
    // Notify user
    io.to(kyc.user._id.toString()).emit('kycUpdate', {
      status,
      reason
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        kyc
      }
    });
  } catch (err) {
    console.error('Admin review KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while reviewing KYC'
    });
  }
});

app.get('/api/admin/withdrawals/pending', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Get pending withdrawals
    const pendingWithdrawals = await Transaction.find({ 
      type: 'withdrawal',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: pendingWithdrawals.length,
      data: {
        withdrawals: pendingWithdrawals
      }
    });
  } catch (err) {
    console.error('Admin get pending withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching pending withdrawals'
    });
  }
});

app.post('/api/admin/withdrawals/:id/process', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    const { status, transactionHash, notes } = req.body;
    
    // Update withdrawal status
    const withdrawal = await Transaction.findByIdAndUpdate(
      req.params.id,
      { 
        status,
        transactionHash: status === 'completed' ? transactionHash : undefined,
        notes,
        processedBy: decoded.id,
        processedAt: new Date()
      },
      { new: true }
    ).populate('user', 'firstName lastName email');
    
    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    // If rejected, return funds to user
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.user._id, {
        $inc: { balance: withdrawal.amount }
      });
    }
    
    // Notify user
    io.to(withdrawal.user._id.toString()).emit('withdrawalUpdate', {
      id: withdrawal._id,
      status,
      amount: withdrawal.amount
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawal
      }
    });
  } catch (err) {
    console.error('Admin process withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing withdrawal'
    });
  }
});

app.post('/api/admin/loans/:id/approve', async (req, res) => {
  try {
    // Verify admin token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    
    // Approve loan
    const loan = await Loan.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'active',
        startDate: new Date(),
        endDate: moment().add(req.body.duration, 'days').toDate(),
        approvedBy: decoded.id,
        approvedAt: new Date()
      },
      { new: true }
    ).populate('user', 'firstName lastName email');
    
    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Loan not found'
      });
    }
    
    // Add funds to user balance
    await User.findByIdAndUpdate(loan.user._id, {
      $inc: { balance: loan.amount }
    });
    
    // Create transaction
    await Transaction.create({
      user: loan.user._id,
      type: 'loan',
      amount: loan.amount,
      status: 'completed'
    });
    
    // Schedule loan repayment
    const dailyPayment = (loan.amount * (loan.interestRate / 100)) / loan.duration;
    const interval = setInterval(async () => {
      try {
        // Check if loan is still active
        const currentLoan = await Loan.findById(loan._id);
        if (!currentLoan || currentLoan.status !== 'active') {
          clearInterval(interval);
          return;
        }
        
        // Check if loan period has ended
        if (new Date() > currentLoan.endDate) {
          // Finalize loan
          currentLoan.status = 'completed';
          await currentLoan.save();
          
          clearInterval(interval);
          return;
        }
        
        // Deduct daily payment from user balance
        const user = await User.findById(currentLoan.user._id);
        if (user.balance >= dailyPayment) {
          user.balance -= dailyPayment;
          await user.save();
          
          // Record payment transaction
          await Transaction.create({
            user: currentLoan.user._id,
            type: 'loan_payment',
            amount: dailyPayment,
            status: 'completed'
          });
        } else {
          // Mark loan as defaulted if payment fails
          currentLoan.status = 'defaulted';
          await currentLoan.save();
          clearInterval(interval);
        }
      } catch (err) {
        console.error('Loan payment error:', err);
        clearInterval(interval);
      }
    }, 24 * 60 * 60 * 1000); // 24 hours
    
    // Notify user
    io.to(loan.user._id.toString()).emit('loanUpdate', {
      id: loan._id,
      status: 'active',
      amount: loan.amount
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        loan
      }
    });
  } catch (err) {
    console.error('Admin approve loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while approving loan'
    });
  }
});

// 11. Mining Data Routes
app.get('/api/mining/metrics', async (req, res) => {
  try {
    // Check cache first
    const cachedMetrics = await getCachedData('miningMetrics');
    if (cachedMetrics) {
      return res.status(200).json({
        status: 'success',
        data: {
          metrics: cachedMetrics
        }
      });
    }
    
    // Simulate mining metrics (in production, this would come from mining software API)
    const metrics = {
      hashRate: Math.floor(Math.random() * 100) + 50, // TH/s
      uptime: Math.floor(Math.random() * 100), // %
      activeRigs: Math.floor(Math.random() * 50) + 10,
      btcMined: (Math.random() * 0.5).toFixed(8),
      powerConsumption: Math.floor(Math.random() * 500) + 1000, // kW
      difficulty: Math.floor(Math.random() * 10) + 20 // T
    };
    
    // Cache metrics
    await cacheResponse('miningMetrics', metrics, 300); // 5 minutes
    
    res.status(200).json({
      status: 'success',
      data: {
        metrics
      }
    });
  } catch (err) {
    console.error('Get mining metrics error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching mining metrics'
    });
  }
});

// 12. Platform Stats Routes
app.get('/api/stats', async (req, res) => {
  try {
    // Check cache first
    const cachedStats = await getCachedData('platformStats');
    if (cachedStats) {
      return res.status(200).json({
        status: 'success',
        data: {
          stats: cachedStats
        }
      });
    }
    
    // Get platform stats
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ active: true });
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    
    const stats = {
      totalUsers,
      activeUsers,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      activeInvestments,
      btcPrice: await getBTCPrice() // Get current BTC price
    };
    
    // Cache stats
    await cacheResponse('platformStats', stats, 60); // 1 minute
    
    res.status(200).json({
      status: 'success',
      data: {
        stats
      }
    });
  } catch (err) {
    console.error('Get platform stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching platform stats'
    });
  }
});

// Utility function to get BTC price
async function getBTCPrice() {
  try {
    // In production, this would fetch from CoinGecko API
    // For demo purposes, we'll return a random value
    return Math.random() * 10000 + 30000; // Between 30k and 40k
  } catch (err) {
    console.error('Get BTC price error:', err);
    return 35000; // Fallback value
  }
}

// 13. Support Routes
app.post('/api/support', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { subject, message } = req.body;
    
    // Create support ticket
    const ticket = await SupportTicket.create({
      user: decoded.id,
      subject,
      message,
      status: 'open'
    });
    
    // Notify admins
    io.emit('newSupportTicket', ticket);
    
    res.status(201).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    console.error('Create support ticket error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating support ticket'
    });
  }
});

app.get('/api/support', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get support tickets
    const tickets = await SupportTicket.find({ user: decoded.id })
      .sort('-createdAt');
    
    res.status(200).json({
      status: 'success',
      results: tickets.length,
      data: {
        tickets
      }
    });
  } catch (err) {
    console.error('Get support tickets error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching support tickets'
    });
  }
});

// 14. Chat Routes
app.get('/api/chat/history', async (req, res) => {
  try {
    // Get user from JWT
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get chat history
    const messages = await SupportTicket.find({
      $or: [
        { sender: decoded.id, receiver: { $exists: true } },
        { receiver: decoded.id }
      ]
    })
    .sort('createdAt')
    .limit(100);
    
    res.status(200).json({
      status: 'success',
      results: messages.length,
      data: {
        messages
      }
    });
  } catch (err) {
    console.error('Get chat history error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching chat history'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', err => {
  console.error('Unhandled Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', err => {
  console.error('Uncaught Exception:', err);
  server.close(() => {
    process.exit(1);
  });
});
