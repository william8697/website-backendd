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
const path = require('path');
const fs = require('fs');
const { ethers } = require('ethers');
const redis = require('redis');
const validator = require('validator');

// **Initialize Express**
const app = express();
const PORT = process.env.PORT || 5000;

// **Redis for Rate Limiting**
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

redisClient.on('error', (err) => console.error('Redis Error:', err));

// **MongoDB Connection**
const DB_URI = process.env.MONGODB_URI || 'mongodb+srv://mosesmwainaina1994:<OWlondlAbn3bJuj4>@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(DB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  poolSize: 50,
  socketTimeoutMS: 30000,
  connectTimeoutMS: 30000
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// **Middleware**
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true
}));
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// **Rate Limiting**
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 100, // 100 req/IP
  handler: (req, res) => res.status(429).json({ status: 'fail', message: 'Too many requests' })
});
app.use('/api', limiter);

// **Models**
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true },
  nonce: { type: String, select: false },
  firstName: String,
  lastName: String,
  balance: { type: Number, default: 0 },
  portfolio: { type: Map, of: Number, default: {} },
  isAdmin: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  lastLogin: Date
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' }
}, { timestamps: true });

const Trade = mongoose.model('Trade', TradeSchema);

// **JWT Token Generation**
const signToken = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET || '17581758Na.%', {
    expiresIn: '30d'
  });
};

// **Authentication Middleware**
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) return res.status(401).json({ status: 'fail', message: 'Not logged in' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%');
    const user = await User.findById(decoded.id);
    if (!user) throw new Error('User not found');
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ status: 'fail', message: 'Invalid token' });
  }
};

const restrictToAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ status: 'fail', message: 'Unauthorized' });
  }
  next();
};

// **WebSocket Server**
const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  if (!token) return ws.close(1008, 'Unauthorized');

  jwt.verify(token, process.env.JWT_SECRET || '17581758Na.%', (err, decoded) => {
    if (err) return ws.close(1008, 'Invalid token');
    ws.userId = decoded.id;
    console.log(`User ${decoded.id} connected`);
  });
});

// **Routes**
// **1. Auth Routes**
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const user = await User.create({ email, password, firstName, lastName });
    const token = signToken(user._id);
    res.status(201).json({ status: 'success', token });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: 'Registration failed' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Invalid credentials' });
    }
    const token = signToken(user._id);
    res.status(200).json({ status: 'success', token });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Login failed' });
  }
});

// **2. User Routes**
app.get('/api/v1/users/me', protect, async (req, res) => {
  res.status(200).json({ status: 'success', data: { user: req.user } });
});

// **3. Admin Routes**
app.get('/api/v1/admin/users', protect, restrictToAdmin, async (req, res) => {
  const users = await User.find();
  res.status(200).json({ status: 'success', data: { users } });
});

// **4. Trade Routes**
app.post('/api/v1/trades/buy', protect, async (req, res) => {
  try {
    const { fromCoin, toCoin, amount } = req.body;
    const rate = getExchangeRate(fromCoin, toCoin);
    const trade = await Trade.create({
      userId: req.user._id,
      type: 'buy',
      fromCoin,
      toCoin,
      amount,
      rate
    });
    res.status(201).json({ status: 'success', data: { trade } });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: 'Trade failed' });
  }
});

// **Error Handling**
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
});
