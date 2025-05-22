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
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto-arbitrage?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected successfully');
    
    // Check if any admin exists
    const adminCount = await mongoose.model('Admin').countDocuments();
    if (adminCount === 0) {
      const adminEmail = 'admin@yourdomain.com';
      const adminPassword = 'yourSecurePassword123!';
      const salt = bcrypt.genSaltSync(12);
      const hashedPassword = bcrypt.hashSync(adminPassword, salt);
      
      await mongoose.model('Admin').create({
        email: adminEmail,
        password: hashedPassword,
        permissions: ['superadmin']
      });
      
      console.log('Initial admin created:', adminEmail);
    }
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors()); // Enable preflight for all routes
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api', limiter);

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false },
  walletAddress: { type: String, unique: true, sparse: true },
  country: { type: String },
  balance: {
    USD: { type: Number, default: 0 }
  },
  isSuspended: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDetails: {
    idFront: String,
    idBack: String
  },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pair: { type: String, required: true },
  type: { type: String, enum: ['buy', 'sell', 'arbitrage'], required: true },
  amount: { type: Number, required: true },
  price: { type: Number, required: true },
  profit: { type: Number },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'resolved'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  permissions: [String],
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const LogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  description: { type: String, required: true },
  type: { type: String, enum: ['login', 'trade', 'withdrawal', 'deposit'], required: true },
  timestamp: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  type: { type: String, enum: ['user', 'trade', 'ticket'], required: true },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Log = mongoose.model('Log', LogSchema);
const Notification = mongoose.model('Notification', NotificationSchema);

// JWT Config
const JWT_SECRET = 'your_jwt_secret_key';
const JWT_EXPIRES_IN = '30d';

// Utility functions
const createToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

// Auth Middleware
const adminProtect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ status: 'fail', message: 'You are not logged in! Please log in to get access.' });
  }

  try {
    const decoded = verifyToken(token);
    const currentAdmin = await Admin.findById(decoded.id);
    if (!currentAdmin) {
      return res.status(401).json({ status: 'fail', message: 'The admin belonging to this token does no longer exist.' });
    }
    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'fail', message: 'Invalid token. Please log in again.' });
  }
};

// API Routes

// Admin Auth Routes
app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password!' });
    }

    const admin = await Admin.findOne({ email }).select('+password');

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    const token = createToken(admin._id);

    admin.lastLogin = new Date();
    await admin.save();

    res.status(200).json({
      status: 'success',
      token,
      data: {
        admin: {
          _id: admin._id,
          email: admin.email,
          permissions: admin.permissions,
          lastLogin: admin.lastLogin,
          createdAt: admin.createdAt
        }
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/verify', adminProtect, (req, res) => {
  res.status(200).json({ 
    status: 'success', 
    data: {
      admin: req.admin
    }
  });
});

// Admin Dashboard Routes
app.get('/api/v1/admin/dashboard-stats', adminProtect, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ kycStatus: 'verified' });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          totalUsers,
          verifiedUsers,
          totalTrades,
          totalVolume: totalVolume.length ? totalVolume[0].total : 0
        }
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/notifications', adminProtect, async (req, res) => {
  try {
    const unreadCount = await Notification.countDocuments({ isRead: false });
    const pendingTickets = await Ticket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });

    const notifications = await Notification.find()
      .sort({ timestamp: -1 })
      .limit(5);

    res.status(200).json({
      status: 'success',
      data: {
        unreadCount,
        pendingTickets,
        pendingKYC,
        notifications
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin User Management Routes
app.get('/api/v1/admin/users', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status, kyc } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    if (status === 'active') query.isSuspended = false;
    if (status === 'inactive') query.isSuspended = true;
    if (kyc) query.kycStatus = kyc;

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password');

    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.post('/api/v1/admin/users/:id/reset-password', adminProtect, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Password has been reset successfully'
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.put('/api/v1/admin/users/:id/status', adminProtect, async (req, res) => {
  try {
    const { suspend } = req.body;
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    user.isSuspended = suspend;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: `User has been ${suspend ? 'suspended' : 'activated'}`
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin Trade Management Routes
app.get('/api/v1/admin/trades', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status, type } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { pair: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.status = status;
    if (type) query.type = type;

    const trades = await Trade.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Trade.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: trades.length,
      total,
      data: {
        trades
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin Ticket Management Routes
app.get('/api/v1/admin/tickets', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (search) {
      query.$or = [
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.status = status;

    const tickets = await Ticket.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Ticket.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: tickets.length,
      total,
      data: {
        tickets
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/tickets/:id', adminProtect, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id)
      .populate('userId', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.put('/api/v1/admin/tickets/:id', adminProtect, async (req, res) => {
  try {
    const { status } = req.body;

    const ticket = await Ticket.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('userId', 'firstName lastName email');

    if (!ticket) {
      return res.status(404).json({ status: 'fail', message: 'Ticket not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        ticket
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin KYC Management Routes
app.get('/api/v1/admin/kyc', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status } = req.query;
    const skip = (page - 1) * limit;

    const query = { kycStatus: { $ne: 'none' } };
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status) query.kycStatus = status;

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('firstName lastName email kycStatus kycDetails createdAt');

    const total = await User.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      data: {
        kycApplications: users
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.put('/api/v1/admin/kyc/:id/approve', adminProtect, async (req, res) => {
  try {
    const { approve } = req.body;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { kycStatus: approve ? 'verified' : 'rejected' },
      { new: true }
    ).select('firstName lastName email kycStatus');

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      message: `KYC has been ${approve ? 'approved' : 'rejected'}`,
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin Logs Routes
app.get('/api/v1/admin/logs', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 5 } = req.query;
    const skip = (page - 1) * limit;

    const logs = await Log.find()
      .populate('userId', 'firstName lastName email')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Log.countDocuments();

    res.status(200).json({
      status: 'success',
      results: logs.length,
      total,
      data: {
        logs
      }
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// Admin Export Routes
app.get('/api/v1/admin/users/export', adminProtect, async (req, res) => {
  try {
    const users = await User.find().select('-password');

    let csv = 'ID,First Name,Last Name,Email,Wallet Address,Country,KYC Status,Created At\n';
    users.forEach(user => {
      csv += `${user._id},${user.firstName},${user.lastName},${user.email},${user.walletAddress || ''},${user.country || ''},${user.kycStatus},${user.createdAt}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=users-export.csv');
    res.status(200).send(csv);
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/trades/export', adminProtect, async (req, res) => {
  try {
    const trades = await Trade.find().populate('userId', 'firstName lastName email');

    let csv = 'ID,User,Type,Amount,Profit,Status,Created At\n';
    trades.forEach(trade => {
      csv += `${trade._id},${trade.user.firstName} ${trade.user.lastName},${trade.type},${trade.amount},${trade.profit || 0},${trade.status},${trade.createdAt}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=trades-export.csv');
    res.status(200).send(csv);
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

app.get('/api/v1/admin/tickets/export', adminProtect, async (req, res) => {
  try {
    const tickets = await Ticket.find().populate('userId', 'firstName lastName email');

    let csv = 'ID,User,Subject,Status,Priority,Created At\n';
    tickets.forEach(ticket => {
      csv += `${ticket._id},${ticket.user.firstName} ${ticket.user.lastName},${ticket.subject},${ticket.status},${ticket.priority},${ticket.createdAt}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=tickets-export.csv');
    res.status(200).send(csv);
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
});

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  
  try {
    const decoded = verifyToken(token);
    ws.userId = decoded.id;
  } catch (err) {
    ws.close(1008, 'Invalid token');
    return;
  }

  ws.on('message', (message) => {
    console.log(`Received message from user ${ws.userId}: ${message}`);
  });

  ws.send(JSON.stringify({ type: 'connection', status: 'success' }));
});

// Upgrade HTTP server to WebSocket
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  server.close(() => {
    process.exit(1);
  });
});
