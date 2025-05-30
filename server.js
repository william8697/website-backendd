require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const http = require('http');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.##';
const DEPOSIT_WALLET = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB Connection
mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email Transport
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// Models
const User = mongoose.model('User', new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, select: false },
    walletAddress: { type: String, unique: true, sparse: true },
    country: { type: String, required: true },
    currency: { type: String, default: 'USD' },
    balance: { type: Number, default: 0 },
    balances: {
        BTC: { type: Number, default: 0 },
        ETH: { type: Number, default: 0 },
        BNB: { type: Number, default: 0 },
        USDT: { type: Number, default: 0 },
        XRP: { type: Number, default: 0 },
        SOL: { type: Number, default: 0 },
        ADA: { type: Number, default: 0 },
        DOGE: { type: Number, default: 0 },
        DOT: { type: Number, default: 0 },
        MATIC: { type: Number, default: 0 }
    },
    isAdmin: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
    kycDocs: [{
        docType: String,
        docNumber: String,
        frontImage: String,
        backImage: String,
        selfieImage: String,
        submittedAt: Date
    }],
    apiKey: { type: String, unique: true, sparse: true },
    settings: {
        twoFA: { type: Boolean, default: false },
        notifications: {
            email: { type: Boolean, default: true },
            push: { type: Boolean, default: true }
        },
        theme: { type: String, default: 'light' }
    },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion', 'bonus'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
    details: Object,
    txHash: String,
    walletAddress: String,
    createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    pair: { type: String, required: true },
    type: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true },
    price: { type: Number, required: true },
    total: { type: Number, required: true },
    status: { type: String, enum: ['open', 'filled', 'cancelled', 'partial'], default: 'open' },
    fee: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: Date
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'pending', 'resolved', 'closed'], default: 'open' },
    attachments: [String],
    responses: [{
        message: String,
        isAdmin: Boolean,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: Date
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    category: { type: String, required: true },
    order: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
}));

const SystemLog = mongoose.model('SystemLog', new mongoose.Schema({
    action: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    ipAddress: String,
    userAgent: String,
    details: Object,
    createdAt: { type: Date, default: Date.now }
}));

// Initialize default admin
async function initializeAdmin() {
    const adminExists = await User.findOne({ email: 'Admin@youngblood.com' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('17581758..', 12);
        await User.create({
            firstName: 'Admin',
            lastName: 'System',
            email: 'Admin@youngblood.com',
            password: hashedPassword,
            country: 'US',
            isAdmin: true,
            isVerified: true,
            balance: 1000000,
            apiKey: crypto.randomBytes(32).toString('hex')
        });
        console.log('Default admin account created');
    }
}

initializeAdmin();

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(helmet());

const allowedOrigins = [
    'http://localhost:3000',
    'https://website-xi-ten-52.vercel.app',
    'https://yourdomain.com'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// File upload
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = './uploads';
            if (!fs.existsSync(dir)) fs.mkdirSync(dir);
            cb(null, dir);
        },
        filename: (req, file, cb) => {
            cb(null, `${Date.now()}-${file.originalname}`);
        }
    }),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 }
});

// Auth middleware
const auth = async (req, res, next) => {
    try {
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies?.token) {
            token = req.cookies.token;
        }

        if (!token) return res.status(401).json({ success: false, message: 'Not authorized' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');

        if (!user) return res.status(401).json({ success: false, message: 'User not found' });

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Not authorized' });
    }
};

const adminAuth = async (req, res, next) => {
    try {
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies?.token) {
            token = req.cookies.token;
        }

        if (!token) return res.status(401).json({ success: false, message: 'Not authorized' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');

        if (!user || !user.isAdmin) return res.status(403).json({ success: false, message: 'Admin access required' });

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Not authorized' });
    }
};

// WebSocket Server
const wss = new WebSocket.Server({ 
    server,
    path: '/api/v1/admin/ws',
    verifyClient: (info, done) => {
        const token = info.req.url.split('token=')[1];
        if (!token) return done(false, 401, 'Unauthorized');
        
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            info.req.userId = decoded.id;
            done(true);
        } catch (err) {
            done(false, 401, 'Invalid token');
        }
    }
});

const clients = new Map();

wss.on('connection', (ws, req) => {
    const clientId = req.userId;
    if (!clientId) {
        ws.close(1008, 'Authentication required');
        return;
    }

    clients.set(clientId, ws);
    console.log(`Client connected: ${clientId}`);

    ws.on('message', (message) => {
        console.log(`Received message from ${clientId}: ${message}`);
    });

    ws.on('close', () => {
        clients.delete(clientId);
        console.log(`Client disconnected: ${clientId}`);
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error for client ${clientId}:`, err);
        clients.delete(clientId);
    });
});

function broadcastToUser(userId, data) {
    const ws = clients.get(userId.toString());
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
    }
}

function broadcastToAdmins(data) {
    clients.forEach((ws, userId) => {
        const user = User.findById(userId);
        if (user && user.isAdmin && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
        }
    });
}

// Serve static files
app.use(express.static('public'));

// Authentication Endpoints (10 endpoints)
app.post('/api/v1/auth/signup', [
    body('firstName').notEmpty().trim().escape(),
    body('lastName').notEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
    body('confirmPassword').custom((value, { req }) => value === req.body.password),
    body('country').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { firstName, lastName, email, password, country, currency } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = await User.create({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            country,
            currency: currency || 'USD',
            apiKey: crypto.randomBytes(32).toString('hex')
        });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: email,
            subject: 'Welcome to Our Crypto Platform',
            html: `<h1>Welcome ${firstName}!</h1><p>Your account has been successfully created.</p>`
        });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        user.lastLogin = new Date();
        await user.save();

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/wallet-signup', [
    body('walletAddress').notEmpty().trim().escape(),
    body('signature').notEmpty().trim(),
    body('firstName').notEmpty().trim().escape(),
    body('lastName').notEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('country').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { walletAddress, signature, firstName, lastName, email, country, currency } = req.body;

        const existingUser = await User.findOne({ $or: [{ email }, { walletAddress }] });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email or wallet already in use' });
        }

        const user = await User.create({
            firstName,
            lastName,
            email,
            walletAddress,
            country,
            currency: currency || 'USD',
            isVerified: true,
            apiKey: crypto.randomBytes(32).toString('hex')
        });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: email,
            subject: 'Welcome to Our Crypto Platform',
            html: `<h1>Welcome ${firstName}!</h1><p>Your wallet account has been successfully created.</p>`
        });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/wallet-login', [
    body('walletAddress').notEmpty().trim().escape(),
    body('signature').notEmpty().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { walletAddress, signature } = req.body;
        const user = await User.findOne({ walletAddress });

        if (!user) {
            return res.status(401).json({ success: false, message: 'Wallet not registered' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        user.lastLogin = new Date();
        await user.save();

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/forgot-password', [
    body('email').isEmail().normalizeEmail()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({ success: true, message: 'If an account exists, a reset link has been sent' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpiry;
        await user.save();

        const resetUrl = `https://yourdomain.com/reset-password?token=${resetToken}`;

        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: email,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`
        });

        res.json({ success: true, message: 'If an account exists, a reset link has been sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/reset-password', [
    body('token').notEmpty(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
    body('confirmPassword').custom((value, { req }) => value === req.body.password)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { token, password } = req.body;
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired token' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: user.email,
            subject: 'Password Changed Successfully',
            html: `<p>Your password has been successfully changed.</p>`
        });

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/logout', auth, async (req, res) => {
    try {
        res.clearCookie('token');
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/auth/status', auth, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                email: req.user.email,
                walletAddress: req.user.walletAddress,
                isAdmin: req.user.isAdmin,
                isVerified: req.user.isVerified
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/auth/check', auth, async (req, res) => {
    try {
        res.json({ success: true, message: 'Token is valid' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// User Endpoints (15 endpoints)
app.get('/api/v1/users/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password -apiKey');
        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/users/me', auth, [
    body('firstName').optional().trim().escape(),
    body('lastName').optional().trim().escape(),
    body('country').optional().trim().escape(),
    body('currency').optional().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const updates = req.body;
        const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true }).select('-password -apiKey');
        
        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/auth/update-password', auth, [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
    body('confirmPassword').custom((value, { req }) => value === req.body.newPassword)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user._id).select('+password');

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        await user.save();

        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: user.email,
            subject: 'Password Changed Successfully',
            html: `<p>Your password has been successfully changed.</p>`
        });

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/users/settings', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('settings');
        res.json({ success: true, settings: user.settings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/users/settings', auth, [
    body('settings.twoFA').optional().isBoolean(),
    body('settings.notifications.email').optional().isBoolean(),
    body('settings.notifications.push').optional().isBoolean(),
    body('settings.theme').optional().isIn(['light', 'dark'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { settings } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: { settings } },
            { new: true }
        ).select('settings');

        res.json({ success: true, settings: user.settings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/users/generate-api-key', auth, async (req, res) => {
    try {
        const apiKey = crypto.randomBytes(32).toString('hex');
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { apiKey },
            { new: true }
        ).select('apiKey');

        res.json({ success: true, apiKey: user.apiKey });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/users/kyc', auth, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 },
    { name: 'selfieImage', maxCount: 1 }
]), [
    body('docType').isIn(['passport', 'id_card', 'drivers_license']),
    body('docNumber').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { docType, docNumber } = req.body;
        const files = req.files;

        if (!files.frontImage || !files.selfieImage) {
            return res.status(400).json({ success: false, message: 'Front image and selfie are required' });
        }

        const kycDoc = {
            docType,
            docNumber,
            frontImage: files.frontImage[0].path,
            selfieImage: files.selfieImage[0].path,
            submittedAt: new Date()
        };

        if (files.backImage) {
            kycDoc.backImage = files.backImage[0].path;
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                $push: { kycDocs: kycDoc },
                kycStatus: 'pending'
            },
            { new: true }
        );

        broadcastToAdmins({
            type: 'KYC_SUBMITTED',
            userId: user._id,
            message: 'New KYC submission received'
        });

        res.json({ success: true, message: 'KYC documents submitted for review' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/users/kyc-status', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('kycStatus kycDocs');
        res.json({ success: true, status: user.kycStatus, docs: user.kycDocs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/users/export-data', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password -apiKey');
        const transactions = await Transaction.find({ userId: req.user._id });
        const trades = await Trade.find({ userId: req.user._id });

        const data = {
            user,
            transactions,
            trades
        };

        res.json({ success: true, data });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.delete('/api/v1/users/delete-account', auth, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.user._id);
        await Transaction.deleteMany({ userId: req.user._id });
        await Trade.deleteMany({ userId: req.user._id });

        res.clearCookie('token');
        res.json({ success: true, message: 'Account deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/team', async (req, res) => {
    try {
        const team = [
            {
                name: "John Doe",
                position: "CEO",
                bio: "Founder and CEO with 10+ years in blockchain technology.",
                image: "/images/team/john.jpg"
            },
            {
                name: "Jane Smith",
                position: "CTO",
                bio: "Technical lead with expertise in cryptography and distributed systems.",
                image: "/images/team/jane.jpg"
            }
        ];
        res.json({ success: true, team });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Wallet Endpoints (8 endpoints)
app.get('/api/v1/wallet/balance', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('balance balances');
        res.json({ success: true, balance: user.balance, balances: user.balances });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/deposit-address', auth, async (req, res) => {
    try {
        res.json({ success: true, address: DEPOSIT_WALLET });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/wallet/deposit', auth, [
    body('amount').isFloat({ min: 0.01 }),
    body('currency').isIn(['BTC', 'ETH', 'USDT', 'USD']),
    body('txHash').optional().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { amount, currency, txHash } = req.body;

        const transaction = await Transaction.create({
            userId: req.user._id,
            type: 'deposit',
            amount,
            currency,
            status: 'pending',
            details: { txHash },
            walletAddress: DEPOSIT_WALLET
        });

        setTimeout(async () => {
            const user = await User.findById(req.user._id);
            if (currency === 'USD') {
                user.balance += amount;
            } else {
                user.balances[currency] = (user.balances[currency] || 0) + amount;
            }
            await user.save();

            transaction.status = 'completed';
            await transaction.save();

            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance,
                balances: user.balances
            });
        }, 5000);

        res.json({ success: true, transaction });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/wallet/withdraw', auth, [
    body('amount').isFloat({ min: 0.01 }),
    body('currency').isIn(['BTC', 'ETH', 'USDT', 'USD']),
    body('walletAddress').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { amount, currency, walletAddress } = req.body;
        const user = await User.findById(req.user._id);

        if (currency === 'USD') {
            if (user.balance < amount) {
                return res.status(400).json({ success: false, message: 'Insufficient balance' });
            }
        } else {
            if ((user.balances[currency] || 0) < amount) {
                return res.status(400).json({ success: false, message: 'Insufficient balance' });
            }
        }

        if (currency === 'USD') {
            user.balance -= amount;
        } else {
            user.balances[currency] = (user.balances[currency] || 0) - amount;
        }
        await user.save();

        const transaction = await Transaction.create({
            userId: req.user._id,
            type: 'withdrawal',
            amount,
            currency,
            status: 'pending',
            walletAddress,
            details: { fee: 0.001 * amount }
        });

        setTimeout(async () => {
            transaction.status = 'completed';
            await transaction.save();

            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance,
                balances: user.balances
            });
        }, 5000);

        res.json({ success: true, transaction });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/transactions', auth, async (req, res) => {
    try {
        const { page = 1, limit = 10, type } = req.query;
        const query = { userId: req.user._id };
        if (type) query.type = type;

        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Transaction.countDocuments(query);

        res.json({
            success: true,
            transactions,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/portfolio', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('balances');
        res.json({ success: true, portfolio: user.balances });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/recent', auth, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(5);

        res.json({ success: true, transactions });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Trading Endpoints (12 endpoints)
const COIN_PRICES = {
    BTC: 50000,
    ETH: 3000,
    BNB: 400,
    USDT: 1,
    XRP: 0.5,
    SOL: 100,
    ADA: 0.4,
    DOGE: 0.1,
    DOT: 7,
    MATIC: 0.8
};

app.get('/api/v1/exchange/coins', auth, async (req, res) => {
    try {
        res.json({ success: true, coins: Object.keys(COIN_PRICES) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/exchange/rates', auth, async (req, res) => {
    try {
        res.json({ success: true, rates: COIN_PRICES });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/exchange/rate', auth, [
    body('from').isIn(Object.keys(COIN_PRICES)),
    body('to').isIn(Object.keys(COIN_PRICES))
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { from, to } = req.query;
        const rate = COIN_PRICES[from] / COIN_PRICES[to];
        res.json({ success: true, rate });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/exchange/convert', auth, [
    body('from').isIn(Object.keys(COIN_PRICES)),
    body('to').isIn(Object.keys(COIN_PRICES)),
    body('amount').isFloat({ min: 0.0001 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { from, to, amount } = req.body;
        const user = await User.findById(req.user._id);

        if ((user.balances[from] || 0) < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        const rate = COIN_PRICES[from] / COIN_PRICES[to];
        const convertedAmount = amount * rate * 0.998;

        user.balances[from] = (user.balances[from] || 0) - amount;
        user.balances[to] = (user.balances[to] || 0) + convertedAmount;
        await user.save();

        const transaction = await Transaction.create({
            userId: req.user._id,
            type: 'conversion',
            amount,
            currency: from,
            status: 'completed',
            details: {
                from,
                to,
                rate,
                convertedAmount,
                fee: amount * 0.002
            }
        });

        broadcastToUser(user._id, {
            type: 'BALANCE_UPDATE',
            balance: user.balance,
            balances: user.balances
        });

        res.json({ success: true, transaction, newBalances: user.balances });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/exchange/history', auth, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const transactions = await Transaction.find({
            userId: req.user._id,
            type: { $in: ['conversion', 'trade'] }
        })
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Transaction.countDocuments({
            userId: req.user._id,
            type: { $in: ['conversion', 'trade'] }
        });

        res.json({
            success: true,
            transactions,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/trades/buy', auth, [
    body('pair').matches(/^[A-Z]{3,4}\/[A-Z]{3,4}$/),
    body('amount').isFloat({ min: 0.0001 }),
    body('price').optional().isFloat({ min: 0.000001 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { pair, amount, price } = req.body;
        const [base, quote] = pair.split('/');
        const user = await User.findById(req.user._id);

        const requiredBalance = amount * (price || COIN_PRICES[base] / COIN_PRICES[quote]);
        if ((user.balances[quote] || 0) < requiredBalance) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        user.balances[quote] = (user.balances[quote] || 0) - requiredBalance;
        await user.save();

        const trade = await Trade.create({
            userId: req.user._id,
            pair,
            type: 'buy',
            amount,
            price: price || COIN_PRICES[base] / COIN_PRICES[quote],
            total: requiredBalance,
            status: 'open'
        });

        setTimeout(async () => {
            trade.status = 'filled';
            await trade.save();

            user.balances[base] = (user.balances[base] || 0) + amount;
            await user.save();

            await Transaction.create({
                userId: req.user._id,
                type: 'trade',
                amount,
                currency: base,
                status: 'completed',
                details: {
                    pair,
                    type: 'buy',
                    price: trade.price,
                    total: trade.total,
                    fee: trade.total * 0.001
                }
            });

            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance,
                balances: user.balances
            });

            broadcastToUser(user._id, {
                type: 'TRADE_UPDATE',
                trade: trade.toObject()
            });
        }, 1000);

        res.json({ success: true, trade });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/trades/sell', auth, [
    body('pair').matches(/^[A-Z]{3,4}\/[A-Z]{3,4}$/),
    body('amount').isFloat({ min: 0.0001 }),
    body('price').optional().isFloat({ min: 0.000001 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { pair, amount, price } = req.body;
        const [base, quote] = pair.split('/');
        const user = await User.findById(req.user._id);

        if ((user.balances[base] || 0) < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        user.balances[base] = (user.balances[base] || 0) - amount;
        await user.save();

        const trade = await Trade.create({
            userId: req.user._id,
            pair,
            type: 'sell',
            amount,
            price: price || COIN_PRICES[base] / COIN_PRICES[quote],
            total: amount * (price || COIN_PRICES[base] / COIN_PRICES[quote]),
            status: 'open'
        });

        setTimeout(async () => {
            trade.status = 'filled';
            await trade.save();

            user.balances[quote] = (user.balances[quote] || 0) + trade.total;
            await user.save();

            await Transaction.create({
                userId: req.user._id,
                type: 'trade',
                amount,
                currency: base,
                status: 'completed',
                details: {
                    pair,
                    type: 'sell',
                    price: trade.price,
                    total: trade.total,
                    fee: trade.total * 0.001
                }
            });

            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance,
                balances: user.balances
            });

            broadcastToUser(user._id, {
                type: 'TRADE_UPDATE',
                trade: trade.toObject()
            });
        }, 1000);

        res.json({ success: true, trade });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/trades/active', auth, async (req, res) => {
    try {
        const trades = await Trade.find({
            userId: req.user._id,
            status: { $in: ['open', 'partial'] }
        }).sort({ createdAt: -1 });

        res.json({ success: true, trades });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/trades/history', auth, async (req, res) => {
    try {
        const { page = 1, limit = 10, pair } = req.query;
        const query = { 
            userId: req.user._id,
            status: { $in: ['filled', 'cancelled'] }
        };
        
        if (pair) query.pair = pair;

        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Trade.countDocuments(query);

        res.json({
            success: true,
            trades,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/trades/cancel/:id', auth, async (req, res) => {
    try {
        const trade = await Trade.findOne({
            _id: req.params.id,
            userId: req.user._id,
            status: 'open'
        });

        if (!trade) {
            return res.status(404).json({ success: false, message: 'Trade not found or not cancellable' });
        }

        const user = await User.findById(req.user._id);
        if (trade.type === 'buy') {
            user.balances[trade.pair.split('/')[1]] = (user.balances[trade.pair.split('/')[1]] || 0) + trade.total;
        } else {
            user.balances[trade.pair.split('/')[0]] = (user.balances[trade.pair.split('/')[0]] || 0) + trade.amount;
        }
        await user.save();

        trade.status = 'cancelled';
        await trade.save();

        broadcastToUser(user._id, {
            type: 'BALANCE_UPDATE',
            balance: user.balance,
            balances: user.balances
        });

        broadcastToUser(user._id, {
            type: 'TRADE_UPDATE',
            trade: trade.toObject()
        });

        res.json({ success: true, trade });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Support Endpoints (6 endpoints)
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = await FAQ.find().sort({ order: 1 });
        res.json({ success: true, faqs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/contact', [
    body('email').isEmail().normalizeEmail(),
    body('subject').notEmpty().trim().escape(),
    body('message').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { email, subject, message } = req.body;
        
        const ticket = await SupportTicket.create({
            email,
            subject,
            message,
            status: 'open'
        });

        broadcastToAdmins({
            type: 'NEW_SUPPORT_TICKET',
            ticketId: ticket._id,
            message: 'New support ticket received'
        });

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/tickets', auth, [
    body('subject').notEmpty().trim().escape(),
    body('message').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { subject, message } = req.body;
        
        const ticket = await SupportTicket.create({
            userId: req.user._id,
            email: req.user.email,
            subject,
            message,
            status: 'open'
        });

        broadcastToAdmins({
            type: 'NEW_SUPPORT_TICKET',
            ticketId: ticket._id,
            message: 'New support ticket received'
        });

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/support/tickets', auth, async (req, res) => {
    try {
        const { page = 1, limit = 10, status } = req.query;
        const query = { userId: req.user._id };
        if (status) query.status = status;

        const tickets = await SupportTicket.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await SupportTicket.countDocuments(query);

        res.json({
            success: true,
            tickets,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/support/tickets/:id', auth, async (req, res) => {
    try {
        const ticket = await SupportTicket.findOne({
            _id: req.params.id,
            userId: req.user._id
        });

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/tickets/:id/reply', auth, [
    body('message').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { message } = req.body;
        const ticket = await SupportTicket.findOne({
            _id: req.params.id,
            userId: req.user._id
        });

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        ticket.responses.push({
            message,
            isAdmin: false
        });
        ticket.status = 'pending';
        ticket.updatedAt = new Date();
        await ticket.save();

        broadcastToAdmins({
            type: 'TICKET_UPDATE',
            ticketId: ticket._id,
            message: 'New reply on support ticket'
        });

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Admin Endpoints (16 endpoints)
app.post('/api/v1/admin/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user || !user.isAdmin) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '8h' });

        user.lastLogin = new Date();
        await user.save();

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 8 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/verify', adminAuth, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                email: req.user.email,
                isAdmin: req.user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/dashboard-stats', adminAuth, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
        const newUsers = await User.countDocuments({ createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $match: { status: 'filled' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
        const openTickets = await SupportTicket.countDocuments({ status: 'open' });

        res.json({
            success: true,
            stats: {
                totalUsers,
                activeUsers,
                newUsers,
                totalTrades,
                totalVolume: totalVolume[0]?.total || 0,
                pendingKYC,
                openTickets
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/users', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search, sortBy, sortOrder = 'asc' } = req.query;
        const query = {};
        
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ];
        }

        const sortOptions = {};
        if (sortBy) sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;

        const users = await User.find(query)
            .select('-password -apiKey')
            .sort(sortOptions)
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await User.countDocuments(query);

        res.json({
            success: true,
            users,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password -apiKey');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const transactions = await Transaction.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(10);

        const trades = await Trade.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(10);

        const tickets = await SupportTicket.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(5);

        res.json({
            success: true,
            user,
            transactions,
            trades,
            tickets
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/admin/users/:id', adminAuth, [
    body('balance').optional().isFloat(),
    body('isVerified').optional().isBoolean(),
    body('isAdmin').optional().isBoolean(),
    body('kycStatus').optional().isIn(['none', 'pending', 'approved', 'rejected'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const updates = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password -apiKey');
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (updates.kycStatus === 'approved' && user.kycStatus !== 'approved') {
            await transporter.sendMail({
                from: '"Crypto Platform" <support@cryptoplatform.com>',
                to: user.email,
                subject: 'KYC Verification Approved',
                html: `<p>Your KYC verification has been approved. You now have full access to all platform features.</p>`
            });
        } else if (updates.kycStatus === 'rejected' && user.kycStatus !== 'rejected') {
            await transporter.sendMail({
                from: '"Crypto Platform" <support@cryptoplatform.com>',
                to: user.email,
                subject: 'KYC Verification Rejected',
                html: `<p>Your KYC verification has been rejected. Please submit new documents for review.</p>`
            });
        }

        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.delete('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        await Transaction.deleteMany({ userId: user._id });
        await Trade.deleteMany({ userId: user._id });
        await SupportTicket.deleteMany({ userId: user._id });

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/transactions', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, type, status, userId } = req.query;
        const query = {};
        
        if (type) query.type = type;
        if (status) query.status = status;
        if (userId) query.userId = userId;

        const transactions = await Transaction.find(query)
            .populate('userId', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Transaction.countDocuments(query);

        res.json({
            success: true,
            transactions,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/admin/transactions/:id', adminAuth, [
    body('status').isIn(['pending', 'completed', 'failed', 'cancelled'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { status } = req.body;
        const transaction = await Transaction.findById(req.params.id).populate('userId');
        
        if (!transaction) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }

        if (transaction.status === status) {
            return res.json({ success: true, transaction });
        }

        if (status === 'completed' && transaction.status !== 'completed') {
            const user = await User.findById(transaction.userId);
            
            if (transaction.type === 'deposit') {
                if (transaction.currency === 'USD') {
                    user.balance += transaction.amount;
                } else {
                    user.balances[transaction.currency] = (user.balances[transaction.currency] || 0) + transaction.amount;
                }
                await user.save();
                
                broadcastToUser(user._id, {
                    type: 'BALANCE_UPDATE',
                    balance: user.balance,
                    balances: user.balances
                });
            }
        } else if (status === 'cancelled' && transaction.type === 'withdrawal' && transaction.status === 'pending') {
            const user = await User.findById(transaction.userId);
            
            if (transaction.currency === 'USD') {
                user.balance += transaction.amount;
            } else {
                user.balances[transaction.currency] = (user.balances[transaction.currency] || 0) + transaction.amount;
            }
            await user.save();
            
            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance,
                balances: user.balances
            });
        }

        transaction.status = status;
        await transaction.save();

        res.json({ success: true, transaction });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/trades', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, type, status, pair, userId } = req.query;
        const query = {};
        
        if (type) query.type = type;
        if (status) query.status = status;
        if (pair) query.pair = pair;
        if (userId) query.userId = userId;

        const trades = await Trade.find(query)
            .populate('userId', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Trade.countDocuments(query);

        res.json({
            success: true,
            trades,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/kyc', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, status } = req.query;
        const query = { kycStatus: status || 'pending' };

        const users = await User.find(query)
            .select('-password -apiKey')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await User.countDocuments(query);

        res.json({
            success: true,
            users,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/tickets', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, status } = req.query;
        const query = {};
        if (status) query.status = status;

        const tickets = await SupportTicket.find(query)
            .populate('userId', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await SupportTicket.countDocuments(query);

        res.json({
            success: true,
            tickets,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/tickets/:id', adminAuth, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id)
            .populate('userId', 'firstName lastName email');

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/admin/tickets/:id/reply', adminAuth, [
    body('message').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { message } = req.body;
        const ticket = await SupportTicket.findById(req.params.id);

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        ticket.responses.push({
            message,
            isAdmin: true
        });
        ticket.status = req.body.status || ticket.status;
        ticket.updatedAt = new Date();
        await ticket.save();

        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'TICKET_UPDATE',
                ticketId: ticket._id,
                message: 'New reply on your support ticket'
            });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/admin/tickets/:id', adminAuth, [
    body('status').isIn(['open', 'pending', 'resolved', 'closed'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { status } = req.body;
        const ticket = await SupportTicket.findByIdAndUpdate(
            req.params.id,
            { status, updatedAt: new Date() },
            { new: true }
        );

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'TICKET_UPDATE',
                ticketId: ticket._id,
                message: `Your ticket status changed to ${status}`
            });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/admin/broadcast', adminAuth, [
    body('message').notEmpty().trim().escape(),
    body('title').notEmpty().trim().escape(),
    body('type').isIn(['info', 'warning', 'error', 'success'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
        const { message, title, type } = req.body;

        clients.forEach((ws, userId) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'BROADCAST',
                    message: { title, message, type }
                }));
            }
        });

        res.json({ success: true, message: 'Broadcast sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/logs', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, action } = req.query;
        const query = {};
        if (action) query.action = { $regex: action, $options: 'i' };

        const logs = await SystemLog.find(query)
            .populate('userId', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await SystemLog.countDocuments(query);

        res.json({
            success: true,
            logs,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Stats Endpoints (1 endpoint)
app.get('/api/v1/stats', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $match: { status: 'filled' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);

        res.json({
            success: true,
            stats: {
                totalUsers,
                activeUsers,
                totalTrades,
                totalVolume: totalVolume[0]?.total || 0
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Serve frontend pages
const pages = [
    'about.html', 'account.html', 'admin.html', 'dashboard.html', 
    'faqs.html', 'forgot-password.html', 'index.html', 'login.html', 
    'logout.html', 'signup.html', 'support.html'
];

pages.forEach(page => {
    app.get(`/${page}`, (req, res) => {
        res.sendFile(path.join(__dirname, 'public', page));
    });
});

// Error handling
app.use((req, res, next) => {
    res.status(404).json({ success: false, message: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
