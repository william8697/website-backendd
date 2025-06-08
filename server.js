require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const { ethers } = require('ethers');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const deviceDetector = require('device-detector-js');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na.%';
const DEPOSIT_ADDRESS = process.env.DEPOSIT_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const IPINFO_TOKEN = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    retryWrites: true
}).then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Email Transport Configuration
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
    port: process.env.EMAIL_PORT || 2525,
    auth: {
        user: process.env.EMAIL_USER || '7c707ac161af1c',
        pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
    }
});

// Middleware
app.use(helmet());
app.use(cookieParser());
app.use(cors({
    origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Disposition']
}));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Device and IP detection middleware
const captureDeviceInfo = async (req, res, next) => {
    try {
        const userAgent = req.headers['user-agent'] || '';
        const ip = req.ip || req.connection.remoteAddress;
        
        const detector = new deviceDetector();
        const device = detector.parse(userAgent);
        
        let geo = {};
        try {
            const response = await fetch(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
            if (response.ok) {
                geo = await response.json();
            }
        } catch (ipError) {
            console.error('Error fetching IP info:', ipError);
        }

        req.deviceInfo = {
            fingerprint: crypto.createHash('md5').update(`${userAgent}-${ip}`).digest('hex'),
            userAgent,
            ip,
            timestamp: new Date(),
            device: {
                type: device.device?.type || 'desktop',
                brand: device.device?.brand || 'unknown',
                model: device.device?.model || 'unknown',
                os: {
                    name: device.os?.name || 'Unknown',
                    version: device.os?.version || '',
                    platform: device.os?.platform || ''
                },
                browser: {
                    name: device.client?.name || 'Unknown',
                    version: device.client?.version || '',
                    engine: device.client?.engine || ''
                }
            },
            location: {
                ip,
                country: geo.country || 'Unknown',
                region: geo.region || 'Unknown',
                city: geo.city || 'Unknown',
                timezone: geo.timezone || 'UTC',
                coordinates: geo.loc ? {
                    latitude: parseFloat(geo.loc.split(',')[0]),
                    longitude: parseFloat(geo.loc.split(',')[1])
                } : null
            }
        };
        next();
    } catch (err) {
        console.error('Device info error:', err);
        req.deviceInfo = {
            fingerprint: 'unknown',
            userAgent: req.headers['user-agent'] || '',
            ip: req.ip || req.connection.remoteAddress,
            timestamp: new Date(),
            device: {
                type: 'desktop',
                brand: 'unknown',
                model: 'unknown',
                os: {
                    name: 'Unknown',
                    version: '',
                    platform: ''
                },
                browser: {
                    name: 'Unknown',
                    version: '',
                    engine: ''
                }
            },
            location: {
                ip: req.ip || req.connection.remoteAddress,
                country: 'Unknown',
                region: 'Unknown',
                city: 'Unknown',
                timezone: 'UTC',
                coordinates: null
            }
        };
        next();
    }
};

app.use(captureDeviceInfo);

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

// Database Models
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: false },
    walletAddress: { type: String, unique: true, sparse: true },
    firstName: String,
    lastName: String,
    country: String,
    currency: { type: String, default: 'USD' },
    balance: { type: Number, default: 0 },
    kycStatus: { type: String, enum: ['pending', 'approved', 'rejected', 'not_submitted'], default: 'not_submitted' },
    kycDocuments: [{
        documentType: String,
        documentNumber: String,
        frontImage: String,
        backImage: String,
        selfie: String,
        submittedAt: Date
    }],
    apiKey: { type: String, unique: true, sparse: true },
    isAdmin: { type: Boolean, default: false },
    emailNotifications: { type: Boolean, default: true },
    smsNotifications: { type: Boolean, default: false },
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    isVerified: { type: Boolean, default: false },
    twoFactorEnabled: { type: Boolean, default: false },
    lastLogin: Date,
    status: { type: String, enum: ['active', 'inactive', 'suspended'], default: 'active' },
    ipAddresses: [String],
    deviceInfo: [{
        fingerprint: String,
        userAgent: String,
        deviceType: String,
        os: String,
        browser: String,
        location: Object,
        timestamp: Date
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    permissions: [String],
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    amount: { type: Number, required: true },
    rate: { type: Number, required: true },
    fee: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'transfer'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
    txHash: String,
    address: String,
    fee: Number,
    adminNote: String,
    createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    attachments: [String],
    responses: [{
        message: String,
        isAdmin: Boolean,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const FAQSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    category: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const CoinSchema = new mongoose.Schema({
    symbol: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    change24h: { type: Number, required: true },
    volume24h: { type: Number, required: true },
    marketCap: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
    lastUpdated: { type: Date, default: Date.now }
});

const SystemLogSchema = new mongoose.Schema({
    action: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    ipAddress: String,
    userAgent: String,
    device: {
        type: { type: String },
        os: String,
        browser: String,
        vendor: String
    },
    location: {
        ip: String,
        country: String,
        region: String,
        city: String,
        timezone: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    metadata: mongoose.Schema.Types.Mixed,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);
const Coin = mongoose.model('Coin', CoinSchema);
const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

// Initialize default admin if not exists
async function initializeAdmin() {
    const adminExists = await Admin.findOne({ email: 'admin@cryptotradingmarket.com' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('17581758..', 10);
        await Admin.create({
            email: 'admin@cryptotradingmarket.com',
            password: hashedPassword,
            permissions: ['all']
        });
        console.log('Default admin account created');
    }
}

// Initialize coins data
async function initializeCoins() {
    const coins = [
        { symbol: 'BTC', name: 'Bitcoin', price: 50000, change24h: 2.5, volume24h: 25000000000, marketCap: 950000000000 },
        { symbol: 'ETH', name: 'Ethereum', price: 3000, change24h: 1.8, volume24h: 15000000000, marketCap: 360000000000 },
        { symbol: 'SOL', name: 'Solana', price: 150, change24h: 5.2, volume24h: 3000000000, marketCap: 60000000000 },
        { symbol: 'XRP', name: 'Ripple', price: 0.5, change24h: -1.2, volume24h: 2000000000, marketCap: 25000000000 },
        { symbol: 'ADA', name: 'Cardano', price: 0.45, change24h: 0.8, volume24h: 800000000, marketCap: 15000000000 },
        { symbol: 'DOGE', name: 'Dogecoin', price: 0.12, change24h: 3.5, volume24h: 1000000000, marketCap: 16000000000 },
        { symbol: 'DOT', name: 'Polkadot', price: 7.5, change24h: -0.5, volume24h: 500000000, marketCap: 7500000000 },
        { symbol: 'USDT', name: 'Tether', price: 1.0, change24h: 0.0, volume24h: 50000000000, marketCap: 80000000000 },
        { symbol: 'BNB', name: 'Binance Coin', price: 400, change24h: 1.2, volume24h: 2000000000, marketCap: 65000000000 },
        { symbol: 'LTC', name: 'Litecoin', price: 75, change24h: 0.7, volume24h: 800000000, marketCap: 5300000000 }
    ];

    for (const coin of coins) {
        await Coin.updateOne({ symbol: coin.symbol }, coin, { upsert: true });
    }
}

// Initialize FAQs
async function initializeFAQs() {
    const faqs = [
        {
            question: 'How do I create an account?',
            answer: 'Click on the Sign Up button and fill in the required information. You can sign up using your email or connect your crypto wallet.',
            category: 'Account'
        },
        {
            question: 'How do I deposit funds?',
            answer: 'Go to the Wallet section and click on Deposit. You will see the deposit address where you can send your funds.',
            category: 'Wallet'
        },
        {
            question: 'How long do withdrawals take?',
            answer: 'Withdrawals are processed manually by our team within 24 hours. You will receive a notification once processed.',
            category: 'Wallet'
        },
        {
            question: 'What is the minimum deposit amount?',
            answer: 'There is no minimum deposit amount. However, network fees may make small deposits impractical.',
            category: 'Wallet'
        },
        {
            question: 'How do I verify my identity?',
            answer: 'Go to Settings > KYC Verification and upload the required documents (ID, proof of address, and a selfie).',
            category: 'Account'
        },
        {
            question: 'What fees do you charge for trading?',
            answer: 'We charge a 0.1% fee for all trades. There are no deposit fees, but withdrawal fees vary by network.',
            category: 'Trading'
        },
        {
            question: 'How do I contact support?',
            answer: 'You can submit a ticket through the Support page or email us at support@youngblood.com.',
            category: 'Support'
        },
        {
            question: 'Is my personal information secure?',
            answer: 'Yes, we use bank-grade encryption and follow strict data protection protocols to keep your information safe.',
            category: 'Security'
        },
        {
            question: 'Can I use the platform without KYC?',
            answer: 'Basic functionality is available without KYC, but certain features like withdrawals require verified accounts.',
            category: 'Account'
        },
        {
            question: 'How do I enable two-factor authentication?',
            answer: 'Go to Settings > Security and follow the instructions to set up 2FA using Google Authenticator or similar apps.',
            category: 'Security'
        }
    ];

    for (const faq of faqs) {
        await FAQ.updateOne({ question: faq.question }, faq, { upsert: true });
    }
}

// Initialize data on startup
initializeAdmin().then(initializeCoins).then(initializeFAQs).catch(console.error);

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });
const adminWss = new WebSocket.Server({ noServer: true });

const clients = new Map();
const adminClients = new Map();

wss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1] || 
                req.headers.cookie?.split('token=')[1]?.split(';')[0];
    
    if (!token) {
        ws.close(1008, 'Unauthorized');
        return;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        clients.set(decoded.userId, ws);

        ws.on('close', () => {
            clients.delete(decoded.userId);
        });

        ws.send(JSON.stringify({ type: 'connection_success' }));
    } catch (err) {
        ws.close(1008, 'Invalid token');
    }
});

adminWss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1];
    if (!token) {
        ws.close(1008, 'Unauthorized');
        return;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.isAdmin) {
            ws.close(1008, 'Admin access required');
            return;
        }

        adminClients.set(decoded.userId, ws);

        ws.on('close', () => {
            adminClients.delete(decoded.userId);
        });

        ws.on('message', (message) => {
            console.log(`Received message from admin ${decoded.userId}: ${message}`);
        });

        ws.send(JSON.stringify({ type: 'connection_success', message: 'Admin WebSocket connection established' }));
    } catch (err) {
        ws.close(1008, 'Invalid token');
    }
});

// Helper Functions
function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

function notifyUser(userId, message) {
    const ws = clients.get(userId);
    if (ws) {
        ws.send(JSON.stringify(message));
    }
}

function notifyAdmins(message) {
    adminClients.forEach(ws => {
        ws.send(JSON.stringify(message));
    });
}

async function logAction(userId, action, metadata = {}) {
    const logData = {
        action,
        userId,
        ipAddress: metadata.ipAddress || req.deviceInfo.ip,
        userAgent: metadata.userAgent || req.deviceInfo.userAgent,
        device: {
            type: req.deviceInfo.device.device?.type || 'desktop',
            os: req.deviceInfo.device.os?.name || 'Unknown',
            browser: req.deviceInfo.device.client?.name || 'Unknown',
            vendor: req.deviceInfo.device.device?.brand || 'Unknown'
        },
        location: req.deviceInfo.location,
        metadata
    };

    await SystemLog.create(logData);
}

// Authentication Middleware
async function authenticate(req, res, next) {
    const token = req.cookies?.token || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.query.token;
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Invalid token' });
    }
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies?.token || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.query.token;
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = await Admin.findOne({ email: decoded.email });
        if (!admin) {
            return res.status(401).json({ success: false, error: 'Admin not found' });
        }

        req.admin = admin;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Invalid token' });
    }
}

// Auth status endpoint
app.get('/api/v1/auth/status', async (req, res) => {
    const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.json({ isAuthenticated: false });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.json({ isAuthenticated: false });
        }

        res.json({
            isAuthenticated: true,
            user: {
                id: user._id,
                email: user.email,
                walletAddress: user.walletAddress,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus
            }
        });
    } catch (err) {
        res.json({ isAuthenticated: false });
    }
});

// Authentication Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { email, password, firstName, lastName, country, currency, confirmPassword } = req.body;

        if (!email || !password || !firstName || !lastName || !country || !currency || !confirmPassword) {
            return res.status(400).json({ success: false, error: 'All fields are required' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, error: 'Passwords do not match' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, error: 'Invalid email format' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, error: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            country,
            currency,
            balance: 0,
            deviceInfo: [req.deviceInfo]
        });

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        await logAction(user._id, 'user_signup', { method: 'email' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).status(201).json({
            success: true,
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus
            }
        });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ 
            success: false,
            error: err.code === 11000 ? 'Email already in use' : 'Server error during signup'
        });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        await User.updateOne(
            { _id: user._id }, 
            { 
                $set: { lastLogin: new Date() },
                $push: { deviceInfo: req.deviceInfo }
            }
        );

        await logAction(user._id, 'user_login', { method: 'email', ipAddress: req.ip });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).json({
            success: true,
            message: 'Login successful',
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, error: 'Server error during login' });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature, walletProvider, message } = req.body;

        if (!walletAddress || !walletProvider) {
            return res.status(400).json({
                success: false,
                error: 'Wallet address and provider are required'
            });
        }

        let normalizedAddress;
        try {
            normalizedAddress = ethers.utils.getAddress(walletAddress);
        } catch (err) {
            return res.status(400).json({
                success: false,
                error: 'Invalid wallet address format'
            });
        }

        if (signature && message) {
            try {
                const recoveredAddress = ethers.utils.verifyMessage(message, signature);
                if (recoveredAddress.toLowerCase() !== normalizedAddress.toLowerCase()) {
                    return res.status(401).json({
                        success: false,
                        error: 'Signature verification failed'
                    });
                }
            } catch (sigError) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid signature format'
                });
            }
        }

        const existingUser = await User.findOne({ walletAddress: normalizedAddress });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Wallet address already registered'
            });
        }

        const user = await User.create({
            walletAddress: normalizedAddress,
            walletProvider,
            firstName: 'Wallet',
            lastName: 'User',
            country: 'Unknown',
            currency: 'USD',
            balance: 0,
            isVerified: true,
            status: 'active',
            email: `${normalizedAddress}@walletuser.com`,
            deviceInfo: [req.deviceInfo]
        });

        const token = jwt.sign(
            { userId: user._id, walletAddress: user.walletAddress, isVerified: user.isVerified },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).status(201).json({
            success: true,
            message: 'Wallet registration successful',
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                isVerified: user.isVerified,
                balance: user.balance
            }
        });

    } catch (err) {
        console.error('Wallet signup error:', err);
        res.status(500).json({
            success: false,
            error: err.code === 11000 ? 'Wallet address already registered' : 'Internal server error'
        });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature, walletType } = req.body;

        if (!walletAddress || !walletType) {
            return res.status(400).json({ success: false, error: 'Wallet address and type are required' });
        }

        let normalizedAddress;
        try {
            normalizedAddress = ethers.utils.getAddress(walletAddress);
        } catch (err) {
            return res.status(400).json({ success: false, error: 'Invalid wallet address format' });
        }

        const user = await User.findOne({ walletAddress: normalizedAddress });
        if (!user) {
            return res.status(404).json({ success: false, error: 'Wallet not registered' });
        }

        const token = jwt.sign({ userId: user._id, walletAddress: user.walletAddress }, JWT_SECRET, { expiresIn: '7d' });

        await User.updateOne(
            { _id: user._id }, 
            { 
                $set: { lastLogin: new Date() },
                $push: { deviceInfo: req.deviceInfo }
            }
        );

        await logAction(user._id, 'user_login', { method: 'wallet', walletType, ipAddress: req.ip });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).json({
            success: true,
            message: 'Wallet login successful',
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                isVerified: user.isVerified,
                balance: user.balance
            }
        });
    } catch (err) {
        console.error('Wallet login error:', err);
        res.status(500).json({ success: false, error: 'Server error during wallet login' });
    }
});

app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email and password are required' });
        }

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const token = jwt.sign({ 
            userId: admin._id, 
            email: admin.email, 
            isAdmin: true,
            permissions: admin.permissions 
        }, JWT_SECRET, { expiresIn: '7d' });

        await Admin.updateOne({ _id: admin._id }, { $set: { lastLogin: new Date() } });
        await logAction(admin._id, 'admin_login', { ipAddress: req.ip });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).json({
            success: true,
            message: 'Admin login successful',
            token,
            admin: {
                id: admin._id,
                email: admin.email,
                permissions: admin.permissions
            }
        });
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).json({ success: false, error: 'Server error during admin login' });
    }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                email: req.user.email,
                walletAddress: req.user.walletAddress,
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                country: req.user.country,
                currency: req.user.currency,
                balance: req.user.balance,
                kycStatus: req.user.kycStatus,
                apiKey: req.user.apiKey,
                twoFactorEnabled: req.user.twoFactorEnabled,
                createdAt: req.user.createdAt,
                isVerified: req.user.kycStatus === 'approved',
                lastLogin: req.user.lastLogin
            }
        });
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ success: false, error: 'Server error fetching user data' });
    }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            address: DEPOSIT_ADDRESS,
            currency: 'BTC',
            note: `Include your user ID (${req.user._id}) in the memo when depositing`
        });
    } catch (err) {
        console.error('Deposit address error:', err);
        res.status(500).json({ success: false, error: 'Server error fetching deposit address' });
    }
});

// Trading Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
    try {
        const coins = await Coin.find({ isActive: true });
        res.json({ success: true, coins });
    } catch (err) {
        console.error('Get coins error:', err);
        res.status(500).json({ success: false, error: 'Server error fetching coins' });
    }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
    try {
        const coins = await Coin.find({ isActive: true }).lean();
        const rates = {};
        
        coins.forEach(fromCoin => {
            rates[fromCoin.symbol] = {};
            coins.forEach(toCoin => {
                rates[fromCoin.symbol][toCoin.symbol] = fromCoin.symbol === toCoin.symbol 
                    ? 1 
                    : (toCoin.price / fromCoin.price) * 0.999;
            });
        });

        res.json({ success: true, rates });
    } catch (err) {
        console.error('Get rates error:', err);
        res.json({ success: true, rates: {} });
    }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const verifiedUsers = await User.countDocuments({ kycStatus: 'approved' });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
        const openTickets = await SupportTicket.countDocuments({ status: 'open' });

        res.json({
            success: true,
            stats: {
                totalUsers,
                verifiedUsers,
                totalTrades,
                totalVolume: totalVolume[0]?.total || 0,
                pendingWithdrawals,
                pendingKYC,
                openTickets
            }
        });
    } catch (err) {
        console.error('Dashboard stats error:', err);
        res.status(500).json({ success: false, error: 'Server error fetching dashboard stats' });
    }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// Start Server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// WebSocket Upgrade Handling
server.on('upgrade', (request, socket, head) => {
    const pathname = request.url.split('?')[0];

    if (pathname === '/api/v1/admin/ws') {
        adminWss.handleUpgrade(request, socket, head, (ws) => {
            adminWss.emit('connection', ws, request);
        });
    } else {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    }
});

// Graceful Shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed');
            process.exit(0);
        });
    });
});
