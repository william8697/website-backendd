require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.%';
const DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB Connection
mongoose.connect('mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
});

// Email Transport Configuration
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: 'https://website-xi-ten-52.vercel.app',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
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
    twoFactorEnabled: { type: Boolean, default: false },
    lastLogin: Date,
    status: { type: String, enum: ['active', 'inactive', 'suspended'], default: 'active' },
    ipAddresses: [String],
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
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });
const adminWss = new WebSocket.Server({ noServer: true });

const clients = new Map();
const adminClients = new Map();

wss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1];
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

        ws.on('message', (message) => {
            // Handle incoming messages from clients
            console.log(`Received message from user ${decoded.userId}: ${message}`);
        });

        ws.send(JSON.stringify({ type: 'connection_success', message: 'WebSocket connection established' }));
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
            // Handle incoming messages from admin clients
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
    await SystemLog.create({
        action,
        userId,
        ipAddress: metadata.ipAddress || '',
        userAgent: metadata.userAgent || '',
        metadata
    });
}

// Authentication Middleware
async function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

async function authenticateAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = await Admin.findOne({ email: decoded.email });
        if (!admin) {
            return res.status(401).json({ error: 'Admin not found' });
        }

        req.admin = admin;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// API Routes

// Authentication Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { email, password, firstName, lastName, country, currency } = req.body;

        if (!email || !password || !firstName || !lastName || !country || !currency) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            country,
            currency,
            balance: 0
        });

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        await logAction(user._id, 'user_signup', { method: 'email' });

        res.status(201).json({
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
        console.error(err);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature, firstName, lastName, country, currency } = req.body;

        if (!walletAddress || !signature || !firstName || !lastName || !country || !currency) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const existingUser = await User.findOne({ walletAddress });
        if (existingUser) {
            return res.status(400).json({ error: 'Wallet already in use' });
        }

        // In a real app, you would verify the signature against the wallet address here
        // For this example, we'll assume the verification is successful

        const user = await User.create({
            walletAddress,
            firstName,
            lastName,
            country,
            currency,
            balance: 0
        });

        const token = jwt.sign({ userId: user._id, walletAddress: user.walletAddress }, JWT_SECRET, { expiresIn: '7d' });

        await logAction(user._id, 'user_signup', { method: 'wallet', walletAddress });

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during wallet signup' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        await User.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
        await logAction(user._id, 'user_login', { method: 'email', ipAddress: req.ip });

        res.json({
            message: 'Login successful',
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
        console.error(err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Dashboard Stats
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const verifiedUsers = await User.countDocuments({ kycStatus: 'approved' });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        res.json({
            data: {
                totalUsers,
                verifiedUsers,
                totalTrades,
                totalVolume: totalVolume[0]?.total || 0,
                userGrowthRate: 10, // Example - calculate real growth
                verifiedGrowthRate: 15,
                tradeGrowthRate: 20,
                volumeChangeRate: 5,
                growthData: {
                    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
                    users: [100, 150, 200, 250, 300],
                    trades: [50, 75, 100, 125, 150]
                },
                userDistribution: {
                    verified: verifiedUsers,
                    pending: await User.countDocuments({ kycStatus: 'pending' }),
                    unverified: await User.countDocuments({ kycStatus: 'not_submitted' }),
                    suspended: await User.countDocuments({ status: 'suspended' })
                }
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching dashboard stats' });
    }
});

// Settings Endpoint
app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
    try {
        res.json({
            data: {
                systemName: "Crypto Trading Platform",
                maintenanceMode: false,
                registrationStatus: true,
                kycRequirement: true,
                tradeFee: 0.1,
                withdrawalFee: 0.05
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error loading settings' });
    }
});

// Users Endpoint
app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search, status, kyc } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query.$or = [
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } }
            ];
        }
        if (status) query.status = status;
        if (kyc) query.kycStatus = kyc;
        
        const users = await User.find(query)
            .skip(skip)
            .limit(parseInt(limit))
            .lean();
            
        const total = await User.countDocuments(query);
        
        res.json({
            data: {
                users: users.map(user => ({
                    ...user,
                    fullName: `${user.firstName} ${user.lastName}`,
                    kycVerified: user.kycStatus === 'approved'
                })),
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching users' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;

        if (!walletAddress || !signature) {
            return res.status(400).json({ error: 'Wallet address and signature are required' });
        }

        // In a real app, you would verify the signature against the wallet address here
        // For this example, we'll assume the verification is successful

        const user = await User.findOne({ walletAddress });
        if (!user) {
            return res.status(404).json({ error: 'Wallet not registered. Please sign up first.' });
        }

        const token = jwt.sign({ userId: user._id, walletAddress: user.walletAddress }, JWT_SECRET, { expiresIn: '7d' });

        await User.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
        await logAction(user._id, 'user_login', { method: 'wallet', walletAddress, ipAddress: req.ip });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during wallet login' });
    }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
    try {
        await logAction(req.user._id, 'user_logout', { ipAddress: req.ip });
        res.json({ message: 'Logout successful' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during logout' });
    }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            // Don't reveal whether the email exists for security reasons
            return res.json({ message: 'If an account with this email exists, a reset link has been sent' });
        }

        const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;

        await transporter.sendMail({
            from: 'support@youngblood.com',
            to: user.email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="${resetLink}">Reset Password</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            `
        });

        await logAction(user._id, 'password_reset_requested', { ipAddress: req.ip });

        res.json({ message: 'If an account with this email exists, a reset link has been sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during password reset request' });
    }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.updateOne({ _id: user._id }, { $set: { password: hashedPassword } });

        await logAction(user._id, 'password_reset_completed', { ipAddress: req.ip });

        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(400).json({ error: 'Reset token has expired' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(400).json({ error: 'Invalid reset token' });
        }
        console.error(err);
        res.status(500).json({ error: 'Server error during password reset' });
    }
});

app.get('/api/v1/auth/status', authenticate, async (req, res) => {
    try {
        res.json({
            isAuthenticated: true,
            user: {
                id: req.user._id,
                email: req.user.email,
                walletAddress: req.user.walletAddress,
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                balance: req.user.balance,
                kycStatus: req.user.kycStatus
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error checking auth status' });
    }
});

// Admin Authentication Routes
app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ 
            userId: admin._id, 
            email: admin.email, 
            isAdmin: true,
            permissions: admin.permissions 
        }, JWT_SECRET, { expiresIn: '7d' });

        await Admin.updateOne({ _id: admin._id }, { $set: { lastLogin: new Date() } });
        await logAction(admin._id, 'admin_login', { ipAddress: req.ip });

        // Modified response structure to match frontend expectations
        res.json({
            message: 'Admin login successful',
            token,
            data: {
                admin: {
                    id: admin._id,
                    email: admin.email,
                    permissions: admin.permissions
                }
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during admin login' });
    }
});
app.get('/api/v1/admin/verify', authenticateAdmin, async (req, res) => {
    try {
        // Modified response structure to match frontend expectations
        res.json({
            isAuthenticated: true,
            data: {
                admin: {
                    id: req.admin._id,
                    email: req.admin.email,
                    permissions: req.admin.permissions
                }
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error verifying admin token' });
    }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
    try {
        res.json({
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
            createdAt: req.user.createdAt
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }    
});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching user data' });
    }
});

app.get('/api/v1/users/settings', authenticate, async (req, res) => {
    try {
        res.json({
            currency: req.user.currency,
            twoFactorEnabled: req.user.twoFactorEnabled,
            notificationPreferences: req.user.notificationPreferences || {}
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching user settings' });
    }
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
    try {
        const { currency, twoFactorEnabled, notificationPreferences } = req.body;

        const update = {};
        if (currency) update.currency = currency;
        if (typeof twoFactorEnabled === 'boolean') update.twoFactorEnabled = twoFactorEnabled;
        if (notificationPreferences) update.notificationPreferences = notificationPreferences;

        await User.updateOne({ _id: req.user._id }, { $set: update });
        await logAction(req.user._id, 'user_settings_updated', { settings: update });

        res.json({ message: 'Settings updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error updating user settings' });
    }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
    try {
        const apiKey = generateApiKey();
        await User.updateOne({ _id: req.user._id }, { $set: { apiKey } });
        await logAction(req.user._id, 'api_key_generated');

        res.json({ message: 'API key generated successfully', apiKey });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error generating API key' });
    }
});

app.post('/api/v1/users/kyc', authenticate, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 },
    { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    try {
        const { documentType, documentNumber } = req.body;
        const files = req.files;

        if (!documentType || !documentNumber || !files?.frontImage || !files?.selfie) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        const kycDocument = {
            documentType,
            documentNumber,
            frontImage: files.frontImage[0].path,
            selfie: files.selfie[0].path,
            submittedAt: new Date()
        };

        if (files.backImage) {
            kycDocument.backImage = files.backImage[0].path;
        }

        await User.updateOne(
            { _id: req.user._id },
            { 
                $set: { kycStatus: 'pending' },
                $push: { kycDocuments: kycDocument }
            }
        );

        await logAction(req.user._id, 'kyc_submitted');
        notifyAdmins({
            type: 'kyc_submitted',
            userId: req.user._id,
            message: `New KYC submission from ${req.user.email}`
        });

        res.json({ message: 'KYC documents submitted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error submitting KYC documents' });
    }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).lean();
        const trades = await Trade.find({ userId: req.user._id }).lean();
        const transactions = await Transaction.find({ userId: req.user._id }).lean();
        const tickets = await SupportTicket.find({ userId: req.user._id }).lean();

        const data = {
            user,
            trades,
            transactions,
            tickets
        };

        // In a real app, you would generate a file and send a download link
        // For this example, we'll just return the data directly

        await logAction(req.user._id, 'data_export_requested');

        res.json({
            message: 'Data export generated successfully',
            data
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error exporting user data' });
    }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // In a real app, you might want to anonymize data instead of deleting it
        await User.deleteOne({ _id: req.user._id });
        await Trade.deleteMany({ userId: req.user._id });
        await Transaction.deleteMany({ userId: req.user._id });
        await SupportTicket.deleteMany({ userId: req.user._id });

        await logAction(req.user._id, 'account_deleted');

        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error deleting account' });
    }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', authenticate, async (req, res) => {
    try {
        res.json({
            address: DEPOSIT_ADDRESS,
            currency: 'BTC',
            note: `Include your user ID (${req.user._id}) in the memo when depositing`
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching deposit address' });
    }
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, currency, address } = req.body;

        if (!amount || !currency || !address) {
            return res.status(400).json({ error: 'Amount, currency, and address are required' });
        }

        if (amount <= 0) {
            return res.status(400).json({ error: 'Amount must be positive' });
        }

        if (req.user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        if (req.user.kycStatus !== 'approved') {
            return res.status(403).json({ error: 'KYC verification required for withdrawals' });
        }

        // Deduct from user balance
        await User.updateOne(
            { _id: req.user._id },
            { $inc: { balance: -amount } }
        );

        // Create withdrawal transaction
        const transaction = await Transaction.create({
            userId: req.user._id,
            type: 'withdrawal',
            amount,
            currency,
            status: 'pending',
            address
        });

        await logAction(req.user._id, 'withdrawal_requested', { amount, currency, address });
        notifyAdmins({
            type: 'withdrawal_request',
            userId: req.user._id,
            transactionId: transaction._id,
            amount,
            currency,
            address,
            message: `New withdrawal request from ${req.user.email} for ${amount} ${currency}`
        });

        res.json({
            message: 'Withdrawal request submitted. It will be processed manually.',
            transactionId: transaction._id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error processing withdrawal' });
    }
});

app.get('/api/v1/wallet/transactions', authenticate, async (req, res) => {
    try {
        const { type, limit = 10, offset = 0 } = req.query;
        const query = { userId: req.user._id };
        
        if (type) {
            query.type = type;
        }

        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit));

        const total = await Transaction.countDocuments(query);

        res.json({
            transactions,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching transactions' });
    }
});

// Trading Routes
app.get('/api/v1/exchange/coins', async (req, res) => {
    try {
        const coins = await Coin.find({ isActive: true });
        res.json(coins);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching coins' });
    }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
    try {
        const coins = await Coin.find({ isActive: true });
        const rates = {};

        // Generate rates between all coin pairs
        for (const fromCoin of coins) {
            rates[fromCoin.symbol] = {};
            for (const toCoin of coins) {
                if (fromCoin.symbol === toCoin.symbol) {
                    rates[fromCoin.symbol][toCoin.symbol] = 1;
                } else {
                    // Simple arbitrage logic - adjust rates slightly to create opportunities
                    const baseRate = toCoin.price / fromCoin.price;
                    const spread = 0.001; // 0.1% spread
                    rates[fromCoin.symbol][toCoin.symbol] = baseRate * (1 - spread);
                    rates[toCoin.symbol][fromCoin.symbol] = 1 / (baseRate * (1 + spread));
                }
            }
        }

        res.json(rates);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching rates' });
    }
});

app.get('/api/v1/exchange/rate', async (req, res) => {
    try {
        const { from, to } = req.query;

        if (!from || !to) {
            return res.status(400).json({ error: 'From and to currencies are required' });
        }

        const fromCoin = await Coin.findOne({ symbol: from, isActive: true });
        const toCoin = await Coin.findOne({ symbol: to, isActive: true });

        if (!fromCoin || !toCoin) {
            return res.status(404).json({ error: 'One or both currencies not found' });
        }

        if (from === to) {
            return res.json({ rate: 1 });
        }

        // Same arbitrage logic as in the rates endpoint
        const baseRate = toCoin.price / fromCoin.price;
        const spread = 0.001; // 0.1% spread
        const rate = baseRate * (1 - spread);

        res.json({ rate });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching rate' });
    }
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
    try {
        const { from, to, amount } = req.body;

        if (!from || !to || !amount) {
            return res.status(400).json({ error: 'From, to, and amount are required' });
        }

        if (amount <= 0) {
            return res.status(400).json({ error: 'Amount must be positive' });
        }

        // Get current rates
        const fromCoin = await Coin.findOne({ symbol: from, isActive: true });
        const toCoin = await Coin.findOne({ symbol: to, isActive: true });

        if (!fromCoin || !toCoin) {
            return res.status(404).json({ error: 'One or both currencies not found' });
        }

        // Calculate rate with spread
        const baseRate = toCoin.price / fromCoin.price;
        const spread = 0.001; // 0.1% spread
        const rate = baseRate * (1 - spread);
        const fee = amount * 0.001; // 0.1% fee
        const amountAfterFee = amount - fee;
        const convertedAmount = amountAfterFee * rate;

        // Check if user has enough balance
        if (from === 'USD') {
            if (req.user.balance < amount) {
                return res.status(400).json({ error: 'Insufficient balance' });
            }
        } else {
            // For crypto-to-crypto trades, we'd need to track individual coin balances
            // For this example, we'll just use the USD balance
            return res.status(400).json({ error: 'Only USD conversions are supported in this demo' });
        }

        // Update balances
        await User.updateOne(
            { _id: req.user._id },
            { $inc: { balance: -amount } }
        );

        // Create trade record
        const trade = await Trade.create({
            userId: req.user._id,
            fromCoin: from,
            toCoin: to,
            amount,
            rate,
            fee,
            status: 'completed'
        });

        // Create transaction for the converted amount
        await Transaction.create({
            userId: req.user._id,
            type: 'trade',
            amount: convertedAmount,
            currency: to,
            status: 'completed',
            txHash: `trade-${trade._id}`
        });

        // Notify user via WebSocket
        notifyUser(req.user._id, {
            type: 'trade_completed',
            tradeId: trade._id,
            from,
            to,
            amount,
            convertedAmount,
            fee
        });

        await logAction(req.user._id, 'trade_executed', { from, to, amount, convertedAmount, fee });

        res.json({
            message: 'Conversion completed successfully',
            from,
            to,
            amount,
            convertedAmount,
            rate,
            fee,
            tradeId: trade._id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during conversion' });
    }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
    try {
        const { limit = 10, offset = 0 } = req.query;
        const trades = await Trade.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit));

        const total = await Trade.countDocuments({ userId: req.user._id });

        res.json({
            trades,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching trade history' });
    }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = await FAQ.find({ isActive: true });
        res.json(faqs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching FAQs' });
    }
});

app.post('/api/v1/support/contact', async (req, res) => {
    try {
        const { email, subject, message } = req.body;

        if (!email || !subject || !message) {
            return res.status(400).json({ error: 'Email, subject, and message are required' });
        }

        const ticket = await SupportTicket.create({
            email,
            subject,
            message,
            status: 'open'
        });

        // Notify admins
        notifyAdmins({
            type: 'new_support_ticket',
            ticketId: ticket._id,
            email,
            subject,
            message: `New support ticket from ${email}: ${subject}`
        });

        res.json({
            message: 'Support ticket submitted successfully',
            ticketId: ticket._id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error submitting support ticket' });
    }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
    try {
        const { subject, message } = req.body;

        if (!subject || !message) {
            return res.status(400).json({ error: 'Subject and message are required' });
        }

        const ticket = await SupportTicket.create({
            userId: req.user._id,
            email: req.user.email,
            subject,
            message,
            status: 'open'
        });

        // Notify admins
        notifyAdmins({
            type: 'new_support_ticket',
            ticketId: ticket._id,
            userId: req.user._id,
            email: req.user.email,
            subject,
            message: `New support ticket from user ${req.user.email}: ${subject}`
        });

        await logAction(req.user._id, 'support_ticket_created', { ticketId: ticket._id });

        res.json({
            message: 'Support ticket submitted successfully',
            ticketId: ticket._id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error submitting support ticket' });
    }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
    try {
        const { status, limit = 10, offset = 0 } = req.query;
        const query = { userId: req.user._id };
        
        if (status) {
            query.status = status;
        }

        const tickets = await SupportTicket.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit));

        const total = await SupportTicket.countDocuments(query);

        res.json({
            tickets,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching support tickets' });
    }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const newUsersToday = await User.countDocuments({
            createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
        const openTickets = await SupportTicket.countDocuments({ status: 'open' });

        res.json({
            totalUsers,
            newUsersToday,
            totalTrades,
            totalVolume: totalVolume[0]?.total || 0,
            pendingWithdrawals,
            pendingKYC,
            openTickets
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching dashboard stats' });
    }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { search, status, kycStatus, limit = 10, offset = 0 } = req.query;
        const query = {};

        if (search) {
            query.$or = [
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ];
        }

        if (status === 'active') {
            query.lastLogin = { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }; // Active in last 30 days
        } else if (status === 'inactive') {
            query.lastLogin = { $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) };
        }

        if (kycStatus) {
            query.kycStatus = kycStatus;
        }

        const users = await User.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .select('-password');

        const total = await User.countDocuments(query);

        res.json({
            users,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching users' });
    }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
        const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
        const tickets = await SupportTicket.find({ userId: user._id }).sort({ createdAt: -1 }).limit(5);

        res.json({
            user,
            recentTrades: trades,
            recentTransactions: transactions,
            recentTickets: tickets
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching user details' });
    }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { balance, kycStatus } = req.body;

        const update = {};
        if (balance !== undefined) update.balance = parseFloat(balance);
        if (kycStatus) update.kycStatus = kycStatus;

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { $set: update },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Notify user if their KYC status changed
        if (kycStatus && kycStatus !== user.kycStatus) {
            notifyUser(user._id, {
                type: 'kyc_status_changed',
                status: kycStatus
            });
        }

        await logAction(req.admin._id, 'user_updated', { userId: user._id, updates: update });

        res.json({
            message: 'User updated successfully',
            user
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error updating user' });
    }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
    try {
        const { userId, status, from, to, limit = 10, offset = 0 } = req.query;
        const query = {};

        if (userId) query.userId = userId;
        if (status) query.status = status;
        if (from) query.fromCoin = from;
        if (to) query.toCoin = to;

        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');

        const total = await Trade.countDocuments(query);

        res.json({
            trades,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching trades' });
    }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const { userId, type, status, currency, limit = 10, offset = 0 } = req.query;
        const query = {};

        if (userId) query.userId = userId;
        if (type) query.type = type;
        if (status) query.status = status;
        if (currency) query.currency = currency;

        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');

        const total = await Transaction.countDocuments(query);

        res.json({
            transactions,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching transactions' });
    }
});

app.put('/api/v1/admin/transactions/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, adminNote } = req.body;

        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        const update = {};
        if (status) update.status = status;
        if (adminNote) update.adminNote = adminNote;

        const updatedTransaction = await Transaction.findByIdAndUpdate(
            req.params.id,
            { $set: update },
            { new: true }
        ).populate('userId', 'email firstName lastName');

        // If this was a withdrawal that was completed, notify the user
        if (status === 'completed' && transaction.type === 'withdrawal') {
            notifyUser(transaction.userId, {
                type: 'withdrawal_completed',
                transactionId: transaction._id,
                amount: transaction.amount,
                currency: transaction.currency
            });
        }

        await logAction(req.admin._id, 'transaction_updated', { 
            transactionId: transaction._id, 
            updates: update 
        });

        res.json({
            message: 'Transaction updated successfully',
            transaction: updatedTransaction
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error updating transaction' });
    }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
    try {
        const { status, search, limit = 10, offset = 0 } = req.query;
        const query = {};

        if (status) query.status = status;
        if (search) {
            query.$or = [
                { subject: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        const tickets = await SupportTicket.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');

        const total = await SupportTicket.countDocuments(query);

        res.json({
            tickets,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching tickets' });
    }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id)
            .populate('userId', 'email firstName lastName');

        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        res.json(ticket);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching ticket' });
    }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, response } = req.body;

        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        const update = {};
        if (status) update.status = status;

        if (response) {
            update.$push = {
                responses: {
                    message: response,
                    isAdmin: true
                }
            };
        }

        const updatedTicket = await SupportTicket.findByIdAndUpdate(
            req.params.id,
            update,
            { new: true }
        ).populate('userId', 'email firstName lastName');

        // Notify user if there was a response
        if (response && ticket.userId) {
            notifyUser(ticket.userId, {
                type: 'ticket_response',
                ticketId: ticket._id,
                message: response
            });
        }

        await logAction(req.admin._id, 'ticket_updated', { 
            ticketId: ticket._id, 
            updates: { status, response: !!response }
        });

        res.json({
            message: 'Ticket updated successfully',
            ticket: updatedTicket
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error updating ticket' });
    }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
    try {
        const { status, limit = 10, offset = 0 } = req.query;
        const query = { kycStatus: status || 'pending' };

        const users = await User.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .select('email firstName lastName kycStatus kycDocuments createdAt');

        const total = await User.countDocuments(query);

        res.json({
            users,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching KYC submissions' });
    }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        if (!status || !['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Valid status is required' });
        }

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { $set: { kycStatus: status } },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Notify user
        notifyUser(user._id, {
            type: 'kyc_status_changed',
            status
        });

        await logAction(req.admin._id, 'kyc_reviewed', { 
            userId: user._id, 
            status 
        });

        res.json({
            message: 'KYC status updated successfully',
            user
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error updating KYC status' });
    }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
    try {
        const { action, userId, limit = 10, offset = 0 } = req.query;
        const query = {};

        if (action) query.action = action;
        if (userId) query.userId = userId;

        const logs = await SystemLog.find(query)
            .sort({ createdAt: -1 })
            .skip(parseInt(offset))
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');

        const total = await SystemLog.countDocuments(query);

        res.json({
            logs,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching logs' });
    }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;

        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }

        // Send to all connected users
        clients.forEach(ws => {
            ws.send(JSON.stringify({
                type: 'admin_broadcast',
                message,
                timestamp: new Date()
            }));
        });

        await logAction(req.admin._id, 'admin_broadcast', { message });

        res.json({ message: 'Broadcast sent successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error sending broadcast' });
    }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({
            lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const kycApproved = await User.countDocuments({ kycStatus: 'approved' });

        res.json({
            totalUsers,
            activeUsers,
            totalTrades,
            totalVolume: totalVolume[0]?.total || 0,
            kycApproved
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching stats' });
    }
});

// Team Routes
app.get('/api/v1/team', async (req, res) => {
    try {
        // In a real app, this would come from a database
        // For this example, we'll return hardcoded data
        const team = [
            {
                id: 1,
                name: 'John Smith',
                position: 'CEO & Founder',
                bio: 'Blockchain expert with 10+ years of experience in cryptocurrency trading platforms.',
                image: '/images/team/john-smith.jpg'
            },
            {
                id: 2,
                name: 'Sarah Johnson',
                position: 'CTO',
                bio: 'Software architect specializing in high-performance trading systems and security.',
                image: '/images/team/sarah-johnson.jpg'
            },
            {
                id: 3,
                name: 'Michael Chen',
                position: 'Lead Developer',
                bio: 'Full-stack developer with expertise in blockchain integration and API design.',
                image: '/images/team/michael-chen.jpg'
            },
            {
                id: 4,
                name: 'Emily Wilson',
                position: 'Customer Support',
                bio: 'Dedicated support specialist ensuring our users have the best possible experience.',
                image: '/images/team/emily-wilson.jpg'
            }
        ];

        res.json(team);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching team data' });
    }
});
// Admin Notifications Endpoint
app.get('/api/v1/admin/notifications', authenticateAdmin, async (req, res) => {
    try {
        // Get pending tickets count
        const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
        
        // Get pending KYC count
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
        
        // Get recent notifications (last 5)
        const notifications = await SystemLog.find({ 
            action: { $in: ['user_signup', 'trade_executed', 'kyc_submitted', 'support_ticket_created'] }
        })
        .sort({ createdAt: -1 })
        .limit(5)
        .populate('userId', 'email firstName lastName');
        
        // Format notifications for frontend
        const formattedNotifications = notifications.map(log => {
            let icon = '';
            let type = '';
            let title = '';
            
            switch(log.action) {
                case 'user_signup':
                    icon = 'bi-person-plus';
                    type = 'user';
                    title = `New user registered: ${log.userId?.firstName || 'Unknown'}`;
                    break;
                case 'trade_executed':
                    icon = 'bi-currency-exchange';
                    type = 'trade';
                    title = `New trade executed by ${log.userId?.firstName || 'Unknown'}`;
                    break;
                case 'kyc_submitted':
                    icon = 'bi-shield-check';
                    type = 'kyc';
                    title = `New KYC submission from ${log.userId?.firstName || 'Unknown'}`;
                    break;
                case 'support_ticket_created':
                    icon = 'bi-ticket-perforated';
                    type = 'ticket';
                    title = `New support ticket created`;
                    break;
            }
            
            return {
                icon,
                type,
                title,
                timestamp: log.createdAt
            };
        });
        
        res.json({
            data: {
                unreadCount: pendingTickets + pendingKYC,
                pendingTickets,
                pendingKYC,
                notifications: formattedNotifications
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load notifications' });
    }
});

// Recent Users Endpoint
app.get('/api/v1/admin/recent-users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .sort({ createdAt: -1 })
            .limit(5)
            .select('firstName lastName email walletAddress balance kycStatus createdAt');
            
        res.json({
            data: users.map(user => ({
                _id: user._id,
                fullName: `${user.firstName} ${user.lastName}`,
                email: user.email,
                walletAddress: user.walletAddress,
                balance: user.balance,
                kycVerified: user.kycStatus === 'approved',
                kycStatus: user.kycStatus,
                status: 'active', // You should add status field to your User model
                createdAt: user.createdAt
            }))
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load recent users' });
    }
});

// Recent Activities Endpoint
app.get('/api/v1/admin/recent-activities', authenticateAdmin, async (req, res) => {
    try {
        const activities = await SystemLog.find()
            .sort({ createdAt: -1 })
            .limit(5)
            .populate('userId', 'firstName lastName');
            
        res.json({
            data: activities.map(activity => ({
                _id: activity._id,
                type: activity.action.includes('login') ? 'login' : 
                      activity.action.includes('trade') ? 'trade' :
                      activity.action.includes('withdrawal') ? 'withdrawal' :
                      activity.action.includes('deposit') ? 'deposit' : 'account',
                description: activity.action,
                ipAddress: activity.ipAddress,
                timestamp: activity.createdAt,
                user: {
                    fullName: activity.userId ? `${activity.userId.firstName} ${activity.userId.lastName}` : 'System'
                }
            }))
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load recent activities' });
    }
});

// Export Endpoints
app.get('/api/v1/admin/:type/export', authenticateAdmin, async (req, res) => {
    try {
        const { type } = req.params;
        let data;
        let filename;
        
        switch(type) {
            case 'users':
                data = await User.find().lean();
                filename = 'users-export.csv';
                break;
            case 'trades':
                data = await Trade.find().lean();
                filename = 'trades-export.csv';
                break;
            case 'transactions':
                data = await Transaction.find().lean();
                filename = 'transactions-export.csv';
                break;
            case 'tickets':
                data = await SupportTicket.find().lean();
                filename = 'tickets-export.csv';
                break;
            case 'logs':
                data = await SystemLog.find().lean();
                filename = 'logs-export.csv';
                break;
            default:
                return res.status(400).json({ error: 'Invalid export type' });
        }
        
        // Convert to CSV
        let csv = '';
        if (data.length > 0) {
            // Headers
            csv = Object.keys(data[0]).join(',') + '\n';
            
            // Rows
            data.forEach(item => {
                csv += Object.values(item).map(val => 
                    typeof val === 'object' ? JSON.stringify(val) : val
                ).join(',') + '\n';
            });
        }
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
        res.send(csv);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
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
