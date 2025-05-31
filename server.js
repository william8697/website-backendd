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
const WebSocket = require('ws');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { ethers } = require('ethers');
const fs = require('fs');

// Constants
const JWT_SECRET = '17581758Na.%';
const DEPOSIT_WALLET = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '17581758..';
const FRONTEND_URL = 'https://website-xi-ten-52.vercel.app';

// Initialize Express
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('MongoDB connected');
    initializeAdmin();
})
.catch(err => console.error('MongoDB connection error:', err));

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: FRONTEND_URL,
    credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api', limiter);

// Models
const UserSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, select: false },
    walletAddress: { type: String, unique: true, sparse: true },
    country: { type: String, required: true },
    currency: { type: String, default: 'USD' },
    balance: { type: Number, default: 0 },
    isAdmin: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    kycStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
    kycDocs: [{
        docType: String,
        docNumber: String,
        frontImage: String,
        backImage: String,
        selfie: String,
        submittedAt: Date
    }],
    settings: {
        twoFactorEnabled: { type: Boolean, default: false },
        notifications: {
            email: { type: Boolean, default: true },
            push: { type: Boolean, default: false }
        }
    },
    apiKey: { type: String },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'conversion'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    details: { type: Object },
    createdAt: { type: Date, default: Date.now }
});

const TradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    fromAmount: { type: Number, required: true },
    toAmount: { type: Number, required: true },
    rate: { type: Number, required: true },
    fee: { type: Number, default: 0 },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
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
    order: { type: Number, default: 0 }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);

// Initialize Admin
async function initializeAdmin() {
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
        await User.create({
            firstName: 'Admin',
            lastName: 'System',
            email: ADMIN_EMAIL,
            password: hashedPassword,
            isAdmin: true,
            isVerified: true,
            balance: 1000000
        });
        console.log('Admin account created');
    }
}

// Email Transport
const transporter = nodemailer.createTransport({
    host: 'sandbox.sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// File Upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage });

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });
const clients = new Map();

wss.on('connection', (ws, userId) => {
    clients.set(userId.toString(), ws);
    
    ws.on('close', () => {
        clients.delete(userId.toString());
    });
});

// Broadcast to specific user
function broadcastToUser(userId, data) {
    const ws = clients.get(userId.toString());
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
    }
}

// Broadcast to all admins
async function broadcastToAdmins(data) {
    const admins = await User.find({ isAdmin: true });
    admins.forEach(admin => {
        broadcastToUser(admin._id, data);
    });
}

// Auth Middleware
const auth = async (req, res, next) => {
    try {
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies?.token) {
            token = req.cookies.token;
        }

        if (!token) {
            return res.status(401).json({ success: false, message: 'Not authorized' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            return res.status(401).json({ success: false, message: 'Not authorized' });
        }

        req.user = user;
        next();
    } catch (err) {
        console.error(err);
        res.status(401).json({ success: false, message: 'Not authorized' });
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

        if (!token) {
            return res.status(401).json({ success: false, message: 'Not authorized' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');

        if (!user || !user.isAdmin) {
            return res.status(401).json({ success: false, message: 'Not authorized as admin' });
        }

        req.user = user;
        next();
    } catch (err) {
        console.error(err);
        res.status(401).json({ success: false, message: 'Not authorized' });
    }
};

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'Passwords do not match' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = await User.create({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            country,
            currency
        });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

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
        if (err.code === 11000) {
            return res.status(400).json({ success: false, message: 'Email already exists' });
        }
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
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
        user.lastLogin = Date.now();
        await user.save();

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

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature, firstName, lastName, country, currency } = req.body;

        // Verify signature
        const message = `Welcome to CryptoApp! Please sign this message to verify your wallet. Nonce: ${crypto.randomBytes(16).toString('hex')}`;
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);

        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(401).json({ success: false, message: 'Signature verification failed' });
        }

        const user = await User.create({
            firstName,
            lastName,
            walletAddress,
            country,
            currency
        });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        if (err.code === 11000) {
            return res.status(400).json({ success: false, message: 'Wallet already registered' });
        }
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;

        // Verify signature
        const message = `Welcome back to CryptoApp! Please sign this message to verify your wallet. Nonce: ${crypto.randomBytes(16).toString('hex')}`;
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);

        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(401).json({ success: false, message: 'Signature verification failed' });
        }

        const user = await User.findOne({ walletAddress });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Wallet not registered' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        user.lastLogin = Date.now();
        await user.save();

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpiry;
        await user.save();

        const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;

        await transporter.sendMail({
            to: user.email,
            subject: 'Password Reset Request',
            html: `You are receiving this because you requested a password reset. Please click on the following link to complete the process: <a href="${resetUrl}">${resetUrl}</a>`
        });

        res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'Passwords do not match' });
        }

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired token' });
        }

        user.password = await bcrypt.hash(password, 12);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        await transporter.sendMail({
            to: user.email,
            subject: 'Password Changed',
            html: 'Your password has been successfully changed.'
        });

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/auth/status', auth, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user._id,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            email: req.user.email,
            walletAddress: req.user.walletAddress,
            isAdmin: req.user.isAdmin,
            balance: req.user.balance
        }
    });
});

app.post('/api/v1/auth/logout', auth, (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

// User Routes
app.get('/api/v1/users/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/users/update', auth, async (req, res) => {
    try {
        const { firstName, lastName, country, currency } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { firstName, lastName, country, currency },
            { new: true }
        ).select('-password');

        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.patch('/api/v1/auth/update-password', auth, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'Passwords do not match' });
        }

        const user = await User.findById(req.user._id).select('+password');
        const isMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect' });
        }

        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/users/kyc', auth, upload.array('documents', 3), async (req, res) => {
    try {
        const { docType, docNumber } = req.body;
        const files = req.files;

        if (!files || files.length < 2) {
            return res.status(400).json({ success: false, message: 'Please upload all required documents' });
        }

        const user = await User.findById(req.user._id);
        user.kycStatus = 'pending';
        user.kycDocs = [{
            docType,
            docNumber,
            frontImage: files[0].path,
            backImage: files[1].path,
            selfie: files[2]?.path,
            submittedAt: Date.now()
        }];

        await user.save();

        // Notify admins
        await broadcastToAdmins({
            type: 'KYC_SUBMITTED',
            userId: user._id,
            message: 'New KYC submission'
        });

        res.json({ success: true, message: 'KYC documents submitted for review' });
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

app.patch('/api/v1/users/settings', auth, async (req, res) => {
    try {
        const { settings } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { settings },
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

app.post('/api/v1/users/export-data', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        const transactions = await Transaction.find({ userId: req.user._id });
        const trades = await Trade.find({ userId: req.user._id });

        const data = {
            user,
            transactions,
            trades
        };

        // In a real app, you would generate a file and email it
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

        res.json({ success: true, message: 'Account deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Wallet Routes
app.get('/api/v1/wallet/balance', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('balance');
        res.json({ success: true, balance: user.balance });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/deposit-address', auth, (req, res) => {
    res.json({ success: true, address: DEPOSIT_WALLET });
});

app.post('/api/v1/wallet/deposit', auth, async (req, res) => {
    try {
        const { amount, txHash } = req.body;

        // In a real app, you would verify the transaction on the blockchain
        const user = await User.findById(req.user._id);
        user.balance += amount;
        await user.save();

        await Transaction.create({
            userId: user._id,
            type: 'deposit',
            amount,
            currency: 'USD',
            status: 'completed',
            details: { txHash }
        });

        broadcastToUser(user._id, {
            type: 'BALANCE_UPDATE',
            balance: user.balance
        });

        res.json({ success: true, balance: user.balance });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/wallet/withdraw', auth, async (req, res) => {
    try {
        const { amount, walletAddress } = req.body;
        const user = await User.findById(req.user._id);

        if (user.balance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        user.balance -= amount;
        await user.save();

        const transaction = await Transaction.create({
            userId: user._id,
            type: 'withdrawal',
            amount,
            currency: 'USD',
            status: 'pending',
            details: { walletAddress }
        });

        // In a real app, you would process the withdrawal here
        // For demo, we'll just mark it as completed after a delay
        setTimeout(async () => {
            transaction.status = 'completed';
            await transaction.save();

            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance
            });

            broadcastToUser(user._id, {
                type: 'TRANSACTION_UPDATE',
                transactionId: transaction._id,
                status: 'completed'
            });
        }, 5000);

        broadcastToUser(user._id, {
            type: 'BALANCE_UPDATE',
            balance: user.balance
        });

        res.json({ success: true, balance: user.balance, transactionId: transaction._id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/wallet/transactions', auth, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(50);

        res.json({ success: true, transactions });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Trade Routes
const COIN_PRICES = {
    BTC: 50000,
    ETH: 3000,
    BNB: 500,
    SOL: 100,
    XRP: 0.5,
    ADA: 0.4,
    DOGE: 0.1,
    DOT: 5,
    UNI: 10,
    LINK: 15
};

function getExchangeRate(from, to) {
    const fromPrice = COIN_PRICES[from] || 1;
    const toPrice = COIN_PRICES[to] || 1;
    return fromPrice / toPrice;
}

app.get('/api/v1/trade/coins', (req, res) => {
    res.json({ success: true, coins: Object.keys(COIN_PRICES) });
});

app.get('/api/v1/trade/rates', (req, res) => {
    const rates = {};
    const coins = Object.keys(COIN_PRICES);
    
    for (let from of coins) {
        rates[from] = {};
        for (let to of coins) {
            if (from !== to) {
                rates[from][to] = getExchangeRate(from, to);
            }
        }
    }

    res.json({ success: true, rates });
});

app.get('/api/v1/trade/rate', (req, res) => {
    const { from, to } = req.query;
    if (!from || !to || !COIN_PRICES[from] || !COIN_PRICES[to]) {
        return res.status(400).json({ success: false, message: 'Invalid coins' });
    }

    const rate = getExchangeRate(from, to);
    res.json({ success: true, rate });
});

app.post('/api/v1/trade/convert', auth, async (req, res) => {
    try {
        const { fromCoin, toCoin, fromAmount } = req.body;
        
        if (!COIN_PRICES[fromCoin] || !COIN_PRICES[toCoin]) {
            return res.status(400).json({ success: false, message: 'Invalid coins' });
        }

        if (fromAmount <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid amount' });
        }

        const rate = getExchangeRate(fromCoin, toCoin);
        const toAmount = fromAmount * rate * 0.995; // 0.5% fee

        const trade = await Trade.create({
            userId: req.user._id,
            fromCoin,
            toCoin,
            fromAmount,
            toAmount,
            rate,
            fee: fromAmount * rate * 0.005,
            status: 'completed'
        });

        // In a real app, you would update balances here
        broadcastToUser(req.user._id, {
            type: 'TRADE_COMPLETED',
            trade
        });

        res.json({ success: true, trade });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/trade/history', auth, async (req, res) => {
    try {
        const trades = await Trade.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(50);

        res.json({ success: true, trades });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = await FAQ.find().sort({ order: 1 });
        res.json({ success: true, faqs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/contact', async (req, res) => {
    try {
        const { email, subject, message } = req.body;
        const ticket = await SupportTicket.create({
            email,
            subject,
            message,
            status: 'open'
        });

        // Notify admins
        await broadcastToAdmins({
            type: 'NEW_SUPPORT_TICKET',
            ticketId: ticket._id,
            message: 'New support ticket created'
        });

        res.json({ success: true, ticketId: ticket._id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/tickets', auth, async (req, res) => {
    try {
        const { subject, message } = req.body;
        const ticket = await SupportTicket.create({
            userId: req.user._id,
            email: req.user.email,
            subject,
            message,
            status: 'open'
        });

        // Notify admins
        await broadcastToAdmins({
            type: 'NEW_SUPPORT_TICKET',
            ticketId: ticket._id,
            message: 'New support ticket created'
        });

        res.json({ success: true, ticketId: ticket._id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/support/my-tickets', auth, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user._id })
            .sort({ createdAt: -1 });

        res.json({ success: true, tickets });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/support/tickets/:id', auth, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket || (ticket.userId && ticket.userId.toString() !== req.user._id.toString())) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/support/tickets/:id/reply', auth, async (req, res) => {
    try {
        const { message } = req.body;
        const ticket = await SupportTicket.findById(req.params.id);

        if (!ticket || (ticket.userId && ticket.userId.toString() !== req.user._id.toString())) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        ticket.responses.push({
            message,
            isAdmin: false
        });
        await ticket.save();

        // Notify admins
        await broadcastToAdmins({
            type: 'TICKET_RESPONSE',
            ticketId: ticket._id,
            message: 'New response to support ticket'
        });

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, isAdmin: true }).select('+password');

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        user.lastLogin = Date.now();
        await user.save();

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

app.get('/api/v1/admin/verify', adminAuth, (req, res) => {
    res.json({ success: true, user: req.user });
});

app.get('/api/v1/admin/dashboard-stats', adminAuth, async (req, res) => {
    try {
        const usersCount = await User.countDocuments();
        const activeUsersCount = await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
        const transactionsCount = await Transaction.countDocuments();
        const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });

        res.json({
            success: true,
            stats: {
                usersCount,
                activeUsersCount,
                transactionsCount,
                pendingTickets,
                pendingKYC
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/users', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        const skip = (page - 1) * limit;

        const query = {};
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ];
        }

        const users = await User.find(query)
            .select('-password')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

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
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const transactions = await Transaction.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(10);

        const trades = await Trade.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(10);

        res.json({
            success: true,
            user,
            transactions,
            trades
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/v1/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const { balance, isVerified, isAdmin, kycStatus } = req.body;
        const user = await User.findById(req.params.id).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (balance !== undefined) user.balance = balance;
        if (isVerified !== undefined) user.isVerified = isVerified;
        if (isAdmin !== undefined) user.isAdmin = isAdmin;
        if (kycStatus !== undefined) user.kycStatus = kycStatus;

        await user.save();

        if (balance !== undefined) {
            broadcastToUser(user._id, {
                type: 'BALANCE_UPDATE',
                balance: user.balance
            });
        }

        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/transactions', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, type, status } = req.query;
        const skip = (page - 1) * limit;

        const query = {};
        if (type) query.type = type;
        if (status) query.status = status;

        const transactions = await Transaction.find(query)
            .populate('userId', 'firstName lastName email')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

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

app.get('/api/v1/admin/trades', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;

        const query = {};
        if (status) query.status = status;

        const trades = await Trade.find(query)
            .populate('userId', 'firstName lastName email')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

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

app.get('/api/v1/admin/tickets', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;

        const query = {};
        if (status) query.status = status;

        const tickets = await SupportTicket.find(query)
            .populate('userId', 'firstName lastName email')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

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

app.put('/api/v1/admin/tickets/:id', adminAuth, async (req, res) => {
    try {
        const { status, response } = req.body;
        const ticket = await SupportTicket.findById(req.params.id);

        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }

        if (status) ticket.status = status;
        if (response) {
            ticket.responses.push({
                message: response,
                isAdmin: true
            });
        }

        await ticket.save();

        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'TICKET_UPDATE',
                ticketId: ticket._id,
                status: ticket.status
            });
        }

        res.json({ success: true, ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/kyc', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;

        const query = { kycStatus: status || 'pending' };
        const users = await User.find(query)
            .select('-password')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

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

app.put('/api/v1/admin/kyc/:id', adminAuth, async (req, res) => {
    try {
        const { status } = req.body;
        const user = await User.findById(req.params.id).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ success: false, message: 'Invalid status' });
        }

        user.kycStatus = status;
        await user.save();

        broadcastToUser(user._id, {
            type: 'KYC_UPDATE',
            status: user.kycStatus
        });

        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/v1/admin/logs', adminAuth, async (req, res) => {
    try {
        // In a real app, you would have a proper logging system
        res.json({ success: true, logs: [] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/v1/admin/broadcast', adminAuth, async (req, res) => {
    try {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ success: false, message: 'Message is required' });
        }

        // Broadcast to all connected clients
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'BROADCAST',
                    message
                }));
            }
        });

        res.json({ success: true, message: 'Broadcast sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
    try {
        const usersCount = await User.countDocuments();
        const transactionsCount = await Transaction.countDocuments();
        const tradesCount = await Trade.countDocuments();
        const totalVolume = await Transaction.aggregate([
            { $match: { type: 'deposit', status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        res.json({
            success: true,
            stats: {
                usersCount,
                transactionsCount,
                tradesCount,
                totalVolume: totalVolume[0]?.total || 0
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// WebSocket Upgrade
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
    const pathname = request.url;

    if (pathname === '/api/v1/admin/ws') {
        // Handle admin WS auth
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else {
        // Handle regular WS connections
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    }
});

// Serve Frontend
const allowedPages = [
    'about.html', 'account.html', 'admin.html', 'dashboard.html', 
    'faqs.html', 'forgot-password.html', 'index.html', 
    'login.html', 'logout.html', 'signup.html', 'support.html'
];

app.get('*', (req, res) => {
    const path = req.path.split('/').pop();
    if (allowedPages.includes(path)) {
        res.sendFile(path.join(__dirname, 'public', path));
    } else {
        res.status(404).send('Not found');
    }
});
