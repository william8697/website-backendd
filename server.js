require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { ethers } = require('ethers');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = '17581758Na.%)';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '$2a$10$NxxhbUv6pBEB7nML'; // Hashed version of '17581758..'
const FIXED_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB connection
mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});

// Models
const User = mongoose.model('User', new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
    walletAddress: String,
    walletType: String,
    country: String,
    currency: { type: String, default: 'USD' },
    balance: { type: Number, default: 0 },
    kycStatus: { type: String, default: 'unverified' },
    kycDocs: [{
        docType: String,
        docUrl: String,
        status: String
    }],
    apiKey: String,
    settings: {
        theme: { type: String, default: 'light' },
        notifications: { type: Boolean, default: true }
    },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    fromCoin: String,
    toCoin: String,
    amount: Number,
    rate: Number,
    result: Number,
    status: { type: String, default: 'completed' },
    createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    type: String, // deposit, withdrawal, trade
    amount: Number,
    coin: String,
    address: String,
    txHash: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    email: String,
    subject: String,
    message: String,
    attachments: [String],
    status: { type: String, default: 'open' },
    responses: [{
        message: String,
        fromAdmin: Boolean,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
    question: String,
    answer: String,
    category: String,
    createdAt: { type: Date, default: Date.now }
}));

const AdminLog = mongoose.model('AdminLog', new mongoose.Schema({
    adminId: mongoose.Schema.Types.ObjectId,
    action: String,
    details: Object,
    createdAt: { type: Date, default: Date.now }
}));

// Email transporter
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// Middleware
app.use(cors({
    origin: 'https://website-xi-ten-52.vercel.app',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// File upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage });

// Auth middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
        if (!token) return res.status(401).json({ error: 'Authentication required' });

        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        if (!req.user) return res.status(401).json({ error: 'User not found' });

        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

const authenticateAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
        if (!token) return res.status(401).json({ error: 'Authentication required' });

        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Initialize default admin
async function initializeAdmin() {
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
        const admin = new User({
            firstName: 'Admin',
            lastName: 'System',
            email: ADMIN_EMAIL,
            password: ADMIN_PASSWORD,
            isAdmin: true,
            balance: 0
        });
        await admin.save();
        console.log('Default admin account created');
    }
}

// Coin data (hardcoded as per requirements)
const COINS = [
    { symbol: 'BTC', name: 'Bitcoin', price: 67432.50, change24h: 2.34 },
    { symbol: 'ETH', name: 'Ethereum', price: 3789.21, change24h: 1.56 },
    { symbol: 'SOL', name: 'Solana', price: 142.67, change24h: 5.23 },
    { symbol: 'XRP', name: 'Ripple', price: 0.5234, change24h: -0.78 },
    { symbol: 'ADA', name: 'Cardano', price: 0.4521, change24h: 3.12 },
    { symbol: 'DOGE', name: 'Dogecoin', price: 0.1234, change24h: 10.45 },
    { symbol: 'DOT', name: 'Polkadot', price: 6.78, change24h: -1.23 },
    { symbol: 'USDT', name: 'Tether', price: 1.00, change24h: 0.00 }
];

// WebSocket server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    initializeAdmin();
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1];
    
    try {
        if (!token) {
            ws.close(1008, 'Authentication required');
            return;
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;
        clients.set(userId, ws);

        ws.on('close', () => {
            clients.delete(userId);
        });

        ws.on('error', (err) => {
            console.error('WebSocket error:', err);
        });

    } catch (err) {
        ws.close(1008, 'Invalid token');
    }
});

function broadcastToUser(userId, event, data) {
    const ws = clients.get(userId.toString());
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ event, data }));
    }
}

function broadcastToAdmins(event, data) {
    clients.forEach((ws, userId) => {
        if (ws.readyState === WebSocket.OPEN) {
            User.findById(userId).then(user => {
                if (user && user.isAdmin) {
                    ws.send(JSON.stringify({ event, data }));
                }
            });
        }
    });
}

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;
        
        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            country,
            currency,
            balance: 0
        });

        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ 
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                currency: user.currency
            }
        });
    } catch (err) {
        if (err.code === 11000) {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, walletType, signature, message } = req.body;
        
        // Verify signature
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(400).json({ error: 'Signature verification failed' });
        }

        let user = await User.findOne({ walletAddress });
        if (!user) {
            user = new User({
                walletAddress,
                walletType,
                balance: 0
            });
            await user.save();
        }
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ 
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                balance: user.balance
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Wallet registration failed' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ 
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                currency: user.currency,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        const nonce = uuidv4();
        res.json({ nonce, message: `Sign this message to authenticate: ${nonce}` });
    } catch (err) {
        res.status(500).json({ error: 'Nonce generation failed' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature, message } = req.body;
        
        // Verify signature
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(400).json({ error: 'Signature verification failed' });
        }

        const user = await User.findOne({ walletAddress });
        if (!user) {
            return res.status(404).json({ error: 'Wallet not registered' });
        }
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ 
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                balance: user.balance,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Wallet login failed' });
    }
});

app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, isAdmin: true });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '8h' });
        
        res.json({ 
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Admin login failed' });
    }
});

app.get('/api/v1/auth/status', authenticate, (req, res) => {
    res.json({
        authenticated: true,
        user: {
            id: req.user._id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            balance: req.user.balance,
            currency: req.user.currency,
            isAdmin: req.user.isAdmin
        }
    });
});

app.get('/api/v1/auth/check', authenticate, (req, res) => {
    res.json({
        authenticated: true,
        user: {
            id: req.user._id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            balance: req.user.balance,
            currency: req.user.currency,
            isAdmin: req.user.isAdmin
        }
    });
});

app.get('/api/v1/auth/verify', authenticate, (req, res) => {
    res.json({
        authenticated: true,
        user: {
            id: req.user._id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            balance: req.user.balance,
            currency: req.user.currency,
            isAdmin: req.user.isAdmin
        }
    });
});

app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
    res.json({
        authenticated: true,
        user: {
            id: req.user._id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            isAdmin: req.user.isAdmin
        }
    });
});

app.post('/api/v1/auth/logout', authenticate, (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            // For security, don't reveal if email exists
            return res.json({ message: 'If an account exists with this email, a reset link has been sent' });
        }
        
        const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
        
        await transporter.sendMail({
            from: 'support@youngblood.com',
            to: user.email,
            subject: 'Password Reset Request',
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
        });
        
        res.json({ message: 'Password reset email sent' });
    } catch (err) {
        res.status(500).json({ error: 'Password reset failed' });
    }
});

app.patch('/api/v1/auth/update-password', authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!(await bcrypt.compare(currentPassword, req.user.password))) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        req.user.password = await bcrypt.hash(newPassword, 10);
        await req.user.save();
        
        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Password update failed' });
    }
});

// User Routes
app.get('/api/v1/users/me', authenticate, (req, res) => {
    res.json({
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        walletAddress: req.user.walletAddress,
        walletType: req.user.walletType,
        country: req.user.country,
        currency: req.user.currency,
        balance: req.user.balance,
        kycStatus: req.user.kycStatus,
        apiKey: req.user.apiKey,
        settings: req.user.settings,
        isAdmin: req.user.isAdmin
    });
});

app.get('/api/v1/users/settings', authenticate, (req, res) => {
    res.json(req.user.settings);
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
    try {
        const { theme, notifications } = req.body;
        
        if (theme) req.user.settings.theme = theme;
        if (notifications !== undefined) req.user.settings.notifications = notifications;
        
        await req.user.save();
        
        res.json({ message: 'Settings updated successfully', settings: req.user.settings });
    } catch (err) {
        res.status(500).json({ error: 'Settings update failed' });
    }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
    try {
        const apiKey = jwt.sign({ userId: req.user._id }, JWT_SECRET + req.user.email, { expiresIn: '365d' });
        req.user.apiKey = apiKey;
        await req.user.save();
        
        res.json({ apiKey });
    } catch (err) {
        res.status(500).json({ error: 'API key generation failed' });
    }
});

app.post('/api/v1/users/kyc', upload.array('documents'), authenticate, async (req, res) => {
    try {
        const { docType } = req.body;
        const files = req.files;
        
        if (!files || files.length === 0) {
            return res.status(400).json({ error: 'No documents uploaded' });
        }
        
        req.user.kycDocs = files.map(file => ({
            docType,
            docUrl: `/uploads/${file.filename}`,
            status: 'pending'
        }));
        req.user.kycStatus = 'pending';
        
        await req.user.save();
        
        // Notify admin
        broadcastToAdmins('kyc_submitted', {
            userId: req.user._id,
            email: req.user.email,
            name: `${req.user.firstName} ${req.user.lastName}`
        });
        
        res.json({ message: 'KYC documents submitted for review', kycStatus: req.user.kycStatus });
    } catch (err) {
        res.status(500).json({ error: 'KYC submission failed' });
    }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
    try {
        const userData = {
            profile: {
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                email: req.user.email,
                walletAddress: req.user.walletAddress,
                country: req.user.country,
                currency: req.user.currency,
                createdAt: req.user.createdAt
            },
            balance: req.user.balance,
            transactions: await Transaction.find({ userId: req.user._id }).lean(),
            trades: await Trade.find({ userId: req.user._id }).lean()
        };
        
        // In a real app, you'd generate a file and email it or provide a download link
        res.json({ 
            message: 'Data export requested', 
            data: userData,
            downloadLink: '#' // Placeholder for actual download link
        });
    } catch (err) {
        res.status(500).json({ error: 'Data export failed' });
    }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!(await bcrypt.compare(password, req.user.password))) {
            return res.status(401).json({ error: 'Password is incorrect' });
        }
        
        // In a real app, you might want to anonymize data instead of deleting
        await Transaction.deleteMany({ userId: req.user._id });
        await Trade.deleteMany({ userId: req.user._id });
        await SupportTicket.deleteMany({ userId: req.user._id });
        await req.user.deleteOne();
        
        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Account deletion failed' });
    }
});

// Wallet Routes
app.get('/api/v1/wallet/deposit-address', authenticate, (req, res) => {
    res.json({ 
        address: FIXED_DEPOSIT_ADDRESS,
        note: `Deposit for user ${req.user.email}` 
    });
});

app.post('/api/v1/wallet/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, address, coin } = req.body;
        
        if (req.user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        if (amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }
        
        const tx = new Transaction({
            userId: req.user._id,
            type: 'withdrawal',
            amount,
            coin,
            address,
            status: 'pending'
        });
        
        await tx.save();
        
        // Deduct balance immediately (will be reversed if admin rejects)
        req.user.balance -= amount;
        await req.user.save();
        
        // Notify admin
        broadcastToAdmins('withdrawal_request', {
            userId: req.user._id,
            email: req.user.email,
            name: `${req.user.firstName} ${req.user.lastName}`,
            amount,
            coin,
            address,
            txId: tx._id
        });
        
        // Notify user
        broadcastToUser(req.user._id, 'transaction_update', {
            type: 'withdrawal',
            amount,
            coin,
            status: 'pending'
        });
        
        res.json({ 
            message: 'Withdrawal request submitted', 
            transaction: tx 
        });
    } catch (err) {
        res.status(500).json({ error: 'Withdrawal failed' });
    }
});

// Exchange Routes
app.get('/api/v1/exchange/coins', (req, res) => {
    res.json(COINS);
});

app.get('/api/v1/exchange/rates', (req, res) => {
    const rates = {};
    COINS.forEach(fromCoin => {
        rates[fromCoin.symbol] = {};
        COINS.forEach(toCoin => {
            // Simple conversion logic - in a real app, this would use real rates
            rates[fromCoin.symbol][toCoin.symbol] = fromCoin.symbol === toCoin.symbol ? 
                1 : (fromCoin.price / toCoin.price).toFixed(8);
        });
    });
    res.json(rates);
});

app.get('/api/v1/exchange/rate', (req, res) => {
    const { from, to } = req.query;
    
    const fromCoin = COINS.find(c => c.symbol === from);
    const toCoin = COINS.find(c => c.symbol === to);
    
    if (!fromCoin || !toCoin) {
        return res.status(400).json({ error: 'Invalid coin symbols' });
    }
    
    const rate = from === to ? 1 : (fromCoin.price / toCoin.price).toFixed(8);
    res.json({ from, to, rate });
});

app.post('/api/v1/exchange/convert', authenticate, async (req, res) => {
    try {
        const { from, to, amount } = req.body;
        
        if (amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }
        
        const fromCoin = COINS.find(c => c.symbol === from);
        const toCoin = COINS.find(c => c.symbol === to);
        
        if (!fromCoin || !toCoin) {
            return res.status(400).json({ error: 'Invalid coin symbols' });
        }
        
        if (from === 'USDT' && req.user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        const rate = from === to ? 1 : (fromCoin.price / toCoin.price);
        const result = amount * rate;
        
        // Update user balance
        if (from === 'USDT') {
            req.user.balance -= amount;
        }
        if (to === 'USDT') {
            req.user.balance += result;
        }
        await req.user.save();
        
        // Record trade
        const trade = new Trade({
            userId: req.user._id,
            fromCoin: from,
            toCoin: to,
            amount,
            rate,
            result,
            status: 'completed'
        });
        await trade.save();
        
        // Record transaction if converting to/from USDT
        if (from === 'USDT' || to === 'USDT') {
            const tx = new Transaction({
                userId: req.user._id,
                type: 'trade',
                amount: from === 'USDT' ? amount : result,
                coin: from === 'USDT' ? from : to,
                status: 'completed'
            });
            await tx.save();
        }
        
        // Notify user
        broadcastToUser(req.user._id, 'balance_update', {
            balance: req.user.balance
        });
        
        broadcastToUser(req.user._id, 'trade_executed', {
            from, to, amount, result, rate
        });
        
        res.json({ 
            from, to, amount, rate, result,
            newBalance: req.user.balance
        });
    } catch (err) {
        res.status(500).json({ error: 'Conversion failed' });
    }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
    try {
        const trades = await Trade.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json(trades);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// Trade Routes
app.get('/api/v1/trades/active', authenticate, async (req, res) => {
    try {
        const trades = await Trade.find({ 
            userId: req.user._id,
            status: 'completed'
        }).sort({ createdAt: -1 }).limit(10);
        
        res.json(trades);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch active trades' });
    }
});

// Transaction Routes
app.get('/api/v1/transactions/recent', authenticate, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(10);
        
        res.json(transactions);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

// Market Routes
app.get('/api/v1/market/data', (req, res) => {
    res.json(COINS);
});

app.get('/api/v1/market/detailed', (req, res) => {
    // More detailed market data (simplified for this example)
    const detailed = COINS.map(coin => ({
        ...coin,
        marketCap: (coin.price * 1000000).toFixed(2), // Fake market cap
        volume: (coin.price * 100000).toFixed(2), // Fake volume
        high24h: (coin.price * 1.05).toFixed(2),
        low24h: (coin.price * 0.95).toFixed(2)
    }));
    
    res.json(detailed);
});

// Portfolio Routes
app.get('/api/v1/portfolio', authenticate, (req, res) => {
    res.json({
        balance: req.user.balance,
        currency: req.user.currency
    });
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = await FAQ.find();
        res.json(faqs);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch FAQs' });
    }
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        res.json(tickets);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tickets' });
    }
});

app.post('/api/v1/support/contact', async (req, res) => {
    try {
        const { email, subject, message } = req.body;
        
        const ticket = new SupportTicket({
            email,
            subject,
            message,
            status: 'open'
        });
        
        await ticket.save();
        
        // Notify admin
        broadcastToAdmins('new_ticket', {
            ticketId: ticket._id,
            email,
            subject
        });
        
        res.json({ 
            message: 'Support ticket submitted', 
            ticket 
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to submit ticket' });
    }
});

app.post('/api/v1/support/tickets', authenticate, async (req, res) => {
    try {
        const { subject, message } = req.body;
        
        const ticket = new SupportTicket({
            userId: req.user._id,
            email: req.user.email,
            subject,
            message,
            status: 'open'
        });
        
        await ticket.save();
        
        // Notify admin
        broadcastToAdmins('new_ticket', {
            ticketId: ticket._id,
            email: req.user.email,
            subject
        });
        
        res.json({ 
            message: 'Support ticket submitted', 
            ticket 
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to submit ticket' });
    }
});

// Stats Routes
app.get('/api/v1/stats', async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const tradeCount = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $match: { fromCoin: 'USDT' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        res.json({
            users: userCount,
            trades: tradeCount,
            volume: totalVolume[0]?.total || 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const newUsers = await User.countDocuments({ 
            createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
        });
        const tradeCount = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $match: { fromCoin: 'USDT' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });
        const openTickets = await SupportTicket.countDocuments({ status: 'open' });
        const pendingWithdrawals = await Transaction.countDocuments({ 
            type: 'withdrawal', 
            status: 'pending' 
        });
        
        res.json({
            users: userCount,
            newUsers,
            trades: tradeCount,
            volume: totalVolume[0]?.total || 0,
            pendingKYC,
            openTickets,
            pendingWithdrawals
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        
        const query = search ? {
            $or: [
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ]
        } : {};
        
        const users = await User.find(query)
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .select('-password');
        
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        const transactions = await Transaction.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(20);
        
        const trades = await Trade.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(20);
        
        res.json({
            user,
            transactions,
            trades
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { balance, kycStatus, isAdmin } = req.body;
        const user = await User.findById(req.params.id);
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (balance !== undefined) user.balance = balance;
        if (kycStatus !== undefined) user.kycStatus = kycStatus;
        if (isAdmin !== undefined) user.isAdmin = isAdmin;
        
        await user.save();
        
        // Log admin action
        const log = new AdminLog({
            adminId: req.user._id,
            action: 'user_update',
            details: {
                userId: user._id,
                changes: req.body
            }
        });
        await log.save();
        
        // Notify user if balance changed
        if (balance !== undefined) {
            broadcastToUser(user._id, 'balance_update', {
                balance: user.balance
            });
        }
        
        res.json({ message: 'User updated successfully', user });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const trades = await Trade.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');
        
        const total = await Trade.countDocuments();
        
        res.json({
            trades,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch trades' });
    }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, type, status } = req.query;
        
        const query = {};
        if (type) query.type = type;
        if (status) query.status = status;
        
        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');
        
        const total = await Transaction.countDocuments(query);
        
        res.json({
            transactions,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

app.put('/api/v1/admin/transactions/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const tx = await Transaction.findById(req.params.id).populate('userId');
        
        if (!tx) return res.status(404).json({ error: 'Transaction not found' });
        
        if (status === 'rejected' && tx.status === 'pending' && tx.type === 'withdrawal') {
            // Return funds if withdrawal is rejected
            const user = await User.findById(tx.userId);
            if (user) {
                user.balance += tx.amount;
                await user.save();
                
                broadcastToUser(user._id, 'balance_update', {
                    balance: user.balance
                });
            }
        }
        
        tx.status = status;
        await tx.save();
        
        // Log admin action
        const log = new AdminLog({
            adminId: req.user._id,
            action: 'transaction_update',
            details: {
                txId: tx._id,
                status
            }
        });
        await log.save();
        
        // Notify user
        if (tx.userId) {
            broadcastToUser(tx.userId._id, 'transaction_update', {
                txId: tx._id,
                type: tx.type,
                amount: tx.amount,
                coin: tx.coin,
                status: tx.status
            });
        }
        
        res.json({ message: 'Transaction updated', transaction: tx });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update transaction' });
    }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        
        const query = status ? { status } : {};
        const tickets = await SupportTicket.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('userId', 'email firstName lastName');
        
        const total = await SupportTicket.countDocuments(query);
        
        res.json({
            tickets,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tickets' });
    }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id)
            .populate('userId', 'email firstName lastName');
        
        if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
        
        res.json(ticket);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch ticket' });
    }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, response } = req.body;
        const ticket = await SupportTicket.findById(req.params.id);
        
        if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
        
        if (status) ticket.status = status;
        if (response) {
            ticket.responses.push({
                message: response,
                fromAdmin: true
            });
        }
        
        await ticket.save();
        
        // Log admin action
        const log = new AdminLog({
            adminId: req.user._id,
            action: 'ticket_update',
            details: {
                ticketId: ticket._id,
                status,
                response: response ? true : false
            }
        });
        await log.save();
        
        // Notify user if there's a response
        if (response && ticket.userId) {
            broadcastToUser(ticket.userId, 'ticket_response', {
                ticketId: ticket._id,
                message: response
            });
        }
        
        res.json({ message: 'Ticket updated', ticket });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update ticket' });
    }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        
        const query = status ? { kycStatus: status } : {};
        const users = await User.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .select('-password');
        
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch KYC submissions' });
    }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const user = await User.findById(req.params.id);
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.kycStatus = status;
        await user.save();
        
        // Log admin action
        const log = new AdminLog({
            adminId: req.user._id,
            action: 'kyc_review',
            details: {
                userId: user._id,
                status
            }
        });
        await log.save();
        
        // Notify user
        broadcastToUser(user._id, 'kyc_update', {
            status
        });
        
        res.json({ message: 'KYC status updated', user });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update KYC status' });
    }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const logs = await AdminLog.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('adminId', 'email firstName lastName');
        
        const total = await AdminLog.countDocuments();
        
        res.json({
            logs,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) return res.status(400).json({ error: 'Message is required' });
        
        // Broadcast to all connected clients
        clients.forEach((ws, userId) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ 
                    event: 'admin_broadcast',
                    data: { message }
                }));
            }
        });
        
        // Log admin action
        const log = new AdminLog({
            adminId: req.user._id,
            action: 'broadcast',
            details: { message }
        });
        await log.save();
        
        res.json({ message: 'Broadcast sent successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to send broadcast' });
    }
});

// About Page Routes
app.get('/api/v1/team', (req, res) => {
    // Hardcoded team data - in production would come from DB
    res.json([
        {
            name: "John Smith",
            role: "CEO & Founder",
            bio: "Blockchain expert with 10+ years in crypto trading",
            image: "/images/team/john.jpg"
        },
        {
            name: "Sarah Johnson",
            role: "CTO",
            bio: "Lead developer with extensive experience in financial systems",
            image: "/images/team/sarah.jpg"
        },
        {
            name: "Michael Chen",
            role: "Security Lead",
            bio: "Cybersecurity specialist focused on blockchain security",
            image: "/images/team/michael.jpg"
        }
    ]);
});

// Serve static files (for uploads)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});
