require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = '17581758Na.%';
const ADMIN_EMAIL = 'Admin@youngblood.com';
const ADMIN_PASSWORD = '$2a$10$NxxhbUv6pBEB7nML'; // Hashed version of '17581758..'
const FIXED_DEPOSIT_ADDRESS = 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';

// MongoDB connection
mongoose.connect('mongodb+srv://butlerdavidfur:NxxhbUv6pBEB7nML@cluster0.cm9eibh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email transporter
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
    email: { type: String, unique: true },
    password: String,
    firstName: String,
    lastName: String,
    country: String,
    currency: { type: String, default: 'USD' },
    walletAddress: String,
    isAdmin: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    kycStatus: { type: String, default: 'not_submitted' },
    balance: { type: Map, of: Number, default: {} },
    apiKey: { type: String, default: () => uuidv4() },
    settings: {
        twoFactorEnabled: { type: Boolean, default: false },
        notifications: {
            email: { type: Boolean, default: true },
            push: { type: Boolean, default: false }
        }
    },
    createdAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fromCoin: String,
    toCoin: String,
    amount: Number,
    rate: Number,
    status: { type: String, default: 'completed' },
    createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: String, // 'deposit', 'withdrawal', 'trade'
    coin: String,
    amount: Number,
    address: String,
    txHash: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    email: String,
    subject: String,
    message: String,
    status: { type: String, default: 'open' },
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
}));

const KYCSubmission = mongoose.model('KYCSubmission', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    documentType: String,
    frontImage: String,
    backImage: String,
    selfie: String,
    status: { type: String, default: 'pending' },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewedAt: Date,
    createdAt: { type: Date, default: Date.now }
}));

const AdminLog = mongoose.model('AdminLog', new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: String,
    target: String,
    details: mongoose.Schema.Types.Mixed,
    ip: String,
    createdAt: { type: Date, default: Date.now }
}));

// Hardcoded coin data with arbitrage logic
const COINS = {
    BTC: { name: 'Bitcoin', price: 50000, change24h: 2.5 },
    ETH: { name: 'Ethereum', price: 3000, change24h: -1.2 },
    SOL: { name: 'Solana', price: 150, change24h: 5.8 },
    USDT: { name: 'Tether', price: 1, change24h: 0 },
    BNB: { name: 'Binance Coin', price: 400, change24h: 1.5 },
    XRP: { name: 'Ripple', price: 0.5, change24h: -0.3 },
    ADA: { name: 'Cardano', price: 0.45, change24h: 1.2 },
    DOGE: { name: 'Dogecoin', price: 0.12, change24h: 3.4 }
};

// Calculate conversion rates with arbitrage spread
function getConversionRate(fromCoin, toCoin) {
    const fromPrice = COINS[fromCoin]?.price || 0;
    const toPrice = COINS[toCoin]?.price || 0;
    
    if (fromPrice === 0 || toPrice === 0) return 0;
    
    // Apply a small spread (0.2%) for arbitrage profit
    const baseRate = toPrice / fromPrice;
    return fromCoin === toCoin ? 1 : baseRate * 0.998;
}

// Middleware
app.use(express.json());
app.use(cors({
    origin: 'https://website-xi-ten-52.vercel.app',
    credentials: true
}));
app.use(helmet());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
        if (!token) return res.status(401).json({ error: 'Authentication required' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ error: 'User not found' });

        req.user = user;
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
        const user = await User.findById(decoded.userId);
        if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, 'uploads/');
        },
        filename: (req, file, cb) => {
            cb(null, Date.now() + path.extname(file.originalname));
        }
    }),
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Create default admin user on startup
async function createDefaultAdmin() {
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
        const admin = new User({
            email: ADMIN_EMAIL,
            password: ADMIN_PASSWORD,
            firstName: 'Admin',
            lastName: 'User',
            country: 'US',
            isAdmin: true,
            isVerified: true,
            balance: { USDT: 1000000 }
        });
        await admin.save();
        console.log('Default admin user created');
    }
}

// WebSocket Server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    createDefaultAdmin();
});

const wss = new WebSocket.Server({ server, path: '/api/v1/admin/ws' });

const activeConnections = new Map();

wss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1];
    
    if (!token) {
        ws.close(1008, 'Authentication required');
        return;
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
        if (err) {
            ws.close(1008, 'Invalid token');
            return;
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            ws.close(1008, 'User not found');
            return;
        }

        ws.userId = user._id;
        ws.isAdmin = user.isAdmin;
        activeConnections.set(user._id.toString(), ws);

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message);
                handleWebSocketMessage(ws, data);
            } catch (err) {
                console.error('WebSocket message error:', err);
            }
        });

        ws.on('close', () => {
            activeConnections.delete(user._id.toString());
        });

        // Send initial connection confirmation
        ws.send(JSON.stringify({
            type: 'connection',
            status: 'success',
            message: 'WebSocket connection established',
            isAdmin: user.isAdmin
        }));
    });
});

function handleWebSocketMessage(ws, data) {
    if (!ws.isAdmin) {
        // Handle regular user WebSocket messages
        switch (data.type) {
            case 'subscribe':
                // Handle user subscriptions (balances, trades, etc.)
                break;
            default:
                console.log('Unknown WebSocket message type:', data.type);
        }
    } else {
        // Handle admin WebSocket messages
        switch (data.type) {
            case 'broadcast':
                // Admin broadcast to all users
                broadcastToAll(data.message);
                break;
            default:
                console.log('Unknown admin WebSocket message type:', data.type);
        }
    }
}

function broadcastToUser(userId, data) {
    const ws = activeConnections.get(userId.toString());
    if (ws) {
        ws.send(JSON.stringify(data));
    }
}

function broadcastToAll(data) {
    activeConnections.forEach(ws => {
        ws.send(JSON.stringify(data));
    });
}

// Routes
app.get('/api/v1/auth/status', authenticate, (req, res) => {
    res.json({ authenticated: true, user: req.user });
});

app.get('/api/v1/auth/check', authenticate, (req, res) => {
    res.json({ valid: true, user: req.user });
});

app.get('/api/v1/auth/me', authenticate, (req, res) => {
    res.json({
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        country: req.user.country,
        currency: req.user.currency,
        walletAddress: req.user.walletAddress,
        isVerified: req.user.isVerified,
        kycStatus: req.user.kycStatus,
        settings: req.user.settings
    });
});

app.post('/api/v1/auth/login', [
    body('email').isEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
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
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/nonce', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ error: 'Wallet address required' });
        }

        const nonce = uuidv4();
        res.json({ nonce });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        if (!walletAddress || !signature) {
            return res.status(400).json({ error: 'Wallet address and signature required' });
        }

        let user = await User.findOne({ walletAddress });
        if (!user) {
            // Auto-create user if not exists
            user = new User({
                walletAddress,
                isVerified: true,
                balance: { USDT: 0 }
            });
            await user.save();
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/signup', [
    body('email').isEmail(),
    body('password').isLength({ min: 8 }),
    body('firstName').notEmpty(),
    body('lastName').notEmpty(),
    body('country').notEmpty(),
    body('currency').notEmpty(),
    body('confirmPassword').custom((value, { req }) => value === req.body.password)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password, firstName, lastName, country, currency } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            country,
            currency,
            balance: { USDT: 0 }
        });

        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        // Send welcome email
        await transporter.sendMail({
            from: '"Crypto Platform" <support@cryptoplatform.com>',
            to: email,
            subject: 'Welcome to Our Crypto Platform',
            html: `<p>Hello ${firstName},</p>
                   <p>Your account has been successfully created!</p>`
        });

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        if (!walletAddress || !signature) {
            return res.status(400).json({ error: 'Wallet address and signature required' });
        }

        const existingUser = await User.findOne({ walletAddress });
        if (existingUser) {
            return res.status(400).json({ error: 'Wallet already registered' });
        }

        const user = new User({
            walletAddress,
            isVerified: true,
            balance: { USDT: 0 }
        });

        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (user) {
            const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
            
            await transporter.sendMail({
                from: '"Crypto Platform" <support@cryptoplatform.com>',
                to: email,
                subject: 'Password Reset Request',
                html: `<p>Hello,</p>
                       <p>You requested a password reset. Click <a href="https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}">here</a> to reset your password.</p>
                       <p>This link will expire in 1 hour.</p>`
            });
        }

        res.json({ message: 'If an account with that email exists, a reset link has been sent' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.patch('/api/v1/auth/update-password', authenticate, [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 8 }),
    body('confirmPassword').custom((value, { req }) => value === req.body.newPassword)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { currentPassword, newPassword } = req.body;
        const user = req.user;
        
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        
        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/auth/logout', authenticate, (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// User routes
app.get('/api/v1/users/me', authenticate, (req, res) => {
    const user = req.user;
    res.json({
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        country: user.country,
        currency: user.currency,
        walletAddress: user.walletAddress,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        balance: Object.fromEntries(user.balance),
        apiKey: user.apiKey,
        settings: user.settings
    });
});

app.get('/api/v1/users/settings', authenticate, (req, res) => {
    res.json(req.user.settings);
});

app.patch('/api/v1/users/settings', authenticate, async (req, res) => {
    try {
        const { settings } = req.body;
        const user = req.user;
        
        user.settings = { ...user.settings, ...settings };
        await user.save();
        
        res.json(user.settings);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/users/generate-api-key', authenticate, async (req, res) => {
    try {
        const user = req.user;
        user.apiKey = uuidv4();
        await user.save();
        
        res.json({ apiKey: user.apiKey });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/users/export-data', authenticate, async (req, res) => {
    try {
        const user = req.user;
        
        // In a real app, this would generate and email a data export file
        // For simplicity, we'll just return the user data
        res.json({
            user: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                country: user.country,
                currency: user.currency,
                walletAddress: user.walletAddress,
                createdAt: user.createdAt
            },
            balance: Object.fromEntries(user.balance),
            trades: await Trade.find({ userId: user._id }),
            transactions: await Transaction.find({ userId: user._id })
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/v1/users/delete-account', authenticate, async (req, res) => {
    try {
        const user = req.user;
        
        // In a real app, you might want to anonymize data instead of deleting
        await User.deleteOne({ _id: user._id });
        await Trade.deleteMany({ userId: user._id });
        await Transaction.deleteMany({ userId: user._id });
        
        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// KYC routes
app.post('/api/v1/users/kyc', authenticate, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 },
    { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    try {
        const user = req.user;
        const { documentType } = req.body;
        
        if (!req.files?.frontImage || !req.files?.selfie) {
            return res.status(400).json({ error: 'Front image and selfie are required' });
        }

        const kycSubmission = new KYCSubmission({
            userId: user._id,
            documentType,
            frontImage: req.files.frontImage[0].path,
            backImage: req.files.backImage?.[0]?.path,
            selfie: req.files.selfie[0].path
        });

        await kycSubmission.save();
        
        user.kycStatus = 'pending';
        await user.save();
        
        res.json({ message: 'KYC documents submitted successfully', status: 'pending' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Trading routes
app.get('/api/v1/exchange/coins', (req, res) => {
    res.json(Object.keys(COINS).map(symbol => ({
        symbol,
        name: COINS[symbol].name,
        price: COINS[symbol].price,
        change24h: COINS[symbol].change24h
    }));
});

app.get('/api/v1/exchange/rates', (req, res) => {
    const rates = {};
    const coins = Object.keys(COINS);
    
    for (const fromCoin of coins) {
        rates[fromCoin] = {};
        for (const toCoin of coins) {
            rates[fromCoin][toCoin] = getConversionRate(fromCoin, toCoin);
        }
    }
    
    res.json(rates);
});

app.get('/api/v1/exchange/rate', (req, res) => {
    const { from, to } = req.query;
    if (!from || !to || !COINS[from] || !COINS[to]) {
        return res.status(400).json({ error: 'Invalid coin symbols' });
    }
    
    res.json({ rate: getConversionRate(from, to) });
});

app.post('/api/v1/exchange/convert', authenticate, [
    body('fromCoin').isIn(Object.keys(COINS)),
    body('toCoin').isIn(Object.keys(COINS)),
    body('amount').isFloat({ gt: 0 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { fromCoin, toCoin, amount } = req.body;
        const user = req.user;
        
        // Check balance
        const userBalance = user.balance.get(fromCoin) || 0;
        if (userBalance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Calculate conversion
        const rate = getConversionRate(fromCoin, toCoin);
        const convertedAmount = amount * rate;
        
        // Update balances
        user.balance.set(fromCoin, (user.balance.get(fromCoin) || 0 - amount);
        user.balance.set(toCoin, (user.balance.get(toCoin) || 0) + convertedAmount);
        await user.save();
        
        // Create trade record
        const trade = new Trade({
            userId: user._id,
            fromCoin,
            toCoin,
            amount,
            rate,
            status: 'completed'
        });
        await trade.save();
        
        // Create transaction record
        const transaction = new Transaction({
            userId: user._id,
            type: 'trade',
            coin: fromCoin,
            amount: -amount,
            status: 'completed'
        });
        await transaction.save();
        
        const transaction2 = new Transaction({
            userId: user._id,
            type: 'trade',
            coin: toCoin,
            amount: convertedAmount,
            status: 'completed'
        });
        await transaction2.save();
        
        // Notify user via WebSocket
        broadcastToUser(user._id, {
            type: 'balance_update',
            balance: Object.fromEntries(user.balance)
        });
        
        res.json({
            success: true,
            fromCoin,
            toCoin,
            amount,
            convertedAmount,
            rate,
            newBalance: Object.fromEntries(user.balance)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/exchange/history', authenticate, async (req, res) => {
    try {
        const trades = await Trade.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(50);
            
        res.json(trades);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Wallet routes
app.get('/api/v1/wallet/deposit-address', authenticate, (req, res) => {
    res.json({ address: FIXED_DEPOSIT_ADDRESS, note: `For ${req.user.email}` });
});

app.post('/api/v1/wallet/withdraw', authenticate, [
    body('coin').isIn(Object.keys(COINS)),
    body('amount').isFloat({ gt: 0 }),
    body('address').isLength({ min: 26 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { coin, amount, address } = req.body;
        const user = req.user;
        
        // Check balance
        const userBalance = user.balance.get(coin) || 0;
        if (userBalance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Create withdrawal transaction
        const transaction = new Transaction({
            userId: user._id,
            type: 'withdrawal',
            coin,
            amount: -amount,
            address,
            status: 'pending'
        });
        await transaction.save();
        
        // In a real app, you would process the withdrawal here
        // For this example, we'll just deduct the balance after a delay
        setTimeout(async () => {
            user.balance.set(coin, (user.balance.get(coin) || 0 - amount);
            await user.save();
            
            transaction.status = 'completed';
            await transaction.save();
            
            broadcastToUser(user._id, {
                type: 'balance_update',
                balance: Object.fromEntries(user.balance)
            });
            
            broadcastToUser(user._id, {
                type: 'transaction_update',
                transaction: {
                    ...transaction.toObject(),
                    status: 'completed'
                }
            });
        }, 5000);
        
        res.json({
            success: true,
            message: 'Withdrawal request received',
            transactionId: transaction._id
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Portfolio routes
app.get('/api/v1/portfolio', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const balance = Object.fromEntries(user.balance);
        
        // Calculate portfolio value
        let totalValue = 0;
        const detailedBalance = Object.entries(balance).map(([coin, amount]) => {
            const value = amount * (COINS[coin]?.price || 0);
            totalValue += value;
            return {
                coin,
                amount,
                value,
                price: COINS[coin]?.price || 0,
                change24h: COINS[coin]?.change24h || 0
            };
        });
        
        res.json({
            balance: detailedBalance,
            totalValue,
            performance: Math.random() > 0.5 ? 
                (Math.random() * 15.89).toFixed(2) : 
                (-Math.random() * 7.65).toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Support routes
app.get('/api/v1/support/faqs', (req, res) => {
    const faqs = [
        {
            category: 'General',
            questions: [
                {
                    question: 'What is this platform?',
                    answer: 'This is a cryptocurrency trading platform that allows you to buy, sell, and trade various digital assets.'
                },
                {
                    question: 'How do I get started?',
                    answer: 'Create an account, complete verification, deposit funds, and start trading!'
                }
            ]
        },
        {
            category: 'Account',
            questions: [
                {
                    question: 'How do I reset my password?',
                    answer: 'Use the "Forgot Password" link on the login page to receive a reset email.'
                },
                {
                    question: 'Is two-factor authentication available?',
                    answer: 'Yes, you can enable it in your account settings.'
                }
            ]
        }
    ];
    
    res.json(faqs);
});

app.get('/api/v1/support/my-tickets', authenticate, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
            
        res.json(tickets);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/support/tickets', authenticate, upload.array('attachments', 3), async (req, res) => {
    try {
        const { subject, message } = req.body;
        const user = req.user;
        
        const ticket = new SupportTicket({
            userId: user._id,
            email: user.email,
            subject,
            message,
            attachments: req.files?.map(file => file.path)
        });
        
        await ticket.save();
        
        res.json(ticket);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/support/contact', upload.array('attachments', 3), async (req, res) => {
    try {
        const { email, subject, message } = req.body;
        
        if (!email || !subject || !message) {
            return res.status(400).json({ error: 'Email, subject, and message are required' });
        }
        
        const ticket = new SupportTicket({
            email,
            subject,
            message,
            attachments: req.files?.map(file => file.path)
        });
        
        await ticket.save();
        
        res.json(ticket);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Stats routes
app.get('/api/v1/stats', async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const tradeCount = await Trade.countDocuments();
        const totalVolume = (await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;
        
        res.json({
            users: userCount,
            activeTraders: Math.floor(userCount * 0.3),
            trades: tradeCount,
            volume: totalVolume.toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin routes
app.post('/api/v1/admin/login', [
    body('email').isEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, isAdmin: true });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
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
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/verify', authenticateAdmin, (req, res) => {
    res.json({ valid: true, admin: req.user });
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const userCount = await User.countDocuments();
        const newUsersToday = await User.countDocuments({ createdAt: { $gte: today } });
        const tradeCount = await Trade.countDocuments();
        const tradesToday = await Trade.countDocuments({ createdAt: { $gte: today } });
        const totalVolume = (await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;
        const volumeToday = (await Trade.aggregate([
            { $match: { createdAt: { $gte: today } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;
        
        const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
        const pendingKYC = await KYCSubmission.countDocuments({ status: 'pending' });
        
        res.json({
            users: {
                total: userCount,
                newToday: newUsersToday,
                verified: Math.floor(userCount * 0.7) // Assuming 70% are verified
            },
            trading: {
                totalTrades: tradeCount,
                tradesToday,
                totalVolume: totalVolume.toFixed(2),
                volumeToday: volumeToday.toFixed(2)
            },
            support: {
                pendingTickets,
                pendingKYC
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        const skip = (page - 1) * limit;
        
        const query = {};
        if (search) {
            query.$or = [
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ];
        }
        
        const users = await User.find(query)
            .skip(skip)
            .limit(parseInt(limit))
            .select('-password');
            
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const balance = Object.fromEntries(user.balance);
        const totalValue = Object.entries(balance).reduce((sum, [coin, amount]) => {
            return sum + (amount * (COINS[coin]?.price || 0));
        }, 0);
        
        const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
        const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
        
        res.json({
            user,
            balance,
            totalValue,
            trades,
            transactions
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { kycStatus, isVerified, isAdmin } = req.body;
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (kycStatus) user.kycStatus = kycStatus;
        if (isVerified !== undefined) user.isVerified = isVerified;
        if (isAdmin !== undefined) user.isAdmin = isAdmin;
        
        await user.save();
        
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, userId } = req.query;
        const skip = (page - 1) * limit;
        
        const query = {};
        if (userId) query.userId = userId;
        
        const trades = await Trade.find(query)
            .populate('userId', 'email firstName lastName')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await Trade.countDocuments(query);
        
        res.json({
            trades,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, type, status, userId } = req.query;
        const skip = (page - 1) * limit;
        
        const query = {};
        if (type) query.type = type;
        if (status) query.status = status;
        if (userId) query.userId = userId;
        
        const transactions = await Transaction.find(query)
            .populate('userId', 'email firstName lastName')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await Transaction.countDocuments(query);
        
        res.json({
            transactions,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;
        
        const query = {};
        if (status) query.status = status;
        
        const tickets = await SupportTicket.find(query)
            .populate('userId', 'email firstName lastName')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await SupportTicket.countDocuments(query);
        
        res.json({
            tickets,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
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
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, response } = req.body;
        const ticket = await SupportTicket.findById(req.params.id);
        
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        
        if (status) ticket.status = status;
        if (response) {
            ticket.responses = ticket.responses || [];
            ticket.responses.push({
                adminId: req.user._id,
                message: response,
                createdAt: new Date()
            });
        }
        
        await ticket.save();
        
        // Notify user if ticket was updated
        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'ticket_update',
                ticket
            });
        }
        
        res.json(ticket);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/kyc', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;
        
        const query = {};
        if (status) query.status = status;
        
        const submissions = await KYCSubmission.find(query)
            .populate('userId', 'email firstName lastName')
            .populate('reviewedBy', 'email firstName lastName')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await KYCSubmission.countDocuments(query);
        
        res.json({
            submissions,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
    try {
        const submission = await KYCSubmission.findById(req.params.id)
            .populate('userId', 'email firstName lastName')
            .populate('reviewedBy', 'email firstName lastName');
            
        if (!submission) {
            return res.status(404).json({ error: 'KYC submission not found' });
        }
        
        res.json(submission);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/v1/admin/kyc/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const submission = await KYCSubmission.findById(req.params.id);
        
        if (!submission) {
            return res.status(404).json({ error: 'KYC submission not found' });
        }
        
        submission.status = status;
        submission.reviewedBy = req.user._id;
        submission.reviewedAt = new Date();
        
        await submission.save();
        
        // Update user's KYC status
        const user = await User.findById(submission.userId);
        if (user) {
            user.kycStatus = status === 'approved' ? 'verified' : 'rejected';
            await user.save();
            
            // Notify user
            broadcastToUser(user._id, {
                type: 'kyc_update',
                status: user.kycStatus
            });
        }
        
        res.json(submission);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/logs', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const skip = (page - 1) * limit;
        
        const logs = await AdminLog.find()
            .populate('adminId', 'email firstName lastName')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await AdminLog.countDocuments();
        
        res.json({
            logs,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/v1/admin/broadcast', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Broadcast to all connected clients
        broadcastToAll({
            type: 'admin_broadcast',
            message,
            timestamp: new Date()
        });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
    // In a real app, these would come from a database
    res.json({
        maintenanceMode: false,
        tradingEnabled: true,
        newRegistrations: true,
        depositFee: 0.0005,
        withdrawalFee: 0.001
    });
});

app.post('/api/v1/admin/settings', authenticateAdmin, async (req, res) => {
    try {
        // In a real app, you would save these to a database
        res.json({
            success: true,
            message: 'Settings updated (not persisted in this demo)'
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// About page routes
app.get('/api/v1/team', (req, res) => {
    // Hardcoded team data - in production this would come from a database
    res.json([
        {
            name: 'John Doe',
            role: 'CEO',
            bio: 'Blockchain expert with 10+ years of experience',
            image: '/images/team/john.jpg'
        },
        {
            name: 'Jane Smith',
            role: 'CTO',
            bio: 'Cryptography specialist and security researcher',
            image: '/images/team/jane.jpg'
        }
    ]);
});

// Static file serving (for uploaded files)
app.use('/uploads', express.static('uploads'));

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});
