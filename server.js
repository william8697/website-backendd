require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
mongoose.connect('mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
    origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
    credentials: true
}));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// JWT Secret
const JWT_SECRET = '17581758Na.%';

// Email configuration
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false },
    walletAddress: { type: String, required: false },
    walletProvider: { type: String, required: false },
    country: { type: String, required: true },
    currency: { type: String, default: 'USD' },
    balance: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    verificationTokenExpires: { type: Date },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    isAdmin: { type: Boolean, default: false },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String },
    kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
    tradingVolume: { type: Number, default: 0 },
    apiKey: { type: String, default: () => crypto.randomBytes(16).toString('hex') }
});

const TradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['buy', 'sell', 'convert', 'arbitrage'], required: true },
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: false },
    amount: { type: Number, required: true },
    rate: { type: Number, required: true },
    fee: { type: Number, default: 0 },
    profit: { type: Number, default: 0 },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'completed' },
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'trade', 'fee', 'bonus'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    txHash: { type: String },
    address: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in-progress', 'resolved', 'closed'], default: 'open' },
    attachments: [{ type: String }],
    responses: [{
        message: { type: String },
        isAdmin: { type: Boolean, default: false },
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isSuperAdmin: { type: Boolean, default: false },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const CoinSchema = new mongoose.Schema({
    coinId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    symbol: { type: String, required: true },
    currentPrice: { type: Number, required: true },
    priceChange24h: { type: Number, required: true },
    priceChangePercentage24h: { type: Number, required: true },
    lastUpdated: { type: Date, default: Date.now }
});

const ArbitrageOpportunitySchema = new mongoose.Schema({
    fromCoin: { type: String, required: true },
    toCoin: { type: String, required: true },
    exchangeRate: { type: Number, required: true },
    potentialProfit: { type: Number, required: true },
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Trade = mongoose.model('Trade', TradeSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Coin = mongoose.model('Coin', CoinSchema);
const ArbitrageOpportunity = mongoose.model('ArbitrageOpportunity', ArbitrageOpportunitySchema);

// Helper functions
const generateToken = (userId, isAdmin = false) => {
    return jwt.sign({ id: userId, isAdmin }, JWT_SECRET, { expiresIn: '24h' });
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
};

const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ message: 'Invalid or expired token' });

    try {
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        req.user = user;
        req.isAdmin = decoded.isAdmin;
        next();
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    const decoded = verifyToken(token);
    if (!decoded || !decoded.isAdmin) return res.status(401).json({ message: 'Invalid or expired admin token' });

    try {
        const admin = await Admin.findById(decoded.id);
        if (!admin) return res.status(404).json({ message: 'Admin not found' });

        req.admin = admin;
        next();
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// WebSocket Server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('New WebSocket connection');

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'auth' && data.token) {
                const decoded = verifyToken(data.token);
                if (decoded) {
                    ws.userId = decoded.id;
                    ws.isAdmin = decoded.isAdmin;
                    ws.send(JSON.stringify({ type: 'auth', status: 'success' }));
                } else {
                    ws.send(JSON.stringify({ type: 'auth', status: 'failed', message: 'Invalid token' }));
                }
            }
        } catch (err) {
            console.error('WebSocket message error:', err);
        }
    });

    ws.on('close', () => {
        console.log('WebSocket connection closed');
    });
});

const broadcastToUser = (userId, data) => {
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.userId === userId) {
            client.send(JSON.stringify(data));
        }
    });
};

const broadcastToAdmins = (data) => {
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.isAdmin) {
            client.send(JSON.stringify(data));
        }
    });
};

// Routes
app.get('/', (req, res) => {
    res.send('Crypto Trading Platform Backend');
});

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, country, currency } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const verificationToken = crypto.randomBytes(20).toString('hex');
        const verificationTokenExpires = Date.now() + 3600000; // 1 hour

        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            country,
            currency,
            verificationToken,
            verificationTokenExpires,
            balance: 0
        });

        await newUser.save();

        // Send verification email
        const verificationUrl = `https://website-xi-ten-52.vercel.app/verify?token=${verificationToken}`;
        
        await transporter.sendMail({
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Please click <a href="${verificationUrl}">here</a> to verify your email address.</p>`
        });

        res.status(201).json({ message: 'User created successfully. Please check your email to verify your account.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during signup' });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, walletProvider, firstName, lastName, email, country, currency } = req.body;

        const existingUser = await User.findOne({ walletAddress });
        if (existingUser) {
            return res.status(400).json({ message: 'Wallet already registered' });
        }

        if (email) {
            const emailUser = await User.findOne({ email });
            if (emailUser) {
                return res.status(400).json({ message: 'Email already in use' });
            }
        }

        const newUser = new User({
            firstName,
            lastName,
            email,
            walletAddress,
            walletProvider,
            country,
            currency,
            isVerified: true,
            balance: 0
        });

        await newUser.save();

        const token = generateToken(newUser._id);
        res.status(201).json({ token, user: { id: newUser._id, email: newUser.email, walletAddress: newUser.walletAddress } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during wallet signup' });
    }
});

app.get('/api/v1/auth/verify', async (req, res) => {
    try {
        const { token } = req.query;

        const user = await User.findOne({ 
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification token' });
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during verification' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        user.lastLogin = new Date();
        await user.save();

        const token = generateToken(user._id);
        
        res.status(200).json({ 
            token, 
            user: { 
                id: user._id, 
                email: user.email, 
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                isVerified: user.isVerified,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature, walletProvider } = req.body;

        const user = await User.findOne({ walletAddress });
        if (!user) {
            return res.status(400).json({ message: 'Wallet not registered' });
        }

        // In a real app, you would verify the signature here
        // For simplicity, we'll just check if the wallet exists

        user.lastLogin = new Date();
        await user.save();

        const token = generateToken(user._id);
        
        res.status(200).json({ 
            token, 
            user: { 
                id: user._id, 
                email: user.email, 
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                isVerified: user.isVerified,
                walletAddress: user.walletAddress,
                isAdmin: user.isAdmin
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during wallet login' });
    }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
    try {
        // In a real app, you might want to invalidate the token
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during logout' });
    }
});

app.get('/api/v1/auth/me', authenticate, async (req, res) => {
    try {
        res.status(200).json({ 
            user: { 
                id: req.user._id, 
                email: req.user.email, 
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                balance: req.user.balance,
                isVerified: req.user.isVerified,
                walletAddress: req.user.walletAddress,
                isAdmin: req.user.isAdmin,
                kycStatus: req.user.kycStatus,
                tradingVolume: req.user.tradingVolume
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching user data' });
    }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            // For security, don't reveal if email doesn't exist
            return res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
        
        await transporter.sendMail({
            to: email,
            subject: 'Password Reset Request',
            html: `<p>Please click <a href="${resetUrl}">here</a> to reset your password.</p>`
        });

        res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset' });
    }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        const user = await User.findOne({ 
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset' });
    }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        admin.lastLogin = new Date();
        await admin.save();

        const token = generateToken(admin._id, true);
        
        res.status(200).json({ 
            token, 
            admin: { 
                id: admin._id, 
                email: admin.email,
                isSuperAdmin: admin.isSuperAdmin
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during admin login' });
    }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const verifiedUsers = await User.countDocuments({ isVerified: true });
        const totalTrades = await Trade.countDocuments();
        const totalVolume = await Trade.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5);
        const recentTrades = await Trade.find().sort({ createdAt: -1 }).limit(5).populate('userId', 'email');

        res.status(200).json({
            totalUsers,
            verifiedUsers,
            totalTrades,
            totalVolume: totalVolume.length ? totalVolume[0].total : 0,
            recentUsers,
            recentTrades
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching dashboard stats' });
    }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password -verificationToken -resetPasswordToken');
        res.status(200).json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching users' });
    }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password -verificationToken -resetPasswordToken');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const trades = await Trade.find({ userId: user._id }).sort({ createdAt: -1 });
        const transactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 });

        res.status(200).json({ user, trades, transactions });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching user details' });
    }
});

app.patch('/api/v1/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
    try {
        const { amount, note } = req.body;

        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.balance += amount;
        await user.save();

        // Record transaction
        const transaction = new Transaction({
            userId: user._id,
            type: amount > 0 ? 'bonus' : 'fee',
            amount: Math.abs(amount),
            currency: 'USD',
            status: 'completed',
            txHash: note || 'Admin adjustment'
        });
        await transaction.save();

        broadcastToUser(user._id, {
            type: 'BALANCE_UPDATE',
            balance: user.balance
        });

        res.status(200).json({ message: 'Balance updated successfully', balance: user.balance });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating user balance' });
    }
});

app.patch('/api/v1/admin/users/:id/verify', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: 'User verified successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error verifying user' });
    }
});

// Trade Routes
app.get('/api/v1/trades/coins', async (req, res) => {
    try {
        // Fetch coins from CoinGecko API
        const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
            params: {
                vs_currency: 'usd',
                order: 'market_cap_desc',
                per_page: 100,
                page: 1,
                sparkline: false
            }
        });

        const coins = response.data.map(coin => ({
            id: coin.id,
            symbol: coin.symbol,
            name: coin.name,
            current_price: coin.current_price,
            price_change_percentage_24h: coin.price_change_percentage_24h,
            image: coin.image
        }));

        // Cache in database
        await Promise.all(coins.map(async coin => {
            await Coin.findOneAndUpdate(
                { coinId: coin.id },
                {
                    name: coin.name,
                    symbol: coin.symbol,
                    currentPrice: coin.current_price,
                    priceChange24h: coin.price_change_percentage_24h,
                    lastUpdated: new Date()
                },
                { upsert: true }
            );
        }));

        res.status(200).json(coins);
    } catch (err) {
        console.error(err);
        
        // Fallback to database if API fails
        const coins = await Coin.find().sort({ lastUpdated: -1 }).limit(100);
        if (coins.length) {
            return res.status(200).json(coins.map(coin => ({
                id: coin.coinId,
                symbol: coin.symbol,
                name: coin.name,
                current_price: coin.currentPrice,
                price_change_percentage_24h: coin.priceChange24h,
                image: `https://assets.coingecko.com/coins/images/1/large/${coin.symbol}.png`
            })));
        }

        res.status(500).json({ message: 'Error fetching coin data' });
    }
});

app.post('/api/v1/trades/buy', authenticate, async (req, res) => {
    try {
        const { coinId, amount } = req.body;

        // Get coin price
        const coin = await Coin.findOne({ coinId });
        if (!coin) {
            return res.status(400).json({ message: 'Invalid coin' });
        }

        const totalCost = amount * coin.currentPrice;
        if (req.user.balance < totalCost) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        // Deduct balance
        req.user.balance -= totalCost;
        await req.user.save();

        // Record trade
        const trade = new Trade({
            userId: req.user._id,
            type: 'buy',
            fromCoin: 'USD',
            toCoin: coinId,
            amount,
            rate: coin.currentPrice,
            fee: totalCost * 0.001, // 0.1% fee
            status: 'completed'
        });
        await trade.save();

        // Record transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'trade',
            amount: totalCost,
            currency: 'USD',
            status: 'completed',
            txHash: `BUY-${trade._id}`
        });
        await transaction.save();

        // Update trading volume
        req.user.tradingVolume += totalCost;
        await req.user.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        broadcastToUser(req.user._id, {
            type: 'TRADE_UPDATE',
            trade: {
                id: trade._id,
                type: 'buy',
                coin: coinId,
                amount,
                price: coin.currentPrice,
                total: totalCost,
                fee: totalCost * 0.001,
                timestamp: trade.createdAt
            }
        });

        res.status(200).json({ 
            message: 'Trade executed successfully',
            balance: req.user.balance,
            trade: {
                id: trade._id,
                type: 'buy',
                coin: coinId,
                amount,
                price: coin.currentPrice,
                total: totalCost,
                fee: totalCost * 0.001,
                timestamp: trade.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error executing trade' });
    }
});

app.post('/api/v1/trades/sell', authenticate, async (req, res) => {
    try {
        const { coinId, amount } = req.body;

        // Get coin price
        const coin = await Coin.findOne({ coinId });
        if (!coin) {
            return res.status(400).json({ message: 'Invalid coin' });
        }

        const totalValue = amount * coin.currentPrice;
        const fee = totalValue * 0.001; // 0.1% fee
        const amountReceived = totalValue - fee;

        // Add to balance
        req.user.balance += amountReceived;
        await req.user.save();

        // Record trade
        const trade = new Trade({
            userId: req.user._id,
            type: 'sell',
            fromCoin: coinId,
            toCoin: 'USD',
            amount,
            rate: coin.currentPrice,
            fee,
            status: 'completed'
        });
        await trade.save();

        // Record transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'trade',
            amount: amountReceived,
            currency: 'USD',
            status: 'completed',
            txHash: `SELL-${trade._id}`
        });
        await transaction.save();

        // Update trading volume
        req.user.tradingVolume += totalValue;
        await req.user.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        broadcastToUser(req.user._id, {
            type: 'TRADE_UPDATE',
            trade: {
                id: trade._id,
                type: 'sell',
                coin: coinId,
                amount,
                price: coin.currentPrice,
                total: amountReceived,
                fee,
                timestamp: trade.createdAt
            }
        });

        res.status(200).json({ 
            message: 'Trade executed successfully',
            balance: req.user.balance,
            trade: {
                id: trade._id,
                type: 'sell',
                coin: coinId,
                amount,
                price: coin.currentPrice,
                total: amountReceived,
                fee,
                timestamp: trade.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error executing trade' });
    }
});

app.post('/api/v1/trades/execute', authenticate, async (req, res) => {
    try {
        const { fromCoin, toCoin, amount } = req.body;

        if (fromCoin === toCoin) {
            return res.status(400).json({ message: 'Cannot convert to the same coin' });
        }

        // Get coin prices
        const fromCoinData = await Coin.findOne({ coinId: fromCoin });
        const toCoinData = await Coin.findOne({ coinId: toCoin });

        if (!fromCoinData || !toCoinData) {
            return res.status(400).json({ message: 'Invalid coin selection' });
        }

        let fromAmount, toAmount, fee, profit = 0;

        if (fromCoin === 'USD') {
            // Buying with USD
            fromAmount = amount;
            const usdValue = fromAmount;
            toAmount = usdValue / toCoinData.currentPrice;
            fee = usdValue * 0.001; // 0.1% fee

            if (req.user.balance < usdValue) {
                return res.status(400).json({ message: 'Insufficient balance' });
            }

            req.user.balance -= usdValue;
        } else if (toCoin === 'USD') {
            // Selling to USD
            fromAmount = amount;
            const usdValue = fromAmount * fromCoinData.currentPrice;
            toAmount = usdValue;
            fee = usdValue * 0.001; // 0.1% fee
            toAmount -= fee;

            req.user.balance += toAmount;
        } else {
            // Coin to coin conversion
            fromAmount = amount;
            const usdValue = fromAmount * fromCoinData.currentPrice;
            toAmount = usdValue / toCoinData.currentPrice;
            fee = usdValue * 0.001; // 0.1% fee

            // Check for arbitrage opportunity
            const potentialProfit = (toAmount * toCoinData.currentPrice) - (fromAmount * fromCoinData.currentPrice);
            if (potentialProfit > 0) {
                profit = potentialProfit - fee;
                toAmount += profit / toCoinData.currentPrice;
            }

            // For simplicity, we're not tracking individual coin balances
            // In a real app, you'd need to track coin balances
            return res.status(400).json({ message: 'Direct coin-to-coin conversion not supported. Convert to USD first.' });
        }

        await req.user.save();

        // Record trade
        const trade = new Trade({
            userId: req.user._id,
            type: 'convert',
            fromCoin,
            toCoin,
            amount: fromAmount,
            rate: fromCoin === 'USD' ? toCoinData.currentPrice : fromCoinData.currentPrice,
            fee,
            profit,
            status: 'completed'
        });
        await trade.save();

        // Record transaction
        const transactionType = fromCoin === 'USD' ? 'trade' : 'trade';
        const transaction = new Transaction({
            userId: req.user._id,
            type: transactionType,
            amount: fromCoin === 'USD' ? fromAmount : toAmount,
            currency: fromCoin === 'USD' ? 'USD' : 'USD',
            status: 'completed',
            txHash: `TRADE-${trade._id}`
        });
        await transaction.save();

        // Update trading volume
        const tradeValue = fromCoin === 'USD' ? fromAmount : fromAmount * fromCoinData.currentPrice;
        req.user.tradingVolume += tradeValue;
        await req.user.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        broadcastToUser(req.user._id, {
            type: 'TRADE_UPDATE',
            trade: {
                id: trade._id,
                type: 'convert',
                fromCoin,
                toCoin,
                amount: fromAmount,
                resultAmount: toAmount,
                rate: fromCoin === 'USD' ? toCoinData.currentPrice : fromCoinData.currentPrice,
                fee,
                profit,
                timestamp: trade.createdAt
            }
        });

        res.status(200).json({ 
            message: 'Trade executed successfully',
            balance: req.user.balance,
            trade: {
                id: trade._id,
                type: 'convert',
                fromCoin,
                toCoin,
                amount: fromAmount,
                resultAmount: toAmount,
                rate: fromCoin === 'USD' ? toCoinData.currentPrice : fromCoinData.currentPrice,
                fee,
                profit,
                timestamp: trade.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error executing trade' });
    }
});

app.get('/api/v1/trades/history', authenticate, async (req, res) => {
    try {
        const trades = await Trade.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(trades);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching trade history' });
    }
});

// Arbitrage Routes
app.get('/api/v1/arbitrage/opportunities', authenticate, async (req, res) => {
    try {
        // Get all coins
        const coins = await Coin.find().limit(50); // Limit to 50 coins for performance

        const opportunities = [];

        // Simple arbitrage detection - compare each coin against others
        for (let i = 0; i < coins.length; i++) {
            for (let j = i + 1; j < coins.length; j++) {
                const coinA = coins[i];
                const coinB = coins[j];

                // Calculate potential arbitrage
                const rateAB = coinA.currentPrice / coinB.currentPrice;
                const rateBA = coinB.currentPrice / coinA.currentPrice;

                // Consider a 0.5% threshold for arbitrage after fees
                const threshold = 0.005;
                
                if (rateAB > (1 + threshold)) {
                    opportunities.push({
                        fromCoin: coinA.coinId,
                        toCoin: coinB.coinId,
                        exchangeRate: rateAB,
                        potentialProfit: (rateAB - 1 - 0.001) * 100, // Subtract fee
                        timestamp: new Date()
                    });
                }

                if (rateBA > (1 + threshold)) {
                    opportunities.push({
                        fromCoin: coinB.coinId,
                        toCoin: coinA.coinId,
                        exchangeRate: rateBA,
                        potentialProfit: (rateBA - 1 - 0.001) * 100, // Subtract fee
                        timestamp: new Date()
                    });
                }
            }
        }

        // Sort by highest profit first
        opportunities.sort((a, b) => b.potentialProfit - a.potentialProfit);

        // Save to database
        await ArbitrageOpportunity.deleteMany({});
        await ArbitrageOpportunity.insertMany(opportunities.slice(0, 10)); // Save top 10

        res.status(200).json(opportunities.slice(0, 10));
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error finding arbitrage opportunities' });
    }
});

app.post('/api/v1/arbitrage/execute', authenticate, async (req, res) => {
    try {
        const { fromCoin, toCoin, amount } = req.body;

        if (fromCoin === toCoin) {
            return res.status(400).json({ message: 'Cannot arbitrage the same coin' });
        }

        // Get coin prices
        const fromCoinData = await Coin.findOne({ coinId: fromCoin });
        const toCoinData = await Coin.findOne({ coinId: toCoin });

        if (!fromCoinData || !toCoinData) {
            return res.status(400).json({ message: 'Invalid coin selection' });
        }

        // Calculate arbitrage
        const rate = fromCoinData.currentPrice / toCoinData.currentPrice;
        const threshold = 0.005; // 0.5% threshold for arbitrage after fees

        if (rate <= (1 + threshold)) {
            return res.status(400).json({ message: 'No arbitrage opportunity found' });
        }

        // Calculate amounts
        const fromAmount = amount;
        const usdValue = fromAmount * fromCoinData.currentPrice;
        const toAmount = usdValue / toCoinData.currentPrice;
        const fee = usdValue * 0.001; // 0.1% fee
        const profit = (toAmount * toCoinData.currentPrice) - usdValue - fee;

        if (profit <= 0) {
            return res.status(400).json({ message: 'No profitable arbitrage after fees' });
        }

        // For simplicity, we're just tracking USD balance
        // In a real app, you'd need to track coin balances
        req.user.balance += profit;
        await req.user.save();

        // Record trade
        const trade = new Trade({
            userId: req.user._id,
            type: 'arbitrage',
            fromCoin,
            toCoin,
            amount: fromAmount,
            rate,
            fee,
            profit,
            status: 'completed'
        });
        await trade.save();

        // Record transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'trade',
            amount: profit,
            currency: 'USD',
            status: 'completed',
            txHash: `ARB-${trade._id}`
        });
        await transaction.save();

        // Update trading volume
        req.user.tradingVolume += usdValue;
        await req.user.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        broadcastToUser(req.user._id, {
            type: 'TRADE_UPDATE',
            trade: {
                id: trade._id,
                type: 'arbitrage',
                fromCoin,
                toCoin,
                amount: fromAmount,
                resultAmount: toAmount,
                rate,
                fee,
                profit,
                timestamp: trade.createdAt
            }
        });

        res.status(200).json({ 
            message: 'Arbitrage executed successfully',
            balance: req.user.balance,
            trade: {
                id: trade._id,
                type: 'arbitrage',
                fromCoin,
                toCoin,
                amount: fromAmount,
                resultAmount: toAmount,
                rate,
                fee,
                profit,
                timestamp: trade.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error executing arbitrage' });
    }
});

// User Routes
app.get('/api/v1/users/me', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password -verificationToken -resetPasswordToken');
        res.status(200).json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching user data' });
    }
});

app.patch('/api/v1/users/me', authenticate, async (req, res) => {
    try {
        const { firstName, lastName, country, currency } = req.body;

        const updates = {};
        if (firstName) updates.firstName = firstName;
        if (lastName) updates.lastName = lastName;
        if (country) updates.country = country;
        if (currency) updates.currency = currency;

        const user = await User.findByIdAndUpdate(
            req.user._id,
            updates,
            { new: true }
        ).select('-password -verificationToken -resetPasswordToken');

        res.status(200).json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating user' });
    }
});

app.patch('/api/v1/users/me/password', authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating password' });
    }
});

app.post('/api/v1/users/me/kyc', authenticate, async (req, res) => {
    try {
        // In a real app, you would handle file uploads here
        // For simplicity, we'll just mark as pending
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { kycStatus: 'pending' },
            { new: true }
        ).select('-password -verificationToken -resetPasswordToken');

        res.status(200).json({ message: 'KYC submitted for review', user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error submitting KYC' });
    }
});

app.post('/api/v1/users/me/generate-api-key', authenticate, async (req, res) => {
    try {
        const newApiKey = crypto.randomBytes(16).toString('hex');
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { apiKey: newApiKey },
            { new: true }
        ).select('-password -verificationToken -resetPasswordToken');

        res.status(200).json({ apiKey: user.apiKey });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error generating API key' });
    }
});

// Transaction Routes
app.get('/api/v1/transactions', authenticate, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(transactions);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching transactions' });
    }
});

app.post('/api/v1/transactions/deposit', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;

        // In a real app, you would generate a deposit address
        // For simplicity, we'll just credit the account
        req.user.balance += amount;
        await req.user.save();

        // Record transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'deposit',
            amount,
            currency: 'USD',
            status: 'completed',
            txHash: `DEP-${uuidv4()}`
        });
        await transaction.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        res.status(200).json({ 
            message: 'Deposit successful',
            balance: req.user.balance,
            transaction
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error processing deposit' });
    }
});

app.post('/api/v1/transactions/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, address } = req.body;

        if (amount < 350) {
            return res.status(400).json({ message: 'Minimum withdrawal amount is $350' });
        }

        if (req.user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        // Deduct balance
        req.user.balance -= amount;
        await req.user.save();

        // Record transaction
        const transaction = new Transaction({
            userId: req.user._id,
            type: 'withdrawal',
            amount,
            currency: 'USD',
            status: 'pending', // Would be processed by admin
            address,
            txHash: `WDR-${uuidv4()}`
        });
        await transaction.save();

        broadcastToUser(req.user._id, {
            type: 'BALANCE_UPDATE',
            balance: req.user.balance
        });

        // Notify admins
        broadcastToAdmins({
            type: 'WITHDRAWAL_REQUEST',
            transactionId: transaction._id,
            userId: req.user._id,
            amount,
            address
        });

        res.status(200).json({ 
            message: 'Withdrawal request submitted',
            balance: req.user.balance,
            transaction
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error processing withdrawal' });
    }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = [
            { 
                category: 'Account', 
                questions: [
                    { question: 'How do I create an account?', answer: 'Click on the Sign Up button and follow the instructions.' },
                    { question: 'How do I verify my email?', answer: 'Check your email for a verification link after signing up.' }
                ]
            },
            { 
                category: 'Trading', 
                questions: [
                    { question: 'How do I buy cryptocurrencies?', answer: 'Go to the Trade section, select the coin, enter amount and click Buy.' },
                    { question: 'What are the trading fees?', answer: 'We charge 0.1% fee on all trades.' }
                ]
            },
            { 
                category: 'Deposits & Withdrawals', 
                questions: [
                    { question: 'How long do deposits take?', answer: 'Deposits are usually instant.' },
                    { question: 'What is the minimum withdrawal amount?', answer: 'The minimum withdrawal amount is $350.' }
                ]
            }
        ];

        res.status(200).json(faqs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching FAQs' });
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

        // Notify admins
        broadcastToAdmins({
            type: 'NEW_SUPPORT_TICKET',
            ticketId: ticket._id,
            subject,
            message
        });

        res.status(201).json({ message: 'Ticket created successfully', ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error creating ticket' });
    }
});

app.get('/api/v1/support/tickets', authenticate, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(tickets);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching tickets' });
    }
});

app.get('/api/v1/support/tickets/:id', authenticate, async (req, res) => {
    try {
        const ticket = await SupportTicket.findOne({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        res.status(200).json(ticket);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching ticket' });
    }
});

app.post('/api/v1/support/tickets/:id/reply', authenticate, async (req, res) => {
    try {
        const { message } = req.body;

        const ticket = await SupportTicket.findOne({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        ticket.responses.push({
            message,
            isAdmin: false
        });
        ticket.status = 'in-progress';
        await ticket.save();

        // Notify admins
        broadcastToAdmins({
            type: 'TICKET_REPLY',
            ticketId: ticket._id,
            message
        });

        res.status(200).json({ message: 'Reply added successfully', ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error replying to ticket' });
    }
});

// Admin Support Routes
app.get('/api/v1/admin/support/tickets', authenticateAdmin, async (req, res) => {
    try {
        const tickets = await SupportTicket.find().sort({ createdAt: -1 }).populate('userId', 'email');
        res.status(200).json(tickets);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching tickets' });
    }
});

app.get('/api/v1/admin/support/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id).populate('userId', 'email');
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        res.status(200).json(ticket);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching ticket' });
    }
});

app.post('/api/v1/admin/support/tickets/:id/reply', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;

        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        ticket.responses.push({
            message,
            isAdmin: true
        });
        ticket.status = req.body.status || ticket.status;
        await ticket.save();

        // Notify user
        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'TICKET_UPDATE',
                ticketId: ticket._id,
                message: 'Admin has replied to your ticket'
            });
        }

        res.status(200).json({ message: 'Reply added successfully', ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error replying to ticket' });
    }
});

app.patch('/api/v1/admin/support/tickets/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        ticket.status = status;
        await ticket.save();

        // Notify user
        if (ticket.userId) {
            broadcastToUser(ticket.userId, {
                type: 'TICKET_UPDATE',
                ticketId: ticket._id,
                message: `Your ticket status has been updated to ${status}`
            });
        }

        res.status(200).json({ message: 'Status updated successfully', ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating ticket status' });
    }
});

// Admin Transaction Routes
app.get('/api/v1/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const transactions = await Transaction.find().sort({ createdAt: -1 }).populate('userId', 'email');
        res.status(200).json(transactions);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching transactions' });
    }
});

app.patch('/api/v1/admin/transactions/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { status, txHash } = req.body;

        const transaction = await Transaction.findById(req.params.id).populate('userId');
        if (!transaction) {
            return res.status(404).json({ message: 'Transaction not found' });
        }

        if (transaction.type === 'withdrawal' && status === 'completed') {
            // In a real app, you would process the withdrawal here
            // For simplicity, we'll just update the status
        }

        transaction.status = status;
        if (txHash) transaction.txHash = txHash;
        await transaction.save();

        // Notify user
        if (transaction.userId) {
            broadcastToUser(transaction.userId, {
                type: 'TRANSACTION_UPDATE',
                transactionId: transaction._id,
                status,
                message: `Your ${transaction.type} transaction has been ${status}`
            });
        }

        res.status(200).json({ message: 'Transaction updated successfully', transaction });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating transaction' });
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something broke!' });
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});
