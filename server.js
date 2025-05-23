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
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Middleware
app.use(cors({
    origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api/', apiLimiter);

// Email configuration
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '7c707ac161af1c',
        pass: '6c08aa4f2c679a'
    }
});

// JWT Secret
const JWT_SECRET = '17581758Na.%';

// Models
const UserSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    walletAddress: { type: String, unique: true, sparse: true },
    country: { type: String },
    currencyPreference: { type: String, default: 'USD' },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    kycStatus: { type: String, enum: ['not_verified', 'pending', 'verified', 'rejected'], default: 'not_verified' },
    kycDocuments: {
        idFront: { type: String },
        idBack: { type: String },
        selfie: { type: String }
    },
    twoFactorEnabled: { type: Boolean, default: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    lastLogin: { type: Date },
    accountBalance: {
        BTC: { type: Number, default: 0 },
        ETH: { type: Number, default: 0 },
        USDT: { type: Number, default: 1000 }, // Starting balance for demo
        BNB: { type: Number, default: 0 },
        XRP: { type: Number, default: 0 },
        ADA: { type: Number, default: 0 },
        SOL: { type: Number, default: 0 },
        DOT: { type: Number, default: 0 },
        DOGE: { type: Number, default: 0 }
    },
    tradingHistory: [{
        type: { type: String, enum: ['buy', 'sell', 'convert'] },
        fromCurrency: { type: String },
        toCurrency: { type: String },
        amount: { type: Number },
        rate: { type: Number },
        timestamp: { type: Date, default: Date.now }
    }],
    settings: {
        theme: { type: String, default: 'light' },
        notifications: { type: Boolean, default: true },
        language: { type: String, default: 'en' }
    },
    apiKey: { type: String, default: uuidv4() },
    createdAt: { type: Date, default: Date.now }
});

const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    attachments: [{ type: String }],
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    responses: [{
        message: { type: String },
        responder: { type: String, enum: ['user', 'support'] },
        timestamp: { type: Date, default: Date.now },
        attachments: [{ type: String }]
    }],
    createdAt: { type: Date, default: Date.now }
});

const FAQSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    category: { type: String, enum: ['account', 'trading', 'deposits', 'withdrawals', 'security', 'general'], required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const FAQ = mongoose.model('FAQ', FAQSchema);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// Helper functions
const generateToken = (user) => {
    return jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        if (user.role !== 'admin') return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Initialize WebSocket server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

const broadcastMessage = (type, data) => {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type, data }));
        }
    });
};

wss.on('connection', (ws) => {
    ws.on('message', async (message) => {
        try {
            const { type, token } = JSON.parse(message);
            
            if (type === 'authenticate') {
                jwt.verify(token, JWT_SECRET, (err, user) => {
                    if (err) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
                        ws.close();
                    } else {
                        ws.userId = user.id;
                        ws.send(JSON.stringify({ type: 'authenticated', message: 'WebSocket connection authenticated' }));
                    }
                });
            }
        } catch (err) {
            console.error('WebSocket error:', err);
        }
    });
});

// Routes

// Auth Routes
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, country, currencyPreference } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
        const user = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            country,
            currencyPreference,
            verificationToken: uuidv4()
        });
        
        await user.save();
        
        // Send verification email
        const verificationUrl = `https://website-xi-ten-52.vercel.app/verify-email?token=${user.verificationToken}`;
        
        await transporter.sendMail({
            from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Welcome to Crypto Trading Market! Please verify your email by clicking <a href="${verificationUrl}">here</a>.</p>`
        });
        
        // Generate token
        const token = generateToken(user);
        
        res.status(201).json({ token, user: { 
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role
        } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during signup' });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature, firstName, lastName, email, country, currencyPreference } = req.body;
        
        // Check if wallet already exists
        const existingUser = await User.findOne({ walletAddress });
        if (existingUser) {
            return res.status(400).json({ message: 'Wallet already registered' });
        }
        
        // Create user
        const user = new User({
            firstName,
            lastName,
            email,
            walletAddress,
            country,
            currencyPreference,
            isVerified: true // Skip email verification for wallet users
        });
        
        await user.save();
        
        // Generate token
        const token = generateToken(user);
        
        res.status(201).json({ token, user: { 
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            walletAddress: user.walletAddress,
            role: user.role
        } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during wallet signup' });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = generateToken(user);
        
        res.json({ token, user: { 
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role,
            accountBalance: user.accountBalance,
            settings: user.settings
        } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        
        // Find user
        const user = await User.findOne({ walletAddress });
        if (!user) {
            return res.status(400).json({ message: 'Wallet not registered' });
        }
        
        // Verify signature (in a real app, you would verify the signature against the nonce)
        // For demo purposes, we'll skip this step
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = generateToken(user);
        
        res.json({ token, user: { 
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            walletAddress: user.walletAddress,
            role: user.role,
            accountBalance: user.accountBalance,
            settings: user.settings
        } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during wallet login' });
    }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            // For security, don't reveal if email doesn't exist
            return res.json({ message: 'If an account with that email exists, a password reset link has been sent' });
        }
        
        // Create reset token
        user.resetPasswordToken = uuidv4();
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        
        // Send reset email
        const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${user.resetPasswordToken}`;
        
        await transporter.sendMail({
            from: '"Crypto Trading Market" <support@cryptotradingmarket.com>',
            to: email,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 1 hour.</p>`
        });
        
        res.json({ message: 'If an account with that email exists, a password reset link has been sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset request' });
    }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        // Find user by token
        const user = await User.findOne({ 
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        // Update password and clear token
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        
        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset' });
    }
});

app.post('/api/v1/auth/logout', authenticateToken, (req, res) => {
    // In a real app, you might want to invalidate the token on the server side
    // For JWT, since it's stateless, we just tell the client to remove the token
    res.json({ message: 'Logged out successfully' });
});

// User Routes
app.get('/api/v1/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching user data' });
    }
});

app.patch('/api/v1/users/update', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, country, currencyPreference } = req.body;
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (country) user.country = country;
        if (currencyPreference) user.currencyPreference = currencyPreference;
        
        await user.save();
        
        res.json({ 
            firstName: user.firstName,
            lastName: user.lastName,
            country: user.country,
            currencyPreference: user.currencyPreference
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating user data' });
    }
});

app.patch('/api/v1/users/update-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Check current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        await user.save();
        
        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating password' });
    }
});

app.patch('/api/v1/users/update-settings', authenticateToken, async (req, res) => {
    try {
        const { theme, notifications, language } = req.body;
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        if (theme) user.settings.theme = theme;
        if (notifications !== undefined) user.settings.notifications = notifications;
        if (language) user.settings.language = language;
        
        await user.save();
        
        res.json(user.settings);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating settings' });
    }
});

app.post('/api/v1/users/kyc', authenticateToken, upload.fields([
    { name: 'idFront', maxCount: 1 },
    { name: 'idBack', maxCount: 1 },
    { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Save file paths
        if (req.files.idFront) {
            user.kycDocuments.idFront = req.files.idFront[0].path;
        }
        if (req.files.idBack) {
            user.kycDocuments.idBack = req.files.idBack[0].path;
        }
        if (req.files.selfie) {
            user.kycDocuments.selfie = req.files.selfie[0].path;
        }
        
        user.kycStatus = 'pending';
        await user.save();
        
        res.json({ message: 'KYC documents submitted successfully', kycStatus: user.kycStatus });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error submitting KYC documents' });
    }
});

app.post('/api/v1/users/generate-api-key', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        user.apiKey = uuidv4();
        await user.save();
        
        res.json({ apiKey: user.apiKey });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error generating API key' });
    }
});

app.post('/api/v1/users/export-data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // In a real app, you might want to generate a file and email it to the user
        // For this demo, we'll just return the user data
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error exporting user data' });
    }
});

app.delete('/api/v1/users/delete-account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Password is incorrect' });
        }
        
        // Delete user
        await User.deleteOne({ _id: req.user.id });
        
        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error deleting account' });
    }
});

// Trading Routes
const getCurrentPrices = () => {
    // In a real app, you would fetch these from an exchange API
    // For demo purposes, we'll use fixed prices with some random fluctuation
    const basePrices = {
        BTC: 50000 + Math.random() * 5000,
        ETH: 3000 + Math.random() * 300,
        USDT: 1,
        BNB: 400 + Math.random() * 40,
        XRP: 0.5 + Math.random() * 0.05,
        ADA: 1.5 + Math.random() * 0.15,
        SOL: 100 + Math.random() * 10,
        DOT: 30 + Math.random() * 3,
        DOGE: 0.15 + Math.random() * 0.015
    };
    
    return basePrices;
};

const findArbitrageOpportunities = () => {
    const prices = getCurrentPrices();
    const opportunities = [];
    
    // Simple arbitrage detection (in a real app, this would be more sophisticated)
    const currencies = Object.keys(prices);
    
    for (let i = 0; i < currencies.length; i++) {
        for (let j = 0; j < currencies.length; j++) {
            if (i !== j) {
                const fromCurrency = currencies[i];
                const toCurrency = currencies[j];
                const rate = prices[toCurrency] / prices[fromCurrency];
                
                // Check if this rate is better than the direct rate
                for (let k = 0; k < currencies.length; k++) {
                    if (k !== i && k !== j) {
                        const intermediateCurrency = currencies[k];
                        const intermediateRate = (prices[intermediateCurrency] / prices[fromCurrency]) * 
                                              (prices[toCurrency] / prices[intermediateCurrency]);
                        
                        if (intermediateRate > rate * 1.01) { // 1% better
                            opportunities.push({
                                fromCurrency,
                                toCurrency,
                                via: intermediateCurrency,
                                directRate: rate,
                                arbitrageRate: intermediateRate,
                                profitPercentage: ((intermediateRate - rate) / rate) * 100
                            });
                        }
                    }
                }
            }
        }
    }
    
    return opportunities;
};

app.get('/api/v1/trading/prices', async (req, res) => {
    try {
        const prices = getCurrentPrices();
        res.json(prices);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching prices' });
    }
});

app.get('/api/v1/trading/arbitrage-opportunities', async (req, res) => {
    try {
        const opportunities = findArbitrageOpportunities();
        res.json(opportunities);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error finding arbitrage opportunities' });
    }
});

app.post('/api/v1/trading/convert', authenticateToken, async (req, res) => {
    try {
        const { fromCurrency, toCurrency, amount } = req.body;
        
        if (!fromCurrency || !toCurrency || !amount) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        
        if (amount < 10) {
            return res.status(400).json({ message: 'Minimum conversion amount is $10 equivalent' });
        }
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Check balance
        if (user.accountBalance[fromCurrency] < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }
        
        // Get current prices
        const prices = getCurrentPrices();
        
        // Calculate conversion
        const rate = prices[toCurrency] / prices[fromCurrency];
        const convertedAmount = amount * rate;
        
        // Update balances
        user.accountBalance[fromCurrency] -= amount;
        user.accountBalance[toCurrency] += convertedAmount;
        
        // Add to trading history
        user.tradingHistory.push({
            type: 'convert',
            fromCurrency,
            toCurrency,
            amount,
            rate
        });
        
        await user.save();
        
        // Broadcast balance update
        broadcastMessage('BALANCE_UPDATE', {
            userId: user._id,
            balances: user.accountBalance
        });
        
        res.json({ 
            message: 'Conversion successful',
            fromCurrency,
            toCurrency,
            amount,
            convertedAmount,
            rate,
            newBalances: user.accountBalance
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during conversion' });
    }
});

app.post('/api/v1/trading/arbitrage', authenticateToken, async (req, res) => {
    try {
        const { fromCurrency, toCurrency, viaCurrency, amount } = req.body;
        
        if (!fromCurrency || !toCurrency || !viaCurrency || !amount) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        
        if (amount < 100) {
            return res.status(400).json({ message: 'Minimum arbitrage amount is $100 equivalent' });
        }
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Check balance
        if (user.accountBalance[fromCurrency] < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }
        
        // Get current prices
        const prices = getCurrentPrices();
        
        // Calculate direct rate
        const directRate = prices[toCurrency] / prices[fromCurrency];
        const directAmount = amount * directRate;
        
        // Calculate arbitrage rate
        const arbitrageRate = (prices[viaCurrency] / prices[fromCurrency]) * 
                           (prices[toCurrency] / prices[viaCurrency]);
        const arbitrageAmount = amount * arbitrageRate;
        
        // Check if arbitrage is actually profitable
        if (arbitrageAmount <= directAmount) {
            return res.status(400).json({ message: 'No arbitrage opportunity found' });
        }
        
        // Update balances
        user.accountBalance[fromCurrency] -= amount;
        user.accountBalance[toCurrency] += arbitrageAmount;
        
        // Add to trading history
        user.tradingHistory.push({
            type: 'arbitrage',
            fromCurrency,
            toCurrency,
            via: viaCurrency,
            amount,
            rate: arbitrageRate,
            profit: arbitrageAmount - directAmount
        });
        
        await user.save();
        
        // Broadcast balance update
        broadcastMessage('BALANCE_UPDATE', {
            userId: user._id,
            balances: user.accountBalance
        });
        
        res.json({ 
            message: 'Arbitrage trade successful',
            fromCurrency,
            toCurrency,
            viaCurrency,
            amount,
            arbitrageAmount,
            directAmount,
            profit: arbitrageAmount - directAmount,
            newBalances: user.accountBalance
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during arbitrage trade' });
    }
});

// Support Routes
app.get('/api/v1/support/faqs', async (req, res) => {
    try {
        const faqs = await FAQ.find().sort({ createdAt: -1 });
        res.json(faqs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching FAQs' });
    }
});

app.post('/api/v1/support/tickets', authenticateToken, upload.array('attachments', 5), async (req, res) => {
    try {
        const { subject, message } = req.body;
        
        if (!subject || !message) {
            return res.status(400).json({ message: 'Subject and message are required' });
        }
        
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Get file paths
        const attachments = req.files ? req.files.map(file => file.path) : [];
        
        // Create ticket
        const ticket = new SupportTicket({
            userId: user._id,
            name: `${user.firstName} ${user.lastName}`,
            email: user.email,
            subject,
            message,
            attachments,
            status: 'open'
        });
        
        await ticket.save();
        
        res.json({ 
            message: 'Ticket created successfully',
            ticket: {
                id: ticket._id,
                subject: ticket.subject,
                status: ticket.status,
                createdAt: ticket.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error creating support ticket' });
    }
});

app.get('/api/v1/support/tickets', authenticateToken, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(tickets);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching support tickets' });
    }
});

app.get('/api/v1/support/tickets/:id', authenticateToken, async (req, res) => {
    try {
        const ticket = await SupportTicket.findOne({ 
            _id: req.params.id,
            userId: req.user.id
        });
        
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        res.json(ticket);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching ticket details' });
    }
});

app.post('/api/v1/support/tickets/:id/reply', authenticateToken, upload.array('attachments', 5), async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }
        
        const ticket = await SupportTicket.findOne({ 
            _id: req.params.id,
            userId: req.user.id
        });
        
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        // Get file paths
        const attachments = req.files ? req.files.map(file => file.path) : [];
        
        // Add response
        ticket.responses.push({
            message,
            responder: 'user',
            attachments
        });
        
        await ticket.save();
        
        res.json({ 
            message: 'Reply added successfully',
            ticket: {
                id: ticket._id,
                subject: ticket.subject,
                status: ticket.status,
                responses: ticket.responses
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error replying to ticket' });
    }
});

// Admin Routes
app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find admin user
        const user = await User.findOne({ email, role: 'admin' });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = generateToken(user);
        
        res.json({ token, user: { 
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role
        } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during admin login' });
    }
});

app.get('/api/v1/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        // Count users
        const totalUsers = await User.countDocuments();
        const newUsersToday = await User.countDocuments({
            createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        });
        
        // Count tickets
        const totalTickets = await SupportTicket.countDocuments();
        const openTickets = await SupportTicket.countDocuments({ status: 'open' });
        
        // Get trading volume (simplified for demo)
        const users = await User.find();
        let tradingVolume = 0;
        users.forEach(user => {
            user.tradingHistory.forEach(trade => {
                if (trade.type === 'convert' || trade.type === 'arbitrage') {
                    tradingVolume += trade.amount;
                }
            });
        });
        
        // KYC stats
        const kycStats = {
            not_verified: await User.countDocuments({ kycStatus: 'not_verified' }),
            pending: await User.countDocuments({ kycStatus: 'pending' }),
            verified: await User.countDocuments({ kycStatus: 'verified' }),
            rejected: await User.countDocuments({ kycStatus: 'rejected' })
        };
        
        res.json({
            totalUsers,
            newUsersToday,
            totalTickets,
            openTickets,
            tradingVolume,
            kycStats
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching dashboard stats' });
    }
});

app.get('/api/v1/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        
        const query = {
            $or: [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } }
            ]
        };
        
        const users = await User.find(query)
            .select('-password -verificationToken -resetPasswordToken -resetPasswordExpires')
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });
            
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching users' });
    }
});

app.get('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');
            
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching user details' });
    }
});

app.patch('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { kycStatus, accountBalance, role } = req.body;
        
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        if (kycStatus) user.kycStatus = kycStatus;
        if (accountBalance) {
            for (const currency in accountBalance) {
                if (accountBalance.hasOwnProperty(currency)) {
                    user.accountBalance[currency] = accountBalance[currency];
                }
            }
        }
        if (role) user.role = role;
        
        await user.save();
        
        res.json({ 
            kycStatus: user.kycStatus,
            accountBalance: user.accountBalance,
            role: user.role
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating user' });
    }
});

app.delete('/api/v1/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        await User.deleteOne({ _id: req.params.id });
        
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error deleting user' });
    }
});

app.get('/api/v1/admin/trades', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, userId = '' } = req.query;
        
        const query = userId ? { userId } : {};
        
        // Get all users' trading history
        const users = await User.find(query)
            .select('tradingHistory firstName lastName email')
            .skip((page - 1) * limit)
            .limit(parseInt(limit));
            
        // Flatten trading history
        let trades = [];
        users.forEach(user => {
            user.tradingHistory.forEach(trade => {
                trades.push({
                    ...trade.toObject(),
                    user: {
                        id: user._id,
                        name: `${user.firstName} ${user.lastName}`,
                        email: user.email
                    }
                });
            });
        });
        
        // Sort by timestamp
        trades.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        const total = await User.countDocuments(query);
        
        res.json({
            trades,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching trades' });
    }
});

app.get('/api/v1/admin/tickets', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, status = '' } = req.query;
        
        const query = status ? { status } : {};
        
        const tickets = await SupportTicket.find(query)
            .populate('userId', 'firstName lastName email')
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });
            
        const total = await SupportTicket.countDocuments(query);
        
        res.json({
            tickets,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching tickets' });
    }
});

app.get('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id)
            .populate('userId', 'firstName lastName email');
            
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        res.json(ticket);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching ticket details' });
    }
});

app.patch('/api/v1/admin/tickets/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        if (status) ticket.status = status;
        
        await ticket.save();
        
        res.json({ 
            status: ticket.status
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating ticket' });
    }
});

app.post('/api/v1/admin/tickets/:id/reply', authenticateAdmin, upload.array('attachments', 5), async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }
        
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        // Get file paths
        const attachments = req.files ? req.files.map(file => file.path) : [];
        
        // Add response
        ticket.responses.push({
            message,
            responder: 'support',
            attachments
        });
        
        await ticket.save();
        
        res.json({ 
            message: 'Reply added successfully',
            ticket: {
                id: ticket._id,
                subject: ticket.subject,
                status: ticket.status,
                responses: ticket.responses
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error replying to ticket' });
    }
});

app.post('/api/v1/admin/faqs', authenticateAdmin, async (req, res) => {
    try {
        const { question, answer, category } = req.body;
        
        if (!question || !answer || !category) {
            return res.status(400).json({ message: 'Question, answer, and category are required' });
        }
        
        const faq = new FAQ({
            question,
            answer,
            category
        });
        
        await faq.save();
        
        res.json(faq);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error creating FAQ' });
    }
});

app.patch('/api/v1/admin/faqs/:id', authenticateAdmin, async (req, res) => {
    try {
        const { question, answer, category } = req.body;
        
        const faq = await FAQ.findById(req.params.id);
        if (!faq) {
            return res.status(404).json({ message: 'FAQ not found' });
        }
        
        if (question) faq.question = question;
        if (answer) faq.answer = answer;
        if (category) faq.category = category;
        
        await faq.save();
        
        res.json(faq);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating FAQ' });
    }
});

app.delete('/api/v1/admin/faqs/:id', authenticateAdmin, async (req, res) => {
    try {
        const faq = await FAQ.findById(req.params.id);
        if (!faq) {
            return res.status(404).json({ message: 'FAQ not found' });
        }
        
        await FAQ.deleteOne({ _id: req.params.id });
        
        res.json({ message: 'FAQ deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error deleting FAQ' });
    }
});

// Initialize admin user if not exists
const initializeAdmin = async () => {
    try {
        const adminEmail = 'admin@cryptotradingmarket.com';
        const adminExists = await User.findOne({ email: adminEmail, role: 'admin' });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('Admin@1234', 12);
            
            const admin = new User({
                firstName: 'Admin',
                lastName: 'User',
                email: adminEmail,
                password: hashedPassword,
                role: 'admin',
                isVerified: true,
                accountBalance: {
                    BTC: 10,
                    ETH: 100,
                    USDT: 100000,
                    BNB: 500,
                    XRP: 10000,
                    ADA: 5000,
                    SOL: 1000,
                    DOT: 3000,
                    DOGE: 50000
                }
            });
            
            await admin.save();
            console.log('Default admin user created');
        }
    } catch (err) {
        console.error('Error initializing admin user:', err);
    }
};

// Initialize FAQs if not exists
const initializeFAQs = async () => {
    try {
        const faqCount = await FAQ.countDocuments();
        
        if (faqCount === 0) {
            const defaultFAQs = [
                {
                    question: 'How do I create an account?',
                    answer: 'You can create an account by clicking on the "Sign Up" button and following the registration process. You can choose to sign up with your email or connect a crypto wallet.',
                    category: 'account'
                },
                {
                    question: 'What is the minimum deposit amount?',
                    answer: 'The minimum deposit amount varies by cryptocurrency. Generally, we recommend depositing at least $10 worth of any supported cryptocurrency.',
                    category: 'deposits'
                },
                {
                    question: 'How does arbitrage trading work?',
                    answer: 'Arbitrage trading involves taking advantage of price differences for the same asset across different markets. Our platform automatically identifies these opportunities and executes trades to lock in profits.',
                    category: 'trading'
                },
                {
                    question: 'Is KYC verification mandatory?',
                    answer: 'KYC verification is required for certain features like higher withdrawal limits. Basic trading can be done without KYC, but with some limitations.',
                    category: 'account'
                },
                {
                    question: 'How long do withdrawals take?',
                    answer: 'Withdrawal processing times vary by cryptocurrency. Most withdrawals are processed within 30 minutes, but during periods of high network congestion, it may take longer.',
                    category: 'withdrawals'
                }
            ];
            
            await FAQ.insertMany(defaultFAQs);
            console.log('Default FAQs created');
        }
    } catch (err) {
        console.error('Error initializing FAQs:', err);
    }
};

// Initialize data
initializeAdmin();
initializeFAQs();
