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
const DeviceDetector = require('device-detector-js');
const axios = require('axios');
const geoip = require('geoip-lite');
const useragent = require('express-useragent');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DEPOSIT_ADDRESS = process.env.DEPOSIT_ADDRESS || 'bc1qf98sra3ljvpgy9as0553z79leeq2w2ryvggf3fnvpeh3rz3dk4zs33uf9k';
const IPINFO_TOKEN = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';

// Enhanced MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://pesalifeke:AkAkSa6YoKcDYJEX@cryptotradingmarket.dpoatp3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// Email Transport with better error handling
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io',
    port: process.env.EMAIL_PORT || 2525,
    auth: {
        user: process.env.EMAIL_USER || '7c707ac161af1c',
        pass: process.env.EMAIL_PASS || '6c08aa4f2c679a'
    },
    pool: true,
    maxConnections: 5,
    maxMessages: 100
});

transporter.verify(error => {
    if (error) {
        console.error('SMTP connection error:', error);
    } else {
        console.log('SMTP server is ready to take our messages');
    }
});

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https://*.wikimedia.org", "https://trustwallet.com"],
            connectSrc: ["'self'", "https://website-backendd-1.onrender.com", "https://ipinfo.io"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cookieParser());
app.use(useragent.express());

// Enhanced CORS Configuration
const corsOptions = {
    origin: ['https://website-7t25.vercel.app', 'https://website-xi-ten-52.vercel.app', 'http://localhost:3000', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-Forwarded-For'],
    exposedHeaders: ['Content-Disposition', 'Set-Cookie'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    next();
});

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Enhanced Device Detection Middleware
const captureDeviceInfo = async (req, res, next) => {
    try {
        const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        
        const detector = new DeviceDetector();
        const device = detector.parse(userAgent);
        
        // Get location data from multiple sources
        let geo = {};
        try {
            // First try ipinfo.io
            const response = await axios.get(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
            geo = response.data;
            
            // Fallback to geoip-lite if ipinfo fails
            if (!geo || !geo.country) {
                const geoLiteData = geoip.lookup(ip);
                if (geoLiteData) {
                    geo = {
                        ip,
                        country: geoLiteData.country,
                        region: geoLiteData.region,
                        city: geoLiteData.city,
                        timezone: geoLiteData.timezone,
                        loc: `${geoLiteData.ll[0]},${geoLiteData.ll[1]}`
                    };
                }
            }
        } catch (ipError) {
            console.error('Error fetching IP info:', ipError.message);
            geo = {
                ip,
                country: 'Unknown',
                region: 'Unknown',
                city: 'Unknown',
                timezone: 'UTC',
                loc: null
            };
        }

        // Enhanced device fingerprint
        const fingerprint = crypto.createHash('sha256').update(
            `${userAgent}-${ip}-${device.os?.name || 'unknown'}-${device.client?.name || 'unknown'}-${Date.now()}`
        ).digest('hex');

        const deviceInfo = {
            fingerprint,
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
                },
                isMobile: req.useragent.isMobile,
                isTablet: req.useragent.isTablet,
                isDesktop: req.useragent.isDesktop,
                isBot: req.useragent.isBot
            },
            location: {
                ip: geo.ip || ip,
                country: geo.country || 'Unknown',
                region: geo.region || 'Unknown',
                city: geo.city || 'Unknown',
                timezone: geo.timezone || 'UTC',
                coordinates: geo.loc ? {
                    latitude: parseFloat(geo.loc.split(',')[0]),
                    longitude: parseFloat(geo.loc.split(',')[1])
                } : null
            },
            lastLogin: new Date()
        };

        req.deviceInfo = deviceInfo;
        next();
    } catch (err) {
        console.error('Device info capture error:', err);
        // Fallback device info
        req.deviceInfo = {
            fingerprint: 'unknown',
            userAgent: req.headers['user-agent'] || '',
            ip: req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress,
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
                },
                isMobile: false,
                isTablet: false,
                isDesktop: true,
                isBot: false
            },
            location: {
                ip: req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress,
                country: 'Unknown',
                region: 'Unknown',
                city: 'Unknown',
                timezone: 'UTC',
                coordinates: null
            },
            lastLogin: new Date()
        };
        next();
    }
};

app.use(captureDeviceInfo);

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: {
        error: 'Too many requests from this IP, please try again later',
        status: 429
    },
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: {
        error: 'Too many login attempts, please try again later',
        status: 429
    },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', apiLimiter);
app.use('/api/v1/auth/login', authLimiter);
app.use('/api/v1/auth/signup', authLimiter);

// Database Models with enhanced validation
const UserSchema = new mongoose.Schema({
    email: { 
        type: String, 
        unique: true, 
        sparse: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    password: { 
        type: String,
        select: false,
        validate: {
            validator: function(v) {
                return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
            },
            message: props => 'Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character'
        }
    },
    walletAddress: { 
        type: String, 
        unique: true, 
        sparse: true,
        validate: {
            validator: function(v) {
                return /^(0x)?[0-9a-fA-F]{40}$/.test(v) || /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(v) || /^bc1[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$/.test(v);
            },
            message: props => `${props.value} is not a valid wallet address!`
        }
    },
    firstName: { 
        type: String, 
        required: false,
        trim: true,
        minlength: 2,
        maxlength: 50
    },
    lastName: { 
        type: String, 
        required: false,
        trim: true,
        minlength: 2,
        maxlength: 50
    },
    country: {
        type: String,
        required: false,
        trim: true
    },
    currency: { 
        type: String, 
        default: 'USD',
        enum: ['USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'BTC', 'ETH']
    },
    balance: { 
        type: Number, 
        default: 0,
        min: 0
    },
    kycStatus: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected', 'not_submitted'], 
        default: 'not_submitted' 
    },
    kycDocuments: [{
        documentType: { type: String, enum: ['passport', 'id_card', 'drivers_license'] },
        documentNumber: String,
        frontImage: String,
        backImage: String,
        selfie: String,
        submittedAt: Date,
        verifiedAt: Date,
        verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
    }],
    apiKey: { 
        type: String, 
        unique: true, 
        sparse: true,
        default: () => crypto.randomBytes(32).toString('hex')
    },
    isAdmin: { 
        type: Boolean, 
        default: false,
        select: false
    },
    emailVerified: { type: Boolean, default: false },
    twoFactorEnabled: { type: Boolean, default: false },
    lastLogin: Date,
    status: { 
        type: String, 
        enum: ['active', 'inactive', 'suspended', 'banned'], 
        default: 'active' 
    },
    ipWhitelist: [String],
    deviceInfo: [{
        fingerprint: String,
        userAgent: String,
        deviceType: String,
        os: String,
        browser: String,
        timestamp: Date,
        location: Object,
        isTrusted: { type: Boolean, default: false }
    }],
    loginHistory: [{
        timestamp: Date,
        ip: String,
        location: Object,
        device: Object,
        status: { type: String, enum: ['success', 'failed'] }
    }],
    securityQuestions: [{
        question: String,
        answer: { type: String, select: false }
    }]
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

const AdminSchema = new mongoose.Schema({
    email: { 
        type: String, 
        unique: true, 
        required: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    password: { 
        type: String, 
        required: true,
        select: false
    },
    permissions: {
        type: [String],
        enum: ['users', 'transactions', 'kyc', 'support', 'settings', 'all'],
        default: []
    },
    lastLogin: Date,
    loginHistory: [{
        timestamp: Date,
        ip: String,
        location: Object,
        device: Object
    }],
    isSuperAdmin: { type: Boolean, default: false }
}, { timestamps: true });

// Enhanced models with indexes
const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Initialize default admin if not exists
async function initializeAdmin() {
    try {
        const adminExists = await Admin.findOne({ email: 'admin@cryptotradingmarket.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.DEFAULT_ADMIN_PASSWORD || '17581758..', 12);
            await Admin.create({
                email: 'admin@cryptotradingmarket.com',
                password: hashedPassword,
                permissions: ['all'],
                isSuperAdmin: true
            });
            console.log('Default admin account created');
        }
    } catch (err) {
        console.error('Error initializing admin:', err);
    }
}

// Authentication Middleware with enhanced security
async function authenticate(req, res, next) {
    const token = req.cookies?.token || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.query.token;
    
    if (!token) {
        return res.status(401).json({ 
            success: false,
            error: 'Authentication token is required',
            code: 'AUTH_REQUIRED'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('+lastLogin +status +loginHistory +deviceInfo');
        
        if (!user) {
            return res.status(401).json({ 
                success: false,
                error: 'User account not found',
                code: 'USER_NOT_FOUND'
            });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ 
                success: false,
                error: 'Account is not active',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        // Check if the device is trusted
        const currentDevice = req.deviceInfo;
        const trustedDevice = user.deviceInfo.some(device => 
            device.fingerprint === currentDevice.fingerprint && device.isTrusted
        );

        if (!trustedDevice && user.twoFactorEnabled) {
            return res.status(403).json({ 
                success: false,
                error: 'Device verification required',
                code: 'DEVICE_VERIFICATION_REQUIRED',
                requires2FA: true
            });
        }

        // Update last login and add to login history
        user.lastLogin = new Date();
        user.loginHistory.push({
            timestamp: new Date(),
            ip: currentDevice.ip,
            location: currentDevice.location,
            device: currentDevice.device,
            status: 'success'
        });
        await user.save();

        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false,
                error: 'Session expired, please login again',
                code: 'TOKEN_EXPIRED'
            });
        }
        return res.status(401).json({ 
            success: false,
            error: 'Invalid or malformed token',
            code: 'INVALID_TOKEN'
        });
    }
}

async function authenticateAdmin(req, res, next) {
    const token = req.cookies?.adminToken || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.query.token;
    
    if (!token) {
        return res.status(401).json({ 
            success: false,
            error: 'Admin authentication required',
            code: 'ADMIN_AUTH_REQUIRED'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = await Admin.findOne({ _id: decoded.userId, email: decoded.email })
                               .select('+lastLogin +loginHistory +permissions');
        
        if (!admin) {
            return res.status(401).json({ 
                success: false,
                error: 'Admin account not found',
                code: 'ADMIN_NOT_FOUND'
            });
        }

        // Update last login and add to login history
        admin.lastLogin = new Date();
        admin.loginHistory.push({
            timestamp: new Date(),
            ip: req.deviceInfo.ip,
            location: req.deviceInfo.location,
            device: req.deviceInfo.device
        });
        await admin.save();

        req.admin = admin;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false,
                error: 'Admin session expired, please login again',
                code: 'ADMIN_TOKEN_EXPIRED'
            });
        }
        return res.status(401).json({ 
            success: false,
            error: 'Invalid admin token',
            code: 'INVALID_ADMIN_TOKEN'
        });
    }
}

// Enhanced Auth Routes with proper error handling
app.post('/api/v1/auth/signup', async (req, res) => {
    try {
        const { email, password, firstName, lastName, country, currency, confirmPassword } = req.body;

        // Validate all required fields
        if (!email || !password || !firstName || !lastName || !country || !currency || !confirmPassword) {
            return res.status(400).json({ 
                success: false,
                error: 'All fields are required',
                code: 'MISSING_FIELDS'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false,
                error: 'Passwords do not match',
                code: 'PASSWORD_MISMATCH'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid email format',
                code: 'INVALID_EMAIL'
            });
        }

        // Validate password strength
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                success: false,
                error: 'Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character',
                code: 'WEAK_PASSWORD'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ 
                success: false,
                error: 'Email already in use',
                code: 'EMAIL_EXISTS'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
        const user = await User.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            country,
            currency,
            deviceInfo: [req.deviceInfo],
            loginHistory: [{
                timestamp: new Date(),
                ip: req.deviceInfo.ip,
                location: req.deviceInfo.location,
                device: req.deviceInfo.device,
                status: 'success'
            }]
        });

        // Generate JWT token
        const token = jwt.sign({ 
            userId: user._id, 
            email: user.email 
        }, JWT_SECRET, { 
            expiresIn: '7d' 
        });

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });

        // Send verification email
        try {
            const verificationToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
            const verificationLink = `https://website-7t25.vercel.app/verify-email?token=${verificationToken}`;
            
            await transporter.sendMail({
                from: `"Crypto Trading Market" <${process.env.EMAIL_FROM || 'support@cryptotradingmarket.com'}>`,
                to: user.email,
                subject: 'Verify Your Email Address',
                html: `
                    <p>Welcome to Crypto Trading Market, ${firstName}!</p>
                    <p>Please click the link below to verify your email address:</p>
                    <p><a href="${verificationLink}">Verify Email</a></p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't create an account, please ignore this email.</p>
                `
            });
        } catch (emailError) {
            console.error('Error sending verification email:', emailError);
        }

        // Return success response
        return res.status(201).json({
            success: true,
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus,
                emailVerified: user.emailVerified
            }
        });

    } catch (err) {
        console.error('Signup error:', err);
        
        if (err.code === 11000) {
            return res.status(409).json({ 
                success: false,
                error: 'Email already in use',
                code: 'DUPLICATE_EMAIL'
            });
        }
        
        if (err.name === 'ValidationError') {
            const errors = Object.values(err.errors).map(el => el.message);
            return res.status(400).json({ 
                success: false,
                error: errors.join(', '),
                code: 'VALIDATION_ERROR'
            });
        }
        
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error during signup',
            code: 'SERVER_ERROR'
        });
    }
});

app.post('/api/v1/auth/wallet-signup', async (req, res) => {
    try {
        const { walletAddress, signature, walletProvider, message } = req.body;

        if (!walletAddress || !walletProvider) {
            return res.status(400).json({
                success: false,
                error: 'Wallet address and provider are required',
                code: 'MISSING_WALLET_DATA'
            });
        }

        let normalizedAddress;
        try {
            normalizedAddress = ethers.utils.getAddress(walletAddress);
        } catch (err) {
            return res.status(400).json({
                success: false,
                error: 'Invalid wallet address format',
                code: 'INVALID_WALLET_ADDRESS'
            });
        }

        if (signature && message) {
            try {
                const recoveredAddress = ethers.utils.verifyMessage(message, signature);
                if (recoveredAddress.toLowerCase() !== normalizedAddress.toLowerCase()) {
                    return res.status(401).json({
                        success: false,
                        error: 'Signature verification failed',
                        code: 'SIGNATURE_MISMATCH'
                    });
                }
            } catch (sigError) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid signature format',
                    code: 'INVALID_SIGNATURE'
                });
            }
        }

        const existingUser = await User.findOne({ walletAddress: normalizedAddress });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Wallet address already registered',
                code: 'WALLET_EXISTS'
            });
        }

        const user = await User.create({
            walletAddress: normalizedAddress,
            walletProvider,
            firstName: 'Wallet',
            lastName: 'User',
            country: req.deviceInfo.location.country || 'Unknown',
            currency: 'USD',
            balance: 0,
            isVerified: true,
            status: 'active',
            email: `${normalizedAddress}@walletuser.com`,
            deviceInfo: [{
                ...req.deviceInfo,
                isTrusted: true
            }],
            loginHistory: [{
                timestamp: new Date(),
                ip: req.deviceInfo.ip,
                location: req.deviceInfo.location,
                device: req.deviceInfo.device,
                status: 'success'
            }]
        });

        const token = jwt.sign(
            {
                userId: user._id,
                walletAddress: user.walletAddress,
                isVerified: user.isVerified
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });

        return res.status(201).json({
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
        
        if (err.code === 11000) {
            return res.status(409).json({
                success: false,
                error: 'Wallet address already registered',
                code: 'DUPLICATE_WALLET'
            });
        }
        
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            code: 'WALLET_SIGNUP_ERROR'
        });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        const user = await User.findOne({ email }).select('+password +status +loginHistory +deviceInfo');
        if (!user) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        if (!user.password) {
            return res.status(401).json({ 
                success: false,
                error: 'Please use wallet login or reset your password',
                code: 'WALLET_LOGIN_REQUIRED'
            });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ 
                success: false,
                error: 'Account is not active',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // Log failed login attempt
            user.loginHistory.push({
                timestamp: new Date(),
                ip: req.deviceInfo.ip,
                location: req.deviceInfo.location,
                device: req.deviceInfo.device,
                status: 'failed'
            });
            await user.save();
            
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Check if device is trusted
        const currentDevice = req.deviceInfo;
        const trustedDevice = user.deviceInfo.some(device => 
            device.fingerprint === currentDevice.fingerprint && device.isTrusted
        );

        // If 2FA is enabled and device is not trusted, require verification
        if (user.twoFactorEnabled && !trustedDevice) {
            return res.status(403).json({ 
                success: false,
                error: 'Device verification required',
                code: 'DEVICE_VERIFICATION_REQUIRED',
                requires2FA: true
            });
        }

        // Generate JWT token
        const token = jwt.sign({ 
            userId: user._id, 
            email: user.email 
        }, JWT_SECRET, { 
            expiresIn: '7d' 
        });

        // Update last login and device info
        user.lastLogin = new Date();
        
        // If device not in deviceInfo, add it
        const deviceExists = user.deviceInfo.some(device => 
            device.fingerprint === currentDevice.fingerprint
        );
        
        if (!deviceExists) {
            user.deviceInfo.push({
                ...currentDevice,
                isTrusted: false
            });
        }

        // Add to login history
        user.loginHistory.push({
            timestamp: new Date(),
            ip: currentDevice.ip,
            location: currentDevice.location,
            device: currentDevice.device,
            status: 'success'
        });

        await user.save();

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });

        return res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                balance: user.balance,
                kycStatus: user.kycStatus,
                emailVerified: user.emailVerified,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error during login',
            code: 'LOGIN_ERROR'
        });
    }
});

app.post('/api/v1/auth/wallet-login', async (req, res) => {
    try {
        const { walletAddress, signature, walletType, message } = req.body;

        if (!walletAddress || !walletType) {
            return res.status(400).json({ 
                success: false,
                error: 'Wallet address and type are required',
                code: 'MISSING_WALLET_DATA'
            });
        }

        let normalizedAddress;
        try {
            normalizedAddress = ethers.utils.getAddress(walletAddress);
        } catch (err) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid wallet address format',
                code: 'INVALID_WALLET_ADDRESS'
            });
        }

        if (signature && message) {
            try {
                const recoveredAddress = ethers.utils.verifyMessage(message, signature);
                if (recoveredAddress.toLowerCase() !== normalizedAddress.toLowerCase()) {
                    return res.status(401).json({ 
                        success: false,
                        error: 'Signature verification failed',
                        code: 'SIGNATURE_MISMATCH'
                    });
                }
            } catch (sigError) {
                return res.status(401).json({ 
                    success: false,
                    error: 'Invalid signature format',
                    code: 'INVALID_SIGNATURE'
                });
            }
        }

        const user = await User.findOne({ walletAddress: normalizedAddress })
                             .select('+loginHistory +deviceInfo +status');
        if (!user) {
            return res.status(404).json({ 
                success: false,
                error: 'Wallet not registered. Please sign up first.',
                code: 'WALLET_NOT_REGISTERED'
            });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ 
                success: false,
                error: 'Account is not active',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        // Check if device is trusted
        const currentDevice = req.deviceInfo;
        const trustedDevice = user.deviceInfo.some(device => 
            device.fingerprint === currentDevice.fingerprint && device.isTrusted
        );

        // If 2FA is enabled and device is not trusted, require verification
        if (user.twoFactorEnabled && !trustedDevice) {
            return res.status(403).json({ 
                success: false,
                error: 'Device verification required',
                code: 'DEVICE_VERIFICATION_REQUIRED',
                requires2FA: true
            });
        }

        // Generate JWT token
        const token = jwt.sign({ 
            userId: user._id, 
            walletAddress: user.walletAddress 
        }, JWT_SECRET, { 
            expiresIn: '7d' 
        });

        // Update last login and device info
        user.lastLogin = new Date();
        
        // If device not in deviceInfo, add it
        const deviceExists = user.deviceInfo.some(device => 
            device.fingerprint === currentDevice.fingerprint
        );
        
        if (!deviceExists) {
            user.deviceInfo.push({
                ...currentDevice,
                isTrusted: false
            });
        }

        // Add to login history
        user.loginHistory.push({
            timestamp: new Date(),
            ip: currentDevice.ip,
            location: currentDevice.location,
            device: currentDevice.device,
            status: 'success'
        });

        await user.save();

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });

        return res.json({
            success: true,
            message: 'Wallet login successful',
            token,
            user: {
                id: user._id,
                walletAddress: user.walletAddress,
                isVerified: user.isVerified,
                balance: user.balance,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });
    } catch (err) {
        console.error('Wallet login error:', err);
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error during wallet login',
            code: 'WALLET_LOGIN_ERROR'
        });
    }
});

app.post('/api/v1/auth/logout', authenticate, async (req, res) => {
    try {
        // Clear the token cookie
        res.clearCookie('token', {
            domain: process.env.COOKIE_DOMAIN || undefined
        });
        
        return res.json({ 
            success: true,
            message: 'Logout successful' 
        });
    } catch (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error during logout',
            code: 'LOGOUT_ERROR'
        });
    }
});

// Admin Auth Routes
app.post('/api/v1/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        const admin = await Admin.findOne({ email }).select('+password +loginHistory');
        if (!admin) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            // Log failed login attempt
            admin.loginHistory.push({
                timestamp: new Date(),
                ip: req.deviceInfo.ip,
                location: req.deviceInfo.location,
                device: req.deviceInfo.device
            });
            await admin.save();
            
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Generate JWT token
        const token = jwt.sign({ 
            userId: admin._id, 
            email: admin.email,
            isAdmin: true,
            permissions: admin.permissions
        }, JWT_SECRET, { 
            expiresIn: '8h' // Shorter session for admin
        });

        // Update last login
        admin.lastLogin = new Date();
        admin.loginHistory.push({
            timestamp: new Date(),
            ip: req.deviceInfo.ip,
            location: req.deviceInfo.location,
            device: req.deviceInfo.device
        });
        await admin.save();

        // Set secure cookie
        res.cookie('adminToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 8 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });

        return res.json({
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
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error during admin login',
            code: 'ADMIN_LOGIN_ERROR'
        });
    }
});

// WebSocket Server for real-time updates
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

        ws.on('error', (err) => {
            console.error('WebSocket error:', err);
            clients.delete(decoded.userId);
        });

        ws.send(JSON.stringify({ 
            type: 'connection_success',
            timestamp: new Date().toISOString()
        }));
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

        ws.on('error', (err) => {
            console.error('Admin WebSocket error:', err);
            adminClients.delete(decoded.userId);
        });

        ws.send(JSON.stringify({ 
            type: 'connection_success', 
            message: 'Admin WebSocket connection established',
            timestamp: new Date().toISOString()
        }));
    } catch (err) {
        ws.close(1008, 'Invalid token');
    }
});

// Helper Functions
function notifyUser(userId, message) {
    const ws = clients.get(userId);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            ...message,
            timestamp: new Date().toISOString()
        }));
    }
}

function notifyAdmins(message) {
    adminClients.forEach(ws => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                ...message,
                timestamp: new Date().toISOString()
            }));
        }
    });
}

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Global error handler:', err.stack);
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: 'Validation error',
            details: err.errors,
            code: 'VALIDATION_ERROR'
        });
    }
    
    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(409).json({
            success: false,
            error: 'Duplicate key error',
            code: 'DUPLICATE_KEY'
        });
    }
    
    return res.status(500).json({
        success: false,
        error: 'Internal server error',
        code: 'INTERNAL_SERVER_ERROR'
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        code: 'ENDPOINT_NOT_FOUND'
    });
});

// Start Server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    initializeAdmin();
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
    
    // Close WebSocket servers
    wss.clients.forEach(client => client.close());
    adminWss.clients.forEach(client => client.close());
    
    // Close HTTP server
    server.close(() => {
        console.log('HTTP server closed');
        
        // Close MongoDB connection
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed');
            process.exit(0);
        });
    });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});
