require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://mosesmwainaina1994:OWlondlAbn3bJuj4@cluster0.edyueep.mongodb.net/crypto_trading?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: ['https://website-xi-ten-52.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  country: { type: String, required: true },
  currency: { type: String, default: 'USD' },
  walletAddress: { type: String },
  walletProvider: { type: String },
  balance: { type: Number, default: 0 },
  verified: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['none', 'pending', 'verified', 'rejected'], default: 'none' },
  kycDocuments: [{
    type: { type: String, enum: ['passport', 'id', 'driver'] },
    front: String,
    back: String
  }],
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));

const Trade = mongoose.model('Trade', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromCoin: { type: String, required: true },
  toCoin: { type: String, required: true },
  amount: { type: Number, required: true },
  rate: { type: Number, required: true },
  result: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'trade'], required: true },
  amount: { type: Number, required: true },
  coin: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  txHash: { type: String },
  address: { type: String },
  createdAt: { type: Date, default: Date.now }
}));

const SupportTicket = mongoose.model('SupportTicket', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in-progress', 'resolved'], default: 'open' },
  attachments: [String],
  responses: [{
    message: String,
    from: { type: String, enum: ['user', 'support'] },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

const Coin = mongoose.model('Coin', new mongoose.Schema({
  coinId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  symbol: { type: String, required: true },
  current_price: { type: Number, required: true },
  price_change_percentage_24h: { type: Number, required: true },
  image: { type: String, required: true },
  lastUpdated: { type: Date, default: Date.now }
}));

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

// Helper functions
const generateToken = (userId, role = 'user') => {
  return jwt.sign({ id: userId, role }, JWT_SECRET, { expiresIn: '30d' });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const updateCoinPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
      params: {
        vs_currency: 'usd',
        order: 'market_cap_desc',
        per_page: 100,
        page: 1,
        sparkline: false
      }
    });

    const coins = response.data;
    const updatePromises = coins.map(coin => {
      return Coin.findOneAndUpdate(
        { coinId: coin.id },
        {
          name: coin.name,
          symbol: coin.symbol,
          current_price: coin.current_price,
          price_change_percentage_24h: coin.price_change_percentage_24h,
          image: coin.image,
          lastUpdated: new Date()
        },
        { upsert: true, new: true }
      );
    });

    await Promise.all(updatePromises);
    console.log('Coin prices updated');
  } catch (err) {
    console.error('Error updating coin prices:', err.message);
  }
};

// Initialize coin prices and update every 5 minutes
updateCoinPrices();
setInterval(updateCoinPrices, 5 * 60 * 1000);

// WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'auth' && data.token) {
        const decoded = verifyToken(data.token);
        if (decoded) {
          ws.userId = decoded.id;
          ws.role = decoded.role;
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
    if (client.readyState === WebSocket.OPEN && client.role === 'admin') {
      client.send(JSON.stringify(data));
    }
  });
};

// Routes
app.get('/', (req, res) => {
  res.send('Crypto Trading Platform API');
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
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      currency,
      verified: true // Skip email verification as requested
    });

    await user.save();

    const token = generateToken(user._id);
    res.status(201).json({ token, user: { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.role);
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName, 
        role: user.role,
        balance: user.balance,
        verified: user.verified
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Admin login endpoint
app.post('/api/v1/auth/admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, role: 'admin' });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.role);
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName, 
        role: user.role 
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});

app.post('/api/v1/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: 'Token is required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      valid: true, 
      user: { 
        id: user._id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName, 
        role: user.role,
        balance: user.balance,
        verified: user.verified
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during token verification' });
  }
});

app.post('/api/v1/auth/check', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      valid: true, 
      user: { 
        id: user._id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName, 
        role: user.role,
        balance: user.balance,
        verified: user.verified
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during token check' });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Return success even if email doesn't exist to prevent email enumeration
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent' });
    }

    const resetToken = uuidv4();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `https://website-xi-ten-52.vercel.app/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      to: user.email,
      from: 'no-reply@cryptotrading.com',
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your Crypto Trading account.</p>
        <p>Click <a href="${resetUrl}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'If an account with that email exists, a password reset link has been sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset request' });
  }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;

    const user = await User.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(password, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// User Routes
app.get('/api/v1/users/me', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      country: user.country,
      currency: user.currency,
      balance: user.balance,
      verified: user.verified,
      kycStatus: user.kycStatus,
      createdAt: user.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching user data' });
  }
});

app.patch('/api/v1/users/update', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { firstName, lastName, country, currency } = req.body;
    const updates = {};

    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (country) updates.country = country;
    if (currency) updates.currency = currency;

    const user = await User.findByIdAndUpdate(decoded.id, updates, { new: true });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      country: user.country,
      currency: user.currency
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user data' });
  }
});

app.patch('/api/v1/users/update-password', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating password' });
  }
});

app.post('/api/v1/users/kyc', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { documentType, frontImage, backImage } = req.body;

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.kycStatus = 'pending';
    user.kycDocuments = user.kycDocuments.filter(doc => doc.type !== documentType);
    user.kycDocuments.push({
      type: documentType,
      front: frontImage,
      back: backImage
    });

    await user.save();

    // Notify admins
    broadcastToAdmins({
      type: 'KYC_SUBMITTED',
      userId: user._id,
      email: user.email,
      name: `${user.firstName} ${user.lastName}`
    });

    res.json({ message: 'KYC documents submitted for review', kycStatus: user.kycStatus });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error submitting KYC documents' });
  }
});

// Trade Routes
app.get('/api/v1/market/data', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ market_cap_rank: 1 }).limit(50);
    res.json(coins);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching market data' });
  }
});

app.get('/api/v1/exchange/coins', async (req, res) => {
  try {
    const coins = await Coin.find().sort({ market_cap_rank: 1 });
    res.json(coins.map(coin => ({
      id: coin.coinId,
      symbol: coin.symbol,
      name: coin.name,
      image: coin.image,
      price: coin.current_price
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching coins' });
  }
});

app.get('/api/v1/exchange/rates', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    if (!from || !to) {
      return res.status(400).json({ message: 'Both from and to parameters are required' });
    }

    const fromCoin = await Coin.findOne({ coinId: from });
    const toCoin = await Coin.findOne({ coinId: to });

    if (!fromCoin || !toCoin) {
      return res.status(404).json({ message: 'One or both coins not found' });
    }

    const rate = toCoin.current_price / fromCoin.current_price;
    res.json({ from: fromCoin.symbol, to: toCoin.symbol, rate });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching exchange rates' });
  }
});

app.post('/api/v1/exchange/convert', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid parameters' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // In a real app, you would check if the user has enough balance in 'from' currency
    // For this demo, we'll assume they're converting from a coin they own

    const fromCoin = await Coin.findOne({ coinId: from });
    const toCoin = await Coin.findOne({ coinId: to });

    if (!fromCoin || !toCoin) {
      return res.status(404).json({ message: 'One or both coins not found' });
    }

    const rate = toCoin.current_price / fromCoin.current_price;
    const result = amount * rate;

    // Create trade record
    const trade = new Trade({
      userId: user._id,
      fromCoin: fromCoin.symbol,
      toCoin: toCoin.symbol,
      amount,
      rate,
      result,
      status: 'completed'
    });

    await trade.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'trade',
      amount,
      coin: fromCoin.symbol,
      status: 'completed',
      txHash: `trade-${trade._id}`
    });

    await transaction.save();

    // Broadcast balance update
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({
      from: fromCoin.symbol,
      to: toCoin.symbol,
      amount,
      rate,
      result,
      transactionId: transaction._id
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during conversion' });
  }
});

app.get('/api/v1/exchange/history', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const trades = await Trade.find({ userId: decoded.id }).sort({ createdAt: -1 }).limit(20);
    res.json(trades);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching trade history' });
  }
});

app.get('/api/v1/trades/active', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const trades = await Trade.find({ 
      userId: decoded.id,
      status: 'pending'
    }).sort({ createdAt: -1 });

    res.json(trades);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching active trades' });
  }
});

app.get('/api/v1/transactions/recent', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const transactions = await Transaction.find({ 
      userId: decoded.id 
    }).sort({ createdAt: -1 }).limit(10);

    res.json(transactions);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching transactions' });
  }
});

// Portfolio Routes
app.get('/api/v1/portfolio', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // In a real app, you would fetch the user's actual portfolio holdings
    // For this demo, we'll return a mock portfolio
    const coins = await Coin.find().limit(5);
    const portfolio = coins.map(coin => ({
      coin: coin.symbol,
      name: coin.name,
      amount: Math.random() * 10,
      value: Math.random() * 10 * coin.current_price,
      image: coin.image
    }));

    res.json({
      balance: user.balance,
      portfolio
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching portfolio' });
  }
});

// Support Routes
app.post('/api/v1/support', async (req, res) => {
  try {
    const { email, subject, message, attachments = [] } = req.body;

    if (!email || !subject || !message) {
      return res.status(400).json({ message: 'Email, subject and message are required' });
    }

    let userId = null;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      const decoded = verifyToken(token);
      if (decoded) {
        userId = decoded.id;
      }
    }

    const ticket = new SupportTicket({
      userId,
      email,
      subject,
      message,
      attachments,
      responses: [{
        message,
        from: 'user'
      }]
    });

    await ticket.save();

    // Notify admins
    broadcastToAdmins({
      type: 'NEW_SUPPORT_TICKET',
      ticketId: ticket._id,
      subject: ticket.subject,
      email: ticket.email
    });

    res.json({ 
      message: 'Support ticket created successfully',
      ticketId: ticket._id
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating support ticket' });
  }
});

app.get('/api/v1/support/tickets', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const tickets = await SupportTicket.find({ 
      userId: decoded.id 
    }).sort({ createdAt: -1 });

    res.json(tickets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching support tickets' });
  }
});

app.get('/api/v1/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        category: 'Account',
        questions: [
          {
            question: 'How do I create an account?',
            answer: 'Click on the "Sign Up" button and fill in the required information to create your account.'
          },
          {
            question: 'How do I verify my email?',
            answer: 'After signing up, you will receive an email with a verification link. Click on the link to verify your email address.'
          }
        ]
      },
      {
        category: 'Trading',
        questions: [
          {
            question: 'How do I buy cryptocurrencies?',
            answer: 'Navigate to the "Trade" section, select the cryptocurrency you want to buy, enter the amount, and confirm the transaction.'
          },
          {
            question: 'What are the trading fees?',
            answer: 'Our trading fee is 0.1% per trade. There may be additional network fees for blockchain transactions.'
          }
        ]
      },
      {
        category: 'Deposits & Withdrawals',
        questions: [
          {
            question: 'How do I deposit funds?',
            answer: 'Go to the "Wallet" section, click on "Deposit", select the cryptocurrency, and follow the instructions to send funds to your deposit address.'
          },
          {
            question: 'How long do withdrawals take?',
            answer: 'Withdrawal processing times vary by cryptocurrency. Most withdrawals are processed within 30 minutes, but some may take longer depending on network congestion.'
          }
        ]
      }
    ];

    res.json(faqs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching FAQs' });
  }
});

// Admin Routes
app.get('/api/v1/admin/dashboard-stats', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ verified: true });
    const totalTrades = await Trade.countDocuments();
    const totalVolume = await Trade.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    const pendingTickets = await SupportTicket.countDocuments({ status: 'open' });
    const pendingKYC = await User.countDocuments({ kycStatus: 'pending' });

    res.json({
      totalUsers,
      verifiedUsers,
      totalTrades,
      totalVolume: totalVolume[0]?.total || 0,
      pendingTickets,
      pendingKYC
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching admin stats' });
  }
});

app.get('/api/v1/admin/users', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const users = await User.find().sort({ createdAt: -1 });
    res.json(users.map(user => ({
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      country: user.country,
      balance: user.balance,
      verified: user.verified,
      kycStatus: user.kycStatus,
      createdAt: user.createdAt
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

app.patch('/api/v1/admin/users/:id/balance', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { amount } = req.body;
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.balance = amount;
    await user.save();

    // Broadcast balance update to user
    broadcastToUser(user._id, {
      type: 'BALANCE_UPDATE',
      balance: user.balance
    });

    res.json({ message: 'User balance updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating user balance' });
  }
});

app.patch('/api/v1/admin/users/:id/kyc', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { status } = req.body;
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid KYC status' });
    }

    user.kycStatus = status;
    await user.save();

    // Notify user
    broadcastToUser(user._id, {
      type: 'KYC_STATUS_UPDATE',
      status: user.kycStatus
    });

    res.json({ message: 'KYC status updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating KYC status' });
  }
});

app.get('/api/v1/admin/trades', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const trades = await Trade.find().populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
    res.json(trades);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching trades' });
  }
});

app.get('/api/v1/admin/transactions', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const transactions = await Transaction.find().populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
    res.json(transactions);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching transactions' });
  }
});

app.get('/api/v1/admin/tickets', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const tickets = await SupportTicket.find().populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching support tickets' });
  }
});

app.patch('/api/v1/admin/tickets/:id/status', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { status } = req.body;
    const ticketId = req.params.id;

    const ticket = await SupportTicket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    if (!['open', 'in-progress', 'resolved'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    ticket.status = status;
    await ticket.save();

    if (ticket.userId) {
      broadcastToUser(ticket.userId, {
        type: 'TICKET_STATUS_UPDATE',
        ticketId: ticket._id,
        status: ticket.status
      });
    }

    res.json({ message: 'Ticket status updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating ticket status' });
  }
});

app.post('/api/v1/admin/tickets/:id/reply', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { message } = req.body;
    const ticketId = req.params.id;

    const ticket = await SupportTicket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    ticket.responses.push({
      message,
      from: 'support'
    });

    ticket.status = 'in-progress';
    await ticket.save();

    if (ticket.userId) {
      broadcastToUser(ticket.userId, {
        type: 'TICKET_REPLY',
        ticketId: ticket._id,
        message
      });
    }

    res.json({ message: 'Reply added successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error adding reply' });
  }
});

// Initialize admin user if not exists
const initAdmin = async () => {
  try {
    const adminEmail = 'admin@cryptotrading.com';
    const adminPassword = 'Admin@1234';
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      const admin = new User({
        firstName: 'Admin',
        lastName: 'User',
        email: adminEmail,
        password: hashedPassword,
        country: 'US',
        currency: 'USD',
        role: 'admin',
        verified: true
      });
      await admin.save();
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Error initializing admin:', err);
  }
};

initAdmin();
