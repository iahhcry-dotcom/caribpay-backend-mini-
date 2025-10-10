// server.js
// CaribPay backend – Express + MongoDB + JWT
// Works on Render.com. Port defaults to 10000 for your service.

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

// --- Security / middlewares
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(
  cors({
    origin: [
      'https://snack.expo.dev',
      'https://*.snack.expo.dev',
      'https://expo.dev',
      'http://localhost:19006',
      'http://localhost:19000',
      'http://localhost:8081',
      'http://localhost:3000',
      /\.onrender\.com$/,
    ],
    credentials: false,
  })
);
app.use(morgan('tiny'));

// --- DB
mongoose
  .connect(MONGO_URI, { dbName: 'caribpay' })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// --- Models
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: 'users' }
);

const User = mongoose.model('User', userSchema);

// --- Helpers
function signToken(user) {
  return jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes

// Health root (Render checks this)
app.get('/', (_req, res) => {
  res.json({ ok: true, name: 'CaribPay API', ts: Date.now() });
});

// Simple connectivity check for your Snack toggle
app.get('/api/debug', (_req, res) => {
  res.json({ ok: true, message: 'API reachable' });
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    email = String(email).toLowerCase().trim();
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    const token = signToken(user);

    return res.status(201).json({ token, user: { email: user.email } });
  } catch (e) {
    console.error('Register error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    email = String(email).toLowerCase().trim();
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken(user);
    return res.json({ token, user: { email: user.email } });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.uid).select('email createdAt');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// (Optional) change password
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both currentPassword and newPassword are required' });
    }
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password too short' });

    const user = await User.findById(req.user.uid);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Current password incorrect' });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ ok: true });
  } catch (e) {
    console.error('Change password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// 404
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => {
  console.log(`CaribPay backend running on port ${PORT}`);
});
