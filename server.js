// server.js — CaribPay backend (MongoDB + Auth)
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();

/* ------------ Middleware ------------ */
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));
app.use(express.json());

/* ------------ Config ------------ */
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const MONGO_URI = process.env.MONGO_URI;

/* ------------ MongoDB ------------ */
if (!MONGO_URI) {
  console.error('❌ Missing MONGO_URI env var. Set it in Render.');
}

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err.message));

/* ------------ Models ------------ */
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

/* ------------ Helpers ------------ */
function isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').toLowerCase());
}
function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 6;
}
function issueToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

/* ------------ Routes ------------ */

// Health checks (Render can hit these)
app.get('/', (_req, res) => res.status(200).send('CaribPay backend is running ✅'));
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

// Register new user
app.post('/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = (email || '').trim().toLowerCase();

    if (!isValidEmail(email)) return res.status(400).json({ message: 'Invalid email address' });
    if (!isValidPassword(password)) return res.status(400).json({ message: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });

    const token = issueToken(user);
    return res.status(201).json({ token, user: { id: user._id, email: user.email } });
  } catch (e) {
    console.error('Register error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Login user
app.post('/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = (email || '').trim().toLowerCase();

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password || '', user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = issueToken(user);
    return res.json({ token, user: { id: user._id, email: user.email } });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Get current user (requires token)
app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('_id email');
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ id: user._id, email: user.email });
  } catch (e) {
    return res.status(500).json({ message: 'Server error' });
  }
});

/* ------------ Start server (Render needs 0.0.0.0 + dynamic PORT) ------------ */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
