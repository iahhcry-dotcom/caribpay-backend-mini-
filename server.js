// server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// --- Config ---
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const MONGO_URI = process.env.MONGO_URI;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Mongoose ---
mongoose
  .connect(MONGO_URI, { dbName: 'caribpay' })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// --- User Model ---
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema);

// --- Utility: auth middleware ---
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { sub, email, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// --- Routes ---
app.get('/', (_req, res) => res.send('CaribPay backend is live'));

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    time: new Date().toISOString(),
  });
});

// Register
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ message: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash });

    const token = jwt.sign({ sub: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { email: user.email } });
  } catch (err) {
    next(err);
  }
});

// Login
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ sub: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { email: user.email } });
  } catch (err) {
    next(err);
  }
});

// Me (auto-login)
app.get('/api/auth/me', authRequired, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub).select('email');
    if (!user) return res.status(401).json({ message: 'User not found' });
    res.json({ user: { email: user.email } });
  } catch (err) {
    next(err);
  }
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Server error', detail: err.message });
});

// Start
app.listen(PORT, '0.0.0.0', () => {
  console.log(`CaribPay backend running on port ${PORT}`);
});
