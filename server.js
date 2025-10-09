// server.js — CaribPay backend (no JSX)
// Run with: node server.js

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ===== Env & constants
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

if (!MONGO_URI) {
  console.error('❌ Missing MONGO_URI env var');
  process.exit(1);
}

// ===== Mongo connection
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ===== User model
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true }
  },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema);

// ===== Helpers
function signToken(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '7d' });
}

// ===== Health routes
app.get('/', (_req, res) => res.status(200).send('CaribPay backend is live'));
app.get('/api/auth/test', (_req, res) => res.json({ ok: true, service: 'caribpay-backend' }));

// ===== Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, passwordHash });
    const token = signToken(newUser._id);
    return res.json({ token });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });

    const token = signToken(user._id);
    return res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Start server
app.listen(PORT, () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
