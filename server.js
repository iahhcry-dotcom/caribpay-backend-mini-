const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');

dotenv.config();
const app = express();

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.use(express.json());

// ===== In-memory users (temporary; resets on deploy) =====
const USERS = [];

// Seed a demo user (email: demo@caribpay.com, password: demo123)
(async () => {
  const email = 'demo@caribpay.com';
  if (!USERS.find(u => u.email === email)) {
    const hash = await bcrypt.hash('demo123', 10);
    USERS.push({ id: 'u1', email, passwordHash: hash });
  }
})();

// ===== Helpers =====
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

function isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').toLowerCase());
}

function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 6;
}

// Health check
app.get('/', (_req, res) => res.status(200).send('CaribPay backend is running ✅'));

// ===== NEW: Register =====
app.post('/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = (email || '').trim().toLowerCase();

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Invalid email address' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    if (USERS.find(u => u.email === email)) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { id: uuid(), email, passwordHash };
    USERS.push(user);

    const token = issueToken(user);
    return res.status(201).json({ token, user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error('Register error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// ===== Login (bcrypt compare) =====
app.post('/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = (email || '').trim().toLowerCase();

    const user = USERS.find(u => u.email === email);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password || '', user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = issueToken(user);
    return res.json({ token, user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// ===== Me =====
app.get('/auth/me', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ id: payload.sub, email: payload.email });
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
});

// Start (Render port)
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
