// server.js – CaribPay backend (secure)
// Features: Email validation, rate limiting, password reset via email

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// ====== CONFIG ======
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const APP_NAME = 'CaribPay';
const CLIENT_ORIGINS = [
  'https://snack.expo.dev',
  'https://*.snack.expo.dev',
  'https://expo.dev',
  'http://localhost:19006',
  'http://localhost:19000',
  'http://localhost:8081',
  'http://localhost:3000',
];

// Email sender (Nodemailer) – use any SMTP provider
// Required envs: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false, // true for 465; false for 587/STARTTLS
  auth: process.env.SMTP_USER
    ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    : undefined,
});

// ====== SECURITY / MIDDLEWARE ======
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (CLIENT_ORIGINS.some((o) => origin.startsWith(o.replace('*.', '')))) return cb(null, true);
      if (/\.onrender\.com$/.test(new URL(origin).hostname)) return cb(null, true);
      return cb(null, true); // be permissive for mobile debug
    },
    credentials: false,
  })
);

app.use(morgan('tiny'));

// Global rate limit: 100 req / 15 min per IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

// Tighter limit for auth endpoints: 10 req / 10 min per IP
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Please wait and try again.' },
});
app.use('/api/auth', authLimiter);

// ====== DB ======
mongoose
  .connect(MONGO_URI, { dbName: 'caribpay' })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// ====== MODELS ======
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    // password reset
    resetTokenHash: String,
    resetTokenExp: Date,
    createdAt: { type: Date, default: Date.now },
  },
  { collection: 'users' }
);

const User = mongoose.model('User', userSchema);

// ====== HELPERS ======
const EMAIL_RE =
  /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;

function validEmail(email) {
  return EMAIL_RE.test(String(email || '').trim());
}

function strongEnough(pw) {
  // at least 6 chars; recommend 1 letter + 1 digit
  return typeof pw === 'string' && pw.length >= 6;
}

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

async function sendMail(to, subject, html) {
  if (!process.env.SMTP_HOST) {
    console.warn('SMTP not configured; skipping email send.');
    return;
  }
  const from = process.env.MAIL_FROM || `${APP_NAME} <no-reply@caribpay.local>`;
  await transporter.sendMail({ from, to, subject, html });
}

// ====== ROUTES ======
app.get('/', (_req, res) => res.json({ ok: true, name: `${APP_NAME} API`, ts: Date.now() }));
app.get('/api/debug', (_req, res) => res.json({ ok: true, message: 'API reachable' }));

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    email = String(email).toLowerCase().trim();
    if (!validEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (!strongEnough(password)) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    const token = signToken(user);
    res.status(201).json({ token, user: { email: user.email } });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error' });
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
    res.json({ token, user: { email: user.email } });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.uid).select('email createdAt');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// Change password (logged-in)
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'currentPassword and newPassword required' });
    if (!strongEnough(newPassword)) return res.status(400).json({ error: 'New password too short' });

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

// Request password reset (email link)
app.post('/api/auth/request-reset', async (req, res) => {
  try {
    let { email } = req.body || {};
    email = String(email || '').toLowerCase().trim();
    if (!validEmail(email)) return res.status(200).json({ ok: true }); // do not leak users

    const user = await User.findOne({ email });
    if (!user) return res.status(200).json({ ok: true });

    const token = crypto.randomBytes(24).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    user.resetTokenHash = hash;
    user.resetTokenExp = new Date(Date.now() + 1000 * 60 * 15); // 15 min
    await user.save();

    const resetUrl = `${process.env.FRONTEND_RESET_URL || 'https://snack.expo.dev'}/?resetToken=${token}&email=${encodeURIComponent(email)}`;
    await sendMail(
      email,
      `${APP_NAME} password reset`,
      `<p>We received a request to reset your ${APP_NAME} password.</p>
       <p><a href="${resetUrl}">Tap here to reset</a> (valid for 15 minutes).</p>
       <p>If you didn't request this, you can ignore this email.</p>`
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('Request reset error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Complete password reset with token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body || {};
    if (!email || !token || !newPassword)
      return res.status(400).json({ error: 'email, token and newPassword required' });
    if (!strongEnough(newPassword)) return res.status(400).json({ error: 'New password too short' });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user || !user.resetTokenHash || !user.resetTokenExp) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    if (Date.now() > new Date(user.resetTokenExp).getTime()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const hash = crypto.createHash('sha256').update(token).digest('hex');
    if (hash !== user.resetTokenHash) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.resetTokenHash = undefined;
    user.resetTokenExp = undefined;
    await user.save();

    res.json({ ok: true });
  } catch (e) {
    console.error('Reset password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// 404
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// Errors
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log(`${APP_NAME} backend running on port ${PORT}`));
