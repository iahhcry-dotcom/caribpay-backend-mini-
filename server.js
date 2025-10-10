// server.js — CaribPay minimal backend (Express + MongoDB + JWT)
// Install: npm i express cors mongoose bcryptjs jsonwebtoken nodemailer

// ====== Imports ======
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// ====== Config / Env ======
const {
  MONGO_URI,
  JWT_SECRET,
  NODE_ENV = 'Production',
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM = 'CaribPay <no-reply@caribpay.com>',
  FRONTEND_RESET_URL = 'https://snack.expo.dev', // where your reset link points to
} = process.env;

if (!MONGO_URI) {
  console.error('❌ Missing MONGO_URI env var');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('❌ Missing JWT_SECRET env var');
  process.exit(1);
}

const PORT = process.env.PORT || 10000;

// ====== App ======
const app = express();

// CORS: allow Snack + everything (safe for this mini demo)
app.use(
  cors({
    origin: true, // reflect request origin
    credentials: false,
  })
);
app.use(express.json());

// ====== DB ======
mongoose
  .connect(MONGO_URI, { dbName: 'caribpay' })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ====== Models ======
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    password: { type: String, required: true }, // hashed
    name: { type: String },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

// ====== Helpers ======
function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

async function sendResetEmail(toEmail, token) {
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    console.log('ℹ️  SMTP not configured; skipping email send.');
    return;
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465, // true for 465, false otherwise
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });

  const resetLink = `${FRONTEND_RESET_URL}/reset?token=${encodeURIComponent(
    token
  )}`;

  await transporter.sendMail({
    from: MAIL_FROM,
    to: toEmail,
    subject: 'CaribPay password reset',
    html: `
      <div style="font-family:system-ui,Segoe UI,Roboto,sans-serif">
        <h2>Reset your CaribPay password</h2>
        <p>Click the button below to set a new password. This link expires in 30 minutes.</p>
        <p><a href="${resetLink}" 
              style="background:#111;color:#fff;padding:12px 16px;border-radius:8px;
                     text-decoration:none;display:inline-block">Reset Password</a></p>
        <p>If the button doesn’t work, copy this URL into your browser:</p>
        <code>${resetLink}</code>
      </div>
    `,
  });
}

// ====== Routes ======

// Health & debug
app.get('/', (req, res) => res.send('CaribPay API is live ✅'));
app.get('/api/health', (req, res) =>
  res.json({ ok: true, env: NODE_ENV, time: new Date().toISOString() })
);

// Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name = '' } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required' });

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(409).json({ message: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase().trim(),
      password: hash,
      name,
    });

    const token = signToken(user);
    res.status(201).json({ token, email: user.email, name: user.name });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user =
      email &&
      (await User.findOne({ email: email.toLowerCase().trim() }));
    if (!user || !(await bcrypt.compare(password || '', user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = signToken(user);
    res.json({ token, email: user.email, name: user.name || '' });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Auth: Me (token check)
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.sub).select('email name createdAt');
  if (!user) return res.status(404).json({ message: 'Not found' });
  res.json({ email: user.email, name: user.name || '', createdAt: user.createdAt });
});

// Auth: Forgot password (email link)
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body;
    const user =
      email &&
      (await User.findOne({ email: email.toLowerCase().trim() }));
    // Always respond 200 to avoid user enumeration
    if (!user) return res.json({ ok: true });

    const resetToken = jwt.sign(
      { sub: user._id.toString(), purpose: 'reset' },
      JWT_SECRET,
      { expiresIn: '30m' }
    );

    await sendResetEmail(user.email, resetToken);
    res.json({ ok: true });
  } catch (err) {
    console.error('forgot error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Auth: Reset password
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password)
      return res.status(400).json({ message: 'token and password required' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    if (payload.purpose !== 'reset')
      return res.status(400).json({ message: 'Invalid token purpose' });

    const user = await User.findById(payload.sub);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.password = await bcrypt.hash(password, 10);
    await user.save();

    res.json({ ok: true });
  } catch (err) {
    console.error('reset error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== Start ======
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
  console.log(`   Environment: ${NODE_ENV}`);
});
