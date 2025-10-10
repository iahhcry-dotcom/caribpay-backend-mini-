// server.js — CaribPay mini backend (CommonJS for Render)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const {
  JWT_SECRET = 'devsecret',
  MONGO_URI = 'mongodb://localhost:27017/caribpay',
  NODE_ENV = 'Production',
  PORT = 10000,
} = process.env;

const app = express();

// ---- Middleware
app.use(express.json());
app.use(
  cors({
    origin: true, // allow Expo, Snack, and your site
    credentials: false,
  })
);

// ---- DB
mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log('MongoDB connected'))
  .catch((e) => console.error('Mongo error', e.message));

// ---- Schemas
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, index: true },
    passwordHash: String,
    balance: { type: Number, default: 10000 }, // cents; default $100.00
  },
  { timestamps: true }
);

const txSchema = new mongoose.Schema(
  {
    userId: mongoose.Types.ObjectId, // owner
    type: { type: String, enum: ['send', 'receive'] },
    amount: Number, // cents
    to: String,     // email (for send)
    from: String,   // email (for receive)
    note: String,
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Tx = mongoose.model('Tx', txSchema);

// ---- Helpers
function sign(user) {
  return jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: '7d',
  });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ---- Health
app.get('/', (_req, res) => res.json({ ok: true, env: NODE_ENV }));
app.get('/api/debug', (_req, res) => res.json({ message: 'OK' }));

// ---- Auth: register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'Email & password required' });
    }
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(),
      passwordHash,
      balance: 8551, // show $85.51 like your screenshot
    });
    const token = sign(user);
    res.json({ token, email: user.email });
  } catch (e) {
    console.error('register error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ---- Auth: login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email: (email || '').toLowerCase() });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const match = await bcrypt.compare(password || '', user.passwordHash || '');
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    res.json({ token: sign(user), email: user.email });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ---- Me
app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.uid).lean();
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ email: user.email, balance: user.balance });
});

// ---- Transactions list (last 20)
app.get('/api/transactions', auth, async (req, res) => {
  const txs = await Tx.find({ userId: req.user.uid })
    .sort({ createdAt: -1 })
    .limit(20)
    .lean();
  res.json({ items: txs });
});

// ---- Send
app.post('/api/transfer/send', auth, async (req, res) => {
  try {
    const { to, amount } = req.body || {};
    const cents = Math.round(Number(amount || 0) * 100);
    if (!to || !cents || cents <= 0)
      return res.status(400).json({ message: 'Invalid amount or recipient' });

    const me = await User.findById(req.user.uid);
    if (!me) return res.status(404).json({ message: 'User not found' });
    if (me.balance < cents) return res.status(400).json({ message: 'Insufficient funds' });

    // decrement sender
    me.balance -= cents;
    await me.save();

    // log sender tx
    await Tx.create({
      userId: me._id,
      type: 'send',
      amount: cents,
      to: to.toLowerCase(),
      note: '',
    });

    // credit recipient if exists
    const rcpt = await User.findOne({ email: to.toLowerCase() });
    if (rcpt) {
      rcpt.balance += cents;
      await rcpt.save();
      await Tx.create({
        userId: rcpt._id,
        type: 'receive',
        amount: cents,
        from: me.email,
        note: '',
      });
    }

    res.json({ ok: true, balance: me.balance });
  } catch (e) {
    console.error('send error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ---- Receive (manual add)
app.post('/api/transfer/receive', auth, async (req, res) => {
  try {
    const { from, amount } = req.body || {};
    const cents = Math.round(Number(amount || 0) * 100);
    if (!from || !cents || cents <= 0)
      return res.status(400).json({ message: 'Invalid amount or sender' });

    const me = await User.findById(req.user.uid);
    if (!me) return res.status(404).json({ message: 'User not found' });

    me.balance += cents;
    await me.save();

    await Tx.create({
      userId: me._id,
      type: 'receive',
      amount: cents,
      from: from.toLowerCase(),
      note: '',
    });

    res.json({ ok: true, balance: me.balance });
  } catch (e) {
    console.error('receive error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ---- 404
app.use((_req, res) => res.status(404).json({ message: 'Not found' }));

app.listen(PORT, () =>
  console.log(`CaribPay backend running on port ${PORT}`)
);
