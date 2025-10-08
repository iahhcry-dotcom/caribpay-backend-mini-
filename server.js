// server.js — CaribPay backend mini (with server-side transactions)
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Config ---
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// --- In-memory stores (for demo) ---
// These reset when Render restarts. Use a database later for persistence.
const usersByEmail = {};
const walletsByPhone = {};
const txByPhone = {};

// --- Helpers ---
const minor = (amt) => Math.round(Number(amt) * 100); // convert to cents
const major = (cents) => Number(cents || 0) / 100;
const ensureWallet = (phone) => {
  if (!walletsByPhone[phone]) {
    walletsByPhone[phone] = { phone, currency: 'XCD', balanceMinor: 0 };
    txByPhone[phone] = txByPhone[phone] || [];
  }
  return walletsByPhone[phone];
};
const addTx = (phone, tx) => {
  txByPhone[phone] = txByPhone[phone] || [];
  txByPhone[phone].unshift({
    id: uuid(),
    timestamp: Date.now(),
    currency: 'XCD',
    ...tx,
  });
};

const auth = (req, res, next) => {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
};

// --- Routes ---

// Health check
app.get('/api/ping', (_req, res) => res.json({ ok: true, message: 'pong' }));

// --- Auth ---
app.post('/api/auth/register', async (req, res) => {
  const { email, password, phone } = req.body || {};
  if (!email || !password || !phone)
    return res.json({ ok: false, error: 'email, password, phone required' });
  if (usersByEmail[email])
    return res.json({ ok: false, error: 'Email already registered' });

  const passHash = await bcrypt.hash(password, 10);
  usersByEmail[email] = { id: uuid(), email, passHash, phone };
  ensureWallet(phone);
  res.json({ ok: true });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = usersByEmail[email];
  if (!user) return res.json({ ok: false, error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.json({ ok: false, error: 'Invalid credentials' });

  const token = jwt.sign(
    { sub: user.id, email: user.email, phone: user.phone },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ ok: true, token, phone: user.phone });
});

// --- Wallets ---
app.get('/api/wallets', auth, (req, res) => {
  const phone = req.user.phone;
  const w = ensureWallet(phone);
  res.json({
    ok: true,
    wallets: [{ currency: 'XCD', balance: major(w.balanceMinor) }],
  });
});

app.post('/api/wallets/topup', auth, (req, res) => {
  const phone = req.user.phone;
  const { amount } = req.body || {};
  const amtMinor = minor(amount);
  if (!(amtMinor > 0))
    return res.json({ ok: false, error: 'Amount must be > 0' });

  const w = ensureWallet(phone);
  w.balanceMinor += amtMinor;
  addTx(phone, { type: 'TopUp', amountMinor: amtMinor });

  res.json({ ok: true, balance: major(w.balanceMinor) });
});

// --- Transfers ---
app.post('/api/transfer/send', auth, (req, res) => {
  const fromPhone = req.user.phone;
  const { toPhone, amount } = req.body || {};
  const amtMinor = minor(amount);

  if (!toPhone || !(amtMinor > 0))
    return res.json({ ok: false, error: 'toPhone and amount required' });
  if (toPhone === fromPhone)
    return res.json({ ok: false, error: 'Cannot send to self' });

  const fromW = ensureWallet(fromPhone);
  if (fromW.balanceMinor < amtMinor)
    return res.json({ ok: false, error: 'Insufficient funds' });

  const toW = ensureWallet(toPhone);
  fromW.balanceMinor -= amtMinor;
  toW.balanceMinor += amtMinor;

  addTx(fromPhone, { type: 'Send', toPhone, amountMinor: amtMinor });
  addTx(toPhone, { type: 'Receive', fromPhone, amountMinor: amtMinor });

  res.json({ ok: true, status: 'sent', balance: major(fromW.balanceMinor) });
});

// --- Transactions (server-side history) ---
app.get('/api/transactions', auth, (req, res) => {
  const phone = req.user.phone;
  const list = (txByPhone[phone] || []).map((t) => ({
    id: t.id,
    type: t.type,
    amount: major(t.amountMinor),
    currency: t.currency,
    toPhone: t.toPhone,
    fromPhone: t.fromPhone,
    timestamp: t.timestamp,
  }));
  res.json({ ok: true, transactions: list });
});

app.listen(PORT, () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
