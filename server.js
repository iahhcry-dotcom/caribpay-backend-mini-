// Minimal backend: users + wallet + XCD transfers (in-memory)
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

const users = new Map();   // email -> { id, email, phone, passHash }
const wallets = new Map(); // userId -> { id, currency:'XCD', balanceMinor }

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ ok:false, error:'missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ ok:false, error:'invalid token' });
  }
}

app.get('/api/ping', (req,res) => res.json({ message: 'Backend working!' }));

app.post('/api/auth/register', async (req,res) => {
  const { email, password, phone } = req.body || {};
  if (!email || !password || !phone) return res.status(400).json({ ok:false, error:'email, password, phone required' });
  if (users.has(email)) return res.status(400).json({ ok:false, error:'email already exists' });
  const id = uuidv4();
  const passHash = await bcrypt.hash(password, 10);
  users.set(email, { id, email, phone, passHash });
  wallets.set(id, { id: uuidv4(), currency: 'XCD', balanceMinor: 0 });
  return res.json({ ok:true });
});

app.post('/api/auth/login', async (req,res) => {
  const { email, password } = req.body || {};
  const u = users.get(email);
  if (!u) return res.status(400).json({ ok:false, error:'invalid credentials' });
  const ok = await bcrypt.compare(password, u.passHash);
  if (!ok) return res.status(400).json({ ok:false, error:'invalid credentials' });
  const token = jwt.sign({ userId: u.id, email: u.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok:true, token, phone: u.phone });
});

app.get('/api/wallets', auth, (req,res) => {
  const w = wallets.get(req.userId);
  res.json({ ok:true, wallets:[{ currency: w.currency, balance: (w.balanceMinor||0)/100 }] });
});

app.post('/api/wallets/topup', auth, (req,res) => {
  const { amount } = req.body || {};
  if (!amount || amount <= 0) return res.status(400).json({ ok:false, error:'amount > 0 required' });
  const w = wallets.get(req.userId);
  w.balanceMinor = (w.balanceMinor || 0) + Math.round(amount * 100);
  res.json({ ok:true, balance: w.balanceMinor/100 });
});

app.post('/api/transfer/send', auth, (req,res) => {
  const { toPhone, amount } = req.body || {};
  if (!toPhone || !amount || amount <= 0) return res.status(400).json({ ok:false, error:'toPhone and amount > 0 required' });
  const senderWallet = wallets.get(req.userId);
  const amtMinor = Math.round(amount * 100);
  if ((senderWallet.balanceMinor || 0) < amtMinor) return res.status(400).json({ ok:false, error:'insufficient funds' });

  const recUser = [...users.values()].find(u => u.phone === toPhone);
  senderWallet.balanceMinor -= amtMinor;

  if (recUser) {
    const recWallet = wallets.get(recUser.id);
    recWallet.balanceMinor = (recWallet.balanceMinor || 0) + amtMinor;
    return res.json({ ok:true, status:'completed', toPhone, amount, currency:'XCD' });
  } else {
    return res.json({ ok:true, status:'completed_external', toPhone, amount, currency:'XCD' });
  }
});

app.listen(PORT, () => console.log(`CaribPay mini backend listening on ${PORT}`));
