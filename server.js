const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();
const app = express();

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.use(express.json());

// --- demo in-memory users (replace with DB later)
const USERS = [{ id: 'u1', email: 'demo@caribpay.com', password: 'demo123' }];

// Health check
app.get('/', (_req, res) => res.status(200).send('CaribPay backend is running ✅'));

// Simple login route
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = USERS.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

// Me route
app.get('/auth/me', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    res.json({ id: payload.sub, email: payload.email });
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Start (Render port)
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
