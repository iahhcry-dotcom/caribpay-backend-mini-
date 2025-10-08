// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Simple health check route so Render knows the app is alive
app.get('/', (_req, res) => {
  res.status(200).send('CaribPay backend is running ✅');
});

// Example environment variable usage
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// Your routes would go here
// e.g. app.use('/api', require('./routes/api'));

// IMPORTANT: Listen on Render's dynamic port
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ CaribPay backend running on port ${PORT}`);
});
