// server.js — CaribPay minimal backend (CommonJS)

require('dotenv').config();                  // harmless on Render; used locally
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();

// ---------- Basic middleware ----------
app.use(cors());
app.use(express.json());

// ---------- MongoDB connection ----------
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('❌ Missing MONGO_URI env var');
} else {
  mongoose.set('strictQuery', true);
  mongoose
    .connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch((err) => console.error('❌ MongoDB connection error:', err.message));
}

// (Optional) very small User model so /forgot can check if email exists.
// If you already have a model elsewhere, you can delete this and use yours.
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String }
  },
  { timestamps: true }
);
const User = mongoose.models.User || mongoose.model('User', userSchema);

// ---------- Email (Nodemailer) ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,        // e.g. "smtp.gmail.com"
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,                      // STARTTLS on 587
  auth: {
    user: process.env.SMTP_USER,      // your Gmail address
    pass: process.env.SMTP_PASS       // your Gmail "App password"
  }
});

// quick verify on boot (shows in Render logs)
transporter.verify()
  .then(() => console.log('✅ SMTP ready'))
  .catch((e) => console.warn('⚠️ SMTP verify failed:', e.message));

// ---------- Routes ----------
app.get('/', (_req, res) => {
  res.json({ message: 'Welcome to CaribPay API' });
});

app.get('/api/health', async (_req, res) => {
  res.json({
    ok: true,
    db: mongoose.connection.readyState, // 1 = connected
    time: new Date().toISOString()
  });
});

/**
 * POST /api/auth/forgot
 * Body: { "email": "user@example.com" }
 * Sends a reset email (demo link).
 */
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: 'Email required' });

    // Ensure the user exists (optional but typical)
    const existing = await User.findOne({ email }).lean();
    if (!existing) {
      // hide enumeration: pretend success
      return res.json({ message: 'If an account exists, an email was sent' });
    }

    // In a real app, create a signed token. Demo link below:
    const resetLink = `${process.env.FRONTEND_RESET_URL || 'https://snack.expo.dev'}/reset?email=${encodeURIComponent(email)}`;

    const info = await transporter.sendMail({
      from: process.env.MAIL_FROM || 'CaribPay <no-reply@caribpay.com>',
      to: email,
      subject: 'CaribPay password reset',
      text: `Reset your password: ${resetLink}`,
      html: `<p>Reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p>`
    });

    console.log('✉️  Password reset email queued:', info.messageId);
    res.json({ message: `Email sent successfully to ${email}` });
  } catch (e) {
    console.error('forgot error:', e);
    res.status(500).json({ message: 'Email send failed', error: e.message });
  }
});

// ---------- Start server ----------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
