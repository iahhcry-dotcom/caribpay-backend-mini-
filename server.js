/**
 * CaribPay backend – minimal, production-ready
 * CommonJS build (no "type":"module" needed)
 */

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

// ========= Config =========
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const FRONTEND_RESET_URL = process.env.FRONTEND_RESET_URL || "https://snack.expo.dev";

// SMTP (Gmail App Password recommended)
const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const MAIL_FROM = process.env.MAIL_FROM || "CaribPay <no-reply@caribpay.com>";

// ========= App =========
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "*", // relax for Snack; tighten later to your bundle URLs if you want
  })
);

// ========= Mongo =========
mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ Mongo connection error:", err.message);
    process.exit(1);
  });

// ========= Models =========
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true }, // hashed
    balance: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ========= Helpers =========
function signToken(payload, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d", ...opts });
}

function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const [, token] = hdr.split(" ");
    if (!token) return res.status(401).json({ message: "Missing token" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465, // 465 = SSL, 587 = STARTTLS
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// ========= Routes =========

// Health / root
app.get("/", (_req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// --- Auth: Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed, balance: 0 });

    return res.status(201).json({ message: "User registered successfully", id: user._id });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error during registration" });
  }
});

// --- Auth: Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // 👇 FIX: compare plain vs hashed
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken({ id: user._id, email: user.email });

    return res.json({
      message: "Login successful",
      token,
      user: { id: user._id, email: user.email, balance: user.balance || 0 },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error during login" });
  }
});

// --- Auth: Me (used by the app after login)
app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ user: { id: user._id, email: user.email, balance: user.balance || 0 } });
});

// --- Password: Forgot (send reset email)
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    // Always respond the same for privacy
    if (!user) return res.json({ message: "If an account exists, an email was sent" });

    const token = signToken({ id: user._id, purpose: "reset" }, { expiresIn: "15m" });
    const url = `${FRONTEND_RESET_URL.replace(/\/$/, "")}/reset?token=${encodeURIComponent(token)}`;

    await mailer.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "CaribPay password reset",
      html: `
        <p>Hello,</p>
        <p>We received a request to reset your CaribPay password.</p>
        <p>Click this link to continue (valid for 15 minutes):</p>
        <p><a href="${url}">${url}</a></p>
        <p>If you didn't request this, you can safely ignore this email.</p>
      `,
    });

    res.json({ message: "If an account exists, an email was sent" });
  } catch (err) {
    console.error("Forgot error:", err);
    res.status(500).json({ message: "Could not send reset email" });
  }
});

// --- Password: Reset
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ message: "Token and password required" });

    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose !== "reset") return res.status(400).json({ message: "Invalid token" });

    const hashed = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(payload.id, { $set: { password: hashed } });

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset error:", err);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

// --- Transactions: simple list used by Snack
app.get("/api/tx/list", auth, async (req, res) => {
  // You can replace with real collection later. For now return empty or demo.
  res.json({
    items: [],
  });
});

// --- Optional: send money mock (extend later)
app.post("/api/tx/send", auth, async (req, res) => {
  const { to, amount } = req.body || {};
  if (!to || !amount) return res.status(400).json({ message: "Recipient and amount required" });
  // No ledger yet—just acknowledge
  res.json({ message: "Transfer queued (demo)", to, amount: Number(amount) || 0 });
});

// ========= Start =========
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
