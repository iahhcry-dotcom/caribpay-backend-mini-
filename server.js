/**
 * CaribPay Backend — ESM Version
 * Built for Node.js + Render + MongoDB Atlas
 */

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

// ========= CONFIG =========
const app = express();
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const FRONTEND_RESET_URL = process.env.FRONTEND_RESET_URL || "https://snack.expo.dev";

const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const MAIL_FROM = process.env.MAIL_FROM || "CaribPay <no-reply@caribpay.com>";

// ========= MIDDLEWARE =========
app.use(cors({ origin: "*" }));
app.use(express.json());

// ========= DATABASE =========
mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ========= MODEL =========
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

// ========= HELPERS =========
const signToken = (payload, opts = {}) =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: "7d", ...opts });

const auth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Missing token" });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// ========= ROUTES =========

// 🌍 Root
app.get("/", (req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// 👤 Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashedPassword, balance: 0 });

    res.status(201).json({ message: "User registered successfully", id: user._id });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// 🔑 Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken({ id: user._id, email: user.email });
    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, email: user.email, balance: user.balance || 0 },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// 👁️ Authenticated Profile
app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ user: { id: user._id, email: user.email, balance: user.balance || 0 } });
});

// 🔄 Forgot Password
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "If an account exists, an email was sent" });

    const token = signToken({ id: user._id, purpose: "reset" }, { expiresIn: "15m" });
    const resetUrl = `${FRONTEND_RESET_URL.replace(/\/$/, "")}/reset?token=${encodeURIComponent(token)}`;

    await mailer.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "CaribPay Password Reset",
      html: `
        <p>Hello,</p>
        <p>We received a password reset request for your CaribPay account.</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>This link is valid for 15 minutes.</p>
        <p>If you didn’t request this, you can ignore this email.</p>
      `,
    });

    res.json({ message: "If an account exists, an email was sent" });
  } catch (err) {
    console.error("Forgot error:", err);
    res.status(500).json({ message: "Could not send reset email" });
  }
});

// 🔐 Reset Password
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password)
      return res.status(400).json({ message: "Token and password required" });

    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.purpose !== "reset")
      return res.status(400).json({ message: "Invalid token" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset error:", err);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

// 💳 Transactions (demo)
app.get("/api/tx/list", auth, async (req, res) => {
  res.json({ items: [] });
});

app.post("/api/tx/send", auth, async (req, res) => {
  const { to, amount } = req.body;
  if (!to || !amount)
    return res.status(400).json({ message: "Recipient and amount required" });
  res.json({ message: "Transfer successful (demo)", to, amount });
});

// ========= START SERVER =========
app.listen(PORT, () => {
  console.log
