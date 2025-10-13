/**
 * CaribPay – minimal full stack backend
 * Auth: register / login / me / forgot / reset
 * Wallet: balance / send / history
 */

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");

// ----- ENV ---------------------------------------------------------
require("dotenv").config();

const {
  PORT = 10000,
  MONGO_URI,
  JWT_SECRET = "changeme",
  NODE_ENV = "production",
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM = "CaribPay <no-reply@caribpay.com>",
  FRONTEND_RESET_URL = "https://snack.expo.dev"
} = process.env;

// ----- APP ---------------------------------------------------------
const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(
  cors({
    origin: true,
    credentials: false
  })
);

// ----- DB ----------------------------------------------------------
mongoose.set("strictQuery", true);
mongoose
  .connect(MONGO_URI, { dbName: "caribpay" })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((e) => {
    console.error("❌ MongoDB error:", e.message);
    process.exit(1);
  });

// ----- MODELS ------------------------------------------------------
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, index: true, required: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 100 }, // start with $100 for demo
    resetToken: { type: String, default: null },
    resetTokenExp: { type: Date, default: null }
  },
  { timestamps: true }
);

const TxSchema = new mongoose.Schema(
  {
    fromUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    toUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    amount: { type: Number, required: true },
    memo: { type: String, default: "" }
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Tx = mongoose.model("Tx", TxSchema);

// ----- UTILS -------------------------------------------------------
const signToken = (user) =>
  jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d"
  });

const auth = async (req, res, next) => {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(payload.uid);
    if (!req.user) return res.status(401).json({ message: "Unauthorized" });
    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 587),
  secure: false,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

// ----- ROUTES: HEALTH ----------------------------------------------
app.get("/", (req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// ----- ROUTES: AUTH -------------------------------------------------
// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash });
    const token = signToken(user);
    res.json({
      token,
      user: { email: user.email, balance: user.balance }
    });
  } catch (e) {
    console.error("register error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email: (email || "").toLowerCase() });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password || "", user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken(user);
    res.json({
      token,
      user: { email: user.email, balance: user.balance }
    });
  } catch (e) {
    console.error("login error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// Me
app.get("/api/auth/me", auth, async (req, res) => {
  res.json({
    user: { email: req.user.email, balance: req.user.balance }
  });
});

// Forgot (email always responds 200)
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    const user = await User.findOne({ email: (email || "").toLowerCase() });
    if (user) {
      const token = jwt.sign({ uid: user._id }, JWT_SECRET, { expiresIn: "1h" });
      user.resetToken = token;
      user.resetTokenExp = new Date(Date.now() + 60 * 60 * 1000);
      await user.save();

      const link = `${FRONTEND_RESET_URL.replace(/\/$/, "")}/reset?token=${encodeURIComponent(
        token
      )}`;
      await mailer.sendMail({
        from: MAIL_FROM,
        to: user.email,
        subject: "CaribPay password reset",
        text: `Reset your password: ${link}`,
        html: `<p>Reset your password:</p><p><a href="${link}">${link}</a></p>`
      });
      console.log(`📧 reset link sent to ${user.email}`);
    }
    res.json({ message: "If an account exists, an email was sent" });
  } catch (e) {
    console.error("forgot error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password)
      return res.status(400).json({ message: "token and password required" });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const user = await User.findById(payload.uid);
    if (
      !user ||
      user.resetToken !== token ||
      !user.resetTokenExp ||
      user.resetTokenExp < new Date()
    ) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.passwordHash = await bcrypt.hash(password, 10);
    user.resetToken = null;
    user.resetTokenExp = null;
    await user.save();

    res.json({ message: "Password updated" });
  } catch (e) {
    console.error("reset error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// ----- ROUTES: WALLET -----------------------------------------------
// Balance
app.get("/api/wallet/balance", auth, async (req, res) => {
  res.json({ balance: req.user.balance });
});

// History (alias also available below)
app.get("/api/wallet/history", auth, async (req, res) => {
  const items = await Tx.find({
    $or: [{ fromUser: req.user._id }, { toUser: req.user._id }]
  })
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();

  const mapped = items.map((t) => ({
    _id: t._id,
    amount: t.amount,
    direction: String(t.fromUser) === String(req.user._id) ? "debit" : "credit",
    memo: t.memo || "",
    createdAt: t.createdAt
  }));

  res.json({ items: mapped });
});

// Send
app.post("/api/wallet/send", auth, async (req, res) => {
  try {
    const { to, amount, memo = "" } = req.body || {};
    const amt = Number(amount);
    if (!to || !amt || isNaN(amt) || amt <= 0)
      return res.status(400).json({ message: "Invalid payload" });

    const toUser = await User.findOne({ email: to.toLowerCase() });
    if (!toUser) return res.status(404).json({ message: "Recipient not found" });
    if (String(toUser._id) === String(req.user._id))
      return res.status(400).json({ message: "Cannot send to yourself" });

    // Ensure sufficient funds
    const sender = await User.findById(req.user._id);
    if (sender.balance < amt)
      return res.status(400).json({ message: "Insufficient balance" });

    // Atomic-ish (simplified)
    sender.balance -= amt;
    toUser.balance += amt;
    await sender.save();
    await toUser.save();

    const tx = await Tx.create({
      fromUser: sender._id,
      toUser: toUser._id,
      amount: amt,
      memo
    });

    res.json({
      message: "Sent",
      txId: tx._id,
      balance: sender.balance
    });
  } catch (e) {
    console.error("send error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// ----- LEGACY/ALIAS ENDPOINTS to match your Snack -------------------
app.get("/api/tx/list", auth, (req, res) => app._router.handle(req, res, () => {}, "/api/wallet/history"));
app.post("/api/tx/send", auth, (req, res) => app._router.handle(req, res, () => {}, "/api/wallet/send"));

// ----- START --------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
