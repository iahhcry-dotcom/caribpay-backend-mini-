// server.js — CaribPay mini backend (Express + MongoDB)
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// ---------- Middleware ----------
app.use(express.json());
app.use(morgan("dev"));

// Allow Snack, Expo Web, and local dev
app.use(
  cors({
    origin: [
      /.*\.expo\.dev$/,
      /.*\.snack\.expo\.dev$/,
      "http://localhost:19006",
      "http://localhost:3000",
      "http://localhost:5173",
      "https://localhost",
      "*",
    ],
    credentials: false,
  })
);

// Basic health
app.get("/", (_, res) => res.json({ ok: true, service: "CaribPay backend" }));

// ---------- Mongo ----------
mongoose
  .connect(process.env.MONGO_URI, { dbName: "caribpay" })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ Mongo connection error:", err.message);
    process.exit(1);
  });

// ---------- Schemas ----------
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 0 }, // store cents (integer)
  },
  { timestamps: true }
);

const txSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true }, // cents
    counterparty: { type: String, required: true }, // email/handle
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Tx = mongoose.model("Tx", txSchema);

// ---------- Helpers ----------
const toCents = (n) => Math.round(Number(n) * 100);
const toDollars = (cents) => Number((cents / 100).toFixed(2));

function makeToken(user) {
  return jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ---------- Auth ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      passwordHash: hash,
      balance: 10000, // $100.00 initial demo balance
    });

    const token = makeToken(user);
    return res.json({
      token,
      email: user.email,
      balance: toDollars(user.balance),
    });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = makeToken(user);
    return res.json({
      token,
      email: user.email,
      balance: toDollars(user.balance),
    });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user.uid).lean();
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ email: user.email, balance: toDollars(user.balance) });
});

// ---------- Wallet ----------
app.get("/api/wallet/balance", auth, async (req, res) => {
  const user = await User.findById(req.user.uid).lean();
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ balance: toDollars(user.balance) });
});

app.get("/api/wallet/history", auth, async (req, res) => {
  const txs = await Tx.find({ userId: req.user.uid })
    .sort({ createdAt: -1 })
    .limit(25)
    .lean();

  res.json(
    txs.map((t) => ({
      id: t._id,
      type: t.type,
      amount: toDollars(t.amount),
      counterparty: t.counterparty,
      createdAt: t.createdAt,
    }))
  );
});

app.post("/api/wallet/send", auth, async (req, res) => {
  try {
    const amountDollars = Number(req.body.amount);
    const to = String(req.body.to || "").trim().toLowerCase();

    if (!amountDollars || amountDollars <= 0)
      return res.status(400).json({ message: "Amount must be > 0" });
    if (!to) return res.status(400).json({ message: "Recipient required" });

    const cents = toCents(amountDollars);
    const sender = await User.findById(req.user.uid);
    if (!sender) return res.status(404).json({ message: "User not found" });

    if (sender.balance < cents)
      return res.status(400).json({ message: "Insufficient balance" });

    // Reduce sender balance and add send tx
    sender.balance -= cents;
    await sender.save();
    await Tx.create({
      userId: sender._id,
      type: "send",
      amount: cents,
      counterparty: to,
    });

    // If the recipient exists, credit them and record a receive tx
    const recipient = await User.findOne({ email: to });
    if (recipient) {
      recipient.balance += cents;
      await recipient.save();
      await Tx.create({
        userId: recipient._id,
        type: "receive",
        amount: cents,
        counterparty: sender.email,
      });
    }

    res.json({ ok: true, balance: toDollars(sender.balance) });
  } catch (e) {
    console.error("send error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------- Preload a test user (email: arkim.robertson1@gmail.com / pwd: 123456) ----------
async function preload() {
  try {
    const email = "arkim.robertson1@gmail.com";
    const exists = await User.findOne({ email });
    if (!exists) {
      const hash = await bcrypt.hash("123456", 10);
      await User.create({
        email,
        passwordHash: hash,
        balance: 8551, // $85.51 demo
      });
      console.log("✅ Test user created:", email, "/ 123456");
    } else {
      console.log("ℹ️ Test user exists:", email);
    }
  } catch (e) {
    console.error("preload error:", e);
  }
}

// ---------- 404 (keep JSON for Snack) ----------
app.use((req, res) => res.status(404).json({ message: "Not found" }));

// ---------- Start ----------
app.listen(PORT, async () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
  await preload();
});
