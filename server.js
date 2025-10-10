// server.js — CaribPay Backend (2025 updated version)

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// --- MongoDB connection ---
mongoose
  .connect(process.env.MONGO_URI, { })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- Models ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  balance: { type: Number, default: 10000 }, // cents
});
const User = mongoose.model("User", userSchema);

const transactionSchema = new mongoose.Schema({
  from: String,
  to: String,
  type: String,
  amount: Number,
  createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model("Transaction", transactionSchema);

// --- Middleware ---
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// --- Routes ---
// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "User already exists" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get user info
app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ email: user.email, balance: user.balance });
});

// Get transactions
app.get("/api/transactions", auth, async (req, res) => {
  const tx = await Transaction.find({
    $or: [{ from: req.user.email }, { to: req.user.email }],
  }).sort({ createdAt: -1 });
  res.json({ items: tx });
});

// Send money
app.post("/api/transfer/send", auth, async (req, res) => {
  try {
    const { to, amount } = req.body;
    const sender = await User.findById(req.user.id);
    const receiver = await User.findOne({ email: to });
    if (!receiver) return res.status(404).json({ message: "Recipient not found" });
    if (sender.balance < amount * 100)
      return res.status(400).json({ message: "Insufficient funds" });

    sender.balance -= amount * 100;
    receiver.balance += amount * 100;

    await sender.save();
    await receiver.save();

    await Transaction.create({ from: sender.email, to, type: "send", amount: amount * 100 });
    await Transaction.create({ from: sender.email, to, type: "receive", amount: amount * 100 });

    res.json({ message: "Transfer complete" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

// Receive (add funds)
app.post("/api/transfer/receive", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);
    user.balance += amount * 100;
    await user.save();
    await Transaction.create({ to: user.email, type: "receive", amount: amount * 100 });
    res.json({ message: "Funds added" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// --- Default route ---
app.get("/", (req, res) => {
  res.json({ message: "CaribPay backend active ✅" });
});

// --- Preload test user if not exists ---
async function preload() {
  const exists = await User.findOne({ email: "arkim.robertson1@gmail.com" });
  if (!exists) {
    const hash = await bcrypt.hash("123456", 10);
    await User.create({
      email: "arkim.robertson1@gmail.com",
      passwordHash: hash,
      balance: 8551
    });
    console.log("✅ Test user created: arkim.robertson1@gmail.com / 123456");
  }
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, async () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
  await preload();
});
