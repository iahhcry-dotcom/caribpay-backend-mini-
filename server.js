// server.js — CaribPay backend (MongoDB + JWT + Transfers + History)
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://<your-mongodb-uri>";

/* ====== MODELS ====== */
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  balance: { type: Number, default: 100.0 },
});

const txSchema = new mongoose.Schema({
  from: String,
  to: String,
  amount: Number,
  type: String, // 'send' or 'receive'
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", txSchema);

/* ====== HELPERS ====== */
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

/* ====== ROUTES ====== */

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "User already exists" });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET);
    res.json({ token });
  } catch (e) {
    res.status(500).json({ message: "Server error", error: e.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET);
    res.json({ token });
  } catch (e) {
    res.status(500).json({ message: "Server error", error: e.message });
  }
});

// Get profile
app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "Not found" });
  res.json({ email: user.email, balance: user.balance });
});

// Get transaction history
app.get("/api/history", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "Not found" });
  const txs = await Transaction.find({
    $or: [{ from: user.email }, { to: user.email }],
  }).sort({ createdAt: -1 });
  res.json(txs);
});

// Transfer funds
app.post("/api/transfer", auth, async (req, res) => {
  const { to, amount } = req.body;
  const sender = await User.findById(req.user.id);
  const recipient = await User.findOne({ email: to });
  if (!recipient)
    return res.status(404).json({ message: "Recipient not found" });
  if (sender.balance < amount)
    return res.status(400).json({ message: "Insufficient funds" });

  // update balances
  sender.balance -= amount;
  recipient.balance += amount;
  await sender.save();
  await recipient.save();

  // record transactions
  await Transaction.create({
    from: sender.email,
    to: recipient.email,
    amount,
    type: "send",
  });
  await Transaction.create({
    from: sender.email,
    to: recipient.email,
    amount,
    type: "receive",
  });

  res.json({ ok: true });
});

// Default
app.get("/", (req, res) => res.json({ message: "CaribPay backend running" }));

/* ====== CONNECT + START ====== */
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((e) => console.error("MongoDB error", e));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`🚀 CaribPay backend running on port ${PORT}`)
);
