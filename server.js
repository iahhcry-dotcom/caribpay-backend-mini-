// server.js — CaribPay backend (Render-ready)
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import morgan from "morgan";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// ===== DATABASE =====
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://admin:admin@cluster0.mongodb.net/caribpay";

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// ===== MODELS =====
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  balance: { type: Number, default: 100 },
});

const txSchema = new mongoose.Schema({
  from: String,
  to: String,
  amount: Number,
  type: String, // "in" or "out"
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", txSchema);

// ===== MIDDLEWARE =====
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

// ===== ROUTES =====
app.get("/", (req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email, passwordHash: hash, balance: 100 });
    await user.save();

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET || "secret123", {
      expiresIn: "7d",
    });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET || "secret123", {
      expiresIn: "7d",
    });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// ME
app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ email: user.email, balance: user.balance });
});

// TRANSFER
app.post("/api/transfer", auth, async (req, res) => {
  try {
    const { to, amount } = req.body;
    const fromUser = await User.findById(req.user.id);
    const toUser = await User.findOne({ email: to });

    if (!toUser) return res.status(404).json({ message: "Recipient not found" });
    if (fromUser.balance < amount)
      return res.status(400).json({ message: "Insufficient funds" });

    fromUser.balance -= amount;
    toUser.balance += amount;
    await fromUser.save();
    await toUser.save();

    await Transaction.create([
      { from: fromUser.email, to: toUser.email, amount, type: "out" },
      { from: fromUser.email, to: toUser.email, amount, type: "in" },
    ]);

    res.json({ message: "Transfer complete" });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// TRANSACTIONS
app.get("/api/transactions", auth, async (req, res) => {
  const me = await User.findById(req.user.id);
  const list = await Transaction.find({
    $or: [{ from: me.email }, { to: me.email }],
  }).sort({ createdAt: -1 });
  res.json(list);
});

// ===== TEST USER CREATION =====
const ensureTestUser = async () => {
  const email = "arkim.robertson1@gmail.com";
  const exists = await User.findOne({ email });
  if (!exists) {
    const hash = await bcrypt.hash("123456", 10);
    await User.create({ email, passwordHash: hash, balance: 85.51 });
    console.log(`✅ Test user created: ${email} / 123456`);
  } else {
    console.log("✅ Test user already exists");
  }
};

// ===== SERVER START =====
const PORT = process.env.PORT || 10000;
mongoose.connection.once("open", async () => {
  await ensureTestUser();
  app.listen(PORT, () => {
    console.log(`🚀 CaribPay backend running on port ${PORT}`);
  });
});
