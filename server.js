// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// === CONFIG ===
const PORT = process.env.PORT || 10000;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://caribpay:caribpay123@cluster0.mongodb.net/caribpay";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretjwtkey";

// === CONNECT DATABASE ===
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// === USER MODEL ===
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("User", UserSchema);

// === TRANSACTION MODEL ===
const TransactionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: "USD" },
    to: String,
    from: String,
    note: String,
  },
  { timestamps: true }
);
const Transaction = mongoose.model("Transaction", TransactionSchema);

// === AUTH MIDDLEWARE ===
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// === AUTH ROUTES ===

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ error: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ token, user: { email: user.email } });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { email: user.email } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// === TRANSACTION ROUTES ===

// Seed sample transactions (for test/demo)
app.post("/api/transactions/seed", auth, async (req, res) => {
  const userId = req.userId;
  const seed = [
    { userId, type: "send", amount: 25.5, to: "Cafe" },
    { userId, type: "receive", amount: 120, from: "A. Roberts" },
    { userId, type: "send", amount: 8.99, to: "Transit Top-up" },
  ];
  await Transaction.deleteMany({ userId });
  await Transaction.insertMany(seed);
  res.json({ ok: true, count: seed.length });
});

// Get recent transactions (JWT protected)
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const list = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();
    res.json({ items: list });
  } catch (err) {
    console.error("Transactions fetch error:", err);
    res.status(500).json({ error: "Failed to load transactions" });
  }
});

// === SERVER START ===
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
