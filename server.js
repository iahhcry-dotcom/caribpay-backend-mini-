// server.mjs — CaribPay backend (ESM)
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import morgan from "morgan";

// ---- ENV ----
const {
  MONGO_URI,
  JWT_SECRET = "dev_secret_change_me",
  PORT = process.env.PORT || 10000,
} = process.env;

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(morgan("tiny"));

// ---- DB ----
if (!MONGO_URI) {
  console.error("❌ Missing MONGO_URI");
  process.exit(1);
}
await mongoose.connect(MONGO_URI);
console.log("✅ MongoDB connected");

// ---- MODELS ----
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 100.0 },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const txnSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true },
    to: String,
    from: String,
  },
  { timestamps: true }
);
const Txn = mongoose.model("Txn", txnSchema);

// ---- AUTH HELPERS ----
const signToken = (user) =>
  jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

// ---- ROUTES ----
app.get("/", (_req, res) => res.json({ ok: true, version: "esm" }));

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Email & password required" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash });

    // seed demo data
    await Txn.insertMany([
      { userId: user._id, type: "receive", amount: 120, from: "A. Roberts" },
      { userId: user._id, type: "send", amount: 25.5, to: "Cafe" },
      { userId: user._id, type: "send", amount: 8.99, to: "Transit Top-up" },
    ]);

    res.status(201).json({ message: "Registered" });
  } catch (e) {
    console.error("register:", e);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Email & password required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken(user);
    res.json({ token, email: user.email, balance: user.balance ?? 0 });
  } catch (e) {
    console.error("login:", e);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/transactions", auth, async (req, res) => {
  try {
    const items = await Txn.find({ userId: req.user.uid })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();
    res.json({ items });
  } catch (e) {
    console.error("txns:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// ---- START ----
app.listen(PORT, () => console.log(`🚀 CaribPay backend running on port ${PORT}`));
