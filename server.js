// server.mjs — CaribPay minimal backend (ESM / Render-ready)
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const {
  PORT = 10000,
  MONGO_URI,
  JWT_SECRET = "change-me",
  NODE_ENV = "production",
} = process.env;

if (!MONGO_URI) {
  console.error("❌ Missing MONGO_URI in environment");
  process.exit(1);
}
if (!JWT_SECRET || JWT_SECRET === "change-me") {
  console.warn("⚠️  Using default JWT secret. Set JWT_SECRET in Render env vars.");
}

// ----- Mongo -----
await mongoose.connect(MONGO_URI, { dbName: "caribpay" });
console.log("✅ MongoDB connected");

const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 100.0 },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ----- App -----
const app = express();
app.use(cors());
app.use(express.json());

// Health
app.get("/", (_req, res) => res.json({ ok: true, service: "caribpay-backend", env: NODE_ENV }));

// Auth: register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: "User already exists" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash, balance: 100.0 });
    const token = jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
    return res.json({ token, user: { email: user.email, balance: user.balance } });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// Auth: login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign({ uid: user._id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
    return res.json({ token, user: { email: user.email, balance: user.balance } });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// Middleware to require auth
function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const [, token] = h.split(" ");
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Me
app.get("/api/auth/me", requireAuth, async (req, res) => {
  const user = await User.findById(req.user.uid).lean();
  if (!user) return res.status(404).json({ message: "User not found" });
  return res.json({ email: user.email, balance: user.balance });
});

// Demo transactions list (static)
app.get("/api/tx/list", requireAuth, (_req, res) => {
  const now = new Date();
  const iso = (d) => new Date(d).toISOString();
  res.json({
    items: [
      { id: "t1", type: "receive", amount: 120.0, from: "A. Roberts", at: iso(now) },
      { id: "t2", type: "send", amount: 8.99, to: "Transit Top-up", at: iso(now) },
      { id: "t3", type: "send", amount: 25.5, to: "Cafe", at: iso(now) },
    ],
  });
});

// 404
app.use((_req, res) => res.status(404).json({ message: "Not found" }));

app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
