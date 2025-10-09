// server.js  — CaribPay mini backend (auth + transactions + send money)
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

// ---- ENV ----
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI;         // set on Render
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// ---- DB ----
mongoose
  .connect(MONGO_URI, { dbName: "caribpay" })
  .then(() => console.log("MongoDB connected"))
  .catch((e) => {
    console.error("Mongo error", e.message);
    process.exit(1);
  });

// ---- MODELS ----
const UserSchema = new mongoose.Schema(
  { email: { type: String, unique: true, index: true }, password: String },
  { timestamps: true }
);
const User = mongoose.model("User", UserSchema);

const TransactionSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true },
    from: { type: String, required: true },
    to: { type: String, required: true },
    note: String,
  },
  { timestamps: true }
);
const Transaction = mongoose.model("Transaction", TransactionSchema);

// ---- AUTH HELPERS ----
function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    if (!token) return res.status(401).json({ message: "Missing token" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id, email: payload.email };
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ---- ROUTES ----
app.get("/", (_req, res) => res.json({ ok: true, name: "CaribPay API" }));

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash });
    const token = signToken(user);
    return res.json({ token, email: user.email });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    const token = signToken(user);
    return res.json({ token, email: user.email });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

// List transactions for current user (sent OR received)
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const email = req.user.email;
    const items = await Transaction.find({
      $or: [{ from: email }, { to: email }],
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    return res.json({ items });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

// NEW: Send money
app.post("/api/transactions/send", auth, async (req, res) => {
  try {
    let { to, amount, note } = req.body || {};
    if (!to || !amount) return res.status(400).json({ message: "Recipient and amount required" });

    amount = Number(amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ message: "Amount must be a positive number" });
    }

    const tx = await Transaction.create({
      type: "send",
      from: req.user.email,
      to,
      amount,
      note: note || "",
    });

    return res.status(201).json({ ok: true, item: tx });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => console.log(`CaribPay backend running on port ${PORT}`));
