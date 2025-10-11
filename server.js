// server.js  — CaribPay minimal backend (CommonJS)
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

// ===== ENV =====
const {
  MONGO_URI,
  JWT_SECRET = "devsecret",
  NODE_ENV = "production",
  PORT = 10000,
} = process.env;

// ===== DB =====
mongoose.set("strictQuery", true);
mongoose
  .connect(MONGO_URI, { dbName: "caribpay" })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((e) => {
    console.error("❌ Mongo error:", e.message);
    process.exit(1);
  });

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, index: true, required: true },
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 100.0 },
  },
  { timestamps: true }
);

const TxSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true },
    to: String,
    from: String,
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Tx = mongoose.model("Tx", TxSchema);

// Seed a test user once
async function seedUser() {
  const email = "arkim.robertson1@gmail.com"; // keep your email if you want
  const pass = "caribpay123";
  const found = await User.findOne({ email });
  if (!found) {
    const passwordHash = await bcrypt.hash(pass, 10);
    await User.create({ email, passwordHash, balance: 100 });
    console.log("🌱 Seeded user:", email, "/", pass);
  } else {
    console.log("🔁 Test user already exists");
  }
}
seedUser().catch(console.error);

// ===== APP =====
const app = express();
app.use(cors());
app.use(express.json());
if (NODE_ENV !== "production") app.use(morgan("dev"));

// Health / welcome
app.get("/", (req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// ===== Helpers =====
function sign(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "30d",
  });
}

async function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(payload.id);
    if (!req.user) return res.status(401).json({ message: "Unauthorized" });
    next();
  } catch (e) {
    res.status(401).json({ message: "Unauthorized" });
  }
}

// ===== Auth =====
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User exists" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash, balance: 100 });
    return res.json({ token: sign(user), user: { email: user.email, balance: user.balance } });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const ok = await bcrypt.compare(password || "", user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    res.json({ token: sign(user), user: { email: user.email, balance: user.balance } });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  const { email, balance } = req.user;
  res.json({ user: { email, balance } });
});

// ===== Transactions (demo data) =====
app.get("/api/tx/list", auth, async (req, res) => {
  // Return recent tx (seed simple demo if none)
  let list = await Tx.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(20);
  if (!list.length) {
    list = await Tx.create([
      { userId: req.user._id, type: "receive", amount: 120, from: "A. Roberts" },
      { userId: req.user._id, type: "send", amount: 8.99, to: "Transit Top-up" },
      { userId: req.user._id, type: "send", amount: 25.5, to: "Cafe" },
    ]);
  }
  res.json({
    items: list.map((t) => ({
      id: t._id,
      type: t.type,
      amount: t.amount,
      to: t.to,
      from: t.from,
      createdAt: t.createdAt,
    })),
  });
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
