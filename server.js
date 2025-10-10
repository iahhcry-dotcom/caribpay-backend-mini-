// server.js — CaribPay backend (Express + MongoDB + JWT)
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ---- env (Render injects these) ----
const {
  MONGO_URI,
  JWT_SECRET = "changeme",
  NODE_ENV = "production",
} = process.env;

const app = express();

// ---- CORS (allow Snack & dev) ----
app.use(
  cors({
    origin: [
      "https://snack.expo.dev",
      "https://preview.snack.expo.dev",
      "http://localhost:19006",
      "http://localhost:5173",
      "http://localhost:3000",
      "*",
    ],
  })
);

// ---- JSON parsing ----
app.use(express.json());

// ---- Mongo connect ----
mongoose
  .connect(MONGO_URI, { dbName: "caribpay" })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("Mongo connect error:", err.message);
    process.exit(1);
  });

// ---- Models ----
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    password: { type: String, required: true }, // hashed
    createdAt: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

// hash password on create / change
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (e) {
    next(e);
  }
});

const User = mongoose.model("User", userSchema);

const txSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    type: { type: String, enum: ["send", "receive"], required: true },
    amount: { type: Number, required: true },
    to: String,
    from: String,
  },
  { timestamps: true, versionKey: false }
);

const Transaction = mongoose.model("Transaction", txSchema);

// ---- helpers ----
function sign(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ---- routes ----

// health/info
app.get("/", (req, res) => {
  res.json({
    name: "CaribPay backend",
    status: "ok",
    env: NODE_ENV,
    routes: [
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET  /api/me (auth)",
      "GET  /api/transactions (auth)",
    ],
  });
});

// register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const user = await User.create({ email, password });

    // Optional: seed a couple of example transactions for new users
    await Transaction.insertMany([
      {
        userId: user._id,
        type: "send",
        amount: 25.5,
        to: "Cafe",
      },
      {
        userId: user._id,
        type: "receive",
        amount: 120.0,
        from: "A. Roberts",
      },
      {
        userId: user._id,
        type: "send",
        amount: 8.99,
        to: "Transit Top-up",
      },
    ]);

    return res.json({ token: sign(user) });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    return res.json({ token: sign(user) });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// current user + computed balance
app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) return res.status(404).json({ message: "User not found" });

    // compute balance from transactions
    const txs = await Transaction.find({ userId: user._id }).lean();
    const balance = txs.reduce((acc, t) => {
      if (t.type === "receive") return acc + t.amount;
      if (t.type === "send") return acc - t.amount;
      return acc;
    }, 0);

    res.json({
      email: user.email,
      createdAt: user.createdAt,
      balance: Math.round(balance * 100) / 100,
    });
  } catch (e) {
    console.error("me error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// recent transactions for the user
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "15", 10), 50);
    const txs = await Transaction.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    res.json(
      txs.map((t) => ({
        id: t._id,
        type: t.type,
        amount: t.amount,
        to: t.to,
        from: t.from,
        createdAt: t.createdAt,
      }))
    );
  } catch (e) {
    console.error("transactions error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// 404
app.use((req, res) => res.status(404).json({ message: "Not found" }));

// start
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`CaribPay backend running on port ${PORT}`)
);
