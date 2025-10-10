// server.js — CaribPay mini backend (CommonJS)

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const helmet = require("helmet");

// ===== ENV =====
const {
  MONGO_URI,
  JWT_SECRET = "change-me",
  NODE_ENV = "production",
  PORT = process.env.PORT || 10000,
} = process.env;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI is not set");
}
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is not set");
}

const app = express();

// ===== MIDDLEWARE =====
app.use(helmet());
app.use(
  cors({
    origin: "*", // limit to your Snack/website later
  })
);
app.use(express.json());
app.use(morgan(NODE_ENV === "production" ? "combined" : "dev"));

// ===== DB =====
mongoose
  .connect(MONGO_URI, {
    // these options are OK on modern drivers
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
  });

const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ===== HELPERS =====
function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function cleanEmail(e) {
  return (e || "").trim().toLowerCase();
}

// ===== ROUTES =====

// Health + base
app.get("/", (_req, res) => res.type("text").send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true, uptime: process.uptime() }));

// Create account
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });

    // (Optionally email a welcome message here)
    return res.status(201).json({ id: user._id, email: user.email });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // bcrypt.compare requires two strings — ensure both are strings
    const match = await bcrypt.compare(password, user.passwordHash || "");
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = signToken(user);
    return res.json({ token });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// DEBUG route (optional) — enable from client with USE_DEBUG=true
app.post("/api/auth/login-test", (req, res) => {
  try {
    const email = cleanEmail(req.body.email) || "test@example.com";
    const token = jwt.sign({ email, demo: true }, JWT_SECRET, { expiresIn: "1h" });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Not found
app.use((req, res) => res.status(404).json({ message: "Not found" }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Server error" });
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
