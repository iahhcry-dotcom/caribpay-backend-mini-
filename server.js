import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "caribpaysecret";

app.use(cors());
app.use(express.json());

// ✅ MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ✅ User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model("User", userSchema);

// ✅ Health check route
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ✅ Register route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Login route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
