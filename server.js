// server.js — CaribPay (CommonJS)
const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();

// ---------- config ----------
const PORT = process.env.PORT || 10000;
const FRONTEND_RESET_URL = process.env.FRONTEND_RESET_URL || "https://snack.expo.dev";
const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;         // e.g. caribpay@gmail.com
const SMTP_PASS = process.env.SMTP_PASS;         // Gmail APP PASSWORD (not your normal pw)
const MAIL_FROM  = process.env.MAIL_FROM || "CaribPay <no-reply@caribpay.com>";

// ---------- middleware ----------
app.use(cors());
app.use(express.json());

// health / root
app.get("/", (req, res) => {
  res.json({ message: "Welcome to CaribPay API" });
});

// ---------- password reset (POST /api/auth/forgot) ----------
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || typeof email !== "string") {
      return res.status(400).json({ message: "Email is required" });
    }

    // In a real app you’d look up the user and create a signed token.
    // For now we send a simple link with a placeholder token.
    const resetLink = `${FRONTEND_RESET_URL}/reset?token=demo-token&email=${encodeURIComponent(email)}`;

    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465, // true for 465, false for 587
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    await transporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "CaribPay password reset",
      text: `Tap this link to reset your CaribPay password: ${resetLink}`,
      html: `<p>Tap this link to reset your CaribPay password:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
    });

    res.json({ message: "Email sent successfully" });
  } catch (err) {
    console.error("Forgot error:", err);
    res.status(500).json({ message: "Email failed to send" });
  }
});

// 404 fallback
app.use((req, res) => res.status(404).json({ message: "Not found" }));

// start
app.listen(PORT, () => {
  console.log(`🚀 CaribPay backend running on port ${PORT}`);
});
