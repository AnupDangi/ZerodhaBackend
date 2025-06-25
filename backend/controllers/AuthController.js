require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/UserModel");
const { createSecretToken } = require("../utils/SecretToken");

const cookieConfig = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  maxAge: 24 * 60 * 60 * 1000, // 1 day
};

// --- SIGNUP ---
exports.Signup = async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({ email, password: hashedPassword, username });

    const token = createSecretToken(user._id);
    res.cookie("token", token, cookieConfig);

    res.status(201).json({
      success: true,
      message: "Signed up successfully",
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// --- LOGIN ---
exports.Login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: "Email doesnot exists" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("LOGIN: Trying user", user.email);
  console.log("Input password:", password);
  console.log("Stored hash:", user.password);
  console.log("Password valid?", isPasswordValid);

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = createSecretToken(user._id);
    res.cookie("token", token, cookieConfig);

    res.json({
      success: true,
      message: "Logged in successfully",
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// --- VERIFY USER ---
exports.userVerification = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ status: false, message: "No token" });

    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const user = await User.findById(decoded.id).select("username");

    if (!user) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    res.json({ status: true, user: { id: user._id, username: user.username } });
  } catch (err) {
    console.error("Verification error:", err);
    res.status(401).json({ status: false, message: "Invalid token" });
  }
};

// --- LOGOUT ---
exports.logout = (req, res) => {
  res.cookie("token", "", {
    ...cookieConfig,
    maxAge: 0,
  });

  res.json({ success: true, message: "Logged out successfully" });
};
