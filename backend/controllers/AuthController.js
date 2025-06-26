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
    const email = req.body.email.trim();
    const password = req.body.password.trim();
    const username = req.body.username.trim();

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

// --- LOGIN with enhanced debugging ---
exports.Login = async (req, res) => {
  try {
    console.log("Login attempt - Raw body:", req.body);
    
    const email = req.body.email?.trim();
    const password = req.body.password?.trim();
    
    console.log("Login attempt - Cleaned:", { email, password: password ? "***" : "empty" });
    
    if (!email || !password) {
      console.log("Missing fields - email:", !!email, "password:", !!password);
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    console.log("Searching for user with email:", email);
    const user = await User.findOne({ email });
    
    if (!user) {
      console.log("User not found for email:", email);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    
    console.log("User found:", { id: user._id, email: user.email, hasPassword: !!user.password });
    console.log("Stored password hash:", user.password);
    console.log("Input password:", password);
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password comparison result:", isPasswordValid);
    
    if (!isPasswordValid) {
      console.log("Password validation failed");
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = createSecretToken(user._id);
    res.cookie("token", token, cookieConfig);
    
    console.log("Login successful for user:", user.email);
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
