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

// Helper function to sanitize input
const sanitizeInput = (input) => {
  return input ? input.toString().trim() : '';
};
// --- SIGNUP WITH DETAILED LOGGING ---
exports.Signup = async (req, res) => {
  try {
    console.log("=== SIGNUP DEBUG ===");
    console.log("Raw request body:", req.body);
    
    const email = req.body.email?.trim();
    const password = req.body.password?.trim();
    const username = req.body.username?.trim();
    
    // console.log("Processed inputs:", {
    //   email,
    //   username,
    //   password: password, // Show actual password for debugging
    //   passwordLength: password?.length
    // });

    if (!email || !password || !username) {
      console.log("Missing fields validation failed");
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log("User already exists");
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    // console.log("About to hash password:", password);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    console.log("Password hashed successfully, hash starts with:", hashedPassword.substring(0, 20) + "...");

    const user = await User.create({ email, password: hashedPassword, username });
    // console.log("User created with ID:", user._id);

    // const token = createSecretToken(user._id);
    res.cookie("token", token, cookieConfig);

    console.log("=== SIGNUP SUCCESS ===");
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
    // Sanitize inputs consistently
    const email = sanitizeInput(req.body.email);
    const password = sanitizeInput(req.body.password);

    console.log("Login attempt:", { email, hasPassword: !!password });

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Email and password are required" 
      });
    }

    // Find user (case-insensitive)
    const user = await User.findOne({ 
      email: { $regex: new RegExp(`^${email}$`, 'i') }
    });

    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ 
        success: false, 
        message: "Invalid email or password" 
      });
    }

    // console.log("User found, comparing passwords...");
    
    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    // console.log("Password comparison result:", isPasswordValid);

    if (!isPasswordValid) {
      console.log("Password validation failed for:", email);
      return res.status(401).json({ 
        success: false, 
        message: "Invalid email or password" 
      });
    }

    // Generate token
    const token = createSecretToken(user._id);
    
    // Set cookie
    res.cookie("token", token, cookieConfig);

    console.log("Login successful for:", user.email);

    res.json({
      success: true,
      message: "Logged in successfully",
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email 
      },
      token // Include token in response for localStorage
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Server error during login" 
    });
  }
};

// --- VERIFY USER ---
exports.userVerification = async (req, res) => {
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "No authentication token" 
      });
    }

    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const user = await User.findById(decoded.id).select("username email");
    
    if (!user) {
      return res.status(404).json({ 
        status: false, 
        message: "User not found" 
      });
    }

    res.json({ 
      status: true, 
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email 
      } 
    });

  } catch (err) {
    console.error("Verification error:", err);
    res.status(401).json({ 
      status: false, 
      message: "Invalid or expired token" 
    });
  }
};

// --- LOGOUT ---
exports.logout = (req, res) => {
  res.cookie("token", "", {
    ...cookieConfig,
    maxAge: 0,
  });
  res.json({ 
    success: true, 
    message: "Logged out successfully" 
  });
};
