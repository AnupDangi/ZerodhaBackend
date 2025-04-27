// require("dotenv").config();
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcryptjs");
// const User = require("../models/UserModel");
// const { createSecretToken } = require("../utils/SecretToken");

// exports.Signup = async (req, res) => {
//   try {
//     const { email, password, username } = req.body;
//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(409).json({ success: false, message: "User already exists" });

//     const user = await User.create({ email, password, username });
//     const token = createSecretToken(user._id);

//     res.cookie("token", token, {
//       httpOnly: true,
//       sameSite: "lax", // use lax for localhost
//       secure: false,   // secure: false for http localhost
//       maxAge: 24 * 60 * 60 * 1000,
//     });

//     res.status(201).json({ success: true, message: "Signed up", user: { id: user._id, username: user.username } });
//   } catch (err) {
//     console.error("Signup error:", err);
//     res.status(500).json({ success: false, message: "Server error" });
//   }
// };

// exports.Login = async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ success: false, message: "Missing fields" });

//     const user = await User.findOne({ email });
//     if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

//     const isPasswordValid = await bcrypt.compare(password, user.password);
//     if (!isPasswordValid) return res.status(401).json({ success: false, message: "Invalid credentials" });

//     const token = createSecretToken(user._id);

//     res.cookie("token", token, {
//       httpOnly: true,
//       sameSite: "lax", // Important: lax mode for local testing
//       secure: false,
//       maxAge: 24 * 60 * 60 * 1000,
//     });

//     res.json({ success: true, message: "Logged in", user: { id: user._id, username: user.username } });
//   } catch (err) {
//     console.error("Login error:", err);
//     res.status(500).json({ success: false, message: "Server error" });
//   }
// };

// exports.userVerification = async (req, res) => {
//   try {
//     const token = req.cookies.token;
//     if (!token) return res.status(401).json({ status: false, message: "No token" });

//     const decoded = jwt.verify(token, process.env.TOKEN_KEY);
//     const user = await User.findById(decoded.id).select("username");
//     if (!user) return res.status(404).json({ status: false, message: "User not found" });

//     res.json({ status: true, user: { id: user._id, username: user.username } });
//   } catch (err) {
//     console.error("Verification error:", err);
//     res.status(401).json({ status: false, message: "Invalid token" });
//   }
// };

// exports.logout = (req, res) => {
//   res.cookie("token", "", {
//     httpOnly: true,
//     sameSite: "lax",
//     secure: false,
//     maxAge: 0,
//   });
//   res.json({ success: true, message: "Logged out" });
// };

require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/UserModel");
const { createSecretToken } = require("../utils/SecretToken");

exports.Signup = async (req, res) => {
  try {
    const { email, password, username } = req.body;

    // Check for missing fields
    if (!email || !password || !username) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    // Hash password before storing
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({ email, password: hashedPassword, username });

    // Create JWT token
    const token = createSecretToken(user._id);

    // Set cookie with token
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: 'None', // Allow cross-origin cookies (for production)
      secure: true,     // Only send over HTTPS (for production)
      maxAge: 24 * 60 * 60 * 1000,  // 1 day expiration
    });

    // Respond with user data
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

exports.Login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for missing fields
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Create JWT token
    const token = createSecretToken(user._id);

    // Set cookie with token
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: 'None', // Allow cross-origin cookies (for production)
      secure: true,     // Only send over HTTPS (for production)
      maxAge: 24 * 60 * 60 * 1000,  // 1 day expiration
    });

    // Respond with user data
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

exports.userVerification = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ status: false, message: "No token" });

    // Verify the token
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const user = await User.findById(decoded.id).select("username");

    if (!user) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    // Return user details if verification is successful
    res.json({ status: true, user: { id: user._id, username: user.username } });
  } catch (err) {
    console.error("Verification error:", err);
    res.status(401).json({ status: false, message: "Invalid token" });
  }
};

exports.logout = (req, res) => {
  // Clear the cookie to log the user out
  res.cookie("token", "", {
    httpOnly: true,
    sameSite: 'None',  // Allow cross-origin cookies (for production)
    secure: true,      // Only send over HTTPS (for production)
    maxAge: 0,         // Expire immediately
  });

  res.json({ success: true, message: "Logged out successfully" });
};
