const express = require("express");
const router = express.Router();
const {
  Signup,
  Login,
  logout,
  userVerification,
} = require("../controllers/AuthController");

router.post("/signup", Signup);
router.post("/login", Login);
router.post("/logout",logout);
router.get("/userVerification", userVerification);

module.exports = router;
