const jwt = require("jsonwebtoken");

module.exports.createSecretToken = (id) => {
  // Check if TOKEN_KEY is set
  if (!process.env.TOKEN_KEY) {
    console.error("WARNING: TOKEN_KEY is not set in environment variables!");
  }

  return jwt.sign({ id }, process.env.TOKEN_KEY, {
    expiresIn: "24h"
  });
};