const { model } = require("mongoose");
const { Schema } = require("mongoose");

const HoldingSchema = new Schema({
  name: String,
  qty: Number,
  avg: Number,
  price: Number,
  net: String,
  day: String,
});

const HoldingsModel = model("Holding", HoldingSchema);  // Correct model registration
module.exports = { HoldingsModel };
