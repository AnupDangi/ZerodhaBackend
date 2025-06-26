require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const { HoldingsModel } = require("./models/HoldingsModel");
const { PositionModel } = require("./models/PositionsModel");
const { OrderModel } = require("./models/OrdersModel");
const port = process.env.port || 5000;
const MONGOURL = process.env.MONGO_URL;
const bodyParser = require("body-parser");
const cors = require("cors");
const authRoute = require("./Routes/AuthRoute");
const cookieParser = require("cookie-parser");

app.use(
  cors({
    // origin: ["http://localhost:5173", "http://localhost:5174"],
    origin: [
      "https://zerodha-clone-ykwn.vercel.app", // frontend
      "https://dashboard-lemon-phi-34.vercel.app",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(cookieParser());

app.use(bodyParser.json());
app.use(cookieParser());

try {
  mongoose
    .connect(MONGOURL)
    .then(console.log("db connected"))
    .catch("error occured");
} catch (err) {
  console.log("error while connecting database");
}

app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  if (req.headers.authorization) {
    console.log("Authorization header present");
  }
  next();
});


app.get("/", (req, res) => {
  res.send("This is root");
});
app.use("/auth", authRoute);

app.get("/allHoldings", async (req, res) => {
  let allHoldings = await HoldingsModel.find({});
  console.log("received holdings data");
  res.json(allHoldings);
});

app.get("/allPositions", async (req, res) => {
  let allPostions = await PositionModel.find({});
  console.log("received positions data");
  res.json(allPostions);
});

app.post("/newOrder", async (req, res) => {
  console.log(req.body);
  try {
    let newOrder = new OrderModel({
      name: req.body.name,
      qty: req.body.qty,
      price: req.body.price,
      mode: req.body.mode,
    });
    await newOrder.save();
    res.send("Order saved");
  } catch (err) {
    console.error("Error saving order:", err);
    res.status(500).send("Failed to save order");
  }
});

app.listen(port, () => {
  console.log(`Server is listening to http://localhost:${port}`);
});
