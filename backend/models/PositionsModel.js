const {model}=require("mongoose");
const {Schema} =require("mongoose");

const PositionsSchema=new Schema({
    product: String,
    name: String,
    qty: Number,
    avg: Number,
    price: Number,
    net: String,
    day: String,
    isLoss:Boolean,
});
const PositionModel=model("position",PositionsSchema);

module.exports={PositionModel};