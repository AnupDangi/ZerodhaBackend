const {model}=require("mongoose");
const {Schema}=require("mongoose");

const OrderSchema=new Schema({
    name:String,
    qty:Number,
    price:Number,
    mode:String,
});

const OrderModel=model("order",OrderSchema);

module.exports={OrderModel};