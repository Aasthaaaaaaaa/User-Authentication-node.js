const mongoose = require ("mongoose");
const connectToMongo = async()=>{
await mongoose.connect("mongodb://localhost:27017/Task1");
}

console.log("connection was successfull")

module.exports = connectToMongo;

