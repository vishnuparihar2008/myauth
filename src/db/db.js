import mongoose from "mongoose";

const DB_URI = process.env.MONGO_URI;
const connectDB = async () => {
  mongoose.connect(DB_URI);
  console.log("Connected to Database.");
};

export default connectDB;
