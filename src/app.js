import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth.routes.js";
import morgan from "morgan";

const app = express();
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRouter);

export default app;
