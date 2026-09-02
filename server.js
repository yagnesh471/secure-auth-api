import express from "express";
import connectDB from "./config/db.js"
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";

dotenv.config();
connectDB();



const app = express();
app.use(helmet());
app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true
    })
);
app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/users", userRoutes);

app.get("/api/health", (req, res) => {
    res.status(200).json({
        success: true,
        message: "API is healthy"
    });
});


import cron from "node-cron";

import { cleanupExpiredSessions }
    from "./utils/cleanupSessions.js";

import { cleanupExpiredRefreshTokens }
    from "./utils/cleanupRefreshTokens.js";

import { cleanupExpiredTokenFamilies }
    from "./utils/cleanupTokenFamilies.js";

cron.schedule("0 * * * *", async () => {

    console.log("Running authentication cleanup...");

    await cleanupExpiredSessions();

    await cleanupExpiredRefreshTokens();

    await cleanupExpiredTokenFamilies();

});

app.listen(5000, () => {
    console.log("Server running on port 5000");
});


