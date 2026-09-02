import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes

    max: 5, // maximum 5 requests

    message: {
        success: false,
        message: "Too many requests. Please try again later."
    },

    standardHeaders: true,
    legacyHeaders: false
});