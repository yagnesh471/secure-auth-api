import express from "express";

import authMiddleware from "../middleware/authMiddleware.js";
import authorizeRoles from "../middleware/authorize.js";

const router = express.Router();

router.get(
    "/dashboard",
    authMiddleware,
    authorizeRoles("admin"),
    (req, res) => {
        res.status(200).json({
            success: true,
            message: "Welcome to admin dashboard"
        });
    }
);

export default router;