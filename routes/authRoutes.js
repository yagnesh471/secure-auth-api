import express from "express";
import { registerUser,verifyOTP,resendOTP,loginUser,getProfile,refreshAccessToken,logoutUser,getSessions,revokeSession,revokeAllSessions} from "../controllers/authController.js";
import authMiddleware from "../middleware/authMiddleware.js";
import { validate } from "../middleware/validate.js";
import { authLimiter } from "../middleware/rateLimiter.js"
import { registerSchema,verifyOTPSchema,loginSchema} from "../middleware/authValidation.js"
import {forgotPassword,resetPassword,changePassword} from "../controllers/authController.js";
import {forgotPasswordSchema,resetPasswordSchema,changePasswordSchema} from "../validators/authValidator.js";

const router = express.Router();

router.post("/register",authLimiter,validate(registerSchema),validate(verifyOTPSchema));
router.post("/verify-otp",authLimiter,validate(verifyOTPSchema),verifyOTP);
router.post("/resend-otp",resendOTP);
router.post("/login",authLimiter,validate(loginSchema),loginUser);
router.post("/refresh",authLimiter,refreshAccessToken);
router.post("/logout", logoutUser);

router.get("/profile", authMiddleware, getProfile);

router.get("/sessions",authMiddleware,getSessions);
router.delete("/sessions/all",authMiddleware,revokeAllSessions);
router.delete("/sessions/:sessionId",authMiddleware,revokeSession);


router.post("/forgot-password",validate(forgotPasswordSchema),forgotPassword);
router.post("/reset-password",validate(resetPasswordSchema),resetPassword);
router.patch("/change-password",authMiddleware,validate(changePasswordSchema),changePassword);

export default router;