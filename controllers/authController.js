import bcrypt from "bcrypt";
import User from "../models/User.js";
import PendingRegistration from "../models/PendingRegistration.js";
import { generateOTP } from "../utils/otp.js";
import { sendOTPEmail } from "../utils/email.js";
import jwt from "jsonwebtoken";
import Session from "../models/Session.js";
import {
    generateAccessToken,
    generateRefreshToken
} from "../utils/tokens.js";
import mongoose from "mongoose";
import { authLimiter } from "../middleware/rateLimiter.js";
import crypto from "crypto";
import TokenFamily from "../models/TokenFamily.js";
import RefreshToken from "../models/RefreshToken.js";
import { sendEmail } from "../utils/email.js";


export const registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email and password are required"
            });
        }

        // Normalize email
        const normalizedEmail = email.trim().toLowerCase();

        // Check if user already exists
        const existingUser = await User.findOne({
            email: normalizedEmail
        });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists"
            });
        }

        // Remove old pending registration
        const existingPending = await PendingRegistration.findOne({
            email: normalizedEmail
        });

        if (existingPending) {
            await PendingRegistration.deleteOne({
                _id: existingPending._id
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);

        // Generate OTP
        const { otp, expiresAt } = generateOTP();

        // Hash OTP
        const otpHash = await bcrypt.hash(otp, 10);

        // Save pending registration
        await PendingRegistration.create({
            name: name.trim(),
            email: normalizedEmail,
            passwordHash,
            otpHash,
            otpExpiresAt: expiresAt
        });

        await sendOTPEmail(normalizedEmail, otp);

        return res.status(200).json({
            success: true,
            message: "OTP generated successfully"
        });

    } catch (error) {
        console.error("Registration error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;

        // Validate input
        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: "Email and OTP are required"
            });
        }

        // Normalize email
        const normalizedEmail = email.trim().toLowerCase();

        // Find pending registration
        const pendingRegistration =
            await PendingRegistration.findOne({
                email: normalizedEmail
            });

        if (!pendingRegistration) {
            return res.status(404).json({
                success: false,
                message: "Registration not found or expired"
            });
        }

        // Check attempt limit
        if (pendingRegistration.otpAttempts >= 5) {
            return res.status(429).json({
                success: false,
                message: "Too many OTP attempts. Please request a new OTP."
            });
        }

        // Check expiration
        if (new Date() > pendingRegistration.otpExpiresAt) {
            return res.status(410).json({
                success: false,
                message: "OTP has expired"
            });
        }

        // Compare OTP
        const isOTPValid = await bcrypt.compare(
            otp,
            pendingRegistration.otpHash
        );

        // Wrong OTP
        if (!isOTPValid) {
            pendingRegistration.otpAttempts += 1;

            await pendingRegistration.save();

            return res.status(401).json({
                success: false,
                message: "Invalid OTP"
            });
        }

        // OTP correct → create actual user
        const user = await User.create({
            name: pendingRegistration.name,
            email: pendingRegistration.email,
            password: pendingRegistration.passwordHash
        });

        // Delete pending registration
        await PendingRegistration.deleteOne({
            _id: pendingRegistration._id
        });

        return res.status(201).json({
            success: true,
            message: "Email verified and registration completed",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("OTP verification error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const pendingRegistration =
            await PendingRegistration.findOne({
                email: normalizedEmail
            });

        if (!pendingRegistration) {
            return res.status(404).json({
                success: false,
                message: "Registration not found"
            });
        }

        const cooldown = 2 * 60 * 1000;
        const now = Date.now();

        if (pendingRegistration.lastOtpSentAt) {
            const lastSent =
                pendingRegistration.lastOtpSentAt.getTime();

            const elapsed = now - lastSent;

            if (elapsed < cooldown) {
                const remainingSeconds = Math.ceil(
                    (cooldown - elapsed) / 1000
                );

                return res.status(429).json({
                    success: false,
                    message: "Please wait before requesting another OTP",
                    retryAfter: remainingSeconds
                });
            }
        }

        // Generate new OTP
        const { otp, expiresAt } = generateOTP();

        // Hash new OTP
        const otpHash = await bcrypt.hash(otp, 10);

        // Update pending registration
        pendingRegistration.otpHash = otpHash;
        pendingRegistration.otpExpiresAt = expiresAt;
        pendingRegistration.otpAttempts = 0;
        pendingRegistration.lastOtpSentAt = new Date();

        await pendingRegistration.save();

        // Send new OTP
        await sendOTPEmail(
            normalizedEmail,
            otp
        );

        return res.status(200).json({
            success: true,
            message: "A new OTP has been sent to your email"
        });

    } catch (error) {
        console.error("Resend OTP error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const loginUser = async (req, res) => {
    try {

        // ==========================================
        // 1. Get validated data from request
        // ==========================================

        const { email, password } = req.body;


        // ==========================================
        // 2. Normalize email
        // ==========================================

        const normalizedEmail = email.toLowerCase();


        // ==========================================
        // 3. Find user
        // ==========================================

        const user = await User.findOne({
            email: normalizedEmail
        });


        // ==========================================
        // 4. Don't reveal whether email exists
        // ==========================================

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }


        // ==========================================
        // 5. Compare password
        // ==========================================

        const isPasswordValid = await bcrypt.compare(
            password,
            user.password
        );


        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }


        // ==========================================
        // 6. Generate access token
        // ==========================================

        const accessToken = generateAccessToken(
            user
        );


        // ==========================================
        // 7. Create token family
        // ==========================================

        const familyId = crypto.randomUUID();


        // ==========================================
        // 8. Create unique refresh-token ID
        // ==========================================

        const tokenId = crypto.randomUUID();


        // ==========================================
        // 9. Refresh token expiration
        // ==========================================

        const refreshTokenExpiresAt = new Date(
            Date.now() +
            7 * 24 * 60 * 60 * 1000
        );


        // ==========================================
        // 10. Create TokenFamily
        // ==========================================

        await TokenFamily.create({
            user: user._id,
            familyId,
            expiresAt: refreshTokenExpiresAt
        });


        // ==========================================
        // 11. Generate refresh token
        // ==========================================

        const refreshToken = generateRefreshToken(
            user,
            familyId,
            tokenId
        );


        // ==========================================
        // 12. Hash refresh token
        // ==========================================

        const refreshTokenHash = await bcrypt.hash(
            refreshToken,
            10
        );


        // ==========================================
        // 13. Store refresh token
        // ==========================================

        await RefreshToken.create({
            tokenId,
            familyId,
            tokenHash: refreshTokenHash,
            user: user._id,
            expiresAt: refreshTokenExpiresAt
        });


        // ==========================================
        // 14. Create login session
        // ==========================================

        await Session.create({
            user: user._id,
            familyId,
            expiresAt: refreshTokenExpiresAt,
            userAgent: req.headers["user-agent"],
            ipAddress: req.ip
        });


        // ==========================================
        // 15. Set refresh token cookie
        // ==========================================

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,

            secure:
                process.env.NODE_ENV === "production",

            sameSite: "strict",

            maxAge:
                7 * 24 * 60 * 60 * 1000
        });


        // ==========================================
        // 16. Authentication successful
        // ==========================================

        return res.status(200).json({
            success: true,
            message: "Login successful",

            accessToken,

            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {

        console.error(
            "Login error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
export const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select("-password");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        return res.status(200).json({
            success: true,
            user
        });

    } catch (error) {
        console.error("Profile error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

export const refreshAccessToken = async (req, res) => {
    try {
        // ==========================================
        // 1. Get refresh token from cookie
        // ==========================================

        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token missing"
            });
        }


        // ==========================================
        // 2. Verify refresh JWT
        // ==========================================

        let decoded;

        try {
            decoded = jwt.verify(
                refreshToken,
                process.env.JWT_REFRESH_SECRET
            );
        } catch (error) {

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });

            return res.status(401).json({
                success: false,
                message: "Invalid or expired refresh token"
            });
        }


        // ==========================================
        // 3. Validate JWT payload
        // ==========================================

        if (
            !decoded.userId ||
            !decoded.familyId ||
            !decoded.tokenId
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid refresh token"
            });
        }


        // ==========================================
        // 4. Find token family
        // ==========================================

        const tokenFamily = await TokenFamily.findOne({
            familyId: decoded.familyId
        });

        if (!tokenFamily) {
            return res.status(401).json({
                success: false,
                message: "Token family not found"
            });
        }


        // ==========================================
        // 5. Check if entire family is revoked
        // ==========================================

        if (tokenFamily.revokedAt) {

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });

            return res.status(401).json({
                success: false,
                message: "Token family has been revoked"
            });
        }


        // ==========================================
        // 6. Check family expiration
        // ==========================================

        if (tokenFamily.expiresAt < new Date()) {

            tokenFamily.revokedAt = new Date();

            await tokenFamily.save();

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });

            return res.status(401).json({
                success: false,
                message: "Refresh token family expired"
            });
        }


        // ==========================================
        // 7. Find exact refresh token
        // ==========================================

        const storedToken = await RefreshToken.findOne({
            tokenId: decoded.tokenId,
            familyId: decoded.familyId
        });

        if (!storedToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token not found"
            });
        }


        // ==========================================
        // 8. Check if token was already revoked
        // ==========================================

        if (storedToken.revokedAt) {
            return res.status(401).json({
                success: false,
                message: "Refresh token has been revoked"
            });
        }


        // ==========================================
        // 9. Check if token expired
        // ==========================================

        if (storedToken.expiresAt < new Date()) {

            storedToken.revokedAt = new Date();

            await storedToken.save();

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });

            return res.status(401).json({
                success: false,
                message: "Refresh token expired"
            });
        }


        // ==========================================
        // 10. Check if token was already used
        // ==========================================

        if (storedToken.usedAt) {

            console.log(
                "🚨 REFRESH TOKEN REUSE DETECTED"
            );

            console.log(
                "Family:",
                decoded.familyId
            );

            console.log(
                "Token:",
                decoded.tokenId
            );


            // Revoke entire token family
            tokenFamily.revokedAt = new Date();

            await tokenFamily.save();


            // Revoke all tokens in this family
            await RefreshToken.updateMany(
                {
                    familyId: decoded.familyId
                },
                {
                    revokedAt: new Date()
                }
            );


            // Clear attacker/current browser cookie
            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });


            return res.status(401).json({
                success: false,
                message:
                    "Refresh token reuse detected. All sessions revoked."
            });
        }


        // ==========================================
        // 11. Compare refresh token hash
        // ==========================================

        const isValid = await bcrypt.compare(
            refreshToken,
            storedToken.tokenHash
        );

        if (!isValid) {

            return res.status(401).json({
                success: false,
                message: "Invalid refresh token"
            });
        }


        // ==========================================
        // 12. Find user
        // ==========================================

        const user = await User.findById(
            storedToken.user
        );

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User no longer exists"
            });
        }


        // ==========================================
        // 13. Mark current token as USED
        // ==========================================

        storedToken.usedAt = new Date();

        await storedToken.save();


        // ==========================================
        // 14. Generate new token ID
        // ==========================================

        const newTokenId = crypto.randomUUID();


        // ==========================================
        // 15. Generate new access token
        // ==========================================

        const accessToken = generateAccessToken(
            user
        );


        // ==========================================
        // 16. Generate new refresh token
        // ==========================================

        const newRefreshToken =
            generateRefreshToken(
                user,
                decoded.familyId,
                newTokenId
            );


        // ==========================================
        // 17. Hash new refresh token
        // ==========================================

        const newRefreshTokenHash =
            await bcrypt.hash(
                newRefreshToken,
                10
            );


        // ==========================================
        // 18. Calculate expiration
        // ==========================================

        const expiresAt = new Date(
            Date.now() +
            7 * 24 * 60 * 60 * 1000
        );


        // ==========================================
        // 19. Store new refresh token
        // ==========================================

        await RefreshToken.create({
            tokenId: newTokenId,

            familyId: decoded.familyId,

            tokenHash: newRefreshTokenHash,

            user: user._id,

            expiresAt
        });


        // ==========================================
        // 20. Update token family expiration
        // ==========================================

        tokenFamily.expiresAt = expiresAt;

        await tokenFamily.save();


        // ==========================================
        // 21. Replace refresh-token cookie
        // ==========================================

        res.cookie(
            "refreshToken",
            newRefreshToken,
            {
                httpOnly: true,

                secure:
                    process.env.NODE_ENV === "production",

                sameSite: "strict",

                maxAge:
                    7 * 24 * 60 * 60 * 1000
            }
        );


        // ==========================================
        // 22. Return new access token
        // ==========================================

        return res.status(200).json({
            success: true,
            accessToken
        });

    } catch (error) {

        console.error(
            "Refresh token error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const logoutUser = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        // ==========================================
        // 1. Always clear refresh-token cookie
        // ==========================================

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        // ==========================================
        // 2. No refresh token
        // ==========================================

        if (!refreshToken) {
            return res.status(200).json({
                success: true,
                message: "Logged out successfully"
            });
        }

        // ==========================================
        // 3. Verify refresh JWT
        // ==========================================

        let decoded;

        try {
            decoded = jwt.verify(
                refreshToken,
                process.env.JWT_REFRESH_SECRET
            );
        } catch (error) {

            // Token is already invalid/expired.
            // Cookie has already been cleared.

            return res.status(200).json({
                success: true,
                message: "Logged out successfully"
            });
        }

        // ==========================================
        // 4. Validate JWT payload
        // ==========================================

        if (
            !decoded.familyId ||
            !decoded.tokenId
        ) {
            return res.status(200).json({
                success: true,
                message: "Logged out successfully"
            });
        }

        // ==========================================
        // 5. Find token family
        // ==========================================

        const tokenFamily = await TokenFamily.findOne({
            familyId: decoded.familyId
        });

        if (!tokenFamily) {
            return res.status(200).json({
                success: true,
                message: "Logged out successfully"
            });
        }

        // ==========================================
        // 6. Revoke entire token family
        // ==========================================

        tokenFamily.revokedAt = new Date();

        await tokenFamily.save();

        // ==========================================
        // 7. Revoke all refresh tokens
        //    belonging to this family
        // ==========================================

        await RefreshToken.updateMany(
            {
                familyId: decoded.familyId
            },
            {
                revokedAt: new Date()
            }
        );

        // ==========================================
        // 8. Return success
        // ==========================================

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });

    } catch (error) {

        console.error(
            "Logout error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};




export const getSessions = async (req, res) => {
    try {
        const sessions = await Session.find({
            user: req.user.userId,
            revokedAt: null,
            expiresAt: { $gt: new Date() }
        })
        .select("-__v")
        .sort({ createdAt: -1 });

        return res.status(200).json({
            success: true,
            sessions
        });

    } catch (error) {

        console.error(
            "Get sessions error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const revokeAllSessions = async (req, res) => {
    try {
        const userId = req.user.userId;

        // 1. Find all token families belonging to user
        const tokenFamilies = await TokenFamily.find({
            user: userId,
            revokedAt: null
        });

        // 2. If no active families
        if (tokenFamilies.length === 0) {
            return res.status(200).json({
                success: true,
                message: "All sessions already logged out"
            });
        }

        // 3. Get all family IDs
        const familyIds = tokenFamilies.map(
            (family) => family.familyId
        );

        // 4. Revoke all token families
        await TokenFamily.updateMany(
            {
                user: userId,
                revokedAt: null
            },
            {
                revokedAt: new Date()
            }
        );

        // 5. Revoke all refresh tokens
        await RefreshToken.updateMany(
            {
                familyId: {
                    $in: familyIds
                }
            },
            {
                revokedAt: new Date()
            }
        );

        // 6. Revoke all sessions
        await Session.updateMany(
            {
                user: userId,
                familyId: {
                    $in: familyIds
                }
            },
            {
                revokedAt: new Date()
            }
        );

        // 7. Clear current browser cookie
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        return res.status(200).json({
            success: true,
            message: "Logged out from all devices"
        });

    } catch (error) {

        console.error(
            "Logout all sessions error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
export const revokeSession = async (req, res) => {
    try {
        const { sessionId } = req.params;

        const userId = req.user.userId;

        // ==========================================
        // 1. Find session belonging to this user
        // ==========================================

        const session = await Session.findOne({
            _id: sessionId,
            user: userId
        });

        if (!session) {
            return res.status(404).json({
                success: false,
                message: "Session not found"
            });
        }

        // ==========================================
        // 2. Check if already revoked
        // ==========================================

        if (session.revokedAt) {
            return res.status(400).json({
                success: false,
                message: "Session already revoked"
            });
        }

        // ==========================================
        // 3. Revoke token family
        // ==========================================

        await TokenFamily.findOneAndUpdate(
            {
                familyId: session.familyId,
                user: userId
            },
            {
                revokedAt: new Date()
            }
        );

        // ==========================================
        // 4. Revoke all refresh tokens
        //    belonging to this family
        // ==========================================

        await RefreshToken.updateMany(
            {
                familyId: session.familyId,
                user: userId
            },
            {
                revokedAt: new Date()
            }
        );

        // ==========================================
        // 5. Revoke session
        // ==========================================

        session.revokedAt = new Date();

        await session.save();

        // ==========================================
        // 6. Check whether this is the current
        //    browser's session
        // ==========================================

        const currentRefreshToken =
            req.cookies.refreshToken;

        if (currentRefreshToken) {

            try {
                const decoded = jwt.verify(
                    currentRefreshToken,
                    process.env.JWT_REFRESH_SECRET
                );

                if (
                    decoded.familyId ===
                    session.familyId
                ) {
                    res.clearCookie(
                        "refreshToken",
                        {
                            httpOnly: true,
                            secure:
                                process.env.NODE_ENV ===
                                "production",
                            sameSite: "strict"
                        }
                    );
                }

            } catch (error) {
                // Token is already invalid/expired.
                // Nothing else needs to be done.
            }
        }

        // ==========================================
        // 7. Response
        // ==========================================

        return res.status(200).json({
            success: true,
            message: "Session revoked successfully"
        });

    } catch (error) {

        console.error(
            "Revoke session error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({
            email
        });


        if (!user) {
            return res.status(200).json({
                success: true,
                message:
                    "If an account exists with this email, a password reset link has been sent."
            });
        }

        // Generate random reset token
        const resetToken = crypto.randomBytes(32).toString("hex");

        // Hash token before storing it
        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        // Token expires after 15 minutes
        const resetPasswordExpires = new Date(
            Date.now() + 15 * 60 * 1000
        );

        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = resetPasswordExpires;

        await user.save();

        const resetUrl =
            `http://localhost:5173/reset-password/${resetToken}`;

        await sendEmail({
            to: user.email,
            subject: "Password Reset Request",
            html: `
                <h2>Password Reset</h2>

                <p>You requested to reset your password.</p>

                <p>
                    Click the link below to reset your password:
                </p>

                <a href="${resetUrl}">
                    Reset Password
                </a>

                <p>
                    This link will expire in 15 minutes.
                </p>

                <p>
                    If you did not request this, you can safely ignore this email.
                </p>
            `
        });

        return res.status(200).json({
            success: true,
            message:
                "If an account exists with this email, a password reset link has been sent."
        });

    } catch (error) {
        console.error(
            "Forgot password error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};







export const resetPassword = async (req, res) => {
    try {
        const {
            token,
            newPassword
        } = req.body;

        // Hash token received from frontend
        const hashedToken = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        // Find user with valid token
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: {
                $gt: new Date()
            }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired reset token"
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(
            newPassword,
            10
        );

        user.password = hashedPassword;

        // IMPORTANT:
        // Invalidate reset token immediately
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully"
        });

    } catch (error) {
        console.error(
            "Reset password error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

export const changePassword = async (req, res) => {
    try {
        const userId = req.user.userId;

        const {
            currentPassword,
            newPassword
        } = req.body;

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Check current password
        const isPasswordValid =
            await bcrypt.compare(
                currentPassword,
                user.password
            );

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Current password is incorrect"
            });
        }

        // Prevent same password
        const isSamePassword =
            await bcrypt.compare(
                newPassword,
                user.password
            );

        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message:
                    "New password must be different from current password"
            });
        }

        // Hash new password
        const hashedPassword =
            await bcrypt.hash(
                newPassword,
                10
            );

        user.password = hashedPassword;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password changed successfully"
        });

    } catch (error) {
        console.error(
            "Change password error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};