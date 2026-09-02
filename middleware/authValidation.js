import { z } from "zod";

export const registerSchema = z.object({
    name: z
        .string()
        .trim()
        .min(2, "Name must be at least 2 characters")
        .max(50, "Name must not exceed 50 characters"),

    email: z
        .string()
        .trim()
        .email("Invalid email address")
        .toLowerCase(),

    password: z
        .string()
        .min(8, "Password must be at least 8 characters")
        .max(100, "Password must not exceed 100 characters")
});



export const verifyOTPSchema = z.object({
    email: z
        .string()
        .trim()
        .email("Invalid email address")
        .toLowerCase(),

    otp: z
        .string()
        .regex(/^\d{6}$/, "OTP must be exactly 6 digits")
});



export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .email("Invalid email address")
    .toLowerCase(),
  password: z
    .string()
    .max(100, "Password must not exceed 100 characters")
});

export const forgotPasswordSchema = z.object({
    email: z
        .string()
        .trim()
        .email("Invalid email address")
        .toLowerCase()
});

export const resetPasswordSchema = z.object({
    token: z
        .string()
        .min(1, "Reset token is required"),

    newPassword: z
        .string()
        .min(8, "Password must be at least 8 characters long")
});

export const changePasswordSchema = z.object({
    currentPassword: z
        .string()
        .min(1, "Current password is required"),

    newPassword: z
        .string()
        .min(8, "Password must be at least 8 characters long")
});