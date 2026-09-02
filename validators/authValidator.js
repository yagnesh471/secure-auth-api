import { z } from "zod";

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