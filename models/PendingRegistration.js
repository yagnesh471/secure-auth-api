import mongoose from "mongoose";

const pendingRegistrationSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true
        },

        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },

        passwordHash: {
            type: String,
            required: true
        },

        otpHash: {
            type: String,
            required: true
        },

        otpExpiresAt: {
            type: Date,
            required: true
        },

        otpAttempts: {
            type: Number,
            default: 0
        },

        lastOtpSentAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

const PendingRegistration = mongoose.model(
    "PendingRegistration",
    pendingRegistrationSchema
);

export default PendingRegistration;