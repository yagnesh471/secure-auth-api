import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
    {
        tokenId: {
            type: String,
            required: true,
            unique: true
        },

        familyId: {
            type: String,
            required: true,
            index: true
        },

        tokenHash: {
            type: String,
            required: true
        },

        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        usedAt: {
            type: Date,
            default: null
        },

        revokedAt: {
            type: Date,
            default: null
        },

        expiresAt: {
            type: Date,
            required: true
        }
    },
    {
        timestamps: true
    }
);

const RefreshToken = mongoose.model(
    "RefreshToken",
    refreshTokenSchema
);

export default RefreshToken;