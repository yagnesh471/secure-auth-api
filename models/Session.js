import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        familyId: {
            type: String,
            required: true,
            unique: true,
            index: true
        },

        expiresAt: {
            type: Date,
            required: true
        },

        revokedAt: {
            type: Date,
            default: null
        },

        userAgent: {
            type: String,
            default: null
        },

        ipAddress: {
            type: String,
            default: null
        }
    },
    {
        timestamps: true
    }
);

const Session = mongoose.model(
    "Session",
    sessionSchema
);

export default Session;