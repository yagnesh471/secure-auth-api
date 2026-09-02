import mongoose from "mongoose";

const tokenFamilySchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        familyId: {
            type: String,
            required: true,
            unique: true
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

const TokenFamily = mongoose.model(
    "TokenFamily",
    tokenFamilySchema
);

export default TokenFamily;