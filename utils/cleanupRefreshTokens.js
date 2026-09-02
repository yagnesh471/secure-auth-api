import RefreshToken from "../models/RefreshToken.js";

export const cleanupExpiredRefreshTokens = async () => {
    try {
        const result = await RefreshToken.deleteMany({
            expiresAt: {
                $lt: new Date()
            }
        });

        console.log(
            `Deleted ${result.deletedCount} expired refresh tokens`
        );

    } catch (error) {
        console.error(
            "Refresh token cleanup error:",
            error.message
        );
    }
};