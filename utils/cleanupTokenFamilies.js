import TokenFamily from "../models/TokenFamily.js";

export const cleanupExpiredTokenFamilies = async () => {
    try {
        const result = await TokenFamily.deleteMany({
            expiresAt: {
                $lt: new Date()
            }
        });

        console.log(
            `Deleted ${result.deletedCount} expired token families`
        );

    } catch (error) {
        console.error(
            "Token family cleanup error:",
            error.message
        );
    }
};