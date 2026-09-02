import Session from "../models/Session.js";

export const cleanupExpiredSessions = async () => {
    try {
        const result = await Session.deleteMany({
            expiresAt: {
                $lt: new Date()
            }
        });

        console.log(
            `Deleted ${result.deletedCount} expired sessions`
        );

    } catch (error) {
        console.error(
            "Session cleanup error:",
            error.message
        );
    }
};