import crypto from "crypto";

export const generateOTP = () => {
    const otp = crypto.randomInt(100000, 1000000).toString();

    const expiresAt = new Date(
        Date.now() + 5 * 60 * 1000
    );

    return {
        otp,
        expiresAt
    };
};