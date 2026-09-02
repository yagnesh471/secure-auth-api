import jwt from "jsonwebtoken";

export const generateAccessToken = (user) => {
    return jwt.sign(
        {
            userId: user._id.toString(),
            role: user.role
        },
        process.env.JWT_ACCESS_SECRET,
        {
            expiresIn: process.env.JWT_ACCESS_EXPIRES || "15m"
        }
    );
};


export const generateRefreshToken = (
    user,
    familyId,
    tokenId
) => {
    return jwt.sign(
        {
            userId: user._id,
            familyId,
            tokenId
        },
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn: "7d"
        }
    );
};