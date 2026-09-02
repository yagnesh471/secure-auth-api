const authorizeUserOrAdmin = (req, res, next) => {

    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: "Authentication required"
        });
    }

    const requestedUserId = req.params.id;
    const loggedInUserId = req.user.userId;

    // Admin can access any user
    if (req.user.role === "admin") {
        return next();
    }

    // Normal user can access only themselves
    if (requestedUserId === loggedInUserId.toString()) {
        return next();
    }

    return res.status(403).json({
        success: false,
        message: "You are not authorized to access this resource"
    });
};

export default authorizeUserOrAdmin;