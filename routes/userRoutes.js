import express from "express";
import authorizeUserOrAdmin from "../middleware/resourceAuth.js";


import {
    getAllUsers,
    getUserById,
    deleteUser,
    updateUserRole
} from "../controllers/userController.js";

import authMiddleware from "../middleware/authMiddleware.js";
import authorizeRoles from "../middleware/authorize.js";

const router = express.Router();

router.get(
    "/",
    authMiddleware,
    authorizeRoles("admin"),
    getAllUsers
);

router.get(
    "/:id",
    authMiddleware,
    authorizeUserOrAdmin,
    getUserById
);

router.delete(
    "/:id",
    authMiddleware,
    authorizeRoles("admin"),
    deleteUser
);

router.patch(
    "/:id/role",
    authMiddleware,
    authorizeRoles("admin"),
    updateUserRole
);

export default router;