import { Router } from "express";
import authControllers from "../controllers/auth.controllers.js";

const router = Router();

router.post("/register", authControllers.register);
router.post("/login", authControllers.login);
router.post("/rotate-token", authControllers.rotateToken);
router.post("/logout", authControllers.logout);
router.post("/logout-all", authControllers.logoutall);

export default router;
