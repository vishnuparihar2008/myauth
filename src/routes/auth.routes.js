import { Router } from "express";
import authControllers from "../controllers/auth.controllers.js";

const router = Router();

router.post("/register", authControllers.register);
router.post("/login", authControllers.login);
router.get("/rotate-token", authControllers.rotateToken);
router.get("/logout", authControllers.logout);
router.get("/logout-all", authControllers.logoutall);

export default router;
