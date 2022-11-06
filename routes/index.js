import express from "express";
import {
  createUserHandler,
  deleteHandler,
  getAllUsers,
  updateHandler,
} from "./handlers";

const router = express.Router();

router.post("/create", createUserHandler);
router.post("/edit", updateHandler);
router.delete("/delete", deleteHandler);
router.get("/getAll", getAllUsers);

export default router;
