import express from "express";
import router from "./routes";
import dbConnect from "./utils/mongodb";
import { sendSuccessResponse } from "./utils/response";
require("dotenv").config();

dbConnect();

const PORT = process.env.PORT || 8080;
const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: false }));
app.use("/user", router);

app.listen(PORT, () => {
  console.log("Server listening on ", PORT);
});
