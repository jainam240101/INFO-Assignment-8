import { userModel } from "../schemas/User";
import { encryptPassword } from "../utils/bcrypt";
import { sendErrorResponse, sendSuccessResponse } from "../utils/response";
import { passwordStrength } from "check-password-strength";

export const createUserHandler = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email === undefined || password === undefined) {
      throw new Error("Arguments Missing");
    }
    const ans = passwordStrength(password).value;
    if (ans === "Weak") throw new Error("Password is Weak");
    const hashPassword = await encryptPassword(password);
    const user = await userModel.create({
      email,
      password: hashPassword,
    });
    sendSuccessResponse(res, user);
  } catch (error) {
    sendSuccessResponse(res, error.message);
  }
};

export const updateHandler = async (req, res) => {
  try {
    const { oldEmail, newEmail, password } = req.body;
    if (
      oldEmail === undefined ||
      newEmail === undefined ||
      password === undefined
    ) {
      throw new Error("Arguments Missing");
    }
    const user = await userModel.findOne({ email: oldEmail });
    if (user === null) throw new Error("User Not Found");

    user.email = newEmail;
    const hashPassword = await encryptPassword(password);
    user.password = hashPassword;
    await user.save();
    sendSuccessResponse(res, user);
  } catch (error) {
    sendErrorResponse(res, error.message);
  }
};

export const deleteHandler = async (req, res) => {
  try {
    const { email } = req.body;
    if (email === undefined) {
      throw new Error("Arguments Missing");
    }
    const user = await userModel.findOne({ email });
    if (user === null) throw new Error("User Not Found");
    await user.remove();
    sendSuccessResponse(res, "Successfully Removed");
  } catch (error) {
    sendErrorResponse(res, error.message);
  }
};

export const getAllUsers = async (req, res) => {
  try {
    const users = await userModel.find();
    sendSuccessResponse(res, users);
  } catch (error) {
    sendErrorResponse(res, error.message);
  }
};
