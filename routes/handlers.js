import { userModel, nameRegex } from "../schemas/User";
import { encryptPassword } from "../utils/bcrypt";
import { sendErrorResponse, sendSuccessResponse } from "../utils/response";
import { passwordStrength } from "check-password-strength";

const passwordRegex =
  /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8}$/;

export const createUserHandler = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (email === undefined) {
      throw new Error("Email Missing");
    } else if (password === undefined) {
      throw new Error("Password Missing");
    } else if (name == undefined) {
      throw new Error("Name Missing");
    }

    if (!name.match(nameRegex)) {
      throw new Error("Name Validation Failed");
    }

    if (password.match(passwordRegex)) {
      throw new Error("Password is Weak");
    }

    const ans = passwordStrength(password).value;
    if (ans === "Weak") throw new Error("Password is Weak");
    const hashPassword = await encryptPassword(password);
    const userExists = await userModel.findOne({ email });
    if (userExists !== null) {
      throw new Error("Duplicate Email Found");
    }
    const user = await userModel.create({
      email,
      full_name: name,
      password: hashPassword,
    });
    sendSuccessResponse(res, user);
  } catch (error) {
    if (error.code == "11000") {
      sendErrorResponse(res, "Duplicate Email Found");
      return;
    }
    sendErrorResponse(res, error.message);
  }
};

export const updateHandler = async (req, res) => {
  try {
    const { oldEmail, name, password } = req.body;

    if (oldEmail === undefined) {
      throw new Error("Email Missing");
    } else if (password === undefined) {
      throw new Error("Password Missing");
    } else if (name == undefined) {
      throw new Error("Name Missing");
    }

    const user = await userModel.findOne({ email: oldEmail });
    if (user === null) throw new Error("User Not Found");

    const hashPassword = await encryptPassword(password);
    user.password = hashPassword;
    user.full_name = name;

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
