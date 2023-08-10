import { isEmail } from "../services/checkemail";
import { passwordFormat } from "../services/checkpassword";
import bcrypt from "bcrypt";
import { UserResponse, CreateUser } from "../Interface/interface";
const User = require("../models/mongo.model");

export default class UserCreator {
  async createUser(
    _parent: string,
    args: any,
    _context: string,
    _info: string
  ) {
    try {
      const { fullName, email, password }: CreateUser = args.user;

      if (!isEmail(email)) {
        return {
          message: "enter a correct Email Address",
        };
      }

      if (!passwordFormat(password)) {
        return {
          message:
            "enter a password that has at least 1 uppercase, 1 lowercase, 1 digit, 1 special character and 8 characters",
        };
      }
      const checkuser = await User.findOne({ email });
      if (checkuser) {
        return {
          message: "User already exists with this Email Address",
        };
      }
      const salt = await bcrypt.genSalt(10);
      const encrypted_password = await bcrypt.hash(password, salt);
      const user = new User({ fullName, email, password: encrypted_password });
      await user.save();
      return user as UserResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
