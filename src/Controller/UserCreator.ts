import { isEmail } from "../services/checkemail";
import { passwordFormat } from "../services/checkpassword";
import bcrypt from "bcrypt";
import { UserResponse, CreateUser } from "../Interface/interface";
const User = require("../models/mongo.model");

export default class UserCreator {
  //  create user and store it in a mongodb database
  async createUser(
    _parent: string,
    args: any,
    _context: string,
    _info: string
  ) {
    try {
      const { fullName, email, password }: CreateUser = args.user;

      if (!isEmail(email)) {  // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }

      if (!passwordFormat(password)) {  // checks for the validity of the Password
        return {
          message:
            "enter a password that has at least 1 uppercase, 1 lowercase, 1 digit, 1 special character and 8 characters",
        };
      }
      const checkuser = await User.findOne({ email });  // retrieves the users data from the database
      if (checkuser) {
        return {
          message: "User already exists with this Email Address",
        };
      }
      const salt = await bcrypt.genSalt(10);
      const encrypted_password = await bcrypt.hash(password, salt); // encrypting the password 
      const user = new User({ fullName, email, password: encrypted_password }); // adding data to the database
      await user.save();
      return user as UserResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
