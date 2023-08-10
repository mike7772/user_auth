import { isEmail } from "../services/checkemail";
import { twoFa } from "../Interface/interface";
import verifyJWT from "../services/verifyJWT";
import { getCookie } from "../services/getcookie";

const User = require("../models/mongo.model");

export default class UserDeleter {
  // remove user from the database
  async removeUser(_parent: string, args: any, { req, res }: any) {
    try {
      const { email }: twoFa = args.user;
      const cookie = getCookie(req.headers.cookie, "token");  // get the token from the cookie

      if (!cookie || !verifyJWT(cookie)) {  // clears the cookie if the user is not authenticated 
        res.clearCookie("token");
        return {
          message: "Session Expired",
        };
      }

      if (!isEmail(email)) {  // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }
      const user = await User.findOne({ email });

      if (!user) { // Checks if their is a user to be deleted
        return { message: "No user registered with this Email Address" };
      }
      await User.deleteOne({ email }); // deletes the user from the database

      return { message: "Your Account has been deleted" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
