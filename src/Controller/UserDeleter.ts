import { isEmail } from "../services/checkemail";
import { twoFa } from "../Interface/interface";
import verifyJWT from "../services/verifyJWT";
import { getCookie } from "../services/getcookie";

const User = require("../models/mongo.model");

export default class UserDeleter {
  async removeUser(_parent: string, args: any, { req, res }: any) {
    try {
      const { email }: twoFa = args.user;
      const cookie = getCookie(req.headers.cookie, "token");

      if (!cookie || !verifyJWT(cookie)) {
        res.clearCookie("token");
        return {
          message: "Session Expired",
        };
      }

      if (!isEmail(email)) {
        return {
          message: "enter a correct Email Address",
        };
      }
      const user = await User.findOne({ email });

      if (!user) {
        return { message: "No user registered with this Email Address" };
      }
      await User.deleteOne({ email });

      return { message: "Your Account has been deleted" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
