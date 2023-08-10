import { isEmail } from "../services/checkemail";
import bcrypt from "bcrypt";
import generateJWT from "../services/generateJWT";
import verifyJWT from "../services/verifyJWT";
import { authenticator } from "otplib";
import { getCookie } from "../services/getcookie";
import { UserResponse, UserLogin, twoFaOTP } from "../Interface/interface";
const User = require("../models/mongo.model");

export default class UserController {
  async getUser(_parent: string, args: any, _context: string, _info: string) {
    try {
      const { email } = args.user;

      return await User.findOne({ email });
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  async login(_parent: string, args: any, { res }: any) {
    try {
      const { email, password }: UserLogin = args.user;

      if (!isEmail(email)) {
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email });

      if (!user) {
        return { message: "No user registered with this Email Address" };
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (validPassword) {
        const token = generateJWT(
          { email: user.email },
          process.env.JWT_SECRET!,
          "2 days"
        );

        res.cookie("token", token, {
          httpOnly: true,
          secure: false, // Set to true in production if using HTTPS
          maxAge: new Date(Date.now() + 48 * 60 * 60 * 1000),
        });

        user.token = token;
        user.message = "Successful";
        return user as UserResponse;
      }
      return { message: "Incorrect Password" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  async logout(_parent: string, args: any, context: any, _info: string) {
    try {
      const { email }: UserLogin = args.user;

      if (!isEmail(email)) {
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email });

      if (!user) {
        return { message: "No user registered with this Email Address" };
      }

      context.res.clearCookie("token");

      return { message: "Logged out Successfully" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  async validateOTP(
    _parent: string,
    args: any,
    { req, res }: any,
    _info: string
  ) {
    try {
      const { email, otpToken }: twoFaOTP = args.user;
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
        return { message: "No user registered with this email" };
      }

      const isValid = authenticator.check(otpToken, user.otp_base32);

      if (!isValid) {
        return { message: "Token is invalid or user doesn't exist" };
      }

      return { message: "Otp Validated Successfully" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
