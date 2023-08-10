import { isEmail } from "../services/checkemail";
import { passwordFormat } from "../services/checkpassword";
import bcrypt from "bcrypt";
import generateJWT from "../services/generateJWT";
import verifyJWT from "../services/verifyJWT";
import { generateRandomBase32 } from "../services/generateString";
import { authenticator } from "otplib";
import { getCookie } from "../services/getcookie";
import {
  TwoFaResponse,
  UserResponse,
  CreateUser,
  UserLogin,
  PasswordChange,
  twoFa,
  twoFaOTP,
} from "../Interface/interface";
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

  async changePassword(
    _parent: string,
    args: any,
    { res, req }: any,
    _info: string
  ) {
    const { email, oldPassword, password }: PasswordChange = args.user;
    try {
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

      if (!passwordFormat(password)) {
        return {
          message:
            "Enter a password that has at least 1 uppercase, 1 lowercase, 1 digit, 1 special character and 8 characters",
        };
      }
      const checkuser = await User.findOne({ email });

      if (!checkuser) {
        return { message: "No user registered with this Email Address" };
      }

      const validPassword = await bcrypt.compare(
        oldPassword,
        checkuser.password
      );

      if (!validPassword) {
        return { message: "The old Password you Inserted is Incorrect" };
      }

      const PasswordDiff = await bcrypt.compare(password, checkuser.password);

      if (PasswordDiff) {
        return { message: "Please Change Your Password to a different one." };
      }

      const salt = await bcrypt.genSalt(10);
      const encrypted_password = await bcrypt.hash(password, salt);
      const user = await User.findOneAndUpdate(
        { email },
        { password: encrypted_password }
      );

      user.message = "Successfully Changed Your Password";

      return user as UserResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  async generateOTP(
    _parent: string,
    args: any,
    { req, res }: any,
    _info: string
  ) {
    try {
      const cookie = getCookie(req.headers.cookie, "token");

      if (!cookie || !verifyJWT(cookie)) {
        res.clearCookie("token");
        return {
          message: "Session Expired",
        };
      }

      const { email }: twoFa = args.user;

      if (!isEmail(email)) {
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email });

      if (!user) {
        return { message: "No user registered with this Email Address" };
      }

      const base32_secret = generateRandomBase32();

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_base32: base32_secret.toString() },
        { new: true }
      );

      updateduser.message = " OTP Generated Successfully";

      return updateduser as TwoFaResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  async verifyOTP(
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

      if (!user.otp_base32) {
        return { message: "OTP secret not set for this user" };
      }

      const isValid = authenticator.verify({
        token: otpToken,
        secret: user.otp_base32,
      });

      if (!isValid) {
        return { message: "Token is invalid or user doesn't exist" };
      }

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_enabled: true, otp_verified: true },
        { new: true }
      );

      updateduser.message = " OTP Verified Successfully";

      return updateduser as UserResponse;
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

  async disableOTP(
    _parent: string,
    args: any,
    { req, res }: any,
    _info: string
  ) {
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
        return { message: "No user registered with this email" };
      }

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_enabled: false },
        { new: true }
      );

      updateduser.message = " 2fa Disabled Successfully";

      return updateduser as UserResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
