import { isEmail } from "../services/checkemail";
import bcrypt from "bcrypt";
import generateJWT from "../services/generateJWT";
import verifyJWT from "../services/verifyJWT";
import { authenticator } from "otplib";
import { getCookie } from "../services/getcookie";
import { UserResponse, UserLogin, twoFaOTP } from "../Interface/interface";
const User = require("../models/mongo.model");

export default class UserController {
  // for getting a specific user by it's email
  async getUser(_parent: string, args: any, _context: string, _info: string) {
    try {
      const { email } = args.user;

      return await User.findOne({ email }); // returns an object value containing the users information from the mongodb database
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  //  function for validating the login request
  async login(_parent: string, args: any, { res }: any) {
    try {
      const { email, password }: UserLogin = args.user;

      if (!isEmail(email)) { // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email }); // retrieves the users data from the database

      if (!user) { 
        return { message: "No user registered with this Email Address" };
      }

      const validPassword = await bcrypt.compare(password, user.password); // compares the password given by the user with the hashed password stored in the Database
      if (validPassword) {
        const token = generateJWT(
          { email: user.email },
          process.env.JWT_SECRET!,
          "2 days"
        ); // signing a token with a 2 days of expiration date

        res.cookie("token", token, {
          httpOnly: true,
          secure: false, // Set to true in production if using HTTPS
          maxAge: new Date(Date.now() + 48 * 60 * 60 * 1000),
        }); // setting a cookie 

        user.token = token;
        user.message = "Successful";
        return user as UserResponse;
      }
      return { message: "Incorrect Password" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  //  function for logout request
  async logout(_parent: string, args: any, {req, res}: any, _info: string) {
    try {
      const { email }: UserLogin = args.user;

      if (!isEmail(email)) { // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email }); // retrieves the users data from the database

      if (!user) {
        return { message: "No user registered with this Email Address" };
      }

      res.clearCookie("token"); // clearing the cookie

      return { message: "Logged out Successfully" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }

  // function for validating the otp 
  async validateOTP(
    _parent: string,
    args: any,
    { req, res }: any,
    _info: string
  ) {
    try {
      const { email, otpToken }: twoFaOTP = args.user;
      const cookie = getCookie(req.headers.cookie, "token");  // get the token from the cookie

      if (!cookie || !verifyJWT(cookie)) {  // clears the cookie if the user is not authenticated 
        res.clearCookie("token");  
        return {
          message: "Session Expired",
        };
      }

      if (!isEmail(email)) { // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email }); // retrieves the users data from the database

      if (!user) {
        return { message: "No user registered with this email" };
      }

      const isValid = authenticator.check(otpToken, user.otp_base32); // validating the otp obtained from the authenticator 

      if (!isValid) {
        return { message: "Token is invalid or user doesn't exist" };
      }

      return { message: "Otp Validated Successfully" };
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
