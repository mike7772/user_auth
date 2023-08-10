import { isEmail } from "../services/checkemail";
import { passwordFormat } from "../services/checkpassword";
import bcrypt from "bcrypt";
import verifyJWT from "../services/verifyJWT";
import { generateRandomBase32 } from "../services/generateString";
import { authenticator } from "otplib";
import { getCookie } from "../services/getcookie";
import {
  TwoFaResponse,
  UserResponse,
  PasswordChange,
  twoFa,
  twoFaOTP,
} from "../Interface/interface";
const qr = require('qrcode');
const User = require("../models/mongo.model");

export default class UserUpdater {

  // function for changing the users password
  async changePassword(
    _parent: string,
    args: any,
    { res, req }: any,
    _info: string
  ) {
    const { email, oldPassword, password }: PasswordChange = args.user;
    try {
      const cookie = getCookie(req.headers.cookie, "token"); // get the token from the cookie

      if (!cookie || !verifyJWT(cookie)) { // clears the cookie if the user is not authenticated 
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

      if (!passwordFormat(password)) {  // checks for the validity of the Password
        return {
          message:
            "Enter a password that has at least 1 uppercase, 1 lowercase, 1 digit, 1 special character and 8 characters",
        };
      }
      const checkuser = await User.findOne({ email }); // gets the data of the user using its email

      if (!checkuser) { // returns error message if their is no user
        return { message: "No user registered with this Email Address" };
      }

      const validPassword = await bcrypt.compare(
        oldPassword,
        checkuser.password
      ); // checks if submitted the old password is the current password 

      if (!validPassword) {
        return { message: "The old Password you Inserted is Incorrect" };
      }

      const PasswordDiff = await bcrypt.compare(password, checkuser.password); 

      if (PasswordDiff) { // returns error message if the user puts the old password as the new one
        return { message: "Please Change Your Password to a different one." };
      }

      const salt = await bcrypt.genSalt(10);
      const encrypted_password = await bcrypt.hash(password, salt); // encrypts the new password
      const user = await User.findOneAndUpdate(
        { email },
        { password: encrypted_password }
      ); // updates the password in the database

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
      const cookie = getCookie(req.headers.cookie, "token"); // get the token from the cookie

      if (!cookie || !verifyJWT(cookie)) { // clears the cookie if the user is not authenticated 
        res.clearCookie("token");
        return {
          message: "Session Expired",
        };
      }

      const { email }: twoFa = args.user;

      if (!isEmail(email)) { // checks for the validity of the Email address
        return {
          message: "enter a correct Email Address",
        };
      }

      const user = await User.findOne({ email }); // gets the user data from the database

      if (!user) { 
        return { message: "No user registered with this Email Address" };
      }

      const base32_secret = generateRandomBase32(); // generate a random string

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_base32: base32_secret.toString() },
        { new: true }
      ); // update the database

      const qrCode = await qr.toDataURL(base32_secret.toString());
      
      updateduser.qr =  `<img src="${qrCode}" alt="QR Code" />`
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
      const cookie = getCookie(req.headers.cookie, "token"); // gets the token from the cookie

      if (!cookie || !verifyJWT(cookie)) { // clears the cookie if the user is not authenticated
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

      const user = await User.findOne({ email }); // gets the user data from the database

      if (!user) {
        return { message: "No user registered with this email" };
      }

      if (!user.otp_base32) { // returns an error message if their is no hashed string stored
        return { message: "OTP secret not set for this user" };
      }

      const isValid = authenticator.verify({
        token: otpToken,
        secret: user.otp_base32,
      }); // verifies the otp from the authenticator

      if (!isValid) {
        return { message: "Token is invalid or user doesn't exist" };
      }

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_enabled: true, otp_verified: true },
        { new: true }
      ); // update the database

      updateduser.message = " OTP Verified Successfully";

      return updateduser as UserResponse;
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
      const cookie = getCookie(req.headers.cookie, "token"); // gets the token from the cookie

      if (!cookie || !verifyJWT(cookie)) { // clears the cookie if the user is not authenticated
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

      const user = await User.findOne({ email }); // gets the user data from the database

      if (!user) {
        return { message: "No user registered with this email" };
      }

      const updateduser = await User.findOneAndUpdate(
        { email },
        { otp_enabled: false },
        { new: true }
      ); // update the database value

      updateduser.message = " 2fa Disabled Successfully";

      return updateduser as UserResponse;
    } catch (error) {
      return { message: "Error occurred" };
    }
  }
}
