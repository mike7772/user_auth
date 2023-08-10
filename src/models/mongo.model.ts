import mongoose from "mongoose";
const UserSchema = new mongoose.Schema({
  fullName: {
    type: String,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  otp_base32: {
    type: String,
  },
  otp_enabled: {
    type: Boolean,
  },
  otp_verified: {
    type: Boolean,
  },
});

module.exports = mongoose.model("User", UserSchema);
