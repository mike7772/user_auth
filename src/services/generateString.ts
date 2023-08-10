const crypto = require("crypto");
import { encode } from "hi-base32";

// generates a random string for the base 32 secret used in the 2fa
export const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return base32;
};
