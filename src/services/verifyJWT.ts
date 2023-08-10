import { verify } from "jsonwebtoken";

// checks whether the given jwt token is valid or not
export default (token: string) => {
  try {
    const decoded = verify(token, process.env.JWT_SECRET!);
    return decoded;
  } catch (error) {
    return false;
  }
};
