import { verify } from "jsonwebtoken";

export default (token: string) => {
  try {
    const decoded = verify(token, process.env.JWT_SECRET!);
    return decoded;
  } catch (error) {
    return false;
  }
};
