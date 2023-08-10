
// checks whether the given value is a valid password or not using a regular expression
// the password must contain at least 1 lowercase, 1 uppercase, 1 special character, 1 number and 8 digits

const regex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

export const passwordFormat = (password: string) => {
  return regex.test(password);
};
