export interface UserResponse {
  email: string;
  fullName: string;
  token: string;
  otp_enabled: boolean;
  message: string;
}

export interface TwoFaResponse {
  otp_auth_url: string;
  otp_base32: string;
  message: string;
}

export interface CreateUser {
  fullName: string;
  email: string;
  password: string;
}
export interface UserLogin {
  email: string;
  password: string;
}
export interface PasswordChange {
  email: string;
  oldPassword: string;
  password: string;
}

export interface twoFa {
  email: string;
}

export interface twoFaOTP {
  email: string;
  otpToken: string;
}
