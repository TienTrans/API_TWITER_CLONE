export enum UserVerifyStatus {
  Unverified, // chua xac thuc email, default la 0
  Verified, // da xac thuc email
  Banned // bi chan
}

export enum TokenType {
  AccessToken,
  RefreshToken,
  ForgotPasswordToken,
  EmailVerifyToken
}
