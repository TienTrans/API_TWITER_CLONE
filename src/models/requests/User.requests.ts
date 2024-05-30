import { JwtPayload } from 'jsonwebtoken'
import { TokenType } from '~/constants/enum'

export interface LoginReqBody {
  email: string
  password: string
}

export interface forgotPasswordReqBody {
  email: string
}
export interface VerifyforgotPasswordReqBody {
  forgot_password_token: string
}

export interface RegisterReqBody {
  name: string
  email: string
  password: string
  confirm_password: string
  data_of_birth: string
}

export interface LogoutReqBody {
  refresh_token: string
}

export interface VerifyEmailReqBody {
  email_verify_token: string
}

export interface TokenPayload extends JwtPayload {
  user_id: string
  token_type: TokenType
}
