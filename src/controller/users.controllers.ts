import { NextFunction, Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { ObjectId } from 'mongodb'
import { UserVerifyStatus } from '~/constants/enum'
import HTTP_STATUS from '~/constants/httpStatus'
import { USER_MESSAGE } from '~/constants/message'
import {
  LoginReqBody,
  LogoutReqBody,
  RegisterReqBody,
  TokenPayload,
  VerifyEmailReqBody,
  VerifyforgotPasswordReqBody,
  forgotPasswordReqBody
} from '~/models/requests/User.requests'
import User from '~/models/schemas/User.schema'
import databaseService from '~/services/database.services'
import usersService from '~/services/user.services'

export const loginController = async (req: Request<ParamsDictionary, any, LoginReqBody>, res: Response) => {
  const user = req.user as User
  const user_id = user._id as ObjectId
  const result = await usersService.login(user_id.toString())
  return res.json({
    message: USER_MESSAGE.LOGIN_SUCCESS,
    result
  })
}

export const registerController = async (
  req: Request<ParamsDictionary, any, RegisterReqBody>,
  res: Response,
  next: NextFunction
) => {
  // const { email, password, confirm_password, data_of_birth, name } = req.body
  try {
    const result = await usersService.register(req.body)
    return res.json({
      message: USER_MESSAGE.REGISTER_SUCCESS,
      result
    })
  } catch (error) {
    next(error)
  }
}

export const logOutController = async (req: Request<ParamsDictionary, any, LogoutReqBody>, res: Response) => {
  const refresh_token = req.body.refresh_token
  const result = await usersService.logout(refresh_token)
  return res.json(result)
}

export const verifyEmailController = async (req: Request<ParamsDictionary, any, VerifyEmailReqBody>, res: Response) => {
  const { user_id } = req.decoded_email_verify_token as TokenPayload
  const user = await databaseService.user.findOne({ _id: new ObjectId(user_id) })
  // KHONG TIM THAY USER
  if (!user) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({ message: USER_MESSAGE.USER_NOT_FOUND })
  }
  // da verify email -> khong bao loi ma se tra ve status ok voi message : da verify truoc do
  if (user.email_verify_token === '') {
    return res.json({ message: USER_MESSAGE.EMAIL_ALREADY_VERIFIED_BEFORE })
  }
  const result = await usersService.verifyEmail(user_id)
  return res.json({
    message: USER_MESSAGE.EMAIL_VERIFY_SUCCESS,
    result
  })
}

export const resendVerifyEmailController = async (req: Request, res: Response) => {
  const { user_id } = req.decode_authorization as TokenPayload
  const user = await databaseService.user.findOne({ _id: new ObjectId(user_id) })
  if (!user) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({ message: USER_MESSAGE.USER_NOT_FOUND })
  }
  if (user.verify === UserVerifyStatus.Verified) {
    return res.json({ message: USER_MESSAGE.EMAIL_ALREADY_VERIFIED_BEFORE })
  }
  const result = await usersService.resendVerifyEmail(user_id)
  return res.json(result)
}

export const forgotPasswordController = async (
  req: Request<ParamsDictionary, any, forgotPasswordReqBody>,
  res: Response
) => {
  const { _id } = req.user as User
  const result = await usersService.forgotPassword((_id as ObjectId).toString())

  return res.json(result)
}

export const verifyForgotPasswordController = async (
  req: Request<ParamsDictionary, any, VerifyforgotPasswordReqBody>,
  res: Response,
  next: NextFunction
) => {
  return res.json({ message: USER_MESSAGE.VERIFY_FORGOT_PASSWORD_TOKEN_SUCCESS })
}
