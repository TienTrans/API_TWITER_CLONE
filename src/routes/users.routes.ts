import { Router } from 'express'
import {
  verifyEmailController,
  logOutController,
  loginController,
  registerController,
  resendVerifyEmailController,
  forgotPasswordController,
  verifyForgotPasswordController
} from '~/controller/users.controllers'
import {
  accessTokenValidator,
  emailVerifyTokenValidator,
  forgotPasswordValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  verifyForgotPasswordValidator
} from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '~/utils/handlers'
const usersRouter = Router()

/**
 * Desription . Login a user
 *  path : /login
 * Method: POST
 * body : { email: string, password: string}
 */
usersRouter.post('/login', loginValidator, wrapRequestHandler(loginController))

/**
 * Desription . Register a new user
 *  path : /registor
 * Method: POST
 * body : { email: string, name: string, password: string,comfirm_password: string, date-of-birth: ISO 8601}
 */

usersRouter.post('/register', registerValidator, wrapRequestHandler(registerController))

/**
 * Desription . Logout a user
 *  path : /logout
 * Method: POST
 * headers : { Authorization: Bearer <access_token>}
 * body : {refresh_token: string }
 */
usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, wrapRequestHandler(logOutController))

/**
 * description: Verify email when a user client click on the link in email
 * path : /verify-email
 * Method: POST
 * body : { email_verify_token: string}
 *
 */

usersRouter.post('/verify-email', emailVerifyTokenValidator, wrapRequestHandler(verifyEmailController))

/**
 * description: Verify email when a user client click on the link in email
 * path : /resend-verify-email
 * Method: POST
 * body : {}
 * header : { Authorization: Bearer <access_token>}
 */

usersRouter.post('/resend-verify-email', accessTokenValidator, wrapRequestHandler(resendVerifyEmailController))

/**
 * description: submit email to get link to reset password
 * path : /forgot-password
 * Method: POST
 * body : {email : string}
 */
usersRouter.post('/forgot-password', forgotPasswordValidator, wrapRequestHandler(forgotPasswordController))

/**
 * description: verify link in email to reset password
 * path : /verify-forgot-password'
 * Method: POST
 * body : {forgot-password-token : string}
 */
usersRouter.post(
  '/verify-forgot-password',
  verifyForgotPasswordValidator,
  wrapRequestHandler(verifyForgotPasswordController)
)

export default usersRouter
