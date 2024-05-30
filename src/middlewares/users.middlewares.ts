import { config } from 'dotenv'
import { checkSchema } from 'express-validator'
import { JsonWebTokenError } from 'jsonwebtoken'
import HTTP_STATUS from '~/constants/httpStatus'
import { USER_MESSAGE } from '~/constants/message'
import { ErrorWithStatus } from '~/models/Errors'
import databaseService from '~/services/database.services'
import usersService from '~/services/user.services'
import { hashPassword } from '~/utils/crypto'
import { verifyToken } from '~/utils/jwt'
import { validate } from '~/utils/validation'
import { Request } from 'express'
import { ObjectId } from 'mongodb'

config()

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGE.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGE.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const user = await databaseService.user.findOne({ email: value, password: hashPassword(req.body.password) })
            if (user === null) {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.EMAIL_OR_PASSWORD_IS_INCORRECT,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            req.user = user
            return true
          }
        }
      },
      password: {
        isString: {
          errorMessage: USER_MESSAGE.PASSWORD_MUST_BE_A_STRING
        },
        notEmpty: {
          errorMessage: USER_MESSAGE.PASSWORD_IS_REQUIRED
        },
        isLength: {
          options: {
            min: 6,
            max: 50
          },
          errorMessage: USER_MESSAGE.PASSWORD_LENGTH_MUST_BE_FROM_6_TO_50
        },
        isStrongPassword: {
          options: {
            minLength: 6,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
          },
          errorMessage: USER_MESSAGE.PASSWORD_MUST_BE_STRONG
        }
      }
    },
    ['body']
  )
)

export const registerValidator = validate(
  checkSchema(
    {
      name: {
        notEmpty: {
          errorMessage: USER_MESSAGE.NAME_IS_REQUIRED
        },
        isString: {
          errorMessage: USER_MESSAGE.NAME_MUST_BE_A_STRING
        },
        isLength: {
          options: {
            min: 1,
            max: 100
          },
          errorMessage: USER_MESSAGE.NAME_LENGTH_MUST_BE_FROM_1_TO_100
        },
        trim: true
      },
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGE.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGE.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value) => {
            const isExistEmail = await usersService.checkEmailExits(value)
            if (isExistEmail) {
              throw new Error(USER_MESSAGE.EMAIL_ALREADY_EXISTS)
            }
            return true
          }
        }
      },
      password: {
        isString: {
          errorMessage: USER_MESSAGE.PASSWORD_MUST_BE_A_STRING
        },
        notEmpty: {
          errorMessage: USER_MESSAGE.PASSWORD_IS_REQUIRED
        },
        isLength: {
          options: {
            min: 6,
            max: 50
          },
          errorMessage: USER_MESSAGE.PASSWORD_LENGTH_MUST_BE_FROM_6_TO_50
        },
        isStrongPassword: {
          options: {
            minLength: 6,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
          },
          errorMessage: USER_MESSAGE.PASSWORD_MUST_BE_STRONG
        }
      },
      comfirm_password: {
        isString: {
          errorMessage: USER_MESSAGE.CONFIRM_PASSWORD_MUST_BE_A_STRING
        },
        notEmpty: {
          errorMessage: USER_MESSAGE.CONFIRM_PASSWORD_IS_REQUIRED
        },
        isLength: {
          options: {
            min: 6,
            max: 50
          },
          errorMessage: USER_MESSAGE.CONFIRM_PASSWORD_MUST_BE_FROM_6_TO_50
        },
        isStrongPassword: {
          options: {
            minLength: 6,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
          },
          errorMessage: USER_MESSAGE.CONFIRM_PASSWORD_MUST_BE_STRONG
        },
        custom: {
          options: (value, { req }) => {
            if (value !== req.body.password) {
              throw new Error(USER_MESSAGE.CONFIRM_PASSWORD_MUST_BE_THE_SAME_AS_PASSWORD)
            }
            return true
          }
        }
      },
      date_of_birth: {
        isISO8601: {
          options: {
            strict: true,
            strictSeparator: true
          },
          errorMessage: USER_MESSAGE.DATE_OF_BIRTH_IS_MUST_BE_ISO8601
        }
      }
    },
    ['body']
  )
)

export const accessTokenValidator = validate(
  checkSchema(
    {
      Authorization: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            const access_token = value.split(' ')[1]
            if (!value) {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.ACCESS_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            if (access_token === '') {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.ACCESS_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            try {
              const decode_authorization = await verifyToken({
                token: access_token,
                secretOrPublicKey: process.env.JWT_SECRET_ACCESS_TOKEN as string
              })
              ;(req as Request).decode_authorization = decode_authorization
            } catch (error) {
              throw new ErrorWithStatus({
                message: (error as JsonWebTokenError).message,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }

            return true
          }
        }
      }
    },
    ['headers']
  )
)

export const refreshTokenValidator = validate(
  checkSchema(
    {
      refresh_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.REFRESH_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            try {
              const [decoded_refresh_token, refresh_token] = await Promise.all([
                verifyToken({ token: value, secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN as string }),
                databaseService.refreshToken.findOne({ token: value })
              ])
              if (refresh_token === null) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGE.USED_REFRESH_TOKEN_OR_NOT_EXITS,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              ;(req as Request).decoded_refresh_token = decoded_refresh_token
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: error.message,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              throw error
            }
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const emailVerifyTokenValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.EMAIL_VERIFY_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            try {
              const decoded_email_verify_token = await verifyToken({
                token: value,
                secretOrPublicKey: process.env.JWT_SECRET_EMAIL_TOKEN as string
              })
              ;(req as Request).decoded_email_verify_token = decoded_email_verify_token
            } catch (error) {
              throw new ErrorWithStatus({
                message: (error as JsonWebTokenError).message,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }

            return true
          }
        }
      }
    },
    ['body']
  )
)

export const forgotPasswordValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGE.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGE.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const user = await databaseService.user.findOne({ email: value })
            if (user === null) {
              throw new Error(USER_MESSAGE.USER_NOT_FOUND)
            }
            req.user = user
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const verifyForgotPasswordValidator = validate(
  checkSchema(
    {
      forgot_password_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                message: USER_MESSAGE.FORGOT_PASSWORD_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            try {
              const decode_forgot_password_token = await verifyToken({
                token: value,
                secretOrPublicKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string
              })
              const { user_id } = decode_forgot_password_token
              const user = await databaseService.user.findOne({ _id: new ObjectId(user_id) })
              if (user === null) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGE.USER_NOT_FOUND,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              if (user.forgot_password_token !== value) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGE.INVALID_FOTGOT_PASSWORD_TOKEN,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: error.message,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
            }

            return true
          }
        }
      }
    },
    ['body']
  )
)
