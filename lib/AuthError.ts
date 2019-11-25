export class AuthError extends Error {
  constructor (public message: string, public code: AuthErrorCodes) {
    super(message)
  }
}

export enum AuthErrorCodes {
  WRONG_ISSUER = 'WRONG_ISSUER',
  UNAUTHORIZED_REQUEST = 'UNAUTHORIZED_REQUEST',
  MISSED_TOKEN = 'MISSED_TOKEN',
  UNKNOWN_ISSUER = 'UNKNOWN_ISSUER',
  INVALID_QSH = 'INVALID_QSH',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED'
}
