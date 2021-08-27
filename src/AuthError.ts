export class AuthError extends Error {
  constructor(message: string, public code: AuthErrorCodes, public originError?: unknown | Error) {
    super(message);
  }
}

export enum AuthErrorCodes {
  MISSED_TOKEN = 'MISSED_TOKEN',
  UNAUTHORIZED_REQUEST = 'UNAUTHORIZED_REQUEST',
  FAILED_TO_DECODE = 'FAILED_TO_DECODE',
  UNKNOWN_ISSUER = 'UNKNOWN_ISSUER',
  WRONG_ISSUER = 'WRONG_ISSUER',
  MISSED_QSH = 'MISSED_QSH',
  INVALID_QSH = 'INVALID_QSH',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
}
