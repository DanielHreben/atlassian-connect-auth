export class AuthError extends Error {
  constructor(public message: string, public code: string, public originError?: Error) {
    super(message);
  }
}

export enum AuthErrorCodes {
  MISSED_TOKEN = 'MISSED_TOKEN',
  UNAUTHORIZED_REQUEST = 'UNAUTHORIZED_REQUEST',
  FAILED_TO_DECODE = 'FAILED_TO_DECODE',
  UNKNOWN_ISSUER = 'UNKNOWN_ISSUER',
  WRONG_ISSUER = 'WRONG_ISSUER',
  INVALID_QSH = 'INVALID_QSH',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
}
