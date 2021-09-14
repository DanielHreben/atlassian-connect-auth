import { ConnectJwt } from './types';

/**
 * Types of possible Validation errors.
 */
export enum AuthErrorCode {
  MISSING_JWT = 'MISSING_JWT',
  UNAUTHORIZED_REQUEST = 'UNAUTHORIZED_REQUEST',
  FAILED_TO_DECODE = 'FAILED_TO_DECODE',
  UNKNOWN_ISSUER = 'UNKNOWN_ISSUER',
  WRONG_ISSUER = 'WRONG_ISSUER',
  WRONG_AUDIENCE = 'WRONG_AUDIENCE',
  MISSING_QSH = 'MISSING_QSH',
  INVALID_QSH = 'INVALID_QSH',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  FAILED_TO_OBTAIN_PUBLIC_KEY = 'FAILED_TO_OBTAIN_PUBLIC_KEY',
  MISSING_KID = 'MISSING_KID',
}

export interface InvalidQshInfo {
  computed: string;
  received: string;
}

interface AuthErrorOptionalAttrs {
  code: AuthErrorCode;
  originError?: unknown | Error;
  connectJwt?: ConnectJwt;
  unverifiedConnectJwt?: ConnectJwt;
  qshInfo?: InvalidQshInfo;
}

/**
 * Error thrown when authentication fails upon installation or request verification.
 */
export class AuthError extends Error implements AuthErrorOptionalAttrs {
  code: AuthErrorCode;
  originError?: unknown | Error;
  connectJwt?: ConnectJwt;
  unverifiedConnectJwt?: ConnectJwt;
  qshInfo?: InvalidQshInfo;

  constructor(
    public message: string,
    { code, originError, connectJwt, unverifiedConnectJwt, qshInfo }: AuthErrorOptionalAttrs
  ) {
    super(message);
    this.code = code;
    this.originError = originError;
    this.connectJwt = connectJwt;
    this.unverifiedConnectJwt = unverifiedConnectJwt;
    this.qshInfo = qshInfo;
  }
}
