import { ConnectJwt } from './types';

export interface InvalidQshInfo {
  computed: string;
  received: string;
}

export enum AuthErrorCode {
  MISSING_JWT = 'MISSING_JWT',
  UNAUTHORIZED_REQUEST = 'UNAUTHORIZED_REQUEST',
  FAILED_TO_DECODE = 'FAILED_TO_DECODE',
  UNKNOWN_ISSUER = 'UNKNOWN_ISSUER',
  WRONG_ISSUER = 'WRONG_ISSUER',
  MISSING_QSH = 'MISSING_QSH',
  INVALID_QSH = 'INVALID_QSH',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
}

interface AuthErrorOptionalAttrs {
  code: AuthErrorCode;
  originError?: unknown | Error;
  connectJwt?: ConnectJwt;
  unverifiedConnectJwt?: ConnectJwt;
  qshInfo?: InvalidQshInfo;
}

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
