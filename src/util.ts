import * as jwt from 'atlassian-jwt';
import { Request } from 'express';

import { AuthError, AuthErrorCodes } from './AuthError';
import { CustomTokenExtractor, TokenPayload } from './types';

const noop = () => undefined;

export function extractToken(
  req: Request,
  customExtractToken: CustomTokenExtractor = noop
): string {
  const token = (req.headers.authorization ||
    req.query.jwt ||
    customExtractToken() ||
    '') as string;
  return token.replace(/^JWT /, '');
}

export function extractClientKey(req: Request): string {
  return req.body.clientKey;
}

export function extractIssuer(token: string): string {
  try {
    return jwt.decodeSymmetric(token, '', jwt.SymmetricAlgorithm.HS256, true).iss;
  } catch (error) {
    throw new AuthError('Failed to decode token', AuthErrorCodes.FAILED_TO_DECODE, error);
  }
}

export function validateQsh(req: Request, payload: TokenPayload, baseUrl: string): void {
  if (!payload.qsh) {
    return;
  }

  // The "atlassian-jwt" 1.x.x release brings some breaking changes,
  // their methods no longer accept the Express.js request object as an argument
  // but instead accepts incoming HTTP Request object that are used to generate a signed JWT.
  // "originalUrl" is Express specific, so it allows us to ease the transition.
  // Details: https://bitbucket.org/atlassian/atlassian-jwt-js/src/e672346f3103c7b079868c931af04bd25028af5d/lib/jwt.ts#lines-51:63
  const expectedHash = jwt.createQueryStringHash(
    req.originalUrl ? jwt.fromExpressRequest(req) : req,
    false,
    baseUrl
  );

  if (payload.qsh !== expectedHash) {
    throw new AuthError('Invalid QSH', AuthErrorCodes.INVALID_QSH);
  }
}

export function validateToken(token: string, sharedSecret: string): TokenPayload {
  let payload;

  try {
    payload = jwt.decodeSymmetric(token, sharedSecret, jwt.SymmetricAlgorithm.HS256);
  } catch (error) {
    throw new AuthError('Invalid signature', AuthErrorCodes.INVALID_SIGNATURE, error);
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && now > payload.exp) {
    throw new AuthError('Token expired', AuthErrorCodes.TOKEN_EXPIRED);
  }

  return payload;
}
