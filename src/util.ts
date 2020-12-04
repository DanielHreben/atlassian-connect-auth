import jwt from 'atlassian-jwt';

import { AuthError } from './AuthError';
import {
  ClientIdRequestFields,
  CommonRequestFields,
  DecodedTokenPayloadFields,
  ExpressRequestField,
  TokenRequestFields,
} from './types';

export function extractToken(req: TokenRequestFields): string {
  const token = req.headers.authorization || req.query.jwt || '';
  return token.replace(/^JWT /, '');
}

export function extractId(req: ClientIdRequestFields, product: string): string {
  if (product === 'bitbucket') {
    return req.body.principal.uuid;
  }

  return req.body.clientKey;
}

export function extractIssuer(token: string): string {
  try {
    return jwt.decode(token, '', true).iss;
  } catch (error) {
    throw new AuthError('Failed to decode token', 'FAILED_TO_DECODE', error);
  }
}

export function validateQsh<DecodedTokenPayload extends DecodedTokenPayloadFields>(
  req: CommonRequestFields & ExpressRequestField,
  payload: DecodedTokenPayload,
  baseUrl: string
): undefined {
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
    throw new AuthError('Invalid QSH', 'INVALID_QSH');
  }
}

export function validateToken<DecodedTokenPayload extends DecodedTokenPayloadFields>(
  token: string,
  sharedSecret: string
): DecodedTokenPayload {
  let payload;

  try {
    payload = jwt.decode(token, sharedSecret);
  } catch (error) {
    throw new AuthError('Invalid signature', 'INVALID_SIGNATURE', error);
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && now > payload.exp) {
    throw new AuthError('Token expired', 'TOKEN_EXPIRED');
  }

  return payload;
}
