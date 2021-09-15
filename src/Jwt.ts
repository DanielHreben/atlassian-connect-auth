import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode } from './AuthError';
import { ConnectJwt } from './types';

/**
 * Decodes a Connect JWT without verifying its authenticity.
 */
export function decodeUnverifiedConnectJwt(rawConnectJwt: string): ConnectJwt {
  try {
    return atlassianJwt.decodeSymmetric(
      rawConnectJwt,
      '',
      atlassianJwt.SymmetricAlgorithm.HS256,
      true
    );
  } catch (error) {
    throw new AuthError('Failed to decode token', {
      code: AuthErrorCode.FAILED_TO_DECODE,
      originError: error,
    });
  }
}

export interface VerifyConnectJwtArgs {
  rawConnectJwt: string;
  sharedSecret: string;
  unverifiedConnectJwt?: ConnectJwt; // information value added to error in case of the verification fails
}

/**
 * Decodes a Connect JWT verifying it against the Shared Secret (provided during installation) and checks expiration.
 */
export function verifyConnectJwt({
  rawConnectJwt,
  sharedSecret,
  unverifiedConnectJwt,
}: VerifyConnectJwtArgs): ConnectJwt {
  let connectJwt;

  try {
    connectJwt = atlassianJwt.decodeSymmetric(
      rawConnectJwt,
      sharedSecret,
      atlassianJwt.SymmetricAlgorithm.HS256
    );
  } catch (error) {
    throw new AuthError('Invalid signature', {
      code: AuthErrorCode.INVALID_SIGNATURE,
      originError: error,
      unverifiedConnectJwt,
    });
  }

  const now = Math.floor(Date.now() / 1000);

  if (connectJwt.exp && now > connectJwt.exp) {
    throw new AuthError('Token expired', {
      code: AuthErrorCode.TOKEN_EXPIRED,
      unverifiedConnectJwt: connectJwt,
    });
  }

  return connectJwt;
}
