import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode } from './AuthError';
import { ConnectJwt } from './types';

/**
 * Checks whether the algorithm is asymmetric. Currently, only RS256 is supported.
 */
export function isAsymmetricAlgorithm(alg?: string): boolean {
  return alg === atlassianJwt.AsymmetricAlgorithm.RS256;
}

/**
 * Decodes a Connect JWT without verifying its authenticity.
 */
export function decodeUnverifiedConnectJwt(rawConnectJwt: string): ConnectJwt {
  try {
    const alg = atlassianJwt.getAlgorithm(rawConnectJwt) as string;

    if (isAsymmetricAlgorithm(alg)) {
      const kid = atlassianJwt.getKeyId(rawConnectJwt) as string;
      return {
        ...(kid ? { kid } : undefined),
        alg,
        ...atlassianJwt.decodeAsymmetric(
          rawConnectJwt,
          '',
          atlassianJwt.AsymmetricAlgorithm.RS256,
          true
        ),
      };
    }

    return {
      alg,
      ...atlassianJwt.decodeSymmetric(
        rawConnectJwt,
        '',
        atlassianJwt.SymmetricAlgorithm.HS256,
        true
      ),
    };
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
  unverifiedConnectJwt?: ConnectJwt; // informational value added to error in case of the verification fails
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
    const alg = atlassianJwt.getAlgorithm(rawConnectJwt) as string;

    connectJwt = {
      alg,
      ...atlassianJwt.decodeSymmetric(
        rawConnectJwt,
        sharedSecret,
        atlassianJwt.SymmetricAlgorithm.HS256
      ),
    };
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

export interface VerifyAsymmetricConnectJwtArgs {
  rawConnectJwt: string;
  publicKey: string;
  unverifiedConnectJwt?: ConnectJwt; // informational value added to error in case of the verification fails
}

/**
 * Decodes an asymmetric Connect JWT verifying it against the public secret (obtained from the CDN by the kid) and
 * checks expiration.
 */
export function verifyAsymmetricConnectJwt({
  rawConnectJwt,
  publicKey,
  unverifiedConnectJwt,
}: VerifyAsymmetricConnectJwtArgs): ConnectJwt {
  let connectJwt;

  try {
    const alg = atlassianJwt.getAlgorithm(rawConnectJwt) as string;
    const kid = atlassianJwt.getKeyId(rawConnectJwt) as string;

    connectJwt = {
      kid,
      alg,
      ...atlassianJwt.decodeAsymmetric(
        rawConnectJwt,
        publicKey,
        atlassianJwt.AsymmetricAlgorithm.RS256
      ),
    };
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
