import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode } from './AuthError';
import { ConnectJwt, Credentials } from './types';

export function decodeUnverifiedConnectJwtWithoutError(
  rawConnectJwt: string
): ConnectJwt | undefined {
  try {
    return atlassianJwt.decodeSymmetric(
      rawConnectJwt,
      '',
      atlassianJwt.SymmetricAlgorithm.HS256,
      true
    );
  } catch (error) {
    return undefined;
  }
}

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

export function verifyConnectJwt({
  rawConnectJwt,
  credentials: { sharedSecret },
}: {
  rawConnectJwt: string;
  credentials: Credentials;
}): ConnectJwt {
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
      unverifiedConnectJwt: decodeUnverifiedConnectJwtWithoutError(connectJwt),
    });
  }

  const now = Math.floor(Date.now() / 1000);

  if (connectJwt.exp && now > connectJwt.exp) {
    throw new AuthError('Token expired', {
      code: AuthErrorCode.TOKEN_EXPIRED,
      unverifiedConnectJwt: decodeUnverifiedConnectJwtWithoutError(connectJwt),
    });
  }

  return connectJwt;
}

export function verifyQueryStringHash({
  requestComputedQsh,
  connectJwt,
}: {
  requestComputedQsh: string;
  connectJwt: ConnectJwt;
}): void {
  if (connectJwt.qsh !== requestComputedQsh) {
    throw new AuthError('Invalid QSH', {
      code: AuthErrorCode.INVALID_QSH,
      qshInfo: {
        computed: requestComputedQsh || 'empty',
        received: connectJwt.qsh || 'empty',
      },
    });
  }
}
