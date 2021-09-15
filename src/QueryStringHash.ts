import { AuthError, AuthErrorCode } from './AuthError';
import { ConnectJwt, ContextQsh, QueryStringHashType } from './types';

export interface VerifyQueryStringHashArgs {
  queryStringHashType?: QueryStringHashType;
  connectJwt: ConnectJwt;
  computeQueryStringHashFunction: () => string;
}

/**
 * Verifies the Query String Hash value provided in a Connect JWT against an incoming request to make sure it is not
 * tainted.
 */
export function verifyQueryStringHash({
  queryStringHashType = 'computed',
  connectJwt,
  computeQueryStringHashFunction,
}: VerifyQueryStringHashArgs): void {
  if (queryStringHashType === 'skip') {
    return;
  }

  if (!connectJwt.qsh) {
    throw new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
      code: AuthErrorCode.MISSING_QSH,
      connectJwt,
    });
  }

  // Check context QSH
  if (
    (queryStringHashType === 'context' || queryStringHashType === 'any') &&
    connectJwt.qsh === ContextQsh
  ) {
    return;
  }

  // Check computed hash
  let requestComputedQsh = 'skipped';
  if (queryStringHashType === 'computed' || queryStringHashType === 'any') {
    requestComputedQsh = computeQueryStringHashFunction();
    if (connectJwt.qsh === requestComputedQsh) {
      return;
    }
  }

  // Error if no match
  throw new AuthError('Invalid QSH', {
    code: AuthErrorCode.INVALID_QSH,
    qshInfo: {
      computed: requestComputedQsh || /* istanbul ignore next: ignore fallback */ 'empty',
      received: connectJwt.qsh || /* istanbul ignore next: ignore fallback */ 'empty',
    },
    connectJwt,
  });
}
