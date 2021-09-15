import { AuthDataProvider } from './authDataProvider';
import { AuthError, AuthErrorCode } from './AuthError';
import { decodeUnverifiedConnectJwt, verifyConnectJwt } from './Jwt';
import { verifyQueryStringHash } from './QueryStringHash';
import {
  ConnectJwt,
  CredentialsLoader,
  InstallationQueryStringHashType,
  InstallationType,
  QueryStringHashType,
} from './types';

interface CommonVerifyArgs<E, Q> {
  baseUrl: string;
  authDataProvider: AuthDataProvider;
  credentialsLoader: CredentialsLoader<E>;
  queryStringHashType?: Q;
}

export type VerifyInstallationArgs<E> = CommonVerifyArgs<E, InstallationQueryStringHashType>;

export interface NewInstallationResponse {
  type: InstallationType.newInstallation;
  clientKey: string;
}

export interface UpdateInstallationResponse<E> {
  type: InstallationType.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  storedEntity: E;
}

export type VerifyInstallationResponse<E> = NewInstallationResponse | UpdateInstallationResponse<E>;

export type VerifyRequestArgs<E> = CommonVerifyArgs<E, QueryStringHashType>;

export interface VerifyRequestResponse<E> {
  connectJwt: ConnectJwt;
  storedEntity: E;
}

/**
 * Verifies a Connect request installation.
 * Use this function to make sure the request is valid before persisting any data.
 * This function handles both new installations and re-installations or installation updates.
 */
export async function verifyInstallation<E>({
  baseUrl,
  authDataProvider,
  credentialsLoader,
  queryStringHashType,
}: VerifyInstallationArgs<E>): Promise<VerifyInstallationResponse<E>> {
  const clientKey = authDataProvider.extractClientKey();

  // Check issuer
  const rawConnectJwt = authDataProvider.extractConnectJwt();
  let unverifiedConnectJwt;
  if (rawConnectJwt) {
    unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
    if (unverifiedConnectJwt.iss !== clientKey) {
      throw new AuthError('Wrong issuer', {
        code: AuthErrorCode.WRONG_ISSUER,
        unverifiedConnectJwt,
      });
    }
  }

  // Check new installation
  const credentials = await credentialsLoader(clientKey);
  if (!credentials) {
    return {
      type: InstallationType.newInstallation,
      clientKey,
    };
  }

  // Check installation update
  if (rawConnectJwt) {
    const connectJwt = verifyConnectJwt({
      rawConnectJwt,
      sharedSecret: credentials.sharedSecret,
      unverifiedConnectJwt,
    });

    verifyQueryStringHash({
      queryStringHashType,
      connectJwt,
      computeQueryStringHashFunction: () => authDataProvider.computeQueryStringHash(baseUrl),
    });

    return {
      type: InstallationType.update,
      clientKey,
      connectJwt,
      storedEntity: credentials.storedEntity,
    };
  }

  throw new AuthError('Unauthorized update request', {
    code: AuthErrorCode.UNAUTHORIZED_REQUEST,
  });
}

/**
 * Verifies any post-installation incoming connect requests using currently stored Shared Secret.
 * Use this function to verify the request was actually initiated by Atlassian Connect service and that its content
 * is not tainted via the Query String Hash algorithm.
 * This function handles API, frame-loading, context, and some app-lifecycle requests.
 */
export async function verifyRequest<E>({
  baseUrl,
  authDataProvider,
  credentialsLoader,
  queryStringHashType,
}: VerifyRequestArgs<E>): Promise<VerifyRequestResponse<E>> {
  const rawConnectJwt = authDataProvider.extractConnectJwt();
  if (!rawConnectJwt) {
    throw new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT });
  }

  // Load existing installation
  const unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
  const credentials = await credentialsLoader(unverifiedConnectJwt.iss);
  if (!credentials) {
    throw new AuthError('Unknown issuer', { code: AuthErrorCode.UNKNOWN_ISSUER });
  }

  const connectJwt = verifyConnectJwt({
    rawConnectJwt,
    sharedSecret: credentials.sharedSecret,
    unverifiedConnectJwt,
  });

  verifyQueryStringHash({
    queryStringHashType,
    connectJwt,
    computeQueryStringHashFunction: () => authDataProvider.computeQueryStringHash(baseUrl),
  });

  return { connectJwt, storedEntity: credentials.storedEntity };
}
