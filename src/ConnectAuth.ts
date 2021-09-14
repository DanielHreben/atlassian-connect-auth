import { AuthDataProvider } from './authDataProvider';
import { AuthError, AuthErrorCode } from './AuthError';
import {
  decodeUnverifiedConnectJwt,
  isAsymmetricAlgorithm,
  verifyAsymmetricConnectJwt,
  verifyConnectJwt,
} from './Jwt';
import { KeyProvider } from './publicKeyProvider';
import { verifyQueryStringHash } from './QueryStringHash';
import {
  ConnectJwt,
  CredentialsLoader,
  InstallationQueryStringHashType,
  InstallationType,
  QueryStringHashType,
} from './types';

interface CommonVerifyArgs<E, Q> {
  asymmetricKeyProvider?: KeyProvider;
  authDataProvider: AuthDataProvider;
  authorizationMethod?: 'sharedSecret' | 'publicKey' | 'any';
  baseUrl: string;
  credentialsLoader: CredentialsLoader<E>;
  queryStringHashType?: Q;
}

export type VerifyInstallationArgs<E> = CommonVerifyArgs<E, InstallationQueryStringHashType>;

export interface NewInstallationResponse {
  type: InstallationType.newInstallation;
  clientKey: string;
  connectJwt?: ConnectJwt;
}

export interface UpdateInstallationResponse<E> {
  type: InstallationType.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  storedEntity: E;
}

export type VerifyInstallationResponse<E> = NewInstallationResponse | UpdateInstallationResponse<E>;

/**
 * Verifies a Connect request installation.
 * Use this function to make sure the request is valid before persisting any data.
 * This function handles both new installations and re-installations or installation updates.
 */
export async function verifyInstallation<E>({
  asymmetricKeyProvider,
  authDataProvider,
  authorizationMethod = 'any',
  baseUrl,
  credentialsLoader,
  queryStringHashType,
}: VerifyInstallationArgs<E>): Promise<VerifyInstallationResponse<E>> {
  const clientKey = authDataProvider.extractClientKey();
  const rawConnectJwt = authDataProvider.extractConnectJwt();

  // Parse unverified JWT
  let unverifiedConnectJwt;
  if (rawConnectJwt) {
    unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
  }

  // Check for a signed installation
  if (
    authorizationMethod === 'publicKey' ||
    (authorizationMethod === 'any' && isAsymmetricAlgorithm(unverifiedConnectJwt?.alg))
  ) {
    if (!asymmetricKeyProvider) {
      throw new Error('Missing asymmetricKeyProvider instance');
    }

    const connectJwt = await verifyAsymmetricallySignedRequest({
      authDataProvider,
      asymmetricKeyProvider,
      baseUrl,
      queryStringHashType,
      unverifiedConnectJwt,
    });

    // New installation
    const credentials = await credentialsLoader(clientKey);
    if (!credentials) {
      return {
        type: InstallationType.newInstallation,
        connectJwt,
        clientKey,
      };
    }

    // Installation update
    return {
      type: InstallationType.update,
      clientKey,
      connectJwt,
      storedEntity: credentials.storedEntity,
    };
  }

  // Fallback to unsigned installation
  // In non-authenticated installs, we only check issuer if there's a JWT
  if (unverifiedConnectJwt && unverifiedConnectJwt.iss !== clientKey) {
    throw new AuthError('Wrong issuer', {
      code: AuthErrorCode.WRONG_ISSUER,
      unverifiedConnectJwt,
    });
  }

  // Unsigned new installation
  const credentials = await credentialsLoader(clientKey);
  if (!credentials) {
    return {
      type: InstallationType.newInstallation,
      clientKey,
    };
  }
  const { sharedSecret, storedEntity } = credentials;

  // Verify installation update
  if (rawConnectJwt) {
    const connectJwt = verifyConnectJwt({
      rawConnectJwt,
      sharedSecret,
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
      storedEntity,
    };
  }

  throw new AuthError('Unauthorized update request', {
    code: AuthErrorCode.UNAUTHORIZED_REQUEST,
  });
}

export type VerifyRequestArgs<E> = CommonVerifyArgs<E, QueryStringHashType>;

export interface VerifyRequestResponse<E> {
  connectJwt: ConnectJwt;
  storedEntity: E;
}

/**
 * Verifies any post-installation incoming connect requests using currently stored Shared Secret.
 * Use this function to verify the request was actually initiated by Atlassian Connect service and that its content
 * is not tainted via the Query String Hash algorithm.
 * This function handles API, frame-loading, context, and some app-lifecycle requests.
 */
export async function verifyRequest<E>({
  asymmetricKeyProvider,
  authDataProvider,
  authorizationMethod = 'any',
  baseUrl,
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
    throw new AuthError('Unknown issuer', {
      code: AuthErrorCode.UNKNOWN_ISSUER,
      unverifiedConnectJwt,
    });
  }

  // Check for a signed uninstallation
  if (
    authorizationMethod === 'publicKey' ||
    (authorizationMethod === 'any' && isAsymmetricAlgorithm(unverifiedConnectJwt.alg))
  ) {
    if (!asymmetricKeyProvider) {
      throw new Error('Missing asymmetricKeyProvider instance');
    }

    const connectJwt = await verifyAsymmetricallySignedRequest({
      authDataProvider,
      asymmetricKeyProvider,
      baseUrl,
      queryStringHashType,
      unverifiedConnectJwt,
    });

    return { connectJwt, storedEntity: credentials.storedEntity };
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

export interface verifySignedRequestArgs {
  asymmetricKeyProvider: KeyProvider;
  authDataProvider: AuthDataProvider;
  baseUrl: string;
  queryStringHashType?: QueryStringHashType;
  unverifiedConnectJwt?: ConnectJwt;
}

/**
 * Verifies a Connect request containing an asymmetrically signed JWT token.
 */
async function verifyAsymmetricallySignedRequest({
  baseUrl,
  authDataProvider,
  asymmetricKeyProvider,
  queryStringHashType,
  unverifiedConnectJwt,
}: verifySignedRequestArgs): Promise<ConnectJwt> {
  // Check JWT
  if (!unverifiedConnectJwt) {
    throw new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT });
  }

  // Check issuer
  const clientKey = authDataProvider.extractClientKey();
  if (unverifiedConnectJwt.iss !== clientKey) {
    throw new AuthError('Wrong issuer', {
      code: AuthErrorCode.WRONG_ISSUER,
      unverifiedConnectJwt,
    });
  }

  // Check audience
  if (!unverifiedConnectJwt.aud?.includes(baseUrl)) {
    throw new AuthError('Wrong audience', {
      code: AuthErrorCode.WRONG_AUDIENCE,
      unverifiedConnectJwt,
    });
  }

  if (!unverifiedConnectJwt.kid) {
    throw new AuthError('Missing token kid', {
      code: AuthErrorCode.MISSING_KID,
      unverifiedConnectJwt,
    });
  }

  // Fetch public key
  let publicKey;
  try {
    publicKey = await asymmetricKeyProvider.get(unverifiedConnectJwt.kid, unverifiedConnectJwt);
  } catch (error) {
    throw new AuthError('Failed to obtain public key', {
      code: AuthErrorCode.FAILED_TO_OBTAIN_PUBLIC_KEY,
      originError: error,
      unverifiedConnectJwt,
    });
  }

  // Verify asymmetric JWT
  const connectJwt = verifyAsymmetricConnectJwt({
    rawConnectJwt: authDataProvider.extractConnectJwt(),
    publicKey,
    unverifiedConnectJwt,
  });

  // Verify QSH
  verifyQueryStringHash({
    queryStringHashType,
    connectJwt,
    computeQueryStringHashFunction: () => authDataProvider.computeQueryStringHash(baseUrl),
  });

  return connectJwt;
}
