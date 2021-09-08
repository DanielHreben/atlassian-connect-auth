import { AuthError, AuthErrorCode } from './AuthError';
import { decodeUnverifiedConnectJwt, verifyConnectJwt } from './Jwt';
import { RequestReader } from './requestReader';
import { ConnectJwt, ContextQsh, CredentialsLoader, InstallType } from './types';

interface CommonVerifyArgs<E> {
  baseUrl: string;
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<E>;
  skipQueryStringHashCheck?: boolean; // Bitbucket does not implement Query String Hash
}

export type VerifyInstallArgs<E> = CommonVerifyArgs<E>;

export interface VerifyInstallNewResponse {
  type: InstallType.newInstall;
  clientKey: string;
}

export interface VerifyInstallUpdateResponse<E> {
  type: InstallType.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  storedEntity: E;
}

export type VerifyInstallResponse<E> = VerifyInstallNewResponse | VerifyInstallUpdateResponse<E>;

export interface VerifyRequestArgs<E> extends CommonVerifyArgs<E> {
  useContextJwt?: boolean;
}

export interface VerifyRequestResponse<E> {
  connectJwt: ConnectJwt;
  storedEntity: E;
}

export interface VerifyQueryStringHashArgs {
  baseUrl: string;
  connectJwt: ConnectJwt;
  requestReader: RequestReader;
  useContextJwt?: boolean;
  skipQueryStringHashCheck?: boolean; // Bitbucket does not implement Query String Hash
}

/**
 * Entry point for Connect request authentication.
 */
export class ConnectAuth {
  /**
   * Verifies a Connect request installation.
   * Use this method to make sure the request is valid before persisting any data.
   * This method handles both new installations and re-installations or installation updates.
   */
  static async verifyInstall<E>({
    baseUrl,
    requestReader,
    loadCredentials,
    skipQueryStringHashCheck,
  }: VerifyInstallArgs<E>): Promise<VerifyInstallResponse<E>> {
    const clientKey = requestReader.extractClientKey();

    // Check issuer
    const rawConnectJwt = requestReader.extractConnectJwt();
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
    const credentials = await loadCredentials(clientKey);
    if (!credentials) {
      return {
        type: InstallType.newInstall,
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

      if (!skipQueryStringHashCheck) {
        ConnectAuth.verifyQsh({ baseUrl, connectJwt, requestReader });
      }

      return {
        type: InstallType.update,
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
   * Use this method to verify the request was actually initiated by Atlassian Connect service and that its content
   * is not tainted via the Query String Hash algorithm.
   * This method handles both API requests and frame-loading requests, in which case you should pass
   * `useContextJwt: true`.
   */
  static async verifyRequest<E>({
    baseUrl,
    requestReader,
    loadCredentials,
    useContextJwt,
    skipQueryStringHashCheck,
  }: VerifyRequestArgs<E>): Promise<VerifyRequestResponse<E>> {
    const rawConnectJwt = requestReader.extractConnectJwt();
    if (!rawConnectJwt) {
      throw new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT });
    }

    // Load existing installation
    const unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
    const credentials = await loadCredentials(unverifiedConnectJwt.iss);
    if (!credentials) {
      throw new AuthError('Unknown issuer', { code: AuthErrorCode.UNKNOWN_ISSUER });
    }

    const connectJwt = verifyConnectJwt({
      rawConnectJwt,
      sharedSecret: credentials.sharedSecret,
      unverifiedConnectJwt,
    });

    ConnectAuth.verifyQsh({
      baseUrl,
      connectJwt,
      requestReader,
      useContextJwt,
      skipQueryStringHashCheck,
    });

    return { connectJwt, storedEntity: credentials.storedEntity };
  }

  /**
   * Verifies the Query String Hash value provided in a Connect JWT against an incoming request to make sure the payload
   * is not tainted.
   * This method is not usually called directly. See `verifyInstall` and `verifyRequest`.
   */
  static verifyQsh({
    baseUrl,
    connectJwt,
    requestReader,
    useContextJwt = false,
    skipQueryStringHashCheck = false,
  }: VerifyQueryStringHashArgs): void {
    if (skipQueryStringHashCheck) {
      return;
    }

    if (!connectJwt.qsh) {
      throw new AuthError('JWT did not contain the query string hash (qsh) claim', {
        code: AuthErrorCode.MISSING_QSH,
        connectJwt,
      });
    }

    const requestComputedQsh = useContextJwt
      ? ContextQsh
      : requestReader.computeQueryStringHash(baseUrl);

    if (connectJwt.qsh !== requestComputedQsh) {
      throw new AuthError('Invalid QSH', {
        code: AuthErrorCode.INVALID_QSH,

        qshInfo: {
          computed: requestComputedQsh || /* istanbul ignore next: ignore fallback */ 'empty',
          received: connectJwt.qsh || /* istanbul ignore next: ignore fallback */ 'empty',
        },
        connectJwt,
      });
    }
  }
}
