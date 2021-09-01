import { AuthError, AuthErrorCode } from './AuthError';
import { decodeUnverifiedConnectJwt, verifyConnectJwt, verifyQueryStringHash } from './Jwt';
import { RequestReader } from './requestReader';
import { ConnectCredentials, ConnectJwt, ContextQsh } from './types';

export interface AddonOptions {
  baseUrl: string;
  checkQueryStringHashOnInstall: boolean;
  checkQueryStringHashOnRequest: boolean;
}

export interface CredentialsWithEntity<E> extends ConnectCredentials {
  entity: E;
}

export interface CredentialsLoader<E> {
  (clientKey: string): Promise<CredentialsWithEntity<E> | undefined>;
}

export interface VerifyInstallArgs<E> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<E>;
}

export enum InstallType {
  newInstall = 'newInstall',
  update = 'update',
}

export interface VerifyInstallNewResponse {
  type: InstallType.newInstall;
  clientKey: string;
}

export interface VerifyInstallUpdateResponse<E> {
  type: InstallType.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  entity: E;
}

export type VerifyInstallResponse<E> = VerifyInstallNewResponse | VerifyInstallUpdateResponse<E>;

export interface VerifyRequestArgs<E> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<E>;
  useContextJwt?: boolean;
}

export interface VerifyRequestResponse<E> {
  connectJwt: ConnectJwt;
  entity: E;
}

export class ConnectApp {
  baseUrl: string;
  checkQueryStringHashOnInstall: boolean;
  checkQueryStringHashOnRequest: boolean;

  constructor({
    baseUrl,
    checkQueryStringHashOnInstall,
    checkQueryStringHashOnRequest,
  }: AddonOptions) {
    this.baseUrl = baseUrl;
    this.checkQueryStringHashOnInstall = checkQueryStringHashOnInstall;
    this.checkQueryStringHashOnRequest = checkQueryStringHashOnRequest;
  }

  async verifyInstall<E>({
    requestReader,
    loadCredentials,
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
      const connectJwt = verifyConnectJwt({ rawConnectJwt, credentials, unverifiedConnectJwt });

      if (this.checkQueryStringHashOnInstall) {
        this.verifyQsh(connectJwt, requestReader, false);
      }

      return {
        type: InstallType.update,
        clientKey,
        connectJwt,
        entity: credentials.entity,
      };
    }

    throw new AuthError('Unauthorized update request', {
      code: AuthErrorCode.UNAUTHORIZED_REQUEST,
    });
  }

  async verifyRequest<E>({
    requestReader,
    loadCredentials,
    useContextJwt = false,
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

    const connectJwt = verifyConnectJwt({ rawConnectJwt, credentials, unverifiedConnectJwt });

    if (this.checkQueryStringHashOnRequest) {
      this.verifyQsh(connectJwt, requestReader, useContextJwt);
    }

    return { connectJwt, entity: credentials.entity };
  }

  private verifyQsh(connectJwt: ConnectJwt, requestReader: RequestReader, useContextJwt: boolean) {
    if (!connectJwt.qsh) {
      throw new AuthError('JWT did not contain the query string hash (qsh) claim', {
        code: AuthErrorCode.MISSING_QSH,
        connectJwt,
      });
    }

    const requestComputedQsh = useContextJwt
      ? ContextQsh
      : requestReader.computeQueryStringHash(this.baseUrl);

    verifyQueryStringHash({ requestComputedQsh, connectJwt });
  }
}
