import { AuthError, AuthErrorCode } from './AuthError';
import { decodeUnverifiedConnectJwt, verifyConnectJwt, verifyQueryStringHash } from './Jwt';
import { RequestReader } from './requestReader';
import { ConnectCredentials, ConnectJwt, ContextQsh } from './types';

export interface AddonOptions {
  baseUrl: string;
  checkQueryStringHashOnInstall: boolean;
  checkQueryStringHashOnRequest: boolean;
}

export interface CredentialsWithContext<C> extends ConnectCredentials {
  context: C;
}

export interface CredentialsLoader<C> {
  (clientKey: string): Promise<CredentialsWithContext<C> | undefined>;
}

export interface VerifyInstallArgs<C> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<C>;
}

export enum InstallType {
  newInstall = 'newInstall',
  update = 'update',
}

export interface VerifyInstallNewResponse {
  type: InstallType.newInstall;
  clientKey: string;
}

export interface VerifyInstallUpdateResponse<C> {
  type: InstallType.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  context: C;
}

export type VerifyInstallResponse<C> = VerifyInstallNewResponse | VerifyInstallUpdateResponse<C>;

export interface VerifyRequestArgs<C> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<C>;
  useContextJwt?: boolean;
}

export interface VerifyRequestResponse<C> {
  connectJwt: ConnectJwt;
  context: C;
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

  async verifyInstall<C>({
    requestReader,
    loadCredentials,
  }: VerifyInstallArgs<C>): Promise<VerifyInstallResponse<C>> {
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
        context: credentials.context,
      };
    }

    throw new AuthError('Unauthorized update request', {
      code: AuthErrorCode.UNAUTHORIZED_REQUEST,
    });
  }

  async verifyRequest<C>({
    requestReader,
    loadCredentials,
    useContextJwt = false,
  }: VerifyRequestArgs<C>): Promise<VerifyRequestResponse<C>> {
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

    return { connectJwt, context: credentials.context };
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
