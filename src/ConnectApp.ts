import { AuthError, AuthErrorCode } from './AuthError';
import { decodeUnverifiedConnectJwt, verifyConnectJwt, verifyQueryStringHash } from './Jwt';
import { RequestReader } from './requestReader';
import { ConnectJwt, ContextQsh, Credentials } from './types';

export interface AddonOptions {
  baseUrl: string;
  checkQueryStringHashOnInstall: boolean;
  checkQueryStringHashOnRequest: boolean;
}

export interface CredentialsWithContext<C> extends Credentials {
  context: C;
}

export interface CredentialsLoader<C> {
  (clientKey: string): Promise<CredentialsWithContext<C> | undefined>;
}

export interface VerifyInstallArgs<C> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<C>;
}

export enum InstallResponseCode {
  newInstall = 'newInstall',
  update = 'update',
}

export interface VerifyInstallNewResponse {
  type: InstallResponseCode.newInstall;
  clientKey: string;
}

export interface VerifyInstallUpdateResponse<C> {
  type: InstallResponseCode.update;
  clientKey: string;
  connectJwt: ConnectJwt;
  context: C;
}

export type VerifyInstallResponse<C> = VerifyInstallNewResponse | VerifyInstallUpdateResponse<C>;

export interface VerifyRequestArgs<C> {
  requestReader: RequestReader;
  loadCredentials: CredentialsLoader<C>;
  useContextJwt: boolean;
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
    if (rawConnectJwt) {
      const unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
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
        type: InstallResponseCode.newInstall,
        clientKey,
      };
    }

    // Check installation update
    if (credentials && rawConnectJwt) {
      const connectJwt = verifyConnectJwt({ rawConnectJwt, credentials });

      if (this.checkQueryStringHashOnInstall) {
        this.verifyQsh(connectJwt, requestReader, false);
      }

      return {
        type: InstallResponseCode.update,
        clientKey,
        connectJwt,
        context: credentials.context,
      };
    }

    const unverifiedConnectJwt = decodeUnverifiedConnectJwt(rawConnectJwt);
    throw new AuthError('Unauthorized update request', {
      code: AuthErrorCode.UNAUTHORIZED_REQUEST,
      unverifiedConnectJwt,
    });
  }

  async verifyRequest<C>({
    requestReader,
    loadCredentials,
    useContextJwt,
  }: VerifyRequestArgs<C>): Promise<VerifyRequestResponse<C>> {
    const rawConnectJwt = requestReader.extractConnectJwt();

    if (!rawConnectJwt) {
      throw new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT });
    }

    const clientKey = requestReader.extractClientKey();
    const credentials = await loadCredentials(clientKey);

    if (!credentials) {
      throw new AuthError('Unknown issuer', { code: AuthErrorCode.UNKNOWN_ISSUER });
    }

    const connectJwt = verifyConnectJwt({ rawConnectJwt, credentials });

    if (this.checkQueryStringHashOnRequest) {
      this.verifyQsh(connectJwt, requestReader, useContextJwt);
    }

    return { connectJwt, context: credentials.context };
  }

  private verifyQsh(connectJwt: ConnectJwt, requestReader: RequestReader, useContextJwt: boolean) {
    if (!connectJwt.qsh) {
      throw new AuthError('JWT did not contain the query string hash (qsh) claim', {
        code: AuthErrorCode.MISSING_QSH,
      });
    }

    const requestComputedQsh = useContextJwt
      ? ContextQsh
      : requestReader.computeQueryStringHash(this.baseUrl);

    verifyQueryStringHash({ requestComputedQsh, connectJwt });
  }
}
