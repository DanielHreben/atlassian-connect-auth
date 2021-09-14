import { AuthDataProvider } from '../../src';

export class TestAuthDataProvider implements AuthDataProvider {
  qsh: string;
  clientKey: string;
  jwt: string;

  constructor({ qsh, clientKey, jwt }: { qsh: string; clientKey: string; jwt: string }) {
    this.qsh = qsh;
    this.clientKey = clientKey;
    this.jwt = jwt;
  }

  computeQueryStringHash(): string {
    return this.qsh;
  }

  extractClientKey(): string {
    return this.clientKey;
  }

  extractConnectJwt(): string {
    return this.jwt;
  }
}
