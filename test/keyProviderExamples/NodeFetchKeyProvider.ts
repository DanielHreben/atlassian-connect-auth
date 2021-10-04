import fetch, { RequestInit } from 'node-fetch';

import { ConnectInstallKeysCdnUrl, EnvironmentType, KeyProvider } from '../../src';

export interface NodeFetchKeyProviderArgs {
  environment?: EnvironmentType;
  requestOptions?: RequestInit;
}

/**
 * Fetch implementation that downloads the public key.
 */
export class NodeFetchKeyProvider implements KeyProvider {
  baseUrl: string;
  requestOptions: RequestInit | undefined;

  constructor({ environment, requestOptions }: NodeFetchKeyProviderArgs = {}) {
    this.baseUrl = ConnectInstallKeysCdnUrl[environment || 'production'];
    this.requestOptions = requestOptions;
  }

  async get(kid: string): Promise<string> {
    const url = new URL(kid, this.baseUrl);
    const response = await fetch(url.toString(), {
      timeout: 3000,
      ...this.requestOptions,
    });
    return await response.text();
  }
}
