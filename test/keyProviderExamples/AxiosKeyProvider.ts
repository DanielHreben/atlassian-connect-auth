import { AxiosInstance, AxiosRequestConfig, default as axios } from 'axios';

import { ConnectInstallKeysCdnUrl, EnvironmentType, KeyProvider } from '../../src';

export interface AxiosKeyProviderEnvironmentArgs {
  environment?: EnvironmentType;
  config?: AxiosRequestConfig; // Override default Axios configuration
}

function isAxiosInstance(obj: unknown): obj is AxiosInstance {
  const aux = obj as { get?: unknown };
  return Boolean(aux?.get);
}

export type AxiosKeyProviderArgs = AxiosKeyProviderEnvironmentArgs | AxiosInstance;

/**
 * Axios implementation that downloads the public key.
 */
export class AxiosKeyProvider implements KeyProvider {
  client: AxiosInstance;

  constructor(optionsOrClient?: AxiosKeyProviderArgs) {
    if (isAxiosInstance(optionsOrClient)) {
      this.client = optionsOrClient;
    } else {
      this.client = axios.create({
        baseURL: ConnectInstallKeysCdnUrl[optionsOrClient?.environment || 'production'],
        timeout: 3000,
        responseType: 'text',
        ...optionsOrClient?.config,
      });
    }
  }

  async get(kid: string): Promise<string> {
    const result = await this.client.get(kid);
    return result.data;
  }
}
