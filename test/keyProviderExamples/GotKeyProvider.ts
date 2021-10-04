import got, { Got, Options } from 'got';

import { ConnectInstallKeysCdnUrl, EnvironmentType, KeyProvider } from '../../src';

export interface GotKeyProviderOptionsArgs {
  environment?: EnvironmentType;
  options?: Options;
}

function isGotInstance(obj: unknown): obj is Got {
  const aux = obj as { extend?: unknown };
  return Boolean(aux?.extend);
}

export type GotKeyProviderArgs = GotKeyProviderOptionsArgs | Got;

/**
 * Got implementation that downloads the public key.
 */
export class GotKeyProvider implements KeyProvider {
  client: Got;

  constructor(args?: GotKeyProviderArgs) {
    if (isGotInstance(args)) {
      this.client = args;
    } else {
      this.client = got.extend({
        prefixUrl: ConnectInstallKeysCdnUrl[args?.environment || 'production'],
        ...args?.options,
      });
    }
  }

  async get(kid: string): Promise<string> {
    const request = this.client({
      timeout: {
        lookup: 500,
        connect: 500,
        secureConnect: 500,
        socket: 1000,
        send: 1000,
        response: 3000,
      },
      url: kid,
    });

    return request.text();
  }
}
