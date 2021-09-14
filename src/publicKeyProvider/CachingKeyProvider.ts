import { ConnectJwt } from '../types';
import { KeyProvider } from './KeyProvider';

export interface CacheWrapper {
  get(kid: string): Promise<string>;
  set(kid: string, key: string): Promise<void>;
}

export interface CachingKeyProviderArgs {
  provider: KeyProvider;
  cache: CacheWrapper;
}

/**
 * Implementation that facilitates caching a recent public key in case CDN is inaccessible.
 * Caching is optional and, if used, must be done by the `kid`. Public keys should be rotated often and will get a new
 * kid every time which will then effectively invalidate the cache.
 */
export class CachingKeyProvider implements KeyProvider {
  constructor(public provider: KeyProvider, public cache: CacheWrapper) {}

  async get(kid: string, unverifiedConnectJwt: ConnectJwt): Promise<string> {
    // Obtain cached value, if any
    const cachedKey = await this.cache.get(kid);
    if (cachedKey) {
      return cachedKey;
    }

    // Obtain new value
    const newKey = await this.provider.get(kid, unverifiedConnectJwt);

    // Cache new value and return
    await this.cache.set(kid, newKey);
    return newKey;
  }
}
