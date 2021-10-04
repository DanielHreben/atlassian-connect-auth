import { ConnectJwt } from '../types';

/**
 * Implementations should download the public key from the Atlassian CDN.
 */
export interface KeyProvider {
  get(kid: string, unverifiedConnectJwt: ConnectJwt): Promise<string>;
}

/**
 * Default Connect Install Key CDN URLs for production and staging.
 */
export enum ConnectInstallKeysCdnUrl {
  production = 'https://connect-install-keys.atlassian.com',
  staging = 'https://cs-migrations--cdn.us-west-1.staging.public.atl-paas.net',
}

export type EnvironmentType = keyof typeof ConnectInstallKeysCdnUrl;
