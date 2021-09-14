type Timestamp = number;

export const ContextQsh = 'context-qsh';

/**
 * Represents the payload of a Connect JWT.
 */
export interface ConnectJwt {
  iss: string; // When a product is calling the app, this is the clientKey or app key.
  kid?: string; // Public key id used in signed installs.
  alg: string; // Extracted from the JWT header and put here for convenience.
  aud: Array<string>; // App's baseUrl.
  sub?: string; // Atlassian account ID, if associated with a logged-in user.
  qsh?: string | typeof ContextQsh; // Query String Hash: a hash of the request.
  exp: Timestamp; // Expiration timestamp.
  iat: Timestamp; // Token generation timestamp.
  context: unknown; // Optional context from the product. Varies according to the WebHook.
}

export enum InstallationType {
  newInstallation = 'newInstallation',
  update = 'update',
}

/**
 * Holds current credentials and the entity representing an existing installation.
 */
export interface CredentialsWithEntity<E> {
  sharedSecret: string;
  storedEntity: E;
}

/**
 * Used to load data from an existing installation.
 */
export interface CredentialsLoader<E> {
  (clientKey: string): Promise<CredentialsWithEntity<E> | undefined>;
}

/**
 * Chooses the algorithm used to verify the content of an incoming request from Connect.
 */
export type QueryStringHashType = 'computed' | 'context' | 'any' | 'skip';
export type InstallationQueryStringHashType = 'computed' | 'skip';
