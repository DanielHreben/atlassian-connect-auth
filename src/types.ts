type Timestamp = number;

export const ContextQsh = 'context-qsh';

/**
 * Represents an extensible payload of a Connect JWT.
 */
export interface ConnectJwt {
  sub: string;
  qsh?: string | typeof ContextQsh;
  iss: string; // clientKey
  aud: string; // app's baseUrl
  exp: Timestamp;
  iat: Timestamp;
  context: unknown;
  [key: string]: unknown;
}

export enum InstallType {
  newInstall = 'newInstall',
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
