type Timestamp = number;

export const ContextQsh = 'context-qsh';

export interface ConnectCredentials {
  sharedSecret: string;
}

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
