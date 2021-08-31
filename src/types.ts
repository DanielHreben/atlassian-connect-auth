type JSONValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | JSONValue[]
  | { [key: string]: JSONValue };
type Timestamp = number;

export const ContextQsh = 'context-qsh';

export interface ConnectCredentials {
  sharedSecret: string;
}

export interface ConnectJwt {
  sub: string;
  qsh?: typeof ContextQsh;
  iss: string; // clientKey
  aud: string; // app's baseUrl
  exp: Timestamp;
  iat: Timestamp;
  context: JSONValue;
  [key: string]: JSONValue;
}
