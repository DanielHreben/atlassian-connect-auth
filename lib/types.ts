export { Request as CommonRequestFields } from 'atlassian-jwt'

export interface TokenRequestFields {
  headers: {
    authorization?: string;
  };
  query: {
    jwt?: string;
  };
}

export interface ClientIdRequestFields {
  body: {
    clientKey: string;
  };
}

export interface DecodedTokenPayloadFields {
  exp?: number;
  qsh?: string;
}
