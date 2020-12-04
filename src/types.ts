export { Request as CommonRequestFields } from 'atlassian-jwt';
export { Request as ExpressRequestField } from 'express';

export interface DecodedTokenPayloadFields {
  exp?: number;
  qsh?: string;
}

export interface TokenRequestFields {
  headers: {
    authorization?: string;
  };
  query: {
    jwt?: string;
  };
}

export interface JiraClientIdRequestFields {
  body: {
    clientKey: string;
  };
}

export interface BitbucketClientIdRequestFields {
  body: {
    principal: {
      uuid: string;
    };
  };
}

export type ClientIdRequestFields = JiraClientIdRequestFields & BitbucketClientIdRequestFields;
