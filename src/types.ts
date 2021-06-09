export { Request as ExpressRequest } from 'express';

export enum Products {
  jira = 'jira',
  confluence = 'confluence',
  bitbucket = 'bitbucket',
}

export type TokenPayload = Record<string, unknown>;

export type CustomTokenExtractor = () => string | undefined;
