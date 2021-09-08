import * as atlassianJwt from 'atlassian-jwt';
import { Request as ExpressRequest } from 'express';

import { RequestReader } from './RequestReader';

/**
 * Express.js implementation of RequestReader.
 */
export class ExpressRequestReader implements RequestReader {
  constructor(public req: ExpressRequest) {}

  extractConnectJwt(): string {
    const token = (this.req.headers?.authorization || this.req.query?.jwt || '') as string;
    return token.replace(/^JWT /, '');
  }

  extractClientKey(): string {
    return this.req.body.clientKey;
  }

  computeQueryStringHash(baseUrl: string): string {
    const req = atlassianJwt.fromExpressRequest(this.req);
    return atlassianJwt.createQueryStringHash(req, false, baseUrl);
  }
}
