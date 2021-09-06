import { Request } from 'express';

import { AuthError, AuthErrorCodes } from './AuthError';
import { CustomTokenExtractor, Products, TokenPayload } from './types';
import * as util from './util';

export interface Credentials {
  sharedSecret: string;
}
export type LoadCredentials = (clientKey: string) => Promise<Credentials | undefined>;
export type SaveCredentials<RequestBody> = (
  id: string,
  body: RequestBody,
  credentials?: Credentials
) => Promise<Credentials>;

export class Addon {
  constructor(public product: Products, public baseUrl: string) {}

  async install(
    req: Request,
    {
      loadCredentials,
      saveCredentials,
    }: {
      loadCredentials: LoadCredentials;
      saveCredentials: SaveCredentials<Request['body']>;
    }
  ): Promise<{ credentials: Credentials; payload?: unknown }> {
    const clientKey = util.extractClientKey(req);
    const token = util.extractToken(req);
    const credentials = await loadCredentials(clientKey);

    if (token && util.extractIssuer(token) !== clientKey) {
      throw new AuthError('Wrong issuer', AuthErrorCodes.WRONG_ISSUER);
    }

    // Create allowed if nothing was found by clientKey.
    // Sometimes request signed (but we can't validate), sometimes not.
    if (!credentials) {
      const savedCredentials = await saveCredentials(clientKey, req.body);
      return {
        credentials: savedCredentials || req.body,
      };
    }

    // Update allowed only if request was signed
    if (credentials && token) {
      const payload = util.validateToken(token, credentials.sharedSecret);

      if (!payload.qsh && [Products.jira, Products.confluence].includes(this.product)) {
        throw new AuthError(
          'JWT did not contain the query string hash (qsh) claim',
          AuthErrorCodes.MISSED_QSH
        );
      }

      util.validateQsh(req, payload, this.baseUrl);

      const updatedCredentials = await saveCredentials(clientKey, req.body, credentials);

      return {
        credentials: updatedCredentials || req.body,
        payload,
      };
    }

    throw new AuthError('Unauthorized update request', AuthErrorCodes.UNAUTHORIZED_REQUEST);
  }

  async auth(
    req: Request,
    {
      skipQsh,
      loadCredentials,
      customExtractToken,
    }: {
      loadCredentials: LoadCredentials;
      skipQsh?: boolean;
      customExtractToken?: CustomTokenExtractor;
    }
  ): Promise<{ credentials: Credentials; payload: TokenPayload }> {
    const token = util.extractToken(req, customExtractToken);

    if (!token) {
      throw new AuthError('Missed token', AuthErrorCodes.MISSED_TOKEN);
    }

    const clientKey = util.extractIssuer(token);
    const credentials = await loadCredentials(clientKey);

    if (!credentials) {
      throw new AuthError('Unknown issuer', AuthErrorCodes.UNKNOWN_ISSUER);
    }

    const payload = util.validateToken(token, credentials.sharedSecret);

    if (!skipQsh && !payload.qsh && ['jira', 'confluence'].includes(this.product)) {
      throw new AuthError(
        'JWT did not contain the query string hash (qsh) claim',
        AuthErrorCodes.MISSED_QSH
      );
    }

    if (!skipQsh) {
      util.validateQsh(req, payload, this.baseUrl);
    }

    return { payload, credentials };
  }
}
