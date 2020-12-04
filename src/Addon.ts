import { AuthError } from './AuthError';
import {
  ClientIdRequestFields,
  CommonRequestFields,
  DecodedTokenPayloadFields,
  ExpressRequestField,
  TokenRequestFields,
} from './types';
import * as util from './util';

export type LoadCredentials<Credentials> = (
  id: string
) => Promise<Credentials | undefined | null | void>;

export type SaveCredentials<Credentials, RequestBody> = (
  id: string,
  body: RequestBody,
  credentials?: Credentials
) => Promise<Credentials>;

export class Addon<
  Credentials extends { sharedSecret: string },
  DecodedTokenPayload extends DecodedTokenPayloadFields
> {
  private product: string;
  private baseUrl: string;

  constructor(opts: { product: string; baseUrl: string }) {
    this.product = opts.product;
    this.baseUrl = opts.baseUrl;
  }

  /**
   * Handle installation webhook from Atlassian products.
   */
  async install<
    Request extends CommonRequestFields &
      ClientIdRequestFields &
      TokenRequestFields &
      ExpressRequestField
  >(
    req: Request,
    credentialsHandlers: {
      loadCredentials: LoadCredentials<Credentials>;
      saveCredentials: SaveCredentials<Credentials, Request['body']>;
    }
  ): Promise<{ payload?: DecodedTokenPayload; credentials: Credentials }> {
    const id = util.extractId(req, this.product);
    const token = util.extractToken(req);
    const credentials = await credentialsHandlers.loadCredentials(id);

    if (token && util.extractIssuer(token) !== id) {
      throw new AuthError('Wrong issuer', 'WRONG_ISSUER');
    }

    // Create allowed if nothing was found by id.
    // Sometimes request signed (but we can't validate), sometimes not.
    if (!credentials) {
      const savedCredentials = await credentialsHandlers.saveCredentials(id, req.body);
      return {
        credentials: savedCredentials || req.body,
      };
    }

    // Update allowed only if request was signed
    if (credentials && token) {
      const payload = util.validateToken<DecodedTokenPayload>(token, credentials.sharedSecret);
      util.validateQsh(req, payload, this.baseUrl);

      const updatedCredentials = await credentialsHandlers.saveCredentials(
        id,
        req.body,
        credentials
      );
      return {
        credentials: updatedCredentials || req.body,
        payload,
      };
    }

    throw new AuthError('Unauthorized update request', 'UNAUTHORIZED_REQUEST');
  }

  /**
   * Check request jwt and return loaded Credentials
   */
  async auth<Request extends CommonRequestFields & TokenRequestFields & ExpressRequestField>(
    req: Request,
    opts: { skipQsh?: boolean; loadCredentials: LoadCredentials<Credentials> }
  ): Promise<{ payload: DecodedTokenPayload; credentials: Credentials }> {
    const token = util.extractToken(req);
    if (!token) {
      throw new AuthError('Missed token', 'MISSED_TOKEN');
    }

    const id = util.extractIssuer(token);
    const credentials = await opts.loadCredentials(id);

    if (!credentials) {
      throw new AuthError('Unknown issuer', 'UNKNOWN_ISSUER');
    }

    const payload = util.validateToken<DecodedTokenPayload>(token, credentials.sharedSecret);

    if (!opts.skipQsh) {
      util.validateQsh(req, payload, this.baseUrl);
    }

    return { payload, credentials };
  }
}
