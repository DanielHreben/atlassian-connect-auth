import { decode } from 'atlassian-jwt'
import { AuthError, AuthErrorCodes } from './AuthError'
import * as util from './util'
import {
  ClientIdRequestFields,
  TokenRequestFields,
  CommonRequestFields,
  DecodedTokenPayloadFields
} from './types'

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
  private baseUrl: string;

  constructor (opts: { baseUrl: string }) {
    this.baseUrl = opts.baseUrl
  }

  /**
   * Handle installation webhook from Atlassian products.
   */
  public async install<
    Request extends CommonRequestFields &
    ClientIdRequestFields &
    TokenRequestFields
  > (
    req: Request,
    credentialsHandlers: {
      loadCredentials: LoadCredentials<Credentials>;
      saveCredentials: SaveCredentials<Credentials, Request['body']>;
    }
  ) {
    const id = util.extractId(req)
    const token = util.extractToken(req)
    const credentials = await credentialsHandlers.loadCredentials(id)

    if (token && decode(token, '', true).iss !== id) {
      throw new AuthError('Wrong issuer', AuthErrorCodes.WRONG_ISSUER)
    }

    // Create allowed if nothing was found by id.
    // Sometimes request signed (but we can't validate), sometimes not.
    if (!credentials) {
      const savedCredentials = await credentialsHandlers.saveCredentials(
        id,
        req.body
      )

      return {
        credentials: savedCredentials
      }
    }

    // Update allowed only if request was signed
    if (credentials && token) {
      const payload = util.validateToken<DecodedTokenPayload>(
        token,
        credentials.sharedSecret
      )
      util.validateQsh(req, payload, this.baseUrl)

      const updatedCredentials = await credentialsHandlers.saveCredentials(
        id,
        req.body,
        credentials
      )
      return {
        credentials: updatedCredentials,
        payload
      }
    }

    throw new AuthError(
      'Unauthorized update request',
      AuthErrorCodes.UNAUTHORIZED_REQUEST
    )
  }

  /**
   * Check request jwt and return loaded Credentials
   */
  public async auth<Request extends CommonRequestFields & TokenRequestFields> (
    req: Request,
    opts: { skipQsh?: boolean; loadCredentials: LoadCredentials<Credentials> }
  ) {
    const token = util.extractToken(req)
    if (!token) {
      throw new AuthError('Missed token', AuthErrorCodes.MISSED_TOKEN)
    }

    const id = decode(token, '', true).iss
    const credentials = await opts.loadCredentials(id)

    if (!credentials) {
      throw new AuthError('Unknown issuer', AuthErrorCodes.UNKNOWN_ISSUER)
    }

    const payload = util.validateToken<DecodedTokenPayload>(
      token,
      credentials.sharedSecret
    )

    if (!opts.skipQsh) {
      util.validateQsh(req, payload, this.baseUrl)
    }

    return { payload, credentials }
  }
}
