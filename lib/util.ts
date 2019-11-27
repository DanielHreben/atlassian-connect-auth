import { createQueryStringHash, decode } from 'atlassian-jwt'
import { AuthError, AuthErrorCodes } from './AuthError'
import {
  CommonRequestFields,
  TokenRequestFields,
  ClientIdRequestFields,
  DecodedTokenPayloadFields
} from './types'

export function extractToken (req: TokenRequestFields) {
  const token = req.headers.authorization || req.query.jwt || ''
  return token.replace(/^JWT /, '')
}

export function extractId (req: ClientIdRequestFields) {
  return req.body.clientKey
}

export function validateQsh<
  DecodedTokenPayload extends DecodedTokenPayloadFields
> (req: CommonRequestFields, payload: DecodedTokenPayload, baseUrl: string) {
  if (!payload.qsh) {
    return
  }

  const expectedHash = createQueryStringHash(req, false, baseUrl)

  if (payload.qsh !== expectedHash) {
    throw new AuthError('Invalid QSH', AuthErrorCodes.INVALID_QSH)
  }
}

export function validateToken<
  DecodedTokenPayload extends DecodedTokenPayloadFields
> (token: string, sharedSecret: string) {
  let payload: DecodedTokenPayload

  try {
    payload = decode(token, sharedSecret)
  } catch (error) {
    throw new AuthError('Invalid signature', AuthErrorCodes.INVALID_SIGNATURE)
  }

  const now = Math.floor(Date.now() / 1000)

  if (payload.exp && now > payload.exp) {
    throw new AuthError('Token expired', AuthErrorCodes.TOKEN_EXPIRED)
  }

  return payload
}
