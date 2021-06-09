const jwt = require('atlassian-jwt')
const AuthError = require('./AuthError')

const noop = () => {}

function extractToken (req, customExtractToken = noop) {
  const token = req.headers.authorization || req.query.jwt || customExtractToken() || ''
  return token.replace(/^JWT /, '')
}

function extractClientKey (req) {
  return req.body.clientKey
}

function extractIssuer (token) {
  try {
    return jwt.decodeSymmetric(token, null, 'HS256', true).iss
  } catch (error) {
    throw new AuthError('Failed to decode token', 'FAILED_TO_DECODE', error)
  }
}

function validateQsh (req, payload, baseUrl) {
  if (!payload.qsh) {
    return
  }

  // The "atlassian-jwt" 1.x.x release brings some breaking changes,
  // their methods no longer accept the Express.js request object as an argument
  // but instead accepts incoming HTTP Request object that are used to generate a signed JWT.
  // "originalUrl" is Express specific, so it allows us to ease the transition.
  // Details: https://bitbucket.org/atlassian/atlassian-jwt-js/src/e672346f3103c7b079868c931af04bd25028af5d/lib/jwt.ts#lines-51:63
  const expectedHash = jwt.createQueryStringHash(
    req.originalUrl ? jwt.fromExpressRequest(req) : req,
    false,
    baseUrl
  )

  if (payload.qsh !== expectedHash) {
    throw new AuthError('Invalid QSH', 'INVALID_QSH')
  }
}

function validateToken (token, sharedSecret) {
  let payload

  try {
    payload = jwt.decodeSymmetric(token, sharedSecret, 'HS256')
  } catch (error) {
    throw new AuthError('Invalid signature', 'INVALID_SIGNATURE', error)
  }

  const now = Math.floor(Date.now() / 1000)

  if (payload.exp && now > payload.exp) {
    throw new AuthError('Token expired', 'TOKEN_EXPIRED')
  }

  return payload
}

module.exports = {
  extractToken,
  extractClientKey,
  extractIssuer,
  validateQsh,
  validateToken
}
