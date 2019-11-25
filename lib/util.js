const jwt = require('atlassian-jwt')
const AuthError = require('./AuthError')

function extractToken (req) {
  const token = req.headers.authorization || req.query.jwt || ''
  return token.replace(/^JWT /, '')
}

function extractId (req, product) {
  if (product === 'bitbucket') {
    return req.body.principal.uuid
  }

  return req.body.clientKey
}

function validateQsh (req, payload, baseUrl) {
  if (!payload.qsh) {
    return
  }

  // The "atlassian-jwt" 1.x.x release brings some breaking changes,
  // their methods no longer accept the Express.js request object as an argument
  // but instead use our own intermediate Request object.
  // "originalUrl" is Express specific, so it allows us to ease the transition.
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
    payload = jwt.decode(token, sharedSecret)
  } catch (error) {
    throw new AuthError('Invalid signature', 'INVALID_SIGNATURE')
  }

  const now = Math.floor(Date.now() / 1000)

  if (payload.exp && now > payload.exp) {
    throw new AuthError('Token expired', 'TOKEN_EXPIRED')
  }

  return payload
}

module.exports = {
  extractToken,
  extractId,
  validateQsh,
  validateToken
}
