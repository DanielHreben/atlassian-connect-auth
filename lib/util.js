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

  const expectedHash = jwt.createQueryStringHash(req, false, baseUrl)

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
