const jwt = require('atlassian-jwt')
const AuthError = require('./AuthError')
const util = require('./util')

class Addon {
  constructor ({ product, baseUrl }) {
    this.product = product
    this.baseUrl = baseUrl
  }

  async install (req, { loadCredentials, saveCredentials }) {
    const id = util.extractId(req, this.product)
    const token = util.extractToken(req)
    const credentials = await loadCredentials(id)

    if (token && jwt.decode(token, '', true).iss !== id) {
      throw new AuthError('Wrong issuer', 'WRONG_ISSUER')
    }

    // 1. Create allowed if nothing was found by id.
    // Sometimes request signed (but we can't validate), sometimes not.
    // 2. Sometimes Connect sends us a request, we save a new instance,
    // but request fails due to timeout or other reason
    // and Connect don't get 200 and revert installation.
    // Next time it sends us an unauthorized request as it would send for the first install,
    // but we already have this instance in the DB.
    if (!credentials || (
      !token && credentials && credentials.sharedSecret === req.body.sharedSecret
    )) {
      const savedCredentials = await saveCredentials(id, req.body)
      return {
        credentials: savedCredentials || req.body
      }
    }

    // Update allowed only if request was signed
    if (credentials && token) {
      const payload = util.validateToken(token, credentials.sharedSecret)
      util.validateQsh(req, payload, this.baseUrl)

      const updatedCredentials = await saveCredentials(id, req.body, credentials)
      return {
        credentials: updatedCredentials || req.body,
        payload
      }
    }

    throw new AuthError('Unauthorized update request', 'UNAUTHORIZED_REQUEST')
  }

  async auth (req, { skipQsh, loadCredentials }) {
    const token = util.extractToken(req, this.product)
    if (!token) {
      throw new AuthError('Missed token', 'MISSED_TOKEN')
    }

    const id = jwt.decode(token, '', true).iss
    const credentials = await loadCredentials(id)

    if (!credentials) {
      throw new AuthError('Unknown issuer', 'UNKNOWN_ISSUER')
    }

    const payload = util.validateToken(token, credentials.sharedSecret)

    if (!skipQsh) {
      util.validateQsh(req, payload, this.baseUrl)
    }

    return { payload, credentials }
  }
}

module.exports = Addon
