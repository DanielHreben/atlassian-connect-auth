const AuthError = require('./AuthError')
const util = require('./util')

class Addon {
  constructor ({ product, baseUrl }) {
    this.product = product
    this.baseUrl = baseUrl
  }

  async install (req, { loadCredentials, saveCredentials }) {
    const clientKey = util.extractClientKey(req)
    const token = util.extractToken(req)
    const credentials = await loadCredentials(clientKey)

    if (token && util.extractIssuer(token) !== clientKey) {
      throw new AuthError('Wrong issuer', 'WRONG_ISSUER')
    }

    // Create allowed if nothing was found by clientKey.
    // Sometimes request signed (but we can't validate), sometimes not.
    if (!credentials) {
      const savedCredentials = await saveCredentials(clientKey, req.body)
      return {
        credentials: savedCredentials || req.body
      }
    }

    // Update allowed only if request was signed
    if (credentials && token) {
      const payload = util.validateToken(token, credentials.sharedSecret)
      util.validateQsh(req, payload, this.baseUrl)

      const updatedCredentials = await saveCredentials(clientKey, req.body, credentials)

      return {
        credentials: updatedCredentials || req.body,
        payload
      }
    }

    throw new AuthError('Unauthorized update request', 'UNAUTHORIZED_REQUEST')
  }

  async auth (req, { skipQsh, loadCredentials }) {
    const token = util.extractToken(req)

    if (!token) {
      throw new AuthError('Missed token', 'MISSED_TOKEN')
    }

    const clientKey = util.extractIssuer(token)
    const credentials = await loadCredentials(clientKey)

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
