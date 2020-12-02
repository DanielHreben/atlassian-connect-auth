class AuthError extends Error {
  constructor (message, code, originError) {
    super(message)

    this.message = message
    this.code = code
    this.originError = originError
  }
}

module.exports = AuthError
