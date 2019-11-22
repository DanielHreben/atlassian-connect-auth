const jwt = require('atlassian-jwt')
const { Addon } = require('../lib')

const baseUrl = 'https://test.example.com'

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const jiraAddon = new Addon({
  product: 'jira',
  baseUrl
})

describe('Auth', () => {
  test('Missing token', async () => {
    const req = {
      body: jiraPayload,
      headers: {},
      query: {}
    }

    await expect(jiraAddon.auth(req, {})).rejects.toThrow('Missed token')
  })

  test('Unknown issuer', async () => {
    const loadCredentials = () => null
    const token = jwt.encode({
      iss: jiraPayload.clientKey
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, {
      loadCredentials
    })).rejects.toThrow('Unknown issuer')
  })

  test('Invalid signature', async () => {
    const token = jwt.encode({
      iss: jiraPayload.clientKey
    }, 'invalid-shared-secret')

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })).rejects.toThrow('Invalid signature')
  })

  test('Token expired', async () => {
    const now = Math.floor(Date.now() / 1000)

    const token = jwt.encode({
      iss: jiraPayload.clientKey,
      exp: now - 1000
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })).rejects.toThrow('Token expired')
  })

  test('Invalid QSH', async () => {
    const token = jwt.encode({
      iss: jiraPayload.clientKey,
      qsh: 'invalid-qsh'
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    await expect(jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })).rejects.toThrow('Invalid QSH')
  })

  test('No "qsh" in JWT token provided', async () => {
    const token = jwt.encode({
      iss: jiraPayload.clientKey
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const result = await jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
  })

  test('"skipQsh" passed', async () => {
    const token = jwt.encode({
      iss: jiraPayload.clientKey
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const result = await jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload,
      skipQsh: true
    })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
  })
})
