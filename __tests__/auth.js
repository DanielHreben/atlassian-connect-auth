import { encode } from 'atlassian-jwt'
import { Addon } from '../lib'

const baseUrl = 'https://test.example.com'

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const jiraAddon = new Addon({ baseUrl })

describe('Auth', () => {
  test('Missing token', async () => {
    const req = {
      body: jiraPayload,
      headers: {},
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve({ sharedSecret: '' })

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toThrow(
      'Missed token'
    )
  })

  test('Unknown issuer', async () => {
    const loadCredentials = () => Promise.resolve()
    const token = encode(
      {
        iss: jiraPayload.clientKey
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toThrow(
      'Unknown issuer'
    )
  })

  test('Invalid signature', async () => {
    const token = encode(
      {
        iss: jiraPayload.clientKey
      },
      'invalid-shared-secret'
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve(jiraPayload)

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toThrow(
      'Invalid signature'
    )
  })

  test('Token expired', async () => {
    const now = Math.floor(Date.now() / 1000)

    const token = encode(
      {
        iss: jiraPayload.clientKey,
        exp: now - 1000
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve(jiraPayload)

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toThrow(
      'Token expired'
    )
  })

  test('Invalid QSH', async () => {
    const token = encode(
      {
        iss: jiraPayload.clientKey,
        qsh: 'invalid-qsh'
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve(jiraPayload)

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toThrow(
      'Invalid QSH'
    )
  })

  test('No "qsh" in JWT token provided', async () => {
    const token = encode(
      {
        iss: jiraPayload.clientKey
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve(jiraPayload)

    const result = await jiraAddon.auth(req, { loadCredentials })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
  })

  test('"skipQsh" passed', async () => {
    const token = encode(
      {
        iss: jiraPayload.clientKey
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve(jiraPayload)

    const result = await jiraAddon.auth(req, {
      loadCredentials,
      skipQsh: true
    })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
  })
})
