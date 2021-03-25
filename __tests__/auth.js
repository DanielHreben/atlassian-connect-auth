const jwt = require('atlassian-jwt')
const { Addon, AuthError } = require('../lib')

const baseUrl = 'https://test.example.com'

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' },
  clientKey: 'bitbucket-client-key',
  sharedSecret: 'shh-secret-cat'
}

const jiraAddon = new Addon({
  product: 'jira',
  baseUrl
})

const bitbucketAddon = new Addon({
  product: 'bitbucket',
  baseUrl
})

describe('Auth', () => {
  test('Missing token', async () => {
    const req = {
      body: jiraPayload,
      headers: {},
      query: {}
    }

    await expect(jiraAddon.auth(req, {})).rejects.toMatchError(
      new AuthError('Missed token', 'MISSED_TOKEN')
    )
  })

  test('Failed to decode token', async () => {
    const token = 'abc.def.ghi'

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, {})).rejects.toMatchError(
      new AuthError(
        'Failed to decode token',
        'FAILED_TO_DECODE',
        new SyntaxError('Unexpected token i in JSON at position 0')
      )
    )
  })

  test('Unknown issuer', async () => {
    const loadCredentials = jest.fn()
    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(
      jiraAddon.auth(req, {
        loadCredentials
      })
    ).rejects.toMatchError(new AuthError('Unknown issuer', 'UNKNOWN_ISSUER'))
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('Invalid signature', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)

    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey
      },
      'invalid-shared-secret'
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toMatchError(
      new AuthError(
        'Invalid signature',
        'INVALID_SIGNATURE',
        new Error(
          'Signature verification failed for input: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqaXJhLWNsaWVudC1rZXkifQ with method sha256'
        )
      )
    )
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('Token expired', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const now = Math.floor(Date.now() / 1000)

    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey,
        exp: now - 1000
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.auth(req, { loadCredentials })).rejects.toMatchError(
      new AuthError('Token expired', 'TOKEN_EXPIRED')
    )
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('Invalid QSH', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const token = jwt.encode(
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

    await expect(
      jiraAddon.auth(req, {
        loadCredentials
      })
    ).rejects.toMatchError(new AuthError('Invalid QSH', 'INVALID_QSH'))
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('No "qsh" in JWT token provided', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const token = jwt.encode(
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

    await expect(
      jiraAddon.auth(req, {
        loadCredentials
      })
    ).rejects.toMatchError(
      new AuthError(
        'JWT did not contain the query string hash (qsh) claim',
        'MISSED_QSH'
      )
    )
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('No "qsh" in JWT token provided for Bitbucket add-on', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const token = jwt.encode(
      {
        iss: bitbucketPayload.clientKey
      },
      bitbucketPayload.sharedSecret
    )

    const req = {
      body: bitbucketPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const result = await bitbucketAddon.auth(req, {
      loadCredentials
    })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('"skipQsh" passed', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const token = jwt.encode(
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

    const result = await jiraAddon.auth(req, {
      loadCredentials,
      skipQsh: true
    })

    expect(result).toHaveProperty('credentials')
    expect(result).toHaveProperty('payload')
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
  })

  test('Passed Node.js HTTP request object', async () => {
    const expectedHash = jwt.createQueryStringHash(
      {
        body: jiraPayload,
        query: {},
        pathname: '/api/install',
        method: 'POST'
      },
      false,
      baseUrl
    )

    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey,
        sub: 'test:account-id',
        qsh: expectedHash
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      pathname: '/api/install',
      method: 'POST'
    }

    const result = await jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })

    expect(result).toMatchInlineSnapshot(`
      Object {
        "credentials": Object {
          "baseUrl": "https://test.atlassian.net",
          "clientKey": "jira-client-key",
          "sharedSecret": "shh-secret-cat",
        },
        "payload": Object {
          "iss": "jira-client-key",
          "qsh": "308ba56cff8ed9ae4d1a5fde6c4add0c3de1c7bdf6ddcb220a8763711645e298",
          "sub": "test:account-id",
        },
      }
    `)
  })

  test('Passed Express request object', async () => {
    const expectedHash = jwt.createQueryStringHash(
      {
        body: jiraPayload,
        query: {},
        pathname: '/api/install',
        method: 'POST'
      },
      false,
      baseUrl
    )

    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey,
        sub: 'test:account-id',
        qsh: expectedHash
      },
      jiraPayload.sharedSecret
    )

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      pathname: '/install',
      originalUrl: '/api/install',
      method: 'POST'
    }

    const result = await jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload
    })

    expect(result).toMatchInlineSnapshot(`
      Object {
        "credentials": Object {
          "baseUrl": "https://test.atlassian.net",
          "clientKey": "jira-client-key",
          "sharedSecret": "shh-secret-cat",
        },
        "payload": Object {
          "iss": "jira-client-key",
          "qsh": "308ba56cff8ed9ae4d1a5fde6c4add0c3de1c7bdf6ddcb220a8763711645e298",
          "sub": "test:account-id",
        },
      }
    `)
  })

  test('Extract token from a custom place', async () => {
    const token = jwt.encode(
      {
        iss: jiraPayload.clientKey,
        sub: 'test:account-id'
      },
      jiraPayload.sharedSecret
    )

    const req = {
      headers: {},
      body: jiraPayload,
      query: { state: `JWT ${token}` },
      pathname: '/account',
      originalUrl: '/api/account',
      method: 'POST'
    }

    const result = await jiraAddon.auth(req, {
      loadCredentials: () => jiraPayload,
      customExtractToken: () => req.query.state,
      skipQsh: true
    })

    expect(result).toMatchInlineSnapshot(`
      Object {
        "credentials": Object {
          "baseUrl": "https://test.atlassian.net",
          "clientKey": "jira-client-key",
          "sharedSecret": "shh-secret-cat",
        },
        "payload": Object {
          "iss": "jira-client-key",
          "sub": "test:account-id",
        },
      }
    `)
  })
})
