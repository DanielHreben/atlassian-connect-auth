const jwt = require('atlassian-jwt')
const { Addon, AuthError } = require('../lib')

const baseUrl = 'https://test.example.com'
const saveCredentials = jest.fn()

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' },
  clientKey: 'bitbucket-client-key'
}

const jiraAddon = new Addon({
  product: 'jira',
  baseUrl
})

const bitbucketAddon = new Addon({
  product: 'bitbucket',
  baseUrl
})

beforeEach(() => {
  saveCredentials.mockReset()
})

describe('Installation', () => {
  test('First Jira add-on install', async () => {
    const req = { body: jiraPayload, headers: {}, query: {} }
    const loadCredentials = jest.fn()

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(result.credentials).toEqual(jiraPayload)
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body)
  })

  test('First Bitbucket add-on install', async () => {
    const req = { body: bitbucketPayload, headers: {}, query: {} }
    const loadCredentials = jest.fn()

    const result = await bitbucketAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(result.credentials).toEqual(bitbucketPayload)
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body)
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

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = jest.fn()
    const token = jwt.encode({
      iss: 'different-id'
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    await expect(jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })).rejects.toMatchError(
      new AuthError('Wrong issuer', 'WRONG_ISSUER')
    )

    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
    expect(saveCredentials).not.toHaveBeenCalled()
  })

  test('Second and subsequent Jira add-on install', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const token = jwt.encode({
      iss: jiraPayload.clientKey
    }, jiraPayload.sharedSecret)

    const req = {
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {}
    }

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body, jiraPayload)
    expect(result.credentials).toEqual(jiraPayload)
    expect(result.payload).toEqual({
      iss: jiraPayload.clientKey
    })
  })

  test('Unauthorized request to updated existing instance', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload)
    const req = { body: jiraPayload, headers: {}, query: {} }

    await expect(jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })).rejects.toMatchError(
      new AuthError('Unauthorized update request', 'UNAUTHORIZED_REQUEST')
    )
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey)
    expect(saveCredentials).not.toHaveBeenCalled()
  })
})
