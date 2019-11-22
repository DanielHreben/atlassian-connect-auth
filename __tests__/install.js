const jwt = require('atlassian-jwt')
const { Addon } = require('../lib')

const baseUrl = 'https://test.example.com'
const saveCredentials = jest.fn()

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' }
}

const jiraAddon = new Addon({
  product: 'jira',
  baseUrl
})

const bitbucketAddon = new Addon({
  product: 'bitbucket',
  baseUrl
})

describe('Installation', () => {
  test('First Jira add-on install', async () => {
    const req = { body: jiraPayload, headers: {}, query: {} }
    const loadCredentials = () => null

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(result.credentials).toEqual(jiraPayload)
  })

  test('First Bitbucket add-on install', async () => {
    const req = { body: bitbucketPayload, headers: {}, query: {} }
    const loadCredentials = () => null

    const result = await bitbucketAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(result.credentials).toEqual(bitbucketPayload)
  })

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = () => null
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
    })).rejects.toThrow('Wrong issuer')
  })

  test('Second and subsequent Jira add-on install', async () => {
    const loadCredentials = () => jiraPayload
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

    expect(result.credentials).toEqual(jiraPayload)
    expect(result.payload).toEqual({
      iss: jiraPayload.clientKey
    })
  })

  test('Unauthorized request to updated existing instance', async () => {
    const loadCredentials = () => jiraPayload
    const req = { body: jiraPayload, headers: {}, query: {} }

    await expect(jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })).rejects.toThrow('Unauthorized update request')
  })
})
