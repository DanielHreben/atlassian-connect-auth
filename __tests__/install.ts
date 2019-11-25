import { encode } from 'atlassian-jwt'
import { Addon } from '../lib'

const baseUrl = 'https://test.example.com'
const saveCredentials = jest.fn()

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const jiraAddon = new Addon({ baseUrl })

describe('Installation', () => {
  test('First Jira add-on install', async () => {
    const req = {
      body: jiraPayload,
      headers: {},
      query: {},
      method: 'POST'
    }

    const loadCredentials = () => Promise.resolve()

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials
    })

    expect(result.credentials).toEqual(jiraPayload)
  })

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = () => Promise.resolve()
    const token = encode(
      {
        iss: 'different-id'
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
      jiraAddon.install(req, {
        loadCredentials,
        saveCredentials
      })
    ).rejects.toThrow('Wrong issuer')
  })

  test('Second and subsequent Jira add-on install', async () => {
    const loadCredentials = () => Promise.resolve(jiraPayload)
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
    const loadCredentials = () => Promise.resolve(jiraPayload)
    const req = {
      body: jiraPayload,
      headers: {},
      query: {},
      method: 'POST'
    }

    await expect(
      jiraAddon.install(req, {
        loadCredentials,
        saveCredentials
      })
    ).rejects.toThrow('Unauthorized update request')
  })
})
