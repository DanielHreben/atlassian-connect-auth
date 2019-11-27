import { encode } from 'atlassian-jwt'
import { Addon, LoadCredentials, SaveCredentials } from '../lib'

const baseUrl = 'https://test.example.com'

interface Credentials {
  id: number;

  clientKey: string;
  sharedSecret: string;

  createdAt: Date;
}

interface RequestBody {
  baseUrl: string;
  clientKey: string;
  sharedSecret: string;
}

const requestBody: RequestBody = {
  baseUrl,
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat'
}

const credentials: Credentials = {
  id: 1,

  clientKey: requestBody.clientKey,
  sharedSecret: requestBody.sharedSecret,

  createdAt: new Date()
}

interface TokenPayload {
  qsh?: string;
}

const jiraAddon = new Addon<Credentials, TokenPayload>({ baseUrl })

describe('Installation', () => {
  test('First Jira add-on install', async () => {
    const req = {
      body: requestBody,
      headers: {},
      query: {},
      method: 'POST'
    }

    const loadCredentials: LoadCredentials<Credentials> = () => {
      return Promise.resolve()
    }
    const loadCredentialsMock = jest.fn().mockImplementationOnce(loadCredentials)

    const saveCredentials: SaveCredentials<Credentials, RequestBody> = () => {
      return Promise.resolve(credentials)
    }
    const saveCredentialsMock = jest.fn().mockImplementationOnce(saveCredentials)

    const result = await jiraAddon.install(req, {
      loadCredentials: loadCredentialsMock,
      saveCredentials: saveCredentialsMock
    })

    expect(loadCredentialsMock).toBeCalledWith(credentials.clientKey)
    expect(saveCredentialsMock).toBeCalledWith(credentials.clientKey, requestBody)

    expect(result.credentials).toEqual(credentials)
    expect(result.payload).toEqual(undefined)
  })

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = jest.fn().mockResolvedValue(credentials)
    const saveCredentials = jest.fn()

    const token = encode(
      {
        iss: 'different-id'
      },
      credentials.sharedSecret
    )

    const req = {
      body: credentials,
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

    expect(loadCredentials).toBeCalledWith(credentials.clientKey)
    expect(saveCredentials).not.toBeCalled()
  })

  test('Second and subsequent Jira add-on install', async () => {
    const newBody: RequestBody = {
      ...requestBody,
      sharedSecret: 'new-secret'
    }

    const newCredentials: Credentials = {
      ...credentials,
      sharedSecret: newBody.sharedSecret
    }

    const loadCredentials: LoadCredentials<Credentials> = () => {
      return Promise.resolve(credentials) // Loaded existing credentials
    }
    const loadCredentialsMock = jest.fn().mockImplementationOnce(loadCredentials)

    const saveCredentials: SaveCredentials<Credentials, RequestBody> = () => {
      return Promise.resolve(newCredentials) // Saved updated credentials
    }
    const saveCredentialsMock = jest.fn().mockImplementationOnce(saveCredentials)

    const token = encode(
      {
        iss: credentials.clientKey
      } as TokenPayload,
      credentials.sharedSecret
    )

    const req = {
      body: newBody,
      headers: { authorization: `JWT ${token}` },
      query: {},
      method: 'POST'
    }

    const result = await jiraAddon.install(req, {
      loadCredentials: loadCredentialsMock,
      saveCredentials: saveCredentialsMock
    })

    expect(result.credentials).toEqual(newCredentials)
    expect(result.payload).toEqual({
      iss: requestBody.clientKey
    })

    expect(loadCredentialsMock).toBeCalledWith(credentials.clientKey)
    expect(saveCredentialsMock).toBeCalledWith(credentials.clientKey, newBody, credentials) // new body but old credentials to update
  })

  test('Unauthorized request to updated existing instance', async () => {
    const loadCredentials = jest.fn().mockResolvedValueOnce(credentials)
    const saveCredentials = jest.fn()

    const req = {
      body: requestBody,
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

    expect(loadCredentials).toBeCalledWith(credentials.clientKey)
    expect(saveCredentials).not.toBeCalled()
  })
})
