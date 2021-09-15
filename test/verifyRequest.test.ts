import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode, ConnectJwt, verifyRequest } from '../src';
import { TestAuthDataProvider } from './helpers/util';

const baseUrl = 'https://test.example.com';
const jiraClientKey = 'jira-client-key';
const bitbucketClientKey = 'bitbucket-client-key';
const storedEntity = { appSpecificId: 1 };

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: jiraClientKey,
  sharedSecret: 'shh-secret-cat',
  storedEntity,
};

const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' },
  clientKey: bitbucketClientKey,
  sharedSecret: 'shh-secret-cat',
  storedEntity,
};

describe('verifyRequest', () => {
  const loadCredentials = jest.fn();

  beforeEach(() => jest.clearAllMocks());

  test('Missing token', async () => {
    const clientKey = jiraClientKey;
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt: '',
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT }));
  });

  test('Failed to decode token', async () => {
    const clientKey = jiraClientKey;
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt: 'abc.def.ghi',
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Failed to decode token', {
        code: AuthErrorCode.FAILED_TO_DECODE,
        originError: new SyntaxError('Unexpected token i in JSON at position 0'),
      })
    );
  });

  test('Unknown issuer', async () => {
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(new AuthError('Unknown issuer', { code: AuthErrorCode.UNKNOWN_ISSUER }));
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Invalid signature', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, 'invalid-shared-secret');
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Invalid signature', {
        code: AuthErrorCode.INVALID_SIGNATURE,
        originError: new Error(
          'Signature verification failed for input: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqaXJhLWNsaWVudC1rZXkifQ with method sha256'
        ),
        unverifiedConnectJwt: jwtContent,
      })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Token expired', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const now = Math.floor(Date.now() / 1000);
    const clientKey = jiraClientKey;
    const jwtContent = {
      iss: clientKey,
      exp: now - 1000,
    } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Token expired', {
        code: AuthErrorCode.TOKEN_EXPIRED,
        unverifiedConnectJwt: jwtContent,
      })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Invalid QSH', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = {
      iss: clientKey,
      qsh: 'invalid-qsh',
    } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: 'valid-qsh',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Invalid QSH', {
        code: AuthErrorCode.INVALID_QSH,
        qshInfo: { computed: 'valid-qsh', received: 'invalid-qsh' },
        connectJwt: jwtContent,
      })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Invalid Context QSH', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = {
      iss: clientKey,
      qsh: 'invalid-qsh',
    } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
        queryStringHashType: 'context',
      })
    ).rejects.toMatchError(
      new AuthError('Invalid QSH', {
        code: AuthErrorCode.INVALID_QSH,
        qshInfo: { computed: 'skipped', received: 'invalid-qsh' },
        connectJwt: jwtContent,
      })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('No QSH in JWT token provided', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = {
      iss: jiraPayload.clientKey,
    } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: 'valid-qsh',
      clientKey,
      jwt,
    });

    await expect(
      verifyRequest({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
        code: AuthErrorCode.MISSING_QSH,
        connectJwt: jwtContent,
      })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('No QSH in JWT token provided but QSH check is skipped', async () => {
    loadCredentials.mockReturnValue(bitbucketPayload);
    const clientKey = bitbucketClientKey;
    const jwtContent = { iss: clientKey };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, bitbucketPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    const result = await verifyRequest({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'skip',
    });

    expect(result).toStrictEqual({
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Context QSH', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey, qsh: 'context-qsh' };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey: jiraClientKey,
      jwt,
    });

    const result = await verifyRequest({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'context',
    });

    expect(result).toStrictEqual({
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Context QSH with any option', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey, qsh: 'context-qsh' };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey: jiraClientKey,
      jwt,
    });

    const result = await verifyRequest({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'any',
    });

    expect(result).toStrictEqual({
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Computed QSH', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey, qsh: 'valid-qsh' };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: 'valid-qsh',
      clientKey: jiraClientKey,
      jwt,
    });

    const result = await verifyRequest({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'computed',
    });

    expect(result).toStrictEqual({
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Computed QSH with any option', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: clientKey, qsh: 'valid-qsh' };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: 'valid-qsh',
      clientKey: jiraClientKey,
      jwt,
    });

    const result = await verifyRequest({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'any',
    });

    expect(result).toStrictEqual({
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });
});
