import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode, ConnectJwt, InstallationType, verifyInstallation } from '../src';
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

describe('verifyInstallation', () => {
  const loadCredentials = jest.fn();

  beforeEach(() => jest.clearAllMocks());

  test('First installation', async () => {
    const clientKey = jiraClientKey;
    const requestReader = new TestAuthDataProvider({ qsh: '', clientKey, jwt: '' });

    const result = await verifyInstallation({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
    });

    expect(result).toStrictEqual({
      type: InstallationType.newInstallation,
      clientKey,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('First installation without QSH checking', async () => {
    const clientKey = bitbucketClientKey;
    const requestReader = new TestAuthDataProvider({ qsh: '', clientKey, jwt: '' });

    const result = await verifyInstallation({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'skip',
    });

    expect(result).toStrictEqual({
      type: InstallationType.newInstallation,
      clientKey,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Failed to decode token', async () => {
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey: jiraClientKey,
      jwt: 'abc.def.ghi',
    });

    await expect(
      verifyInstallation({
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

  test('Passed different id in body and authorization header', async () => {
    const clientKey = jiraClientKey;
    const jwtContent = { iss: 'different-id' } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyInstallation({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Wrong issuer', {
        code: AuthErrorCode.WRONG_ISSUER,
        unverifiedConnectJwt: jwtContent,
      })
    );

    expect(loadCredentials).not.toHaveBeenCalledWith(clientKey);
  });

  test('Second and subsequent installation of Jira add-on with no qsh', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: jiraPayload.clientKey } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(
      verifyInstallation({
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
  });

  test('Second and subsequent installation of Bitbucket add-on with no qsh', async () => {
    loadCredentials.mockReturnValue(bitbucketPayload);
    const clientKey = bitbucketClientKey;
    const jwtContent = {
      iss: bitbucketPayload.clientKey,
      qsh: 'context-qsh',
    };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, bitbucketPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt,
    });

    const result = await verifyInstallation({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
      queryStringHashType: 'skip',
    });

    expect(result).toStrictEqual({
      type: InstallationType.update,
      clientKey,
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Second and subsequent Jira add-on installation', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const qsh = 'valid';
    const jwtContent = {
      iss: jiraPayload.clientKey,
      qsh,
    };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestAuthDataProvider({
      qsh,
      clientKey,
      jwt,
    });

    const result = await verifyInstallation({
      baseUrl,
      authDataProvider: requestReader,
      credentialsLoader: loadCredentials,
    });

    expect(result).toStrictEqual({
      type: InstallationType.update,
      clientKey,
      connectJwt: jwtContent,
      storedEntity,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Unauthorized request to updated existing instance', async () => {
    loadCredentials.mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const requestReader = new TestAuthDataProvider({
      qsh: '',
      clientKey,
      jwt: '',
    });

    await expect(
      verifyInstallation({
        baseUrl,
        authDataProvider: requestReader,
        credentialsLoader: loadCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Unauthorized update request', { code: AuthErrorCode.UNAUTHORIZED_REQUEST })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });
});
