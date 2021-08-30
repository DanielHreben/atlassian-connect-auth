import * as atlassianJwt from 'atlassian-jwt';

import { AuthError, AuthErrorCode, ConnectApp, ConnectJwt, InstallType } from '../src';
import { TestRequestReader } from './helpers/util';

const baseUrl = 'https://test.example.com';
const jiraClientKey = 'jira-client-key';
const bitbucketClientKey = 'bitbucket-client-key';
const context = { appSpecificId: 1 };

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: jiraClientKey,
  sharedSecret: 'shh-secret-cat',
  context,
};
const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' },
  clientKey: bitbucketClientKey,
  sharedSecret: 'shh-secret-cat',
  context,
};

const jiraApp = new ConnectApp({
  baseUrl,
  checkQueryStringHashOnInstall: true,
  checkQueryStringHashOnRequest: true,
});
const bitbucketApp = new ConnectApp({
  baseUrl,
  checkQueryStringHashOnInstall: false,
  checkQueryStringHashOnRequest: false,
});

describe('ConnectApp.verifyInstall', () => {
  const table = [
    { name: 'Jira', app: jiraApp, clientKey: jiraClientKey },
    { name: 'Bitbucket', app: bitbucketApp, clientKey: bitbucketClientKey },
  ];

  describe.each(table)('$name app', ({ app, clientKey }) => {
    test('First install', async () => {
      const requestReader = new TestRequestReader({ qsh: '', clientKey, jwt: '' });
      const loadCredentials = jest.fn();

      const result = await app.verifyInstall({ requestReader, loadCredentials });

      expect(result).toStrictEqual({
        type: InstallType.newInstall,
        clientKey,
      });
      expect(loadCredentials).toHaveBeenCalledWith(clientKey);
    });
  });

  test('Failed to decode token', async () => {
    const loadCredentials = jest.fn();
    const requestReader = new TestRequestReader({
      qsh: '',
      clientKey: jiraClientKey,
      jwt: 'abc.def.ghi',
    });

    await expect(jiraApp.verifyInstall({ requestReader, loadCredentials })).rejects.toMatchError(
      new AuthError('Failed to decode token', {
        code: AuthErrorCode.FAILED_TO_DECODE,
        originError: new SyntaxError('Unexpected token i in JSON at position 0'),
      })
    );
  });

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = jest.fn();
    const clientKey = jiraClientKey;
    const jwtContent = { iss: 'different-id' } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestRequestReader({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(jiraApp.verifyInstall({ requestReader, loadCredentials })).rejects.toMatchError(
      new AuthError('Wrong issuer', {
        code: AuthErrorCode.WRONG_ISSUER,
        unverifiedConnectJwt: jwtContent,
      })
    );

    expect(loadCredentials).not.toHaveBeenCalledWith(clientKey);
  });

  test('Second and subsequent installation of Jira add-on with no qsh', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const jwtContent = { iss: jiraPayload.clientKey } as unknown as ConnectJwt;
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestRequestReader({
      qsh: '',
      clientKey,
      jwt,
    });

    await expect(jiraApp.verifyInstall({ requestReader, loadCredentials })).rejects.toMatchError(
      new AuthError('JWT did not contain the query string hash (qsh) claim', {
        code: AuthErrorCode.MISSING_QSH,
        connectJwt: jwtContent,
      })
    );
  });

  test('Second and subsequent installation of Bitbucket add-on with no qsh', async () => {
    const loadCredentials = jest.fn().mockReturnValue(bitbucketPayload);
    const clientKey = bitbucketClientKey;
    const jwtContent = {
      iss: bitbucketPayload.clientKey,
    };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, bitbucketPayload.sharedSecret);
    const requestReader = new TestRequestReader({
      qsh: '',
      clientKey,
      jwt,
    });

    const result = await bitbucketApp.verifyInstall({ requestReader, loadCredentials });

    expect(result).toStrictEqual({
      type: InstallType.update,
      clientKey,
      connectJwt: jwtContent,
      context,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Second and subsequent Jira add-on install', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const qsh = 'valid';
    const jwtContent = {
      iss: jiraPayload.clientKey,
      qsh,
    };
    const jwt = atlassianJwt.encodeSymmetric(jwtContent, jiraPayload.sharedSecret);
    const requestReader = new TestRequestReader({
      qsh,
      clientKey,
      jwt,
    });

    const result = await jiraApp.verifyInstall({ requestReader, loadCredentials });

    expect(result).toStrictEqual({
      type: InstallType.update,
      clientKey,
      connectJwt: jwtContent,
      context,
    });
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });

  test('Unauthorized request to updated existing instance', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const clientKey = jiraClientKey;
    const requestReader = new TestRequestReader({
      qsh: '',
      clientKey,
      jwt: '',
    });

    await expect(jiraApp.verifyInstall({ requestReader, loadCredentials })).rejects.toMatchError(
      new AuthError('Unauthorized update request', { code: AuthErrorCode.UNAUTHORIZED_REQUEST })
    );
    expect(loadCredentials).toHaveBeenCalledWith(clientKey);
  });
});
