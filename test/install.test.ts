import * as jwt from 'atlassian-jwt';

import { Addon, AuthError, AuthErrorCodes, Products } from '../src';
import { createReq, noop } from './helpers/util';

const baseUrl = 'https://test.example.com';
const saveCredentials = jest.fn();

const jiraPayload = {
  baseUrl: 'https://test.atlassian.net',
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat',
};

const bitbucketPayload = {
  principal: { uuid: 'bitbucket-workspace-id' },
  clientKey: 'bitbucket-client-key',
  sharedSecret: 'shh-secret-cat',
};

const jiraAddon = new Addon(Products.jira, baseUrl);

const bitbucketAddon = new Addon(Products.bitbucket, baseUrl);

beforeEach(() => {
  saveCredentials.mockReset();
});

describe('Installation', () => {
  test('First Jira add-on install', async () => {
    const req = createReq({ body: jiraPayload, headers: {}, query: {} });
    const loadCredentials = jest.fn();

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials,
    });

    expect(result.credentials).toEqual(jiraPayload);
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body);
  });

  test('First Bitbucket add-on install', async () => {
    const req = createReq({ body: bitbucketPayload, headers: {}, query: {} });
    const loadCredentials = jest.fn();

    const result = await bitbucketAddon.install(req, {
      loadCredentials,
      saveCredentials,
    });

    expect(result.credentials).toEqual(bitbucketPayload);
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body);
  });

  test('Failed to decode token', async () => {
    const token = 'abc.def.ghi';

    const req = createReq({
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
    });

    await expect(jiraAddon.auth(req, { loadCredentials: noop })).rejects.toMatchError(
      new AuthError(
        'Failed to decode token',
        AuthErrorCodes.FAILED_TO_DECODE,
        new SyntaxError('Unexpected token i in JSON at position 0')
      )
    );
  });

  test('Passed different id in body and authorization header', async () => {
    const loadCredentials = jest.fn();
    const token = jwt.encodeSymmetric(
      {
        iss: 'different-id',
      },
      jiraPayload.sharedSecret
    );

    const req = createReq({
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
    });

    await expect(
      jiraAddon.install(req, {
        loadCredentials,
        saveCredentials,
      })
    ).rejects.toMatchError(new AuthError('Wrong issuer', AuthErrorCodes.WRONG_ISSUER));

    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).not.toHaveBeenCalled();
  });

  test('Second and subsequent installation of Jira add-on with no qsh', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const token = jwt.encodeSymmetric(
      {
        iss: jiraPayload.clientKey,
      },
      jiraPayload.sharedSecret
    );

    const req = createReq({
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
    });

    await expect(
      jiraAddon.install(req, {
        loadCredentials,
        saveCredentials,
      })
    ).rejects.toMatchError(
      new AuthError(
        'JWT did not contain the query string hash (qsh) claim',
        AuthErrorCodes.MISSED_QSH
      )
    );
  });

  test('Second and subsequent installation of Bitbucket add-on with no qsh', async () => {
    const loadCredentials = jest.fn().mockReturnValue(bitbucketPayload);
    const token = jwt.encodeSymmetric(
      {
        iss: bitbucketPayload.clientKey,
      },
      bitbucketPayload.sharedSecret
    );

    const req = createReq({
      body: bitbucketPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
    });

    const result = await bitbucketAddon.install(req, {
      loadCredentials,
      saveCredentials,
    });

    expect(result.credentials).toEqual(bitbucketPayload);
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body, bitbucketPayload);
  });

  test('Second and subsequent Jira add-on install', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const expectedHash = jwt.createQueryStringHash(
      {
        body: jiraPayload,
        query: {},
        pathname: '/api/install',
        method: 'POST',
      },
      false,
      baseUrl
    );
    const token = jwt.encodeSymmetric(
      {
        iss: jiraPayload.clientKey,
        qsh: expectedHash,
      },
      jiraPayload.sharedSecret
    );

    const req = createReq({
      body: jiraPayload,
      headers: { authorization: `JWT ${token}` },
      query: {},
      pathname: '/install',
      originalUrl: '/api/install',
      method: 'POST',
    });

    const result = await jiraAddon.install(req, {
      loadCredentials,
      saveCredentials,
    });

    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).toHaveBeenCalledWith(req.body.clientKey, req.body, jiraPayload);
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
        },
      }
    `);
  });

  test('Unauthorized request to updated existing instance', async () => {
    const loadCredentials = jest.fn().mockReturnValue(jiraPayload);
    const req = createReq({ body: jiraPayload, headers: {}, query: {} });

    await expect(
      jiraAddon.install(req, {
        loadCredentials,
        saveCredentials,
      })
    ).rejects.toMatchError(
      new AuthError('Unauthorized update request', AuthErrorCodes.UNAUTHORIZED_REQUEST)
    );
    expect(loadCredentials).toHaveBeenCalledWith(req.body.clientKey);
    expect(saveCredentials).not.toHaveBeenCalled();
  });
});
