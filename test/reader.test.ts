import * as atlassianJwt from 'atlassian-jwt';

import { ExpressRequestReader } from '../src';
import { createReq } from './helpers/util';

const baseUrl = 'https://test.example.com';
const jiraPayload = {
  baseUrl,
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat',
};
const token = 'tkn';

describe('ExpressRequestReader', () => {
  describe('extractConnectJwt', () => {
    test('obtains JWT from authorization header', async () => {
      const req = createReq({
        headers: { authorization: `JWT ${token}` },
      });
      const jwt = new ExpressRequestReader(req).extractConnectJwt();
      expect(jwt).toEqual(token);
    });

    test('obtains JWT from query string', async () => {
      const req = createReq({
        query: { jwt: token },
      });
      const jwt = new ExpressRequestReader(req).extractConnectJwt();
      expect(jwt).toEqual(token);
    });

    test('fallback to empty JWT if no token is provided', async () => {
      const req = createReq({});
      const jwt = new ExpressRequestReader(req).extractConnectJwt();
      expect(jwt).toEqual('');
    });
  });

  test('obtains JWT from authorization header', async () => {
    const clientKey = 'ck';
    const req = createReq({
      body: { clientKey },
    });
    const result = new ExpressRequestReader(req).extractClientKey();
    expect(result).toEqual(clientKey);
  });

  describe('computeQueryStringHash', () => {
    test('computes correct hash from a request object', async () => {
      const req = createReq({
        body: jiraPayload,
        headers: { authorization: `JWT ${token}` },
        query: {},
        pathname: '/install',
        originalUrl: '/api/install',
        method: 'POST',
      });
      const expectedHash = atlassianJwt.createQueryStringHash(
        {
          body: jiraPayload,
          query: {},
          pathname: '/api/install',
          method: 'POST',
        },
        false,
        baseUrl
      );

      const qsh = new ExpressRequestReader(req).computeQueryStringHash(baseUrl);
      expect(qsh).toEqual(expectedHash);
    });
  });
});
