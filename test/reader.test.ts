import * as atlassianJwt from 'atlassian-jwt';
import { Request as ExpressRequest } from 'express';

import { ExpressReqAuthDataProvider } from '../src';
import { createReq } from './helpers/util';

const baseUrl = 'https://test.example.com';
const jiraPayload = {
  baseUrl,
  clientKey: 'jira-client-key',
  sharedSecret: 'shh-secret-cat',
};
const token = 'tkn';

describe('ExpressReqAuthDataProvider', () => {
  describe('extractConnectJwt', () => {
    test('obtains JWT from authorization header', () => {
      const req = createReq({
        headers: { authorization: `JWT ${token}` },
      });
      const jwt = new ExpressReqAuthDataProvider(req).extractConnectJwt();
      expect(jwt).toEqual(token);
    });

    test('obtains JWT from query string', () => {
      const req = createReq({
        query: { jwt: token },
      });
      const jwt = new ExpressReqAuthDataProvider(req).extractConnectJwt();
      expect(jwt).toEqual(token);
    });

    test('falls back to empty JWT if no token is provided', () => {
      const req = createReq({});
      const jwt = new ExpressReqAuthDataProvider(req).extractConnectJwt();
      expect(jwt).toEqual('');
    });
  });

  test('extractClientKey obtains clientKey', () => {
    const clientKey = 'ck';
    const req = createReq({
      body: { clientKey },
    });
    const result = new ExpressReqAuthDataProvider(req).extractClientKey();
    expect(result).toEqual(clientKey);
  });

  describe('computeQueryStringHash', () => {
    test('computes correct hash from a request object', () => {
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

      const qsh = new ExpressReqAuthDataProvider(req).computeQueryStringHash(baseUrl);
      expect(qsh).toEqual(expectedHash);
    });
  });

  describe('can be extended with a subclass so that', () => {
    class MyExpressReqAuthDataProvider extends ExpressReqAuthDataProvider {
      constructor(req: ExpressRequest) {
        super(req);
      }

      extractConnectJwt(): string {
        return (this.req.query.customJwt as string) ?? super.extractConnectJwt();
      }

      extractClientKey(): string {
        return this.req.body.foo ?? super.extractClientKey();
      }

      computeQueryStringHash(): string {
        return 'static-qsh';
      }
    }

    const req = createReq({
      body: { clientKey: 'jira-client-key' },
      query: { jwt: token },
    });
    const reqWithOverrides = createReq({
      body: { clientKey: 'jira-client-key', foo: 'foo' },
      query: { jwt: token, customJwt: 'customTkn' },
    });

    test('extractConnectJwt supports additional ways of extracting the JWT', () => {
      const jwt = new MyExpressReqAuthDataProvider(req).extractConnectJwt();
      expect(jwt).toEqual(token);
      const overriddenJwt = new MyExpressReqAuthDataProvider(reqWithOverrides).extractConnectJwt();
      expect(overriddenJwt).toEqual('customTkn');
    });

    test('extractClientKey supports additional ways of extracting the clientKey', () => {
      const result = new MyExpressReqAuthDataProvider(req).extractClientKey();
      expect(result).toEqual('jira-client-key');
      const overriddenRrsult = new MyExpressReqAuthDataProvider(
        reqWithOverrides
      ).extractClientKey();
      expect(overriddenRrsult).toEqual('foo');
    });

    test('computeQueryStringHash supports additional ways of computing the hash', () => {
      const overriddenQsh = new MyExpressReqAuthDataProvider(
        reqWithOverrides
      ).computeQueryStringHash();
      expect(overriddenQsh).toEqual('static-qsh');
    });
  });
});
