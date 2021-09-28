import { default as axios } from 'axios';
import got from 'got';
import nock from 'nock';

import {
  AxiosKeyProvider,
  CacheWrapper,
  CachingKeyProvider,
  ConnectInstallKeysCdnUrl,
  ConnectJwt,
  KeyProvider,
} from '../src';
import { GotKeyProvider } from '../src/publicKeyProvider/GotKeyProvider';
import { NodeFetchKeyProvider } from '../src/publicKeyProvider/NodeFetchKeyProvider';

const kid = 'kid';
const publicKey = 'pk';

describe('AxiosKeyProvider', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  test('obtains key with default client', async () => {
    nock(ConnectInstallKeysCdnUrl.production).get('/kid').reply(200, publicKey);

    const key = await new AxiosKeyProvider().get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key with default client from staging environment', async () => {
    nock(ConnectInstallKeysCdnUrl.staging).get('/kid').reply(200, publicKey);

    const key = await new AxiosKeyProvider({ environment: 'staging' }).get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key passing a custom client', async () => {
    const customBaseUrl = 'https://customdomain.com/';
    nock(customBaseUrl).get('/kid').reply(200, publicKey);

    const newClient = axios.create({ baseURL: customBaseUrl });
    const key = await new AxiosKeyProvider(newClient).get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key passing custom config', async () => {
    nock(ConnectInstallKeysCdnUrl.production)
      .get('/kid')
      .matchHeader('foo', (value) => value === 'bar')
      .reply(200, publicKey);

    const key = await new AxiosKeyProvider({ config: { headers: { foo: 'bar' } } }).get(kid);

    expect(key).toEqual(publicKey);
  });
});

describe('NodeFetchKeyProvider', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  test('obtains key with default client', async () => {
    nock(ConnectInstallKeysCdnUrl.production).get('/kid').reply(200, publicKey);

    const key = await new NodeFetchKeyProvider().get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key with default client from staging environment', async () => {
    nock(ConnectInstallKeysCdnUrl.staging).get('/kid').reply(200, publicKey);

    const key = await new NodeFetchKeyProvider({ environment: 'staging' }).get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key passing custom config', async () => {
    nock(ConnectInstallKeysCdnUrl.production)
      .get('/kid')
      .matchHeader('foo', (value) => value.includes('bar'))
      .reply(200, publicKey);

    const key = await new NodeFetchKeyProvider({ requestOptions: { headers: { foo: 'bar' } } }).get(
      kid
    );

    expect(key).toEqual(publicKey);
  });
});

describe('GotKeyProvider', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  test('obtains key with default client', async () => {
    nock(ConnectInstallKeysCdnUrl.production).get('/kid').reply(200, publicKey);

    const key = await new GotKeyProvider().get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key with default client from staging environment', async () => {
    nock(ConnectInstallKeysCdnUrl.staging).get('/kid').reply(200, publicKey);

    const key = await new GotKeyProvider({ environment: 'staging' }).get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key passing a custom client', async () => {
    const customBaseUrl = 'https://customdomain.com/';
    nock(customBaseUrl).get('/kid').reply(200, publicKey);

    const newClient = got.extend({ prefixUrl: customBaseUrl });
    const key = await new GotKeyProvider(newClient).get(kid);

    expect(key).toEqual(publicKey);
  });

  test('obtains key passing custom config', async () => {
    nock(ConnectInstallKeysCdnUrl.production)
      .get('/kid')
      .matchHeader('foo', (value) => value === 'bar')
      .reply(200, publicKey);

    const key = await new GotKeyProvider({ options: { headers: { foo: 'bar' } } }).get(kid);

    expect(key).toEqual(publicKey);
  });
});

describe('CachingKeyProvider', () => {
  const cacheGetMock = jest.fn();
  const cacheSetMock = jest.fn();
  const providerGetMock = jest.fn();
  const cacheMock: CacheWrapper = { get: cacheGetMock, set: cacheSetMock };
  const providerMock: KeyProvider = { get: providerGetMock };
  const unverifiedConnectJwt = {} as unknown as ConnectJwt;

  afterEach(() => {
    jest.resetAllMocks();
  });

  test('obtains uncached key from underlying provider', async () => {
    providerGetMock.mockResolvedValue(publicKey);

    const key = await new CachingKeyProvider(providerMock, cacheMock).get(
      kid,
      unverifiedConnectJwt
    );

    expect(key).toEqual(publicKey);
    expect(cacheGetMock).toHaveBeenCalledWith(kid);
    expect(cacheSetMock).toHaveBeenCalledWith(kid, publicKey);
    expect(providerGetMock).toHaveBeenCalledWith(kid, unverifiedConnectJwt);
  });

  test('obtains cached key', async () => {
    cacheGetMock.mockResolvedValue(publicKey);

    const key = await new CachingKeyProvider(providerMock, cacheMock).get(
      kid,
      unverifiedConnectJwt
    );

    expect(key).toEqual(publicKey);
    expect(cacheSetMock).not.toHaveBeenCalled();
    expect(providerGetMock).not.toHaveBeenCalled();
  });
});
