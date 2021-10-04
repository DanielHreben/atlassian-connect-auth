import * as atlassianJwt from 'atlassian-jwt';

import {
  AuthError,
  AuthErrorCode,
  ConnectJwt,
  CredentialsWithEntity,
  KeyProvider,
  QueryStringHashType,
  verifyRequest,
  VerifyRequestArgs,
} from '../src';
import { generateTestAsymmetricKeys } from './helpers/AsymmetricKey';
import { TestAuthDataProvider } from './helpers/TestAuthDataProvider';

const AsymmetricKey = generateTestAsymmetricKeys();
const AlternativeAsymmetricKey = generateTestAsymmetricKeys();
const baseUrl = 'https://test.example.com';
const clientKey = 'client-key';
const sharedSecret = 'shh-secret-cat';
const storedEntity = { appSpecificId: 1, sharedSecret };
const credentials: CredentialsWithEntity<typeof storedEntity> = {
  sharedSecret,
  storedEntity,
};
const credentialsLoader = jest.fn();
const keyProviderGet = jest.fn();
const asymmetricKeyProvider: KeyProvider = { get: keyProviderGet };

type VerifyArgs = VerifyRequestArgs<typeof storedEntity>;
type OverrideArgs = Partial<{
  qsh: string;
  jwt: string;
  queryStringHashType: QueryStringHashType;
  authorizationMethod: 'sharedSecret' | 'publicKey' | 'any';
}>;

const verifyRequestArgs = ({
  qsh = '',
  jwt = '',
  queryStringHashType,
  authorizationMethod,
}: OverrideArgs = {}): VerifyArgs => ({
  baseUrl,
  authDataProvider: new TestAuthDataProvider({ qsh, clientKey, jwt }),
  credentialsLoader,
  asymmetricKeyProvider,
  queryStringHashType,
  authorizationMethod,
});

afterEach(() => {
  jest.resetAllMocks();
});

describe('verifyRequest', () => {
  const symmetricJwt = ({ iss = clientKey, qsh = '', secret = '', exp = 0 } = {}) => {
    const payload = { iss } as unknown as ConnectJwt;
    if (qsh) payload.qsh = qsh;
    if (exp) payload.exp = exp;
    const jwt = atlassianJwt.encodeSymmetric(payload, secret || sharedSecret);
    return { payload: { ...payload, alg: 'HS256' }, jwt };
  };

  describe('succeeds for', () => {
    beforeEach(() => {
      credentialsLoader.mockReturnValue(credentials);
    });

    test('missing QSH in JWT but QSH check is skipped', async () => {
      const { payload, jwt } = symmetricJwt();

      const result = await verifyRequest(verifyRequestArgs({ jwt, queryStringHashType: 'skip' }));

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('context QSH', async () => {
      const { payload, jwt } = symmetricJwt({ qsh: 'context-qsh' });

      const result = await verifyRequest(
        verifyRequestArgs({ jwt, queryStringHashType: 'context' })
      );

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('Context QSH with any option', async () => {
      const { payload, jwt } = symmetricJwt({ qsh: 'context-qsh' });

      const result = await verifyRequest(verifyRequestArgs({ jwt, queryStringHashType: 'any' }));

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('Computed QSH', async () => {
      const { payload, jwt } = symmetricJwt({ qsh: 'valid' });

      const result = await verifyRequest(
        verifyRequestArgs({ jwt, qsh: 'valid', queryStringHashType: 'computed' })
      );

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('Computed QSH with any option', async () => {
      const { payload, jwt } = symmetricJwt({ qsh: 'valid' });

      const result = await verifyRequest(
        verifyRequestArgs({ jwt, qsh: 'valid', queryStringHashType: 'any' })
      );

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });
  });

  describe('fails', () => {
    test('due to missing token', async () => {
      await expect(verifyRequest(verifyRequestArgs())).rejects.toMatchError(
        new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT })
      );
    });

    test('to decode token', async () => {
      await expect(verifyRequest(verifyRequestArgs({ jwt: 'abc.def.ghi' }))).rejects.toMatchError(
        new AuthError('Failed to decode token', {
          code: AuthErrorCode.FAILED_TO_DECODE,
          originError: new SyntaxError('Unexpected token i in JSON at position 0'),
        })
      );
    });

    test('because issuer is unknown (not found)', async () => {
      const { payload, jwt } = symmetricJwt();

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Unknown issuer', {
          code: AuthErrorCode.UNKNOWN_ISSUER,
          unverifiedConnectJwt: payload,
        })
      );
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('because JWT signature is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt({ secret: 'invalid-shared-secret' });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Invalid signature', {
          code: AuthErrorCode.INVALID_SIGNATURE,
          originError: new Error(
            'Signature verification failed for input: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjbGllbnQta2V5In0 with method sha256'
          ),
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT is expired', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const now = Math.floor(Date.now() / 1000);
      const { payload, jwt } = symmetricJwt({ exp: now - 1000 });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Token expired', {
          code: AuthErrorCode.TOKEN_EXPIRED,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because QSH is missing', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt();

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
          code: AuthErrorCode.MISSING_QSH,
          connectJwt: payload,
        })
      );
    });

    test('because QSH is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt({ qsh: 'valid' });

      await expect(verifyRequest(verifyRequestArgs({ jwt, qsh: 'invalid' }))).rejects.toMatchError(
        new AuthError('Invalid QSH', {
          code: AuthErrorCode.INVALID_QSH,
          connectJwt: payload,
          qshInfo: { computed: 'invalid', received: 'valid' },
        })
      );
    });

    test('because context QSH is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt({ qsh: 'invalid' });

      await expect(
        verifyRequest(verifyRequestArgs({ jwt, queryStringHashType: 'context' }))
      ).rejects.toMatchError(
        new AuthError('Invalid QSH', {
          code: AuthErrorCode.INVALID_QSH,
          connectJwt: payload,
          qshInfo: { computed: 'context', received: 'invalid' },
        })
      );
    });
  });
});

// only use case is uninstallation
describe('verifyRequest with signed install', () => {
  const qsh = 'valid';
  const asymmetricJwt = ({
    iss = clientKey,
    qsh = '',
    aud = '',
    pk = '',
    exp = 0,
    kid = 'kid',
  } = {}) => {
    const payload = { iss, ...(aud ? { aud: [aud] } : undefined) } as unknown as ConnectJwt;
    if (qsh) payload.qsh = qsh;
    if (exp) payload.exp = exp;
    const jwt = atlassianJwt.encodeAsymmetric(
      payload,
      pk || AsymmetricKey.privateKey,
      atlassianJwt.AsymmetricAlgorithm.RS256,
      {
        kid,
      }
    );
    return { payload: { ...payload, ...(kid ? { kid } : undefined), alg: 'RS256' }, jwt };
  };

  describe('succeeds for', () => {
    beforeEach(() => {
      keyProviderGet.mockResolvedValue(AsymmetricKey.publicKey);
    });

    test('uninstallation', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = asymmetricJwt({ qsh, aud: baseUrl });

      const result = await verifyRequest(verifyRequestArgs({ jwt, qsh }));

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('uninstallation without QSH checking', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = asymmetricJwt({ qsh: 'random', aud: baseUrl });

      const result = await verifyRequest(verifyRequestArgs({ jwt, queryStringHashType: 'skip' }));

      expect(result).toStrictEqual({
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });
  });

  describe('fails', () => {
    test('because issuer is unknown (not found)', async () => {
      const { payload, jwt } = asymmetricJwt({ qsh, aud: baseUrl });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Unknown issuer', {
          code: AuthErrorCode.UNKNOWN_ISSUER,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT is missing', async () => {
      await expect(
        verifyRequest(verifyRequestArgs({ authorizationMethod: 'publicKey' }))
      ).rejects.toMatchError(new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT }));
    });

    test('because JWT issuer is different than clientKey', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ iss: 'not-clientKey' });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong issuer', {
          code: AuthErrorCode.WRONG_ISSUER,
          unverifiedConnectJwt: payload,
        })
      );

      expect(credentialsLoader).not.toHaveBeenCalledWith(clientKey);
    });

    test('because JWT aud is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt();

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong audience', {
          code: AuthErrorCode.WRONG_AUDIENCE,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT aud is different than baseUrl', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ aud: 'https://invalid.com' });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong audience', {
          code: AuthErrorCode.WRONG_AUDIENCE,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT kid is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl, kid: '' });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Missing token kid', {
          code: AuthErrorCode.MISSING_KID,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('when fetching public key', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const originError = new Error('http error');
      keyProviderGet.mockRejectedValue(originError);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Failed to obtain public key', {
          code: AuthErrorCode.FAILED_TO_OBTAIN_PUBLIC_KEY,
          originError,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT is expired', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      keyProviderGet.mockResolvedValue(AsymmetricKey.publicKey);
      credentialsLoader.mockReturnValue(credentials);
      const now = Math.floor(Date.now() / 1000);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl, exp: now - 1000 });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Token expired', {
          code: AuthErrorCode.TOKEN_EXPIRED,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because QSH is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      keyProviderGet.mockResolvedValue(AsymmetricKey.publicKey);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
          code: AuthErrorCode.MISSING_QSH,
          connectJwt: payload,
        })
      );
    });

    test('because QSH is invalid', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      keyProviderGet.mockResolvedValue(AsymmetricKey.publicKey);
      const { payload, jwt } = asymmetricJwt({ qsh: 'valid', aud: baseUrl });

      await expect(verifyRequest(verifyRequestArgs({ jwt, qsh: 'invalid' }))).rejects.toMatchError(
        new AuthError('Invalid QSH', {
          code: AuthErrorCode.INVALID_QSH,
          connectJwt: payload,
          qshInfo: { computed: 'invalid', received: 'valid' },
        })
      );
    });

    test('because JWT signature is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      keyProviderGet.mockResolvedValue(AsymmetricKey.publicKey);
      const { payload, jwt } = asymmetricJwt({
        aud: baseUrl,
        pk: AlternativeAsymmetricKey.privateKey,
      });

      await expect(verifyRequest(verifyRequestArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Invalid signature', {
          code: AuthErrorCode.INVALID_SIGNATURE,
          originError: new Error(
            'Signature verification failed for input: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJpc3MiOiJjbGllbnQta2V5IiwiYXVkIjpbImh0dHBzOi8vdGVzdC5leGFtcGxlLmNvbSJdfQ with method RSA-SHA256'
          ),
          unverifiedConnectJwt: payload,
        })
      );
    });
  });
});
