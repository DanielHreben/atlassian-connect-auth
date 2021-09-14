import * as atlassianJwt from 'atlassian-jwt';

import {
  AuthError,
  AuthErrorCode,
  ConnectJwt,
  CredentialsWithEntity,
  InstallationQueryStringHashType,
  InstallationType,
  KeyProvider,
  verifyInstallation,
  VerifyInstallationArgs,
} from '../src';
import {
  AnotherAsymmetricPrivateKey,
  AsymmetricPrivateKey,
  AsymmetricPublicKey,
} from './helpers/AsymmetricKey';
import { TestAuthDataProvider } from './helpers/TestAuthDataProvider';

const baseUrl = 'https://test.example.com';
const clientKey = 'client-key';
const sharedSecret = 'shh-secret-cat';
const storedEntity = { appSpecificId: 1 };
const credentials: CredentialsWithEntity<typeof storedEntity> = {
  sharedSecret,
  storedEntity,
};
const credentialsLoader = jest.fn();
const keyProviderGet = jest.fn();
const asymmetricKeyProvider: KeyProvider = { get: keyProviderGet };

type InstallArgs = VerifyInstallationArgs<typeof storedEntity>;
type OverrideArgs = Partial<{
  qsh: string;
  jwt: string;
  queryStringHashType: InstallationQueryStringHashType;
  authorizationMethod: 'sharedSecret' | 'publicKey' | 'any';
}>;

const verifyInstallationArgs = ({
  qsh = '',
  jwt = '',
  queryStringHashType,
  authorizationMethod,
}: OverrideArgs = {}): InstallArgs => ({
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

describe('verifyInstallation with legacy authentication', () => {
  const symmetricJwt = ({ iss = clientKey, qsh = '', secret = '' } = {}) => {
    const payload = { iss } as unknown as ConnectJwt;
    if (qsh) payload.qsh = qsh;
    const jwt = atlassianJwt.encodeSymmetric(payload, secret || sharedSecret);
    return { payload: { ...payload, alg: 'HS256' }, jwt };
  };

  describe('succeeds for', () => {
    test('first-time installation', async () => {
      const result = await verifyInstallation(verifyInstallationArgs());

      expect(result).toStrictEqual({
        type: InstallationType.newInstallation,
        clientKey,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('first-time installation without QSH checking', async () => {
      const result = await verifyInstallation(
        verifyInstallationArgs({ queryStringHashType: 'skip' })
      );

      expect(result).toStrictEqual({
        type: InstallationType.newInstallation,
        clientKey,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('Installation update', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const qsh = 'valid';
      const { payload, jwt } = symmetricJwt({ qsh });

      const result = await verifyInstallation(verifyInstallationArgs({ jwt, qsh }));

      expect(result).toStrictEqual({
        type: InstallationType.update,
        clientKey,
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('Installation update without QSH checking', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt();

      const result = await verifyInstallation(
        verifyInstallationArgs({ jwt, queryStringHashType: 'skip' })
      );

      expect(result).toStrictEqual({
        type: InstallationType.update,
        clientKey,
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });
  });

  describe('fails', () => {
    test('to decode token', async () => {
      await expect(
        verifyInstallation(verifyInstallationArgs({ jwt: 'abc.def.ghi' }))
      ).rejects.toMatchError(
        new AuthError('Failed to decode token', {
          code: AuthErrorCode.FAILED_TO_DECODE,
          originError: new SyntaxError('Unexpected token i in JSON at position 0'),
        })
      );
    });

    test('because JWT issuer is different than clientKey', async () => {
      const { payload, jwt } = symmetricJwt({ iss: 'not-clientKey' });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong issuer', {
          code: AuthErrorCode.WRONG_ISSUER,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because QSH is missing', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt();

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
          code: AuthErrorCode.MISSING_QSH,
          connectJwt: payload,
        })
      );
    });

    test('because QSH is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt({ qsh: 'valid' });

      await expect(
        verifyInstallation(verifyInstallationArgs({ jwt, qsh: 'invalid' }))
      ).rejects.toMatchError(
        new AuthError('Invalid QSH', {
          code: AuthErrorCode.INVALID_QSH,
          connectJwt: payload,
          qshInfo: { computed: 'invalid', received: 'valid' },
        })
      );
    });

    test('because JWT is missing on installation update', async () => {
      credentialsLoader.mockReturnValue(credentials);
      await expect(verifyInstallation(verifyInstallationArgs())).rejects.toMatchError(
        new AuthError('Unauthorized update request', { code: AuthErrorCode.UNAUTHORIZED_REQUEST })
      );
    });

    test('because JWT signature is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = symmetricJwt({ secret: 'invalid-shared-secret' });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Invalid signature', {
          code: AuthErrorCode.INVALID_SIGNATURE,
          originError: new Error(
            'Signature verification failed for input: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjbGllbnQta2V5In0 with method sha256'
          ),
          unverifiedConnectJwt: payload,
        })
      );
    });
  });
});

describe('verifyInstallation with signed install', () => {
  const qsh = 'valid';
  const asymmetricJwt = ({ iss = clientKey, qsh = '', aud = '', pk = '', kid = 'kid' } = {}) => {
    const payload = { iss, ...(aud ? { aud: [aud] } : undefined) } as unknown as ConnectJwt;
    if (qsh) payload.qsh = qsh;
    const jwt = atlassianJwt.encodeAsymmetric(
      payload,
      pk || AsymmetricPrivateKey,
      atlassianJwt.AsymmetricAlgorithm.RS256,
      {
        kid,
      }
    );
    return { payload: { ...payload, ...(kid ? { kid } : undefined), alg: 'RS256' }, jwt };
  };

  describe('succeeds for', () => {
    beforeEach(() => {
      keyProviderGet.mockResolvedValue(AsymmetricPublicKey);
    });

    test('first-time installation', async () => {
      const { payload, jwt } = asymmetricJwt({ qsh, aud: baseUrl });

      const result = await verifyInstallation(verifyInstallationArgs({ jwt, qsh }));

      expect(result).toStrictEqual({
        type: InstallationType.newInstallation,
        clientKey,
        connectJwt: payload,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
      expect(keyProviderGet).toHaveBeenCalledWith('kid', payload);
    });

    test('first-time installation without QSH checking', async () => {
      const { payload, jwt } = asymmetricJwt({ qsh: 'random', aud: baseUrl });

      const result = await verifyInstallation(
        verifyInstallationArgs({ jwt, qsh, queryStringHashType: 'skip' })
      );

      expect(result).toStrictEqual({
        type: InstallationType.newInstallation,
        clientKey,
        connectJwt: payload,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('installation update', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = asymmetricJwt({ qsh, aud: baseUrl });

      const result = await verifyInstallation(verifyInstallationArgs({ jwt, qsh }));

      expect(result).toStrictEqual({
        type: InstallationType.update,
        clientKey,
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });

    test('installation update without QSH checking', async () => {
      credentialsLoader.mockReturnValue(credentials);
      const { payload, jwt } = asymmetricJwt({ qsh: 'random', aud: baseUrl });

      const result = await verifyInstallation(
        verifyInstallationArgs({ jwt, queryStringHashType: 'skip' })
      );

      expect(result).toStrictEqual({
        type: InstallationType.update,
        clientKey,
        connectJwt: payload,
        storedEntity,
      });
      expect(credentialsLoader).toHaveBeenCalledWith(clientKey);
    });
  });

  describe('fails', () => {
    test('because JWT is missing', async () => {
      await expect(
        verifyInstallation(verifyInstallationArgs({ authorizationMethod: 'publicKey' }))
      ).rejects.toMatchError(new AuthError('Missing JWT', { code: AuthErrorCode.MISSING_JWT }));
    });

    test('because JWT issuer is different than clientKey', async () => {
      const { payload, jwt } = asymmetricJwt({ iss: 'not-clientKey' });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong issuer', {
          code: AuthErrorCode.WRONG_ISSUER,
          unverifiedConnectJwt: payload,
        })
      );

      expect(credentialsLoader).not.toHaveBeenCalledWith(clientKey);
    });

    test('because JWT aud is different than baseUrl', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ aud: 'https://invalid.com' });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong audience', {
          code: AuthErrorCode.WRONG_AUDIENCE,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT aud is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ aud: undefined });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Wrong audience', {
          code: AuthErrorCode.WRONG_AUDIENCE,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because JWT kid is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl, kid: '' });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
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

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('Failed to obtain public key', {
          code: AuthErrorCode.FAILED_TO_OBTAIN_PUBLIC_KEY,
          originError,
          unverifiedConnectJwt: payload,
        })
      );
    });

    test('because QSH is missing', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      keyProviderGet.mockResolvedValue(AsymmetricPublicKey);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
        new AuthError('JWT did not contain the Query String Hash (QSH) claim', {
          code: AuthErrorCode.MISSING_QSH,
          connectJwt: payload,
        })
      );
    });

    test('because QSH is invalid', async () => {
      credentialsLoader.mockReturnValue(storedEntity);
      keyProviderGet.mockResolvedValue(AsymmetricPublicKey);
      const { payload, jwt } = asymmetricJwt({ qsh: 'valid', aud: baseUrl });

      await expect(
        verifyInstallation(verifyInstallationArgs({ jwt, qsh: 'invalid' }))
      ).rejects.toMatchError(
        new AuthError('Invalid QSH', {
          code: AuthErrorCode.INVALID_QSH,
          connectJwt: payload,
          qshInfo: { computed: 'invalid', received: 'valid' },
        })
      );
    });

    test('because JWT is missing on update', async () => {
      credentialsLoader.mockReturnValue(credentials);
      keyProviderGet.mockResolvedValue(AsymmetricPublicKey);

      await expect(verifyInstallation(verifyInstallationArgs())).rejects.toMatchError(
        new AuthError('Unauthorized update request', { code: AuthErrorCode.UNAUTHORIZED_REQUEST })
      );
    });

    test('asymmetricKeyProvider is not provided', async () => {
      const { jwt } = asymmetricJwt();

      await expect(
        verifyInstallation({
          baseUrl,
          authDataProvider: new TestAuthDataProvider({ qsh, clientKey, jwt }),
          credentialsLoader,
        })
      ).rejects.toMatchError(new Error('Missing asymmetricKeyProvider instance'));
    });

    test('because JWT signature is invalid', async () => {
      credentialsLoader.mockReturnValue(credentials);
      keyProviderGet.mockResolvedValue(AsymmetricPublicKey);
      const { payload, jwt } = asymmetricJwt({ aud: baseUrl, pk: AnotherAsymmetricPrivateKey });

      await expect(verifyInstallation(verifyInstallationArgs({ jwt }))).rejects.toMatchError(
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
