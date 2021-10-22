# atlassian-connect-auth

[![Known Vulnerabilities](https://snyk.io/test/github/DanielHreben/atlassian-connect-auth/badge.svg?targetFile=package.json)](https://snyk.io/test/github/DanielHreben/atlassian-connect-auth?targetFile=package.json)

This library implements authentication for installation requests, webhooks, and page loading from Atlassian products built with Connect.

For a deeper understanding of the concepts built into this library, please read through the Atlassian Connect documentation for the corresponding product:

- [Jira Cloud: Understanding JWT for Connect apps](https://developer.atlassian.com/cloud/jira/platform/understanding-jwt-for-connect-apps/)
- [Confluence Cloud: Understanding JWT for Connect apps](https://developer.atlassian.com/cloud/confluence/understanding-jwt/)
- [Bitbucket App: Understanding JWT for apps](https://developer.atlassian.com/cloud/bitbucket/understanding-jwt-for-apps/)

## Usage

```typescript
import {
  AuthError,
  AuthErrorCode,
  CredentialsWithEntity,
  ExpressReqAuthDataProvider,
  InstallationType,
  verifyInstallation,
  verifyRequest,
} from 'atlassian-connect-auth'

// Consumers of this library have to provide a KeyProvider implementation that will fetch the public key from a CDN.
// Examples can be found under the `test` directory in this library.
import { GotKeyProvider } from './GotKeyProvider';

const baseUrl = 'https://your-app-base-url.com'
const asymmetricKeyProvider = new GotKeyProvider()

async function loadInstallationEntity(clientKey: string): Promise<CredentialsWithEntity<InstallationEntity>> {
  const storedEntity = await model.InstallationEntity.findOne({ where: { clientKey } })
  if (storedEntity) {
    return {
      sharedSecret: decrypt(storedEntity.encryptedSharedSecret),
      storedEntity,
    }
  }
}

const handleInstallation = async (req, res) => {
  try {
    const result = await verifyInstallation({
      baseUrl,
      asymmetricKeyProvider,
      authDataProvider: new ExpressReqAuthDataProvider(req),
      credentialsLoader: loadInstallationEntity,
    })

    const newInstallationEntity = req.body

    if (result.type === InstallationType.update) {
      const existingInstallationEntity = result.storedEntity
      await existingInstallationEntity.update(newInstallationEntity)
    } else {
      await model.InstallationEntity.create(newInstallationEntity)
    }

    res.sendStatus(201)
  } catch (error) {
    if (error instanceof AuthError) {
      console.warn(error)
      res.sendStatus(401)
    } else {
      console.error(error)
      res.sendStatus(500)
    }
  }
}

const handleAuth = async (req, res, next) => {
  try {
    const { connectJwt, storedEntity } = await verifyRequest({
      baseUrl,
      asymmetricKeyProvider,
      authDataProvider: new ExpressReqAuthDataProvider(req),
      credentialsLoader: loadInstallationEntity,
      queryStringHashType: 'context',
    })

    req.context = {
      accountId: connectJwt.context?.user?.accountId ?? connectJwt.sub,
      installationData: storedEntity
    }

    next()
  } catch (error) {
    if (error instanceof AuthError) {
      console.warn(error)
      res.sendStatus(401)
    } else {
      console.error(error)
      res.sendStatus(500)
    }
  }
}

const app = express()
  .post('/api/hooks/jira/installed', handleInstall)
  .post('/api/hooks/jira/uninstalled', handleAuth, handleUninstall)
  .post('/api/hooks/jira/project/created', handleAuth, handleProjectCreated)
```

## Upgrading to `3.x` with signed installs

### `Addon` class was replaced with stateless function calls

Remove class instantiation and replace method calls with function calls as follows:
- `addon.auth()` ⟶ `verifyRequest()`
- `addon.install()` ⟶ `verifyInstallation()`

Also:
- Move the `baseUrl` argument from the class instantiation to the function calls.
- Remove the `product` argument altogether.

### Callback changes
- Replace `loadCredentials` with `credentialsLoader`.
  - The return value used to be any object with a required `sharedSecret` property.
  - Now you should return an object with a `sharedSecret` property and optionally your 
stored database value in`storedEntity` as follows:
    ```javascript
      return {
        sharedSecret: '...',
        storedEntity: databaseInstallationData,
      }
    ```
- Remove `saveCredentials` from the installation verification. Use the request body payload to persist the installation data. It's safe after verifying the installation request. 
- `storedEntity` will be returned by the verification function if a value is provided.
  - For installation updates (when the loader callback returns a stored entity), `verifyInstallation()` will return
the loaded entity with an attribute also named `storedEntity`.
  - For new installations (when the loader callback does not return a stored entity), `verifyInstallation()` will not
return the property `storedEntity`.

### Query String Hash

Replace the argument `skipQsh` with `queryStringHashType`, which is an enum with the following values: 
- `'skip'`: skip QSH verification altogether. Use this in routes you had `skipQsg: true`.
- `'computed'`: force verification using regular QSH algorithm.
- `'context'`: force verification using static value `context-qsh`.
- `'any'`: accepts both `'computed'` and `'context'`.

Note: Bitbucket Cloud does not currently support `context-qsh` as it does not have a JavaScript API that 
allows generating a context token.

### Extracting the token from a request

Version `2.x` took a request object as the first argument of the verifications functions. It expected
an Express.js-like request object in order to extract the token from headers or query arguments.

Version `3.x` decouples that from the web framework with the `authDataProvider` parameter.
- Remove the first argument with the request object.
- Provide an implementation of `authDataProvider`.
  - For Express.js, use provided `ExpressReqAuthDataProvider`. Example:
    ```javascript
      verifyRequest({
        authDataProvider: new ExpressReqAuthDataProvider(req),
        ...
      })
    ```
  - Replace custom token extraction with `customExtractToken` with your implementation of `AuthDataProvider`.
    - Implement interface `AuthDataProvider` with your own token extraction.
    - Extend `ExpressReqAuthDataProvider` and add new ways of extracting the token from the `req` object. 
For instance: 
    ```typescript
      export class MyAuthDataProvider extends ExpressReqAuthDataProvider {
        extractConnectJwt(): string {
          // Custom query argument
          const jwt = this.req.query.customJwt as string
          if (jwt) {
            return jwt
          }

          // fallback to regular Connect token extraction
          return super.extractConnectJwt()
        }
      }
    ```

### Signed installs and legacy verification

Add the `authorizationMethod` argument to the verification methods to define how you want installations to be verified.
  - `sharedSecret`: force legacy method that won't check new installations and will use the `sharedSecret` to verify 
installation updates and uninstallations.
  - `publicKey`: force new signed installs that use a public key to verify new installations, installation updates,
and uninstallations.
  - `any`: accept both verification methods, meant to be used during the transition period. This is the default value.

Note: Bitbucket Cloud does not support signed installs as of 2021. You can still upgrade the library
and keep it in compatibility mode (accepting legacy installs) as a preparation for a future upgrade. 

Signed installations need to download a public key from the Atlassian Connect CDN. You need to provide an 
`asymmetricKeyProvider` to the verification functions.
- Implement the `KeyProvider` interface with your HTTP client implementation.
- The enum `ConnectInstallKeysCdnUrl` provides the base URLs for the Atlassian Connect CDN.
- Look into `./test/keyProviderExamples` for examples of implementations using Axios, Got, and Node Fetch.

### Error codes

- When checking error codes, replace string literals with values from the `AuthErrorCode` enum.
- Code changes:
  - `'MISSED_TOKEN'` is now `AuthErrorCode.MISSING_JWT`
  - `'MISSED_QSH'` is now `AuthErrorCode.MISSING_QSH`

### Upgrades in your app
- Enabled **signed installs** in your app descriptor. For instance:
  ```
  apiMigrations: {
    gdpr: true,
    'context-qsh': true,
    'signed-install': true,
  },
  ```
- Upgrade `atlassian-jwt` to `2.x`, if you have a direct dependency.
  - This library depends on `atlassian-jwt@2.x`.
  - Replace `encode()` with `encodeSymmetric()` or `encodeAsymmetric()`.
  - Replace `decode()` with `decodeSymmetric()` or `decodeAsymmetric()`. Passing the algorithm is required.
