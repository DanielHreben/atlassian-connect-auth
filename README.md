# atlassian-connect-auth

[![Known Vulnerabilities](https://snyk.io/test/github/DanielHreben/atlassian-connect-auth/badge.svg?targetFile=package.json)](https://snyk.io/test/github/DanielHreben/atlassian-connect-auth?targetFile=package.json)

This library implements authentication for installation requests, webhooks, and page loading from Atlassian products built with Connect.

For a deeper understanding of the concepts built into this library, please read through the Atlassian Connect documentation for the corresponding product:

- [Jira Cloud: Understanding JWT for Connect apps](https://developer.atlassian.com/cloud/jira/platform/understanding-jwt-for-connect-apps/)
- [Confluence Cloud: Understanding JWT for Connect apps](https://developer.atlassian.com/cloud/confluence/understanding-jwt/)
- [Bitbucket App: Understanding JWT for apps](https://developer.atlassian.com/cloud/bitbucket/understanding-jwt-for-apps/)

Here's an agnostic example of how to use it:

```typescript
import {
  AuthError,
  AuthErrorCode,
  ConnectAuth,
  CredentialsWithEntity,
  ExpressRequestReader,
  InstallType,
} from 'atlassian-connect-auth'

const baseUrl = 'https://your-app-base-url.com'

async function loadInstallationEntity(clientKey: string): Promise<CredentialsWithEntity<InstallationEntity>> {
  const storedEntity = await model.InstallationEntity.findOne({ where: { clientKey } })
  if (storedEntity) {
    return {
      sharedSecret: decrypt(storedEntity.encryptedSharedSecret),
      storedEntity,
    }
  }
}

const handleInstall = async (req, res) => {
  try {
    const result = await ConnectAuth.verifyInstall({
      baseUrl,
      requestReader: new ExpressRequestReader(req),
      loadCredentials: loadInstallationEntity,
    })

    const newInstallationEntity = req.body

    if (result.type === InstallType.update) {
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
    const { connectJwt, storedEntity } = await ConnectAuth.verifyRequest({
      baseUrl,
      requestReader: new ExpressRequestReader(req),
      loadCredentials: loadInstallationEntity,
      useContextJwt: true,
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
