# atlassian-connect-auth
Helper for handling webhooks from Atlassian products

```javascript
const {Addon, AuthError} = require('atlassian-connect-auth')

const addon = new Addon({
  baseUrl: 'https://your-addon-url.com',
  product: 'jira',
})

const handleInstall = (req, res) => {
  try {
    await addon.install(req, {
      loadCredentials: clientKey => model.Credentials.findOne({ where: { clientKey } }),
      saveCredentials: (clientKey, newCredentials, storedCredentials) => {
        if (storedCredentials) {
          return storedCredentials.update(newCredentials)
        }

        return model.Credentials.create(newCredentials)
      }
    })

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

const handleAuth = (req, res, next) => {
  try {
    await addon.auth(req, {
      loadCredentials: clientKey => model.Credentials.findOne({ where: { clientKey } })
    })

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