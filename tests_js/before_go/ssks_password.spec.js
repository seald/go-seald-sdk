import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import SSKSPasswordPluginPkg from '@seald-io/sdk-plugin-ssks-password'
import { generateRegistrationJWT, randomString } from '../utils.spec.js'
import crypto from 'node:crypto'

const SealdSDK = SealdSDKPkg.default
const SSKSPasswordPlugin = SSKSPasswordPluginPkg.default

describe('ssks_password', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/ssks_password/', { recursive: true })

    // create identity
    const sdk = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSPasswordPlugin(credentials.ssks_url)]
    })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    await sdk.initiateIdentity({ signupJWT })

    // export identity
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/ssks_password/exported_identity', exportedIdentity)

    // save identity with password
    const userId = randomString(10)
    await fs.writeFile('./test_artifacts/from_js/ssks_password/user_id', userId, { encoding: 'utf8' })
    const password = randomString(10)
    await fs.writeFile('./test_artifacts/from_js/ssks_password/password', password, { encoding: 'utf8' })
    await sdk.ssksPassword.saveIdentity({
      userId,
      password
    })

    // save identity with raw keys
    const rawStorageKey = crypto.randomBytes(64).toString('base64')
    await fs.writeFile('./test_artifacts/from_js/ssks_password/raw_storage_key', rawStorageKey, { encoding: 'utf8' })
    const rawEncryptionKey = crypto.randomBytes(64).toString('base64')
    await fs.writeFile('./test_artifacts/from_js/ssks_password/raw_encryption_key', rawEncryptionKey, { encoding: 'utf8' })
    await sdk.ssksPassword.saveIdentity({
      userId,
      rawStorageKey,
      rawEncryptionKey
    })
  })
})
