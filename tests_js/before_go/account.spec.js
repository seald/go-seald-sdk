import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { generateRegistrationJWT } from '../utils.spec.js'

const SealdSDK = SealdSDKPkg.default

describe('account', function () {
  this.timeout(60000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/account/', { recursive: true })

    // create identity
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    await sdk.initiateIdentity({ signupJWT })

    // write identity data
    const { sealdId, deviceId } = await sdk.getCurrentAccountInfo()
    await fs.writeFile('./test_artifacts/from_js/account/seald_id', sealdId, { encoding: 'utf8' })
    await fs.writeFile('./test_artifacts/from_js/account/device_id', deviceId, { encoding: 'utf8' })

    // renew key a few times, so that key export is more complex
    await sdk.renewKey()
    await sdk.renewKey()
    await sdk.renewKey()

    // export identity
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/account/exported_identity', exportedIdentity)

    // sub identity
    const subIdentity = await sdk.createSubIdentity()
    await fs.writeFile('./test_artifacts/from_js/account/sub_identity', subIdentity.identity)
    await fs.writeFile('./test_artifacts/from_js/account/sub_device_id', subIdentity.deviceId, { encoding: 'utf8' })
  })
})
