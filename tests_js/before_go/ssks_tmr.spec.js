import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import SSKSTMRPluginPkg from '@seald-io/sdk-plugin-ssks-2mr'
import { strict as assert } from 'node:assert'
import { generateRegistrationJWT, randomString, TMRBackend } from '../utils.spec.js'
import crypto from 'node:crypto'

const SealdSDK = SealdSDKPkg.default
const SSKSTMRPlugin = SSKSTMRPluginPkg.default

describe('ssks_tmr', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/ssks_tmr/', { recursive: true })

    // create identity
    const sdk = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSTMRPlugin(credentials.ssks_url)]
    })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    await sdk.initiateIdentity({ signupJWT })

    // export identity
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/ssks_tmr/exported_identity', exportedIdentity)

    // send challenge
    const backend = TMRBackend(credentials.ssks_url, credentials.app_id, credentials.ssks_backend_app_key)
    const email = `js-go-compat-${randomString(10)}@test.com`
    await fs.writeFile('./test_artifacts/from_js/ssks_tmr/email', email, { encoding: 'utf8' })
    const { sessionId, mustAuthenticate } = await backend.challengeSend(
      'test-user',
      { type: 'EM', value: email },
      { createUser: true }
    )
    assert.equal(mustAuthenticate, false)

    // save identity
    const rawTwoManRuleKey = crypto.randomBytes(64)
    await fs.writeFile('./test_artifacts/from_js/ssks_tmr/raw_tmr_key', rawTwoManRuleKey)
    await sdk.ssks2MR.saveIdentity({
      userId: 'test-user',
      sessionId,
      authFactor: { type: 'EM', value: email },
      rawTwoManRuleKey: rawTwoManRuleKey.toString('base64')
    })
  })
})
