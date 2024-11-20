import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { strict as assert } from 'node:assert'
import {b64UUID, generateRegistrationJWT, TMRBackend} from '../utils.spec.js'
import SSKSTMRPluginPkg from '@seald-io/sdk-plugin-ssks-2mr'

const SealdSDK = SealdSDKPkg.default
const SSKSTMRPlugin = SSKSTMRPluginPkg.default

describe('groups', function () {
  this.timeout(10000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // can import identity from Go
    const identity = await fs.readFile('./test_artifacts/from_go/groups/identity')
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    await sdk.importIdentity(identity)

    // can retrieve first session
    const sessionId = await fs.readFile('./test_artifacts/from_go/groups/session_id', { encoding: 'utf8' })
    await sdk.retrieveEncryptionSession({ sessionId })

    // can retrieve second session
    const sessionId2 = await fs.readFile('./test_artifacts/from_go/groups/session_id2', { encoding: 'utf8' })
    await sdk.retrieveEncryptionSession({ sessionId: sessionId2 })

    // group is known locally
    const groupId = await fs.readFile('./test_artifacts/from_go/groups/group_id', { encoding: 'utf8' })
    const result = await sdk.goatee.dependencies.searchLocally({ type: 'BE', value: b64UUID(groupId) })
    assert.equal(result.length, 1)
    const group = result[0]
    assert.equal(group.isGroup, true)
    assert.equal(group.groupKnownKeysIds.length, 2)

    // Test group TMR temporary key

    // Create sdkTMR that will use the gTMRTK to join the group
    const sdkTMR = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSTMRPlugin(credentials.ssks_url)]
    })
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    await sdkTMR.initiateIdentity({ signupJWT })
    sdkTMR.setLogLevel('silly')

    // Create an SSKS backend
    const backend = TMRBackend(credentials.ssks_url, credentials.app_id, credentials.ssks_backend_app_key)

    // Import the group TMR temp key created in go
    const tmrEmail = await fs.readFile('./test_artifacts/from_go/groups/tmr_temp_key_EM', { encoding: 'utf8' })
    const gTMRTKId = await fs.readFile('./test_artifacts/from_go/groups/tmr_temp_key_keyId', { encoding: 'utf8' })
    const rawOverEncryptionKey = await fs.readFile('./test_artifacts/from_go/groups/tmr_temp_key_OverEncKey', { encoding: 'base64' })
    const authFactor = { type: 'EM', value: tmrEmail }

    // Retrieve a token for the auth factor
    const { sessionId: tmrSessionId } = await backend.challengeSend(
        'test-user',
        authFactor,
        { createUser: true }
    )
    const factor = await sdkTMR.ssks2MR.getFactorToken({ sessionId: tmrSessionId, authFactor, challenge: credentials.ssks_tmr_challenge })

    // Convert the gTMRTK, and retrieve the sessions
    await sdkTMR.convertGroupTMRTemporaryKey(groupId, gTMRTKId, factor.token, rawOverEncryptionKey, { deleteOnConvert: false })
    await sdkTMR.retrieveEncryptionSession({ sessionId })
    await sdkTMR.retrieveEncryptionSession({ sessionId: sessionId2 })

    // import from before_go. The group TMR temp key was created during the before_go, and renew in go
    const beforeSessionId = await fs.readFile('./test_artifacts/from_js/groups/session_id', { encoding: 'utf8' })
    const tmrGroupId = await fs.readFile('./test_artifacts/from_js/groups/group_id', { encoding: 'utf8' })
    const tmrEmailJS = await fs.readFile('./test_artifacts/from_js/groups/tmr_temp_key_EM', { encoding: 'utf8' })
    const gTMRTKIdJS = await fs.readFile('./test_artifacts/from_js/groups/tmr_temp_key_keyId', { encoding: 'utf8' })
    const rawOverEncryptionKeyJS = await fs.readFile('./test_artifacts/from_js/groups/tmr_temp_key_OverEncKey', { encoding: 'base64' })
    const authFactorJS = { type: 'EM', value: tmrEmailJS }

    // Retrieve a token for the auth factor
    const { sessionId: tmrSessionIdJS } = await backend.challengeSend(
        'test-user',
        authFactorJS,
        { createUser: true }
    )
    const factorJS = await sdkTMR.ssks2MR.getFactorToken({ sessionId: tmrSessionIdJS, authFactor: authFactorJS, challenge: credentials.ssks_tmr_challenge })

    // And finally: convert the gTMRTK, and retrieve the session
    await sdkTMR.convertGroupTMRTemporaryKey(tmrGroupId, gTMRTKIdJS, factorJS.token, rawOverEncryptionKeyJS, { deleteOnConvert: false })
    await sdkTMR.retrieveEncryptionSession({ sessionId: beforeSessionId })
  })
})
