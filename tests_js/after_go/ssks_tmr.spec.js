import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import SSKSTMRPluginPkg from '@seald-io/sdk-plugin-ssks-2mr'
import { strict as assert } from 'node:assert'
import { TMRBackend } from '../utils.spec.js'
import * as BSON from 'bson'

const SealdSDK = SealdSDKPkg.default
const SSKSTMRPlugin = SSKSTMRPluginPkg.default

describe('ssks_tmr', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // Send challenge
    const email = await fs.readFile('./test_artifacts/from_go/ssks_tmr/email', { encoding: 'utf8' })
    const backend = TMRBackend(credentials.ssks_url, credentials.app_id, credentials.ssks_backend_app_key)
    const { sessionId, mustAuthenticate } = await backend.challengeSend(
      'test-user',
      { type: 'EM', value: email },
      { createUser: false }
    )
    assert.equal(mustAuthenticate, true)

    // Can retrieve identity
    const sdk = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSTMRPlugin(credentials.ssks_url)]
    })
    sdk.setLogLevel('debug')
    const rawTMRKey = await fs.readFile('./test_artifacts/from_go/ssks_tmr/raw_tmr_key')
    await sdk.ssks2MR.retrieveIdentity({
      userId: 'test-user',
      sessionId,
      authFactor: { type: 'EM', value: email },
      challenge: credentials.ssks_tmr_challenge,
      rawTwoManRuleKey: rawTMRKey.toString('base64')
    })

    // Retrieved identity is as expected
    const exportedIdentity = await fs.readFile('./test_artifacts/from_go/ssks_tmr/exported_identity')
    const retrievedIdentity = await sdk.exportIdentity()
    const exportedIdentityDeserialized = BSON.deserialize(exportedIdentity)
    const retrievedIdentityDeserialized = BSON.deserialize(retrievedIdentity)
    // golang has omitempty on the serializedOldEncryptionKeys & serializedOldSigningKeys arrays, so they may not be defined. If not, put them.
    if (!exportedIdentityDeserialized.serializedOldEncryptionKeys) exportedIdentityDeserialized.serializedOldEncryptionKeys = []
    if (!exportedIdentityDeserialized.serializedOldSigningKeys) exportedIdentityDeserialized.serializedOldSigningKeys = []
    assert.deepEqual(exportedIdentityDeserialized, retrievedIdentityDeserialized)
  })
})
