import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import SSKSPasswordPluginPkg from '@seald-io/sdk-plugin-ssks-password'
import { strict as assert } from 'node:assert'
import * as BSON from 'bson'

const SealdSDK = SealdSDKPkg.default
const SSKSPasswordPlugin = SSKSPasswordPluginPkg.default

describe('ssks_password', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // Can retrieve identity from password
    const sdkPassword = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSPasswordPlugin(credentials.ssks_url)]
    })
    sdkPassword.setLogLevel('debug')
    const userId = await fs.readFile('./test_artifacts/from_go/ssks_password/user_id', {encoding: 'utf8'})
    const password = await fs.readFile('./test_artifacts/from_go/ssks_password/password', {encoding: 'utf8'})
    await sdkPassword.ssksPassword.retrieveIdentity({
      userId,
      password
    })

    // Can retrieve identity from raw keys
    const sdkRawKeys = SealdSDK({
      appId: credentials.app_id,
      apiURL: credentials.api_url,
      plugins: [SSKSPasswordPlugin(credentials.ssks_url)]
    })
    const rawStorageKey = await fs.readFile('./test_artifacts/from_go/ssks_password/raw_storage_key', {encoding: 'utf8'})
    const rawEncryptionKey = await fs.readFile('./test_artifacts/from_go/ssks_password/raw_encryption_key', {encoding: 'utf8'})
    await sdkRawKeys.ssksPassword.retrieveIdentity({
      userId,
      rawStorageKey,
      rawEncryptionKey
    })

    // Retrieved identities are as expected
    const exportedIdentity = await fs.readFile('./test_artifacts/from_go/ssks_password/exported_identity')
    const retrievedIdentityFromPassword = await sdkPassword.exportIdentity()
    const retrievedIdentityFromRawKeys = await sdkRawKeys.exportIdentity()
    const exportedIdentityDeserialized = BSON.deserialize(exportedIdentity)
    const retrievedIdentityFromPasswordDeserialized = BSON.deserialize(retrievedIdentityFromPassword)
    const retrievedIdentityFromRawKeysDeserialized = BSON.deserialize(retrievedIdentityFromRawKeys)
    // golang has omitempty on the serializedOldEncryptionKeys & serializedOldSigningKeys arrays, so they may not be defined. If not, put them.
    if (!exportedIdentityDeserialized.serializedOldEncryptionKeys) exportedIdentityDeserialized.serializedOldEncryptionKeys = []
    if (!exportedIdentityDeserialized.serializedOldSigningKeys) exportedIdentityDeserialized.serializedOldSigningKeys = []
    assert.deepEqual(exportedIdentityDeserialized, retrievedIdentityFromPasswordDeserialized)
    assert.deepEqual(exportedIdentityDeserialized, retrievedIdentityFromRawKeysDeserialized)
  })
})
