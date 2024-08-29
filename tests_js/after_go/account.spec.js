import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { strict as assert } from 'node:assert'

const SealdSDK = SealdSDKPkg.default

describe('account', function () {
  this.timeout(15000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // reading identity data
    const sealdId = await fs.readFile('./test_artifacts/from_go/account/seald_id', { encoding: 'utf8' })
    const deviceId = await fs.readFile('./test_artifacts/from_go/account/device_id', { encoding: 'utf8' })

    // can import identity from JS
    const identity = await fs.readFile('./test_artifacts/from_go/account/exported_identity')
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    const imported = await sdk.importIdentity(identity)

    // imported identity is as expected
    assert.equal(imported.sealdId, sealdId)
    assert.equal(imported.deviceId, deviceId)
    const defaultUser = await sdk.goatee.account.getDefaultUser()
    assert.equal(defaultUser.currentDevice.oldEncryptionKeys.length, 3)
    assert.equal(defaultUser.currentDevice.oldSigningKeys.length, 3)

    // imported identity works
    await sdk.intervals.heartbeat()

    // can import sub-identity from JS
    const subIdentity = await fs.readFile('./test_artifacts/from_go/account/sub_identity')
    const sdk2 = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    const imported2 = await sdk2.importIdentity(subIdentity)

    // imported sub-identity is as expected
    const subDeviceId = await fs.readFile('./test_artifacts/from_go/account/sub_device_id', {encoding: 'utf8'})
    assert.equal(imported2.sealdId, sealdId)
    assert.equal(imported2.deviceId, subDeviceId)
    const defaultUser2 = await sdk2.goatee.account.getDefaultUser()
    assert.equal(defaultUser2.currentDevice.oldEncryptionKeys.length, 0)
    assert.equal(defaultUser2.currentDevice.oldSigningKeys.length, 0)

    // imported sub-identity works
    await sdk2.intervals.heartbeat()
  })
})
