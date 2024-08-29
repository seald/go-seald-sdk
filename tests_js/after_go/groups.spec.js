import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { strict as assert } from 'node:assert'
import { b64UUID } from '../utils.spec.js'

const SealdSDK = SealdSDKPkg.default

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
  })
})
