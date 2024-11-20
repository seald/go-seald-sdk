import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { generateRegistrationJWT } from '../utils.spec.js'

const SealdSDK = SealdSDKPkg.default

describe('groups', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/groups/', { recursive: true })

    // create identity
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    await sdk.initiateIdentity({ signupJWT })
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/groups/identity', exportedIdentity)

    // create a group
    const { sealdId } = await sdk.getCurrentAccountInfo()
    const group = await sdk.createGroup({
      groupName: 'test-js-go',
      members: { sealdIds: [sealdId] },
      admins: { sealdIds: [sealdId] }
    })
    await fs.writeFile('./test_artifacts/from_js/groups/group_id', group.id, { encoding: 'utf8' })

    // create a session for the group
    const session = await sdk.createEncryptionSession({ sealdIds: [group.id] }, { encryptForSelf: false })
    await fs.writeFile('./test_artifacts/from_js/groups/session_id', session.sessionId, { encoding: 'utf8' })

    // renew group key to check if it works for oldKeys
    await sdk.renewGroupKey(group.id)

    // create another session for the group
    const session2 = await sdk.createEncryptionSession({ sealdIds: [group.id] }, { encryptForSelf: false })
    await fs.writeFile('./test_artifacts/from_js/groups/session_id2', session2.sessionId, { encoding: 'utf8' })

    const rand = (await sdk.sscrypto.utils.randomBytesAsync(10)).toString('hex')
    const tmrEmail = `go-cross-test-${rand}@domain.tld`
    const authFactor = { type: 'EM', value: tmrEmail }

    const rawOverEncryptionKey = await sdk.utils.generateB64EncodedSymKey()

    const  gTMRTK = await sdk.createGroupTMRTemporaryKey(group.id, { isAdmin: true, authFactor, rawOverEncryptionKey })
    await fs.writeFile('./test_artifacts/from_js/groups/tmr_temp_key_EM', tmrEmail, { encoding: 'utf8' })
    await fs.writeFile('./test_artifacts/from_js/groups/tmr_temp_key_keyId', gTMRTK.id, { encoding: 'utf8' })
    await fs.writeFile('./test_artifacts/from_js/groups/tmr_temp_key_OverEncKey', rawOverEncryptionKey, { encoding: 'base64' })
  })
})
