import fs from 'node:fs/promises'
import { strict as assert } from 'node:assert'
import SealdSDKPkg, { AnonymousSDKBuilder } from '@seald-io/sdk'

const SealdSDK = SealdSDKPkg.default

describe('anonymous', function () {
  this.timeout(15000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // import identity from Go
    const identity = await fs.readFile('./test_artifacts/from_go/anonymous/identity')
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    await sdk.importIdentity(identity)

    // retrieve first session
    const sessionId = await fs.readFile('./test_artifacts/from_go/anonymous/session_id', { encoding: 'utf8' })
    const session = await sdk.retrieveEncryptionSession({ sessionId })

    // deserialize session
    const anonymousSdk = AnonymousSDKBuilder({ apiURL: credentials.api_url })
    const serializedSession = await fs.readFile('./test_artifacts/from_go/anonymous/serialized_session', { encoding: 'utf8' })
    const deserializedSession = anonymousSdk.utils.deserializeSession(serializedSession)
    assert.equal(deserializedSession.sessionId, session.sessionId)
    assert.ok(deserializedSession._sessionSymKey.key.equals(session._sessionSymKey.key))

    // session can decrypt message
    const encryptedMessage = await fs.readFile('./test_artifacts/from_go/anonymous/encrypted_message', { encoding: 'utf8' })
    const decryptedMessage = await deserializedSession.decryptMessage(encryptedMessage)
    assert.equal(decryptedMessage, 'message content')

    // session can decrypt file
    const encryptedFile = await fs.readFile('./test_artifacts/from_go/anonymous/encrypted_file')
    const decryptedFile = await deserializedSession.decryptFile(encryptedFile)
    assert.equal(decryptedFile.data.toString('utf8'), 'file content')
    assert.equal(decryptedFile.filename, 'test.txt')
  })
})
