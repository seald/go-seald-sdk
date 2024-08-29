import fs from 'node:fs/promises'
import SealdSDKPkg, { EncryptionSessionRetrievalFlow } from '@seald-io/sdk'
import { strict as assert } from 'node:assert'
import { TMRBackend } from '../utils.spec.js'
import SSKSTMRPluginPkg from '@seald-io/sdk-plugin-ssks-2mr'

const SealdSDK = SealdSDKPkg.default
const SSKSTMRPlugin = SSKSTMRPluginPkg.default

describe('encryption session', function () {
  this.timeout(15000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    // can import identity from Go
    const identity = await fs.readFile('./test_artifacts/from_go/encryption_session/identity')
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url, plugins: [SSKSTMRPlugin(credentials.ssks_url)] })
    sdk.setLogLevel('debug')
    await sdk.importIdentity(identity)

    // can retrieve first session (with old key)
    const sessionId = await fs.readFile('./test_artifacts/from_go/encryption_session/session_id', { encoding: 'utf8' })
    const session = await sdk.retrieveEncryptionSession({ sessionId })

    // session can decrypt message
    const encryptedMessage = await fs.readFile('./test_artifacts/from_go/encryption_session/encrypted_message', { encoding: 'utf8' })
    const decryptedMessage = await session.decryptMessage(encryptedMessage)
    assert.equal(decryptedMessage, 'message content')

    // session can decrypt file
    const encryptedFile = await fs.readFile('./test_artifacts/from_go/encryption_session/encrypted_file')
    const decryptedFile = await session.decryptFile(encryptedFile)
    assert.equal(decryptedFile.data.toString('utf8'), 'file content')
    assert.equal(decryptedFile.filename, 'test.txt')

    // can retrieve second session (with current key)
    const sessionId2 = await fs.readFile('./test_artifacts/from_go/encryption_session/session_id2', { encoding: 'utf8' })
    const session2 = await sdk.retrieveEncryptionSession({ sessionId: sessionId2 })

    // session2 can decrypt message
    const encryptedMessage2 = await fs.readFile('./test_artifacts/from_go/encryption_session/encrypted_message2', { encoding: 'utf8' })
    const decryptedMessage2 = await session2.decryptMessage(encryptedMessage2)
    assert.equal(decryptedMessage2, 'message content2')

    // session2 can decrypt file
    const encryptedFile2 = await fs.readFile('./test_artifacts/from_go/encryption_session/encrypted_file2')
    const decryptedFile2 = await session2.decryptFile(encryptedFile2)
    assert.equal(decryptedFile2.data.toString('utf8'), 'file content2')
    assert.equal(decryptedFile2.filename, 'test2.txt')

    // can open proxied session via proxy
    const proxySessionId = await fs.readFile('./test_artifacts/from_go/encryption_session/proxysession_id', { encoding: 'utf8' })
    const proxiedSessionId = await fs.readFile('./test_artifacts/from_go/encryption_session/proxiedsession_id', { encoding: 'utf8' })
    const proxiedSession = await sdk.retrieveEncryptionSession({ sessionId: proxiedSessionId, lookupProxyKey: true })
    assert.equal(proxiedSession.retrievalDetails.flow, EncryptionSessionRetrievalFlow.proxy)
    assert.equal(proxiedSession.retrievalDetails.proxySessionId, proxySessionId)

    // can retrieve session via TMR access
    const userId = await fs.readFile('./test_artifacts/from_go/encryption_session/tmrAccess_userId', { encoding: 'utf8' })
    const authFactorEM = await fs.readFile('./test_artifacts/from_go/encryption_session/tmrAccess_em', { encoding: 'utf8' })
    const rawOverEncryptionKey = await fs.readFile('./test_artifacts/from_go/encryption_session/tmrAccess_rawOverEncryptionKey', { encoding: 'base64' })

    const backend = TMRBackend(credentials.ssks_url, credentials.app_id, credentials.ssks_backend_app_key)
    const { sessionId: ssksSessionId } = await backend.challengeSend(
        userId,
        { type: 'EM', value: authFactorEM },
        { createUser: true }
    )
    const tmrJWT = await sdk.ssks2MR.getFactorToken({ sessionId: ssksSessionId, authFactor: { type: 'EM', value: authFactorEM }, challenge: credentials.ssks_tmr_challenge })

    const tmrSession = await sdk.retrieveEncryptionSessionByTmr(sessionId, tmrJWT.token, rawOverEncryptionKey)
    assert.equal(tmrSession.retrievalDetails.flow, EncryptionSessionRetrievalFlow.tmrMessageKey)
    assert.equal(tmrSession.sessionId, sessionId)
  })
})
