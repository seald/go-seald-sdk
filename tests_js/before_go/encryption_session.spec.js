import fs from 'node:fs/promises'
import SealdSDKPkg from '@seald-io/sdk'
import { generateRegistrationJWT, randomString } from '../utils.spec.js'
import crypto from 'node:crypto'

const SealdSDK = SealdSDKPkg.default

describe('encryption session', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/encryption_session/', { recursive: true })

    // create identity
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    const accountInfo = await sdk.initiateIdentity({ signupJWT })

    // create a session, with a message and a file
    const session = await sdk.createEncryptionSession({})
    await fs.writeFile('./test_artifacts/from_js/encryption_session/session_id', session.sessionId, { encoding: 'utf8' })
    const encryptedMessage = await session.encryptMessage('message content')
    await fs.writeFile('./test_artifacts/from_js/encryption_session/encrypted_message', encryptedMessage, { encoding: 'utf8' })
    const encryptedFile = await session.encryptFile(Buffer.from('file content', 'utf8'), 'test.txt')
    await fs.writeFile('./test_artifacts/from_js/encryption_session/encrypted_file', encryptedFile, { encoding: 'utf8' })

    // renew key to check if it works for oldKeys
    await sdk.renewKey()

    // create another session (with new key), with a message and a file
    const session2 = await sdk.createEncryptionSession({})
    await fs.writeFile('./test_artifacts/from_js/encryption_session/session_id2', session2.sessionId, { encoding: 'utf8' })
    const encryptedMessage2 = await session2.encryptMessage('message content2')
    await fs.writeFile('./test_artifacts/from_js/encryption_session/encrypted_message2', encryptedMessage2, { encoding: 'utf8' })
    const encryptedFile2 = await session2.encryptFile(Buffer.from('file content2', 'utf8'), 'test2.txt')
    await fs.writeFile('./test_artifacts/from_js/encryption_session/encrypted_file2', encryptedFile2, { encoding: 'utf8' })

    // create proxy session and session openable via proxy
    const proxySession = await sdk.createEncryptionSession({})
    await fs.writeFile('./test_artifacts/from_js/encryption_session/proxysession_id', proxySession.sessionId, { encoding: 'utf8' })
    const proxiedSession = await sdk.createEncryptionSession({ proxySessions: [{ id: proxySession.sessionId }] }, { encryptForSelf: false })
    await fs.writeFile('./test_artifacts/from_js/encryption_session/proxiedsession_id', proxiedSession.sessionId, { encoding: 'utf8' })

    // create a session with TMR accesses
    const rawOverEncryptionKey = crypto.randomBytes(64).toString('base64')
    const tmrEmail = `js-go-compat-tmr-access-${randomString(10)}@test.com`
    const authFactor = { type: 'EM', value: tmrEmail }
    await session.addTmrAccess({
      authFactor,
      rights: { read: true, forward: true, revoke: true },
      rawOverEncryptionKey
    })
    await fs.writeFile('./test_artifacts/from_js/encryption_session/tmrAccess_userId', accountInfo.sealdId, { encoding: 'utf8' })
    await fs.writeFile('./test_artifacts/from_js/encryption_session/tmrAccess_em', tmrEmail, { encoding: 'utf8' })
    await fs.writeFile('./test_artifacts/from_js/encryption_session/tmrAccess_rawOverEncryptionKey', rawOverEncryptionKey, { encoding: 'base64' })

    // export identity
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/encryption_session/identity', exportedIdentity)
  })
})
