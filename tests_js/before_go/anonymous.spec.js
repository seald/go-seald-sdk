import fs from 'node:fs/promises'
import SealdSDKPkg, { AnonymousSDKBuilder } from '@seald-io/sdk'
import { createJWT, generateRegistrationJWT } from '../utils.spec.js'

const SealdSDK = SealdSDKPkg.default

describe('anonymous', function () {
  this.timeout(30000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/anonymous/', { recursive: true })

    // create identity
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    const signupJWT = await generateRegistrationJWT(credentials.jwt_shared_secret_id, credentials.jwt_shared_secret)
    const accountInfo = await sdk.initiateIdentity({ signupJWT })

    // create anonymous session, and serialize it, with a message and a file
    const encryptionToken = await createJWT(credentials.jwt_shared_secret, {
      iss: credentials.jwt_shared_secret_id,
      iat: Math.floor(Date.now() / 1000),
      scopes: [0, 1], // FIND KEYS & CREATE MESSAGE
      recipients: [accountInfo.sealdId],
      owner: accountInfo.sealdId
    })
    const anonymousSdk = AnonymousSDKBuilder({ apiURL: credentials.api_url })
    const session = await anonymousSdk.createEncryptionSession({
      encryptionToken,
      recipients: { sealdIds: [accountInfo.sealdId] }
    })
    await fs.writeFile('./test_artifacts/from_js/anonymous/session_id', session.sessionId, { encoding: 'utf8' })
    const serializedSession = session.serialize()
    await fs.writeFile('./test_artifacts/from_js/anonymous/serialized_session', serializedSession, { encoding: 'utf8' })
    const encryptedMessage = await session.encryptMessage('message content')
    await fs.writeFile('./test_artifacts/from_js/anonymous/encrypted_message', encryptedMessage, { encoding: 'utf8' })
    const encryptedFile = await session.encryptFile(Buffer.from('file content', 'utf8'), { filename: 'test.txt' })
    await fs.writeFile('./test_artifacts/from_js/anonymous/encrypted_file', encryptedFile, { encoding: 'utf8' })

    // export identity
    const exportedIdentity = await sdk.exportIdentity()
    await fs.writeFile('./test_artifacts/from_js/anonymous/identity', exportedIdentity)
  })
})
