import fs from 'node:fs/promises'
import { strict as assert } from 'node:assert'
import { PrivateKey } from 'sscrypto/node/index.js'
import { convertPEMToDER } from 'sscrypto/utils/rsaUtils.js'
import { serialize as BSONSerialize } from 'bson'
import SealdSDKPkg from '@seald-io/sdk'
import fetch from 'node-fetch'
import { b64UUID } from '../utils.spec.js'

const SealdSDK = SealdSDKPkg.default

// This test uses the JS SDK to decrypt something encrypted by the Golang anonymous SDK for a pre-created user
describe('anonymous', function () {
  this.timeout(15000)
  let credentials

  before(async function () {
    const credentialsFile = await fs.readFile('./test_credentials.json', { encoding: 'utf8' })
    credentials = JSON.parse(credentialsFile)
  })

  it('compatible with go', async function () {
    const {
      bearduser_id: userId,
      device_id: deviceId
    } = await fetch(credentials.api_url + '/devapi/get_anonymous_sdk_user', {
      method: 'GET',
      headers: { 'X-APIVIEW-SECRET': credentials.debug_api_secret }
    }).then(r => r.json())

    const encryptionKeyString = await fs.readFile('./test_data/sdk_user_privkey.pem', { encoding: 'utf8' })
    const encryptionKey = new PrivateKey(convertPEMToDER(encryptionKeyString, 'RSA PRIVATE KEY'))
    let signingKeyString = await fs.readFile('./test_data/sdk_user_signing_privkey.pem', { encoding: 'utf8' })
    const signingKey = new PrivateKey(convertPEMToDER(signingKeyString, 'RSA PRIVATE KEY'))

    const backupKey = BSONSerialize({
      userId: b64UUID(userId),
      keyId: b64UUID(deviceId),
      encryptionKey: Buffer.from(encryptionKey.toB64(), 'base64').toString('binary'),
      signingKey: Buffer.from(signingKey.toB64(), 'base64').toString('binary'),
      serializedOldEncryptionKeys: [],
      serializedOldSigningKeys: []
    })
    const sdk = SealdSDK({ appId: credentials.app_id, apiURL: credentials.api_url })
    sdk.setLogLevel('debug')
    await sdk.importIdentity(backupKey)

    const encryptedFile = await fs.readFile('./test_artifacts/from_go/anonymous/encrypted_file.seald', { encoding: null })
    const messageId = await fs.readFile('./test_artifacts/from_go/anonymous/message_id', { encoding: 'utf8' })

    const decrypted = await sdk.decryptFile(encryptedFile)
    assert.equal(decrypted.filename, 'test.txt')
    assert.equal(decrypted.sessionId, messageId)
    assert.equal(decrypted.data.toString('utf8'), 'Super secret stuff encrypted in GoLang')
  })
})
