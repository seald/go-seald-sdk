import fs from 'node:fs/promises'
import { strict as assert } from 'node:assert'
import { PrivateKey, PublicKey, utils } from 'sscrypto/node/index.js'

describe('asymkey', function () {
  this.timeout(15000)

  it('compatible with go', async function () {
    // can import private key from go
    const rawPrivateKey = await fs.readFile('./test_artifacts/from_go/asymkey/private_key', { encoding: 'utf8' })
    const privateKey = PrivateKey.fromB64(rawPrivateKey)

    // can import public key from go
    const rawPublicKey = await fs.readFile('./test_artifacts/from_go/asymkey/public_key', { encoding: 'utf8' })
    const publicKey = PublicKey.fromB64(rawPublicKey)

    // B64 exports are identical
    assert.equal(privateKey.toB64({publicOnly: false}), rawPrivateKey)
    assert.equal(privateKey.toB64({publicOnly: true}), rawPublicKey)
    assert.equal(publicKey.toB64(), rawPublicKey)

    // Key hash is as expected
    const keyHash = await fs.readFile('./test_artifacts/from_go/asymkey/key_hash', { encoding: 'utf8' })
    assert.equal(publicKey.getHash(), keyHash)

    // Imported private key can decrypt data
    const clearData = await fs.readFile('./test_artifacts/from_go/asymkey/clear_data')
    const encryptedData = await fs.readFile('./test_artifacts/from_go/asymkey/encrypted_data')
    const decryptedData = await privateKey.decryptAsync(encryptedData)
    assert.ok(decryptedData.equals(clearData))

    // Imported public key can verify signature
    const signature = await fs.readFile('./test_artifacts/from_go/asymkey/signature')
    assert.ok(await publicKey.verifyAsync(clearData, signature))
  })
})
