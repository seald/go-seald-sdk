import fs from 'node:fs/promises'
import { PrivateKey, utils } from 'sscrypto/node/index.js'

describe('asymkey', function () {
  this.timeout(15000)

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/asymkey/', { recursive: true })

    // generate random data
    const data = await utils.randomBytesAsync(100)
    await fs.writeFile('./test_artifacts/from_js/asymkey/clear_data', data)

    // generate private key
    const key = await PrivateKey.generate(4096)
    const privateKeyB64 = key.toB64({ publicOnly: false })
    await fs.writeFile('./test_artifacts/from_js/asymkey/private_key', privateKeyB64, { encoding: 'utf8' })

    // write public key
    const publicKeyB64 = key.toB64({ publicOnly: true })
    await fs.writeFile('./test_artifacts/from_js/asymkey/public_key', publicKeyB64, { encoding: 'utf8' })

    // write key hash
    const keyHash = key.getHash()
    await fs.writeFile('./test_artifacts/from_js/asymkey/key_hash', keyHash, { encoding: 'utf8' })

    // write encrypted data
    const encryptedData = await key.encryptAsync(data)
    await fs.writeFile('./test_artifacts/from_js/asymkey/encrypted_data', encryptedData)

    // write signature
    const signature = await key.sign(data)
    await fs.writeFile('./test_artifacts/from_js/asymkey/signature', signature)
  })
})
