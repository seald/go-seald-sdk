import fs from 'node:fs/promises'
import sscrypto from 'sscrypto/node/index.js'

describe('symkey', function () {
  this.timeout(15000)

  it('write data', async function () {
    // verify dir exists
    await fs.mkdir('./test_artifacts/from_js/symkey/', { recursive: true })

    // generate random data
    const data = await sscrypto.utils.randomBytesAsync(100)
    await fs.writeFile('./test_artifacts/from_js/symkey/clear_data', data)

    // generate sym key
    const key = await sscrypto.SymKey.generate(256)
    await fs.writeFile('./test_artifacts/from_js/symkey/key', key.key)

    // write encrypted data
    const encryptedData = await key.encryptAsync(data)
    await fs.writeFile('./test_artifacts/from_js/symkey/encrypted_data', encryptedData)
  })
})
