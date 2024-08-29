import fs from 'node:fs/promises'
import { strict as assert } from 'node:assert'
import sscrypto from 'sscrypto/node/index.js'

describe('symkey', function () {
  this.timeout(15000)

  it('compatible with go', async function () {
    // can import key from go
    const rawKey = await fs.readFile('./test_artifacts/from_go/symkey/key')
    const key = new sscrypto.SymKey(rawKey)

    // exports are identical
    assert.ok(key.key.equals(rawKey))

    // Imported key can decrypt data
    const clearData = await fs.readFile('./test_artifacts/from_go/symkey/clear_data')
    const encryptedData = await fs.readFile('./test_artifacts/from_go/symkey/encrypted_data')
    const decryptedData = await key.decryptAsync(encryptedData)
    assert.ok(decryptedData.equals(clearData))
  })
})
