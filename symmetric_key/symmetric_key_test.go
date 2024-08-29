package symmetric_key

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"testing"
)

func TestSymKey(t *testing.T) {
	t.Parallel()
	t.Run("SymKey", func(t *testing.T) {
		plainText := []byte("SecretString")

		testSymKey, err := Generate()
		require.NoError(t, err)
		encodedTestSymKey := testSymKey.Encode()
		encryptedText, err := testSymKey.Encrypt(plainText)
		require.NoError(t, err)

		t.Parallel()
		t.Run("Decode", func(t *testing.T) {
			t.Parallel()
			t.Run("can decode", func(t *testing.T) {
				keyBuff := make([]byte, len(encodedTestSymKey))

				copy(keyBuff, encodedTestSymKey)

				decodedSymKey, err := Decode(keyBuff)
				require.NoError(t, err)

				clearText, err := decodedSymKey.Decrypt(encryptedText)
				assert.Equal(t, plainText, clearText)

				// Ensure that keyBuff is not use as reference
				keyBuff, err = utils.GenerateRandomBytes(64)
				require.NoError(t, err)

				clearText, err = decodedSymKey.Decrypt(encryptedText)
				assert.Equal(t, plainText, clearText)
			})
			t.Run("Decode - bad length", func(t *testing.T) {
				_, err = Decode([]byte{})
				assert.ErrorIs(t, err, ErrorDecodeInvalidLength)
				_, err = Decode(make([]byte, 32))
				assert.ErrorIs(t, err, ErrorDecodeInvalidLength)
			})
		})

		// TODO: tests for aesEncrypt/aesDecrypt
		// TODO: tests for pkcs7Pad/pkcs7Unpad ?
		// TODO: tests for calculateHMAC ?

		t.Run("Encrypt/Decrypt", func(t *testing.T) {
			t.Parallel()
			t.Run("can encrypt and decrypt", func(t *testing.T) {
				cipherText, err := testSymKey.Encrypt(plainText)
				require.NoError(t, err)
				decrypted, err := testSymKey.Decrypt(cipherText)
				require.NoError(t, err)
				assert.Equal(t, plainText, decrypted)
			})
			t.Run("decrypt invalid buffer", func(t *testing.T) {
				_, err := testSymKey.Decrypt(make([]byte, 25))
				assert.ErrorIs(t, err, ErrorDecryptCipherTooShort)
				_, err = testSymKey.Decrypt(make([]byte, 425))
				assert.ErrorIs(t, err, ErrorDecryptMacMismatch)
			})
			t.Run("cannot encrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				_, err := key.Encrypt(plainText)
				assert.ErrorIs(t, err, ErrorEncryptInvalidKeySize)
			})
			t.Run("cannot decrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				_, err := key.Decrypt(plainText)
				assert.ErrorIs(t, err, ErrorDecryptInvalidKeySize)
			})
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/symkey")

			// Can import key from JS
			rawKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "key"))
			require.NoError(t, err)
			keyFromJS, err := Decode(rawKey)
			require.NoError(t, err)

			// export is identical
			assert.Equal(t, rawKey, keyFromJS.Encode())

			// Imported key can decrypt data
			clearData, err := os.ReadFile(filepath.Join(testArtifactsDir, "clear_data"))
			require.NoError(t, err)
			encryptedData, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_data"))
			require.NoError(t, err)
			decryptedData, err := keyFromJS.Decrypt(encryptedData)
			require.NoError(t, err)
			assert.Equal(t, clearData, decryptedData)
		})
		t.Run("Export for JS", func(t *testing.T) {
			// make sure dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/symkey")
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// write sym key
			key, err := Generate()
			rawKey := key.Encode()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "key"), rawKey, 0o700)
			require.NoError(t, err)

			// generate & write random clear data
			clearData, err := utils.GenerateRandomBytes(100)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "clear_data"), clearData, 0o700)
			require.NoError(t, err)

			// write encrypted data
			encryptedData, err := key.Encrypt(clearData)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_data"), encryptedData, 0o700)
			require.NoError(t, err)
		})
	})
}
