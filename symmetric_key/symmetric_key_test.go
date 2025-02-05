package symmetric_key

import (
	"bytes"
	"fmt"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
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

		largePlainText, err := utils.GenerateRandomBytes(1024 * 1024)
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
				random, err := utils.GenerateRandomBytes(512)
				require.NoError(t, err)

				// not enough for IV
				_, err = testSymKey.Decrypt(random[:12])
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// enough for IV, but nothing else
				_, err = testSymKey.Decrypt(random[:16])
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// enough for IV, but not enough for MAC
				_, err = testSymKey.Decrypt(random[:25])
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// just invalid
				_, err = testSymKey.Decrypt(random[:425])
				assert.ErrorIs(t, err, ErrorDecryptMacMismatch)
			})
			t.Run("cannot encrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				_, err := key.Encrypt(plainText)
				assert.ErrorIs(t, err, ErrorInvalidKeySize)
			})
			t.Run("cannot decrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				_, err := key.Decrypt(plainText)
				assert.ErrorIs(t, err, ErrorInvalidKeySize)
			})
		})

		t.Run("Encrypt/Decrypt stream io.Reader", func(t *testing.T) {
			t.Parallel()
			t.Run("can encrypt and decrypt in stream", func(t *testing.T) {
				clearTextReader := bytes.NewReader(largePlainText)
				cipherTextReader, err := testSymKey.EncryptReader(clearTextReader)
				require.NoError(t, err)
				decryptedReader, err := testSymKey.DecryptReader(cipherTextReader)
				require.NoError(t, err)

				decrypted, err := io.ReadAll(decryptedReader)
				require.NoError(t, err)

				assert.Equal(t, largePlainText, decrypted)
			})
			t.Run("can encrypt and decrypt in stream with very small chunks", func(t *testing.T) {
				clearTextReader := bytes.NewReader(largePlainText)
				cipherTextReader, err := testSymKey.EncryptReader(clearTextReader)
				require.NoError(t, err)
				decryptedReader, err := testSymKey.DecryptReader(cipherTextReader)
				require.NoError(t, err)

				decrypted, err := test_utils.ReadAll(decryptedReader, 10)
				require.NoError(t, err)

				assert.Equal(t, largePlainText, decrypted)
			})
			t.Run("can encrypt in stream and decrypt normally", func(t *testing.T) {
				clearTextReader := bytes.NewReader(largePlainText)
				cipherTextReader, err := testSymKey.EncryptReader(clearTextReader)
				require.NoError(t, err)
				cipherText, err := io.ReadAll(cipherTextReader)
				require.NoError(t, err)

				decrypted, err := testSymKey.Decrypt(cipherText)
				require.NoError(t, err)

				assert.Equal(t, largePlainText, decrypted)
			})
			t.Run("can encrypt normally and decrypt in stream", func(t *testing.T) {
				cipherText, err := testSymKey.Encrypt(largePlainText)
				require.NoError(t, err)
				cipherTextReader := bytes.NewReader(cipherText)

				decryptedReader, err := testSymKey.DecryptReader(cipherTextReader)
				require.NoError(t, err)

				decrypted, err := io.ReadAll(decryptedReader)
				require.NoError(t, err)

				assert.Equal(t, largePlainText, decrypted)
			})
			t.Run("decrypt invalid buffer", func(t *testing.T) {
				random, err := utils.GenerateRandomBytes(512)
				require.NoError(t, err)

				// not enough for IV
				badCipherTextReader := bytes.NewReader(random[:12])
				decryptedTextReader, err := testSymKey.DecryptReader(badCipherTextReader)
				require.NoError(t, err)
				_, err = io.ReadAll(decryptedTextReader)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// enough for IV, but nothing else
				badCipherTextReader = bytes.NewReader(random[:16])
				decryptedTextReader, err = testSymKey.DecryptReader(badCipherTextReader)
				require.NoError(t, err)
				_, err = io.ReadAll(decryptedTextReader)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// enough for IV, but not enough for MAC
				badCipherTextReader = bytes.NewReader(random[:25])
				decryptedTextReader, err = testSymKey.DecryptReader(badCipherTextReader)
				require.NoError(t, err)
				_, err = io.ReadAll(decryptedTextReader)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

				// just invalid
				badCipherTextReader = bytes.NewReader(random[:425])
				decryptedTextReader, err = testSymKey.DecryptReader(badCipherTextReader)
				require.NoError(t, err)
				_, err = io.ReadAll(decryptedTextReader)
				assert.ErrorIs(t, err, ErrorDecryptMacMismatch)
			})
			t.Run("cannot encrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				clearTextReader := bytes.NewReader(largePlainText)

				_, err := key.EncryptReader(clearTextReader)
				assert.ErrorIs(t, err, ErrorInvalidKeySize)
			})
			t.Run("cannot decrypt with invalid key", func(t *testing.T) {
				key := SymKey{}
				cipherTextReader := bytes.NewReader(largePlainText)

				_, err := key.DecryptReader(cipherTextReader)
				assert.ErrorIs(t, err, ErrorInvalidKeySize)
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

func TestSymKeyPerformance(t *testing.T) {
	testSymKey, err := Generate()
	require.NoError(t, err)

	largePlainText, err := utils.GenerateRandomBytes(100 * 1024 * 1024)
	require.NoError(t, err)

	t.Run("encrypt / decrypt Bytes performance", func(t *testing.T) {
		t0 := time.Now()
		encrypted, err := testSymKey.Encrypt(largePlainText)
		require.NoError(t, err)
		duration := time.Now().Sub(t0).Seconds()
		fmt.Printf("Encrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		t0 = time.Now()
		decrypted, err := testSymKey.Decrypt(encrypted)
		require.NoError(t, err)
		duration = time.Now().Sub(t0).Seconds()
		fmt.Printf("Decrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		assert.Equal(t, largePlainText, decrypted)
	})

	t.Run("encrypt / decrypt Reader performance", func(t *testing.T) {
		clearTextReader := bytes.NewReader(largePlainText)
		t0 := time.Now()
		encryptedReader, err := testSymKey.EncryptReader(clearTextReader)
		require.NoError(t, err)
		encrypted, err := io.ReadAll(encryptedReader)
		require.NoError(t, err)
		duration := time.Now().Sub(t0).Seconds()
		fmt.Printf("Encrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		cipherTextReader := bytes.NewReader(encrypted)
		t0 = time.Now()
		decryptedReader, err := testSymKey.DecryptReader(cipherTextReader)
		require.NoError(t, err)
		decrypted, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		duration = time.Now().Sub(t0).Seconds()
		fmt.Printf("Decrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		assert.Equal(t, largePlainText, decrypted)
	})
}
