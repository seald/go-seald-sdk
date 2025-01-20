package react_native_seald_accelerator

import (
	"bytes"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"runtime"
	"testing"
)

func TestEncryptDecryptFromSerializedSymKey(t *testing.T) {
	clearData := []byte("When was the typewriter invented? - it was invented in 1868 by Americans Christopher Latham Sholes, Carlos Glidden and Samuel W. Soule in Milwaukee, Wisconsin,")
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)
	serializedSymKey := symKey.Encode()

	t.Run("can Encrypt-Decrypt from serialized SymKey", func(t *testing.T) {
		encryptedData, err := EncryptFileFromSerializedSymKey(clearData, testFileName, messageId, serializedSymKey)
		require.NoError(t, err)

		clearFile, err := DecryptFileFromSerializedSymKey(encryptedData, messageId, serializedSymKey)
		require.NoError(t, err)

		assert.Equal(t, clearFile.Filename, testFileName)
		assert.Equal(t, clearFile.SessionId, messageId)
		assert.True(t, bytes.Compare(clearFile.FileContent, clearData) == 0)
	})

	t.Run("encrypt", func(t *testing.T) {
		t.Run("bad SymKey", func(t *testing.T) {
			_, err := EncryptFileFromSerializedSymKey(clearData, testFileName, messageId, []byte{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("nil SymKey", func(t *testing.T) {
			_, err := EncryptFileFromSerializedSymKey(clearData, testFileName, messageId, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
	})

	t.Run("decrypt", func(t *testing.T) {
		encryptedData, err := EncryptFileFromSerializedSymKey(clearData, testFileName, messageId, serializedSymKey)
		require.NoError(t, err)

		t.Run("bad SymKey", func(t *testing.T) {
			_, err := DecryptFileFromSerializedSymKey(encryptedData, messageId, []byte{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("nil SymKey", func(t *testing.T) {
			_, err := DecryptFileFromSerializedSymKey(encryptedData, messageId, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("bad SessionID", func(t *testing.T) {
			_, err := DecryptFileFromSerializedSymKey(encryptedData, "BadSessionId", serializedSymKey)
			assert.ErrorIs(t, err, encrypt_decrypt_file.ErrorDecryptUnexpectedSessionId)
		})
	})
}

func TestEncryptDecryptFromUri(t *testing.T) {
	clearData := []byte("How long is the Grand Canyon? - 446 km long, 29 km wide, 1,800 meters deep")
	testFileName := "random.fact"
	testDir := "./test/"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	err := os.Mkdir(testDir, 0o750)
	if err != nil && !os.IsExist(err) {
		require.NoError(t, err)
	}
	err = os.WriteFile(testDir+testFileName, clearData, 0o666)
	require.NoError(t, err)

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)
	serializedSymKey := symKey.Encode()

	t.Run("Encrypt-Decrypt-Parse from path", func(t *testing.T) {
		encryptedUri, err := EncryptFileFromUriAndSerializedSymKey(testDir+testFileName, testFileName, messageId, serializedSymKey)
		require.NoError(t, err)
		clearPath, err := DecryptFileFromUriAndSerializedSymKey(encryptedUri, messageId, serializedSymKey)
		require.NoError(t, err)

		assert.Equal(t, path.Base(clearPath), "random (1).fact")
		read, err := os.ReadFile(clearPath)
		require.NoError(t, err)
		assert.True(t, bytes.Compare(read, clearData) == 0)

		parsedId, err := ParseFileUri(encryptedUri)
		require.NoError(t, err)
		assert.Equal(t, parsedId, messageId)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Run("bad uri", func(t *testing.T) {
			_, err := EncryptFileFromUriAndSerializedSymKey("", testFileName, messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open : The system cannot find the file specified.")
			} else {
				assert.EqualError(t, err, "open : no such file or directory")
			}

			_, err = EncryptFileFromUriAndSerializedSymKey("That's not an uri !", testFileName, messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open That's not an uri !: The system cannot find the file specified.")
			} else {
				assert.EqualError(t, err, "open That's not an uri !: no such file or directory")
			}

			_, err = EncryptFileFromUriAndSerializedSymKey("../test/this/path/doesnt/exist", testFileName, messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: The system cannot find the path specified.")
			} else {
				assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: no such file or directory")
			}

			_, err = EncryptFileFromUriAndSerializedSymKey("../test/this/file/doesnt/exist.txt", testFileName, messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: The system cannot find the path specified.")
			} else {
				assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: no such file or directory")
			}
		})
		t.Run("bad SymKey", func(t *testing.T) {
			_, err := EncryptFileFromUriAndSerializedSymKey(testDir+testFileName, testFileName, messageId, []byte{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("nil SymKey", func(t *testing.T) {
			_, err := EncryptFileFromUriAndSerializedSymKey(testDir+testFileName, testFileName, messageId, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
	})

	t.Run("Decrypt", func(t *testing.T) {
		encryptedUri, err := EncryptFileFromUriAndSerializedSymKey(testDir+testFileName, testFileName, messageId, serializedSymKey)
		require.NoError(t, err)

		t.Run("bad uri", func(t *testing.T) {
			_, err := DecryptFileFromUriAndSerializedSymKey("", messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open : The system cannot find the file specified.")
			} else {
				assert.EqualError(t, err, "open : no such file or directory")
			}

			_, err = DecryptFileFromUriAndSerializedSymKey("That's not an uri !", messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open That's not an uri !: The system cannot find the file specified.")
			} else {
				assert.EqualError(t, err, "open That's not an uri !: no such file or directory")
			}

			_, err = DecryptFileFromUriAndSerializedSymKey("../test/this/path/doesnt/exist", messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: The system cannot find the path specified.")
			} else {
				assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: no such file or directory")
			}

			_, err = DecryptFileFromUriAndSerializedSymKey("../test/this/file/doesnt/exist.txt", messageId, serializedSymKey)
			if runtime.GOOS == "windows" {
				assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: The system cannot find the path specified.")
			} else {
				assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: no such file or directory")
			}
		})
		t.Run("bad SymKey", func(t *testing.T) {
			_, err := DecryptFileFromUriAndSerializedSymKey(encryptedUri, messageId, []byte{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("nil SymKey", func(t *testing.T) {
			_, err := DecryptFileFromUriAndSerializedSymKey(encryptedUri, messageId, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("bad SessionID", func(t *testing.T) {
			_, err := DecryptFileFromUriAndSerializedSymKey(encryptedUri, "BadSessionId", serializedSymKey)
			assert.ErrorIs(t, err, encrypt_decrypt_file.ErrorDecryptUnexpectedSessionId)
		})
	})

	t.Run("Permission errors", func(t *testing.T) {
		permDir := testDir + "seald_acc_perm/"
		permFile := permDir + "my.file"
		permFileEncrypted := permDir + "my.file.seald"

		err = os.Mkdir(permDir, 0o750)
		if err != nil && !os.IsExist(err) {
			require.NoError(t, err)
		}
		err = os.WriteFile(permFile, clearData, 0o666)
		require.NoError(t, err)
		encryptedData, err := encrypt_decrypt_file.EncryptBytes(clearData, "my.file", messageId, symKey)
		require.NoError(t, err)
		err = os.WriteFile(permFileEncrypted, encryptedData, 0o666)
		require.NoError(t, err)
		// NO parallel
		t.Run("no exec on dir", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			err := os.Chmod(permDir, 0o444) // no exec on Dir, cannot access it
			require.NoError(t, err)
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			err = os.Chmod(permDir, 0o777) // reset dir perm
			require.NoError(t, err)
		})

		t.Run("read only dir", func(t *testing.T) {
			err := os.Chmod(permDir, 0o500) // read only dir
			require.NoError(t, err)
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.ErrorContains(t, err, "permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFileEncrypted, messageId, serializedSymKey)
			assert.ErrorContains(t, err, "permission denied")
			err = os.Chmod(permDir, 0o777) // reset dir perm
			require.NoError(t, err)
		})

		t.Run("file no access", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			err := os.Chmod(permFile, 0o000) // cannot access file
			require.NoError(t, err)
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			err = os.Chmod(permFile, 0o777)
			require.NoError(t, err)
		})

		t.Run("file write only", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			err := os.Chmod(permFile, 0o300) // write-only file
			require.NoError(t, err)
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			err = os.Chmod(permFile, 0o777)
			require.NoError(t, err)
		})
	})

	// <tear-down code>
	err = os.RemoveAll(testDir)
	require.NoError(t, err)
}
