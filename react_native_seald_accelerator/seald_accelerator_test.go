package react_native_seald_accelerator

import (
	"bytes"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
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

		clearFile, err := DecryptFileFromSerializedSymKey(encryptedData, serializedSymKey)
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
			_, err := DecryptFileFromSerializedSymKey(encryptedData, []byte{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("nil SymKey", func(t *testing.T) {
			_, err := DecryptFileFromSerializedSymKey(encryptedData, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
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
		clearPath, err := DecryptFileFromUriAndSerializedSymKey(encryptedUri, serializedSymKey)
		require.NoError(t, err)

		assert.Equal(t, clearPath.Filename, testFileName)
		assert.Equal(t, clearPath.SessionId, messageId)
		read, err := os.ReadFile(clearPath.Path)
		require.NoError(t, err)
		assert.True(t, bytes.Compare(read, clearData) == 0)

		parsedId, err := ParseFileUri(encryptedUri)
		require.NoError(t, err)
		assert.Equal(t, parsedId, messageId)
	})

	t.Run("can handle encrypt/decrypt fail", func(t *testing.T) {
		_, err = EncryptFileFromUriAndSerializedSymKey(testDir+testFileName, testFileName, messageId, nil)
		assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		_, err = DecryptFileFromUriAndSerializedSymKey(testDir+testFileName, nil)
		assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
	})

	t.Run("Encrypt Bad Uri", func(t *testing.T) {
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

	t.Run("Decrypt Bad Uri", func(t *testing.T) {
		_, err := DecryptFileFromUriAndSerializedSymKey("", serializedSymKey)
		if runtime.GOOS == "windows" {
			assert.EqualError(t, err, "open : The system cannot find the file specified.")
		} else {
			assert.EqualError(t, err, "open : no such file or directory")
		}

		_, err = DecryptFileFromUriAndSerializedSymKey("That's not an uri !", serializedSymKey)
		if runtime.GOOS == "windows" {
			assert.EqualError(t, err, "open That's not an uri !: The system cannot find the file specified.")
		} else {
			assert.EqualError(t, err, "open That's not an uri !: no such file or directory")
		}

		_, err = DecryptFileFromUriAndSerializedSymKey("../test/this/path/doesnt/exist", serializedSymKey)
		if runtime.GOOS == "windows" {
			assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: The system cannot find the path specified.")
		} else {
			assert.EqualError(t, err, "open ../test/this/path/doesnt/exist: no such file or directory")
		}

		_, err = DecryptFileFromUriAndSerializedSymKey("../test/this/file/doesnt/exist.txt", serializedSymKey)
		if runtime.GOOS == "windows" {
			assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: The system cannot find the path specified.")
		} else {
			assert.EqualError(t, err, "open ../test/this/file/doesnt/exist.txt: no such file or directory")
		}
	})

	t.Run("Permission errors", func(t *testing.T) {
		permDir := testDir + "seald_acc_perm/"
		permFile := permDir + "my.file"

		err = os.Mkdir(permDir, 0o750)
		if err != nil && !os.IsExist(err) {
			require.NoError(t, err)
		}
		err = os.WriteFile(permFile, clearData, 0o666)
		require.NoError(t, err)
		t.Run("no exec on dir", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			assert.NoError(t, os.Chmod(permDir, 0o444)) // no exec on Dir, cannot access it
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			assert.NoError(t, os.Chmod(permDir, 0o777)) // reset dir perm
		})

		t.Run("read only dir", func(t *testing.T) {
			assert.NoError(t, os.Chmod(permDir, 0o500)) // read only dir
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.ErrorIs(t, err, ErrorEncryptFromUriNoWritePerm)
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, serializedSymKey)
			assert.ErrorIs(t, err, ErrorDecryptFromUriNoWritePerm)
			assert.NoError(t, os.Chmod(permDir, 0o777)) // reset dir perm
		})

		t.Run("file no access", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			assert.NoError(t, os.Chmod(permFile, 0o000)) // cannot access file
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			assert.NoError(t, os.Chmod(permFile, 0o777))
		})

		t.Run("file write only", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip()
			}
			assert.NoError(t, os.Chmod(permFile, 0o300)) // write-only file
			_, err = EncryptFileFromUriAndSerializedSymKey(permFile, testFileName, messageId, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			_, err = DecryptFileFromUriAndSerializedSymKey(permFile, serializedSymKey)
			assert.EqualError(t, err, "open ./test/seald_acc_perm/my.file: permission denied")
			assert.NoError(t, os.Chmod(permFile, 0o666))
		})
	})

	// <tear-down code>
	assert.NoError(t, os.RemoveAll(testDir))
}
