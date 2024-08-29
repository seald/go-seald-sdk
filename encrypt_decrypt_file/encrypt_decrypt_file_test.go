package encrypt_decrypt_file

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/utils"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTarUntar(t *testing.T) {
	clearData := []byte("1 in 5,000 north Atlantic lobsters are born bright blue")
	testFileName := "random.fact"

	t.Parallel()
	t.Run("Can Tar-Untar", func(t *testing.T) {
		tarFile, err := TarFile(clearData, testFileName)
		if !assert.NoError(t, err) {
			return
		}

		unTarfile, unTarFilename, err := UnTarFile(tarFile)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testFileName, unTarFilename)
		assert.Equal(t, clearData, unTarfile)
	})
	t.Run("Tar", func(t *testing.T) {
		t.Run("nil file", func(t *testing.T) {
			_, err := TarFile(nil, testFileName)
			assert.ErrorIs(t, err, ErrorTarFileNoFile)
		})
	})
	t.Run("Untar", func(t *testing.T) {
		t.Run("nil file", func(t *testing.T) {
			_, _, err := UnTarFile(nil)
			assert.ErrorIs(t, err, io.EOF)
		})
		t.Run("not a tar file", func(t *testing.T) {
			_, _, err := UnTarFile([]byte("that's not a tar file!"))
			assert.EqualError(t, err, "unexpected EOF")
		})
		t.Run("bad data followed by a valid tar file", func(t *testing.T) {
			tarFile, err := TarFile(clearData, testFileName)
			data := []byte("that's not a tar file!")
			data = append(data, tarFile...)
			_, _, err = UnTarFile(data)
			assert.EqualError(t, err, "archive/tar: invalid tar header")
		})
		t.Run("no header", func(t *testing.T) {
			var buf bytes.Buffer
			writer := tar.NewWriter(&buf)
			assert.NoError(t, writer.Close())

			_, _, err := UnTarFile(buf.Bytes())
			assert.ErrorIs(t, err, io.EOF)
		})
		t.Run("no file", func(t *testing.T) {
			header := tar.Header{
				Name:     testFileName,
				Size:     int64(len(clearData)),
				Typeflag: tar.TypeReg,
				Mode:     0600,
			}
			var buf bytes.Buffer
			writer := tar.NewWriter(&buf)
			assert.NoError(t, writer.WriteHeader(&header))

			_, _, err := UnTarFile(buf.Bytes())
			assert.EqualError(t, err, "unexpected EOF")
		})
		t.Run("Bad header len - too long", func(t *testing.T) {
			header := tar.Header{
				Name:     testFileName,
				Size:     int64(len(clearData) + 10),
				Typeflag: tar.TypeReg,
				Mode:     0600,
			}
			var buf bytes.Buffer
			writer := tar.NewWriter(&buf)
			assert.NoError(t, writer.WriteHeader(&header))
			_, err := writer.Write(clearData)
			assert.NoError(t, err)

			_, _, err = UnTarFile(buf.Bytes())
			assert.ErrorIs(t, err, ErrorUnTarFileNoEOF)
		})
	})
}

func TestParseFileHeader(t *testing.T) {
	clearData := []byte("how much muscles are in a cats ear? - 32 muscles")
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	validEncryptedFile, err := EncryptFile(clearData, testFileName, messageId, symKey)
	require.NoError(t, err)

	t.Run("Decrypt empty buffer", func(t *testing.T) {
		_, err = ParseFileHeader(bytes.NewReader([]byte{}))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Decrypt bad initial string", func(t *testing.T) {
		data := validEncryptedFile[:3] // SEA
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})
	t.Run("Decrypt only initial string", func(t *testing.T) {
		data := validEncryptedFile[:9] // SEALD.IO_
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Decrypt bad header length", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:9]...)
		data = append(data, []byte("a")...)
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.ErrorIs(t, err, ErrorParseFileHeaderIncorrectHeaderLength)
	})
	t.Run("Decrypt no header", func(t *testing.T) {
		data := validEncryptedFile[:13] // SEALD.IO_ + header length
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Decrypt half header", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:13]...)
		data = append(data, []byte("aaAAaa")...) // SEALD.IO_ + header length + half header
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.EqualError(t, err, "invalid document length")
	})
	t.Run("Decrypt bad header", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:13]...)
		data = append(data, []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")...) // SEALD.IO_ + header length + dummy header with good length
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.EqualError(t, err, "invalid document length")
	})
	t.Run("Decrypt header with bad data", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:45]...)
		data = append(data, []byte("ZZZZZ")...) // SEALD.IO_ + header length + header with bad mid
		_, err = ParseFileHeader(bytes.NewReader(data))
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})
	t.Run("Decrypt good header", func(t *testing.T) {
		mid, err := ParseFileHeader(bytes.NewReader(validEncryptedFile))
		assert.NoError(t, err)
		assert.Equal(t, messageId, mid)
	})
	t.Run("Decrypt a non seald buffer", func(t *testing.T) {
		_, err = DecryptFile(clearData, symKey)
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	clearData := []byte("How many taste buds do catfish have? - Some large catfish can have as many as 175,000.")
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	t.Run("Can Encrypt-Decrypt", func(t *testing.T) {
		encrypted, err := EncryptFile(clearData, testFileName, messageId, symKey)
		if !assert.NoError(t, err) {
			return
		}

		decrypted, err := DecryptFile(encrypted, symKey)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testFileName, decrypted.Filename)
		assert.Equal(t, messageId, decrypted.SessionId)
		assert.Equal(t, clearData, decrypted.FileContent)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Run("Encrypt bad mid", func(t *testing.T) {
			_, err := EncryptFile(clearData, testFileName, "messageId", symKey)
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
		})
		t.Run("Encrypt nil symKey", func(t *testing.T) {
			_, err = EncryptFile(clearData, testFileName, messageId, nil)
			assert.ErrorIs(t, err, ErrorEncryptFileNoSymKey)
		})
		t.Run("Encrypt bad symKey", func(t *testing.T) {
			_, err = EncryptFile(clearData, testFileName, messageId, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorEncryptInvalidKeySize)
		})
		t.Run("Encrypt nil file", func(t *testing.T) {
			_, err := EncryptFile(nil, testFileName, messageId, symKey)
			assert.ErrorIs(t, err, ErrorTarFileNoFile)
		})
	})

	t.Run("Decrypt", func(t *testing.T) {
		validEncryptedFile, err := EncryptFile(clearData, testFileName, messageId, symKey)
		require.NoError(t, err)

		t.Parallel()
		t.Run("Decrypt nil symKey", func(t *testing.T) {
			_, err = DecryptFile(validEncryptedFile, nil)
			assert.ErrorIs(t, err, ErrorDecryptFileNoSymKey)
		})
		t.Run("Decrypt bad symKey", func(t *testing.T) {
			_, err = DecryptFile(validEncryptedFile, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptInvalidKeySize)
		})

		t.Run("Decrypt empty buffer", func(t *testing.T) {
			_, err = DecryptFile([]byte{}, symKey)
			assert.ErrorIs(t, err, io.EOF)
		})
		t.Run("Decrypt good header, no data", func(t *testing.T) {
			data := validEncryptedFile[:59] // SEALD.IO_ + header length + full header + no data to decrypt
			_, err = DecryptFile(data, symKey)
			assert.ErrorIs(t, err, ErrorDecryptFileUnexpectedEOF)
		})
		t.Run("Decrypt good header, short data", func(t *testing.T) {
			data := validEncryptedFile[:89] // SEALD.IO_ + header length + full header + ciphertext really short (not even a full iv)
			_, err = DecryptFile(data, symKey)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptCipherTooShort)
		})
		t.Run("Decrypt good header, incomplete data", func(t *testing.T) {
			data := validEncryptedFile[:300] // SEALD.IO_ + header length + full header + incomplete ciphertext
			_, err = DecryptFile(data, symKey)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptMacMismatch)
		})
		t.Run("Decrypt good file", func(t *testing.T) {
			clearFile, err := DecryptFile(validEncryptedFile, symKey)
			require.NoError(t, err)
			assert.Equal(t, messageId, clearFile.SessionId)
			assert.Equal(t, clearData, clearFile.FileContent)
			assert.Equal(t, testFileName, clearFile.Filename)
		})
		t.Run("Decrypt a non seald buffer", func(t *testing.T) {
			_, err = DecryptFile(clearData, symKey)
			assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
		})
		t.Run("Decrypt an encrypted message that is not a tar", func(t *testing.T) {
			encryptedData, err := symKey.Encrypt([]byte("That's not a tar!"))
			data := append([]byte{}, validEncryptedFile[:59]...)
			data = append(data, encryptedData...)
			_, err = DecryptFile(data, symKey)
			assert.ErrorIs(t, err, ErrorDecryptFileUntarUnexpectedEOF)
		})
	})
}

func TestEncryptDecryptFromPath(t *testing.T) {
	messageId := "00000000-0000-1000-a000-1d0000000000"
	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	// Clean work dir
	_ = os.RemoveAll("tmp/")
	err = os.Mkdir("tmp", 0o700)
	require.NoError(t, err)

	clearData := []byte("The giant squid has the largest eyes in the world.")
	testFileDir, err := filepath.Abs("tmp")
	require.NoError(t, err)
	testFileName := "random"
	testFileExt := ".fact"
	testFilePath := filepath.Join(testFileDir, testFileName+testFileExt)
	err = os.WriteFile(testFilePath, clearData, 0o700)
	require.NoError(t, err)

	encryptedFilePath, err := EncryptFileFromPath(testFilePath, messageId, symKey)
	require.NoError(t, err)
	assert.Equal(t, testFilePath+".seald", encryptedFilePath)

	decryptedFilePath, err := DecryptFileFromPath(encryptedFilePath, symKey)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(testFileDir, testFileName+" (1)"+testFileExt), decryptedFilePath)

	decryptedContent, err := os.ReadFile(decryptedFilePath)
	require.NoError(t, err)
	assert.Equal(t, clearData, decryptedContent)

	t.Run("non-existing file", func(t *testing.T) {
		_, err = EncryptFileFromPath("badPath/file.ext", messageId, symKey)
		assert.EqualError(t, err, "open badPath/file.ext: no such file or directory")

		_, err = DecryptFileFromPath("badPath/file.ext", symKey)
		assert.EqualError(t, err, "open badPath/file.ext: no such file or directory")
	})

	t.Run("no free filename", func(t *testing.T) {
		iteration := 1
		for iteration <= 99 {
			resPath, err := EncryptFileFromPath(testFilePath, messageId, symKey)
			assert.NoError(t, err)
			assert.True(t, strings.Contains(resPath, fmt.Sprintf(" (%d)", iteration)))
			iteration++
		}
		_, err := EncryptFileFromPath(testFilePath, messageId, symKey)
		assert.ErrorIs(t, err, ErrorGetFreeFilenameNoFreeFilename)
	})

	t.Run("wrap encryption error", func(t *testing.T) {
		_, err := EncryptFileFromPath(testFilePath, messageId, &symmetric_key.SymKey{})
		assert.ErrorIs(t, err, symmetric_key.ErrorEncryptInvalidKeySize)
	})

	t.Run("wrap decryption error", func(t *testing.T) {
		_, err := DecryptFileFromPath(testFilePath, symKey)
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})

	err = os.RemoveAll("tmp/")
	assert.NoError(t, err)
}
