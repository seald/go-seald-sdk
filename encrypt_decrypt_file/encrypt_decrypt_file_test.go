package encrypt_decrypt_file

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTarUntar(t *testing.T) {
	t.Parallel()
	t.Run("tarBytes / untarBytes", func(t *testing.T) {
		clearData := []byte("1 in 5,000 north Atlantic lobsters are born bright blue")
		testFileName := "random.fact"

		t.Parallel()
		t.Run("Can tarBytes-untarBytes", func(t *testing.T) {
			tarFile, err := tarBytes(clearData, testFileName)
			require.NoError(t, err)

			unTarfile, unTarFilename, err := untarBytes(tarFile)
			require.NoError(t, err)

			assert.Equal(t, testFileName, unTarFilename)
			assert.Equal(t, clearData, unTarfile)
		})
		t.Run("Tar", func(t *testing.T) {
			t.Run("nil file", func(t *testing.T) {
				_, err := tarBytes(nil, testFileName)
				assert.ErrorIs(t, err, ErrorTarFileNoFile)
			})
		})
		t.Run("Untar", func(t *testing.T) {
			t.Run("nil file", func(t *testing.T) {
				_, _, err := untarBytes(nil)
				assert.ErrorIs(t, err, ErrorTarFileNoFile)
			})
			t.Run("not a tar file", func(t *testing.T) {
				_, _, err := untarBytes([]byte("that's not a tar file!"))
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
			})
			t.Run("bad data followed by a valid tar file", func(t *testing.T) {
				tarFile, err := tarBytes(clearData, testFileName)
				data := []byte("that's not a tar file!")
				data = append(data, tarFile...)
				_, _, err = untarBytes(data)
				assert.ErrorIs(t, err, tar.ErrHeader)
			})
			t.Run("no header", func(t *testing.T) {
				var buf bytes.Buffer
				writer := tar.NewWriter(&buf)
				err := writer.Close()
				require.NoError(t, err)

				_, _, err = untarBytes(buf.Bytes())
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
				err := writer.WriteHeader(&header)
				require.NoError(t, err)

				_, _, err = untarBytes(buf.Bytes())
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
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
				err := writer.WriteHeader(&header)
				require.NoError(t, err)
				_, err = writer.Write(clearData)
				require.NoError(t, err)

				_, _, err = untarBytes(buf.Bytes())
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
			})
		})
	})

	t.Run("tarReader / untarReader", func(t *testing.T) {
		clearData, err := utils.GenerateRandomBytes(1024 * 1024)
		require.NoError(t, err)
		testFileName := "test.bin"

		t.Parallel()
		t.Run("Can TarReader-UntarReader", func(t *testing.T) {
			tarFile, err := tarReader(bytes.NewReader(clearData), int64(len(clearData)), testFileName)
			require.NoError(t, err)

			fileSize, unTarFilename, unTarfile, err := untarReader(tarFile)
			require.NoError(t, err)
			untarBytes, err := io.ReadAll(unTarfile)
			require.NoError(t, err)

			assert.Equal(t, fileSize, int64(len(clearData)))
			assert.Equal(t, testFileName, unTarFilename)
			assert.Equal(t, clearData, untarBytes)
		})
		t.Run("Can tarBytes-untarReader", func(t *testing.T) {
			tarFile, err := tarBytes(clearData, testFileName)
			require.NoError(t, err)

			fileSize, unTarFilename, unTarfile, err := untarReader(bytes.NewReader(tarFile))
			require.NoError(t, err)
			untarBytes, err := io.ReadAll(unTarfile)
			require.NoError(t, err)

			assert.Equal(t, fileSize, int64(len(clearData)))
			assert.Equal(t, testFileName, unTarFilename)
			assert.Equal(t, clearData, untarBytes)
		})
		t.Run("Can tarReader-untarBytes", func(t *testing.T) {
			tarFile, err := tarReader(bytes.NewReader(clearData), int64(len(clearData)), testFileName)
			require.NoError(t, err)
			tarFileBytes, err := io.ReadAll(tarFile)
			require.NoError(t, err)

			unTarfile, unTarFilename, err := untarBytes(tarFileBytes)
			require.NoError(t, err)

			assert.Equal(t, testFileName, unTarFilename)
			assert.Equal(t, clearData, unTarfile)
		})
		t.Run("Tar", func(t *testing.T) {
			t.Run("nil file", func(t *testing.T) {
				_, err := tarReader(nil, 0, testFileName)
				assert.ErrorIs(t, err, ErrorTarFileNoFile)
			})
		})
		t.Run("Untar", func(t *testing.T) {
			t.Run("nil file", func(t *testing.T) {
				_, _, _, err := untarReader(nil)
				assert.ErrorIs(t, err, ErrorTarFileNoFile)
			})
			t.Run("not a tar file", func(t *testing.T) {
				_, _, _, err := untarReader(bytes.NewReader([]byte("that's not a tar file!")))
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
			})
			t.Run("bad data followed by a valid tar file", func(t *testing.T) {
				tarFile, err := tarBytes(clearData, testFileName)
				data := []byte("that's not a tar file!")
				data = append(data, tarFile...)
				_, _, _, err = untarReader(bytes.NewReader(data))
				assert.ErrorIs(t, err, tar.ErrHeader)
			})
			t.Run("no header", func(t *testing.T) {
				var buf bytes.Buffer
				writer := tar.NewWriter(&buf)
				err := writer.Close()
				require.NoError(t, err)

				_, _, _, err = untarReader(&buf)
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
				err := writer.WriteHeader(&header)
				require.NoError(t, err)

				_, _, reader, err := untarReader(&buf)
				require.NoError(t, err)
				_, err = io.ReadAll(reader)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
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
				err := writer.WriteHeader(&header)
				require.NoError(t, err)
				_, err = writer.Write(clearData)
				require.NoError(t, err)

				_, _, reader, err := untarReader(&buf)
				require.NoError(t, err)
				_, err = io.ReadAll(reader)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
			})
		})
	})
}

func TestParseFileHeader(t *testing.T) {
	clearData := []byte("how much muscles are in a cats ear? - 32 muscles")
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	validEncryptedFile, err := EncryptBytes(clearData, testFileName, messageId, symKey)
	require.NoError(t, err)

	t.Run("Parse empty buffer", func(t *testing.T) {
		_, _, err = ParseFileHeaderReader(bytes.NewReader([]byte{}))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Parse bad initial string", func(t *testing.T) {
		data := validEncryptedFile[:3] // SEA
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})
	t.Run("Parse only initial string", func(t *testing.T) {
		data := validEncryptedFile[:9] // SEALD.IO_
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Parse bad header length", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:9]...)
		data = append(data, []byte("a")...)
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("Parse no header", func(t *testing.T) {
		data := validEncryptedFile[:13] // SEALD.IO_ + header length
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("Parse half header", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:13]...)
		data = append(data, []byte("aaAAaa")...) // SEALD.IO_ + header length + half header
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("Parse bad header", func(t *testing.T) {
		data := append([]byte{}, validEncryptedFile[:13]...)
		data = append(data, []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")...) // SEALD.IO_ + header length + dummy header with good length
		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, ErrorParseFileHeaderInvalidHeaderBson)
	})
	t.Run("Parse header with bad data", func(t *testing.T) {
		header := common_models.EncryptedFileHeader{Version: "1", MessageId: "NotAValidUUID"}
		bsonHeader, err := bson.Marshal(header)
		require.NoError(t, err)
		bsonLength := make([]byte, 4)
		binary.LittleEndian.PutUint32(bsonLength, uint32(len(bsonHeader)))
		data := []byte("SEALD.IO_")
		data = append(data, bsonLength...)
		data = append(data, bsonHeader...)

		_, _, err = ParseFileHeaderReader(bytes.NewReader(data))
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})
	t.Run("Parse good header", func(t *testing.T) {
		mid, _, err := ParseFileHeaderReader(bytes.NewReader(validEncryptedFile))
		require.NoError(t, err)
		assert.Equal(t, messageId, mid)
	})
	t.Run("Parse a non seald buffer", func(t *testing.T) {
		_, _, err = ParseFileHeaderReader(bytes.NewReader(clearData))
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})
	t.Run("Parse bytes", func(t *testing.T) {
		mid, _, err := ParseFileHeaderBytes(validEncryptedFile)
		require.NoError(t, err)
		assert.Equal(t, messageId, mid)
	})
}

func TestEncryptBytesDecryptBytes(t *testing.T) {
	clearData := []byte("How many taste buds do catfish have? - Some large catfish can have as many as 175,000.")
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	t.Run("Can Encrypt-Decrypt", func(t *testing.T) {
		encrypted, err := EncryptBytes(clearData, testFileName, messageId, symKey)
		require.NoError(t, err)

		decrypted, err := DecryptBytes(encrypted, messageId, symKey)
		require.NoError(t, err)

		assert.Equal(t, testFileName, decrypted.Filename)
		assert.Equal(t, messageId, decrypted.SessionId)
		assert.Equal(t, clearData, decrypted.FileContent)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Run("Encrypt bad mid", func(t *testing.T) {
			_, err := EncryptBytes(clearData, testFileName, "messageId", symKey)
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
		})
		t.Run("Encrypt nil symKey", func(t *testing.T) {
			_, err = EncryptBytes(clearData, testFileName, messageId, nil)
			assert.ErrorIs(t, err, ErrorEncryptFileNoSymKey)
		})
		t.Run("Encrypt bad symKey", func(t *testing.T) {
			_, err = EncryptBytes(clearData, testFileName, messageId, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorInvalidKeySize)
		})
		t.Run("Encrypt nil file", func(t *testing.T) {
			_, err := EncryptBytes(nil, testFileName, messageId, symKey)
			assert.ErrorIs(t, err, ErrorTarFileNoFile)
		})
	})

	t.Run("Decrypt", func(t *testing.T) {
		validEncryptedFile, err := EncryptBytes(clearData, testFileName, messageId, symKey)
		require.NoError(t, err)

		t.Parallel()
		t.Run("Decrypt nil symKey", func(t *testing.T) {
			_, err = DecryptBytes(validEncryptedFile, messageId, nil)
			assert.ErrorIs(t, err, ErrorDecryptFileNoSymKey)
		})
		t.Run("Decrypt bad symKey", func(t *testing.T) {
			_, err = DecryptBytes(validEncryptedFile, messageId, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorInvalidKeySize)
		})

		t.Run("Decrypt empty buffer", func(t *testing.T) {
			_, err = DecryptBytes([]byte{}, messageId, symKey)
			assert.ErrorIs(t, err, io.EOF)
		})
		t.Run("Decrypt good header, no data", func(t *testing.T) {
			data := validEncryptedFile[:59] // SEALD.IO_ + header length + full header + no data to decrypt
			_, err = DecryptBytes(data, messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from DecryptBytes
		})
		t.Run("Decrypt good header, short data", func(t *testing.T) {
			data := validEncryptedFile[:89] // SEALD.IO_ + header length + full header + ciphertext really short (not even a full iv)
			_, err = DecryptBytes(data, messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from symkey.Decrypt
		})
		t.Run("Decrypt good header, incomplete data", func(t *testing.T) {
			data := validEncryptedFile[:300] // SEALD.IO_ + header length + full header + incomplete ciphertext
			_, err = DecryptBytes(data, messageId, symKey)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptMacMismatch)
		})
		t.Run("Decrypt good file", func(t *testing.T) {
			clearFile, err := DecryptBytes(validEncryptedFile, messageId, symKey)
			require.NoError(t, err)
			assert.Equal(t, messageId, clearFile.SessionId)
			assert.Equal(t, clearData, clearFile.FileContent)
			assert.Equal(t, testFileName, clearFile.Filename)
		})
		t.Run("Decrypt a non seald buffer", func(t *testing.T) {
			_, err = DecryptBytes(clearData, messageId, symKey)
			assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
		})
		t.Run("Decrypt an encrypted message that is not a tar", func(t *testing.T) {
			encryptedData, err := symKey.Encrypt([]byte("That's not a tar!"))
			data := append([]byte{}, validEncryptedFile[:59]...)
			data = append(data, encryptedData...)
			_, err = DecryptBytes(data, messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from Untar
		})
		t.Run("Decrypt with invalid session ID", func(t *testing.T) {
			_, err := DecryptBytes(validEncryptedFile, "BadSessionId", symKey)
			assert.ErrorIs(t, err, ErrorDecryptUnexpectedSessionId)
		})
	})
}

func TestEncryptReaderDecryptReader(t *testing.T) {
	clearData, err := utils.GenerateRandomBytes(1024 * 1024)
	require.NoError(t, err)
	testFileName := "test.bin"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	t.Run("Can Encrypt-Decrypt", func(t *testing.T) {
		encrypted, err := EncryptReader(bytes.NewReader(clearData), testFileName, int64(len(clearData)), messageId, symKey)
		require.NoError(t, err)

		decrypted, err := DecryptReader(encrypted, messageId, symKey)
		require.NoError(t, err)

		assert.Equal(t, testFileName, decrypted.Filename)
		assert.Equal(t, messageId, decrypted.SessionId)
		decryptedBytes, err := io.ReadAll(decrypted)
		require.NoError(t, err)
		assert.Equal(t, clearData, decryptedBytes)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Run("Encrypt bad mid", func(t *testing.T) {
			_, err := EncryptReader(bytes.NewReader(clearData), testFileName, int64(len(clearData)), "messageId", symKey)
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
		})
		t.Run("Encrypt nil symKey", func(t *testing.T) {
			_, err = EncryptReader(bytes.NewReader(clearData), testFileName, int64(len(clearData)), messageId, nil)
			assert.ErrorIs(t, err, ErrorEncryptFileNoSymKey)
		})
		t.Run("Encrypt bad symKey", func(t *testing.T) {
			_, err = EncryptReader(bytes.NewReader(clearData), testFileName, int64(len(clearData)), messageId, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorInvalidKeySize)
		})
		t.Run("Encrypt nil file", func(t *testing.T) {
			_, err := EncryptReader(nil, testFileName, int64(len(clearData)), messageId, symKey)
			assert.ErrorIs(t, err, ErrorTarFileNoFile)
		})
	})

	t.Run("Decrypt", func(t *testing.T) {
		validEncryptedFile, err := EncryptBytes(clearData, testFileName, messageId, symKey)
		require.NoError(t, err)

		t.Parallel()
		t.Run("Decrypt nil symKey", func(t *testing.T) {
			_, err = DecryptReader(bytes.NewReader(validEncryptedFile), messageId, nil)
			assert.ErrorIs(t, err, ErrorDecryptFileNoSymKey)
		})
		t.Run("Decrypt bad symKey", func(t *testing.T) {
			_, err = DecryptReader(bytes.NewReader(validEncryptedFile), messageId, &symmetric_key.SymKey{})
			assert.ErrorIs(t, err, symmetric_key.ErrorInvalidKeySize)
		})

		t.Run("Decrypt empty buffer", func(t *testing.T) {
			_, err = DecryptReader(bytes.NewReader([]byte{}), messageId, symKey)
			assert.ErrorIs(t, err, io.EOF)
		})
		t.Run("Decrypt good header, no data", func(t *testing.T) {
			data := validEncryptedFile[:59] // SEALD.IO_ + header length + full header + no data to decrypt
			_, err = DecryptReader(bytes.NewReader(data), messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from DecryptReader
		})
		t.Run("Decrypt good header, short data", func(t *testing.T) {
			data := validEncryptedFile[:89] // SEALD.IO_ + header length + full header + ciphertext really short (not even a full iv)
			_, err = DecryptReader(bytes.NewReader(data), messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from symkey.Decrypt
		})
		t.Run("Decrypt good header, incomplete data", func(t *testing.T) {
			data := validEncryptedFile[:300] // SEALD.IO_ + header length + full header + incomplete ciphertext
			_, err = DecryptReader(bytes.NewReader(data), messageId, symKey)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptMacMismatch)
		})
		t.Run("Decrypt good file", func(t *testing.T) {
			clearFile, err := DecryptReader(bytes.NewReader(validEncryptedFile), messageId, symKey)
			require.NoError(t, err)
			assert.Equal(t, messageId, clearFile.SessionId)
			assert.Equal(t, testFileName, clearFile.Filename)
			decryptedBytes, err := io.ReadAll(clearFile)
			require.NoError(t, err)
			assert.Equal(t, clearData, decryptedBytes)
		})
		t.Run("Decrypt a non seald buffer", func(t *testing.T) {
			_, err = DecryptReader(bytes.NewReader(clearData), messageId, symKey)
			assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
		})
		t.Run("Decrypt an encrypted message that is not a tar", func(t *testing.T) {
			encryptedData, err := symKey.Encrypt([]byte("That's not a tar!"))
			data := append([]byte{}, validEncryptedFile[:59]...)
			data = append(data, encryptedData...)
			_, err = DecryptReader(bytes.NewReader(data), messageId, symKey)
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF) // from Untar
		})
		t.Run("Decrypt with invalid session ID", func(t *testing.T) {
			_, err := DecryptReader(bytes.NewReader(validEncryptedFile), "BadSessionId", symKey)
			assert.ErrorIs(t, err, ErrorDecryptUnexpectedSessionId)
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

	decryptedFilePath, err := DecryptFileFromPath(encryptedFilePath, messageId, symKey)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(testFileDir, testFileName+" (1)"+testFileExt), decryptedFilePath)

	decryptedContent, err := os.ReadFile(decryptedFilePath)
	require.NoError(t, err)
	assert.Equal(t, clearData, decryptedContent)

	t.Run("non-existing file", func(t *testing.T) {
		_, err = EncryptFileFromPath("badPath/file.ext", messageId, symKey)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		assert.EqualError(t, err, "open badPath/file.ext: no such file or directory")

		_, err = DecryptFileFromPath("badPath/file.ext", messageId, symKey)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		assert.EqualError(t, err, "open badPath/file.ext: no such file or directory")
	})

	t.Run("no free filename", func(t *testing.T) {
		iteration := 1
		for iteration <= 99 {
			resPath, err := EncryptFileFromPath(testFilePath, messageId, symKey)
			require.NoError(t, err)
			assert.True(t, strings.Contains(resPath, fmt.Sprintf(" (%d)", iteration)))
			iteration++
		}
		_, err := EncryptFileFromPath(testFilePath, messageId, symKey)
		assert.ErrorIs(t, err, ErrorGetFreeFilenameNoFreeFilename)
	})

	t.Run("wrap encryption error", func(t *testing.T) {
		_, err := EncryptFileFromPath(testFilePath, messageId, &symmetric_key.SymKey{})
		assert.ErrorIs(t, err, symmetric_key.ErrorInvalidKeySize)
	})

	t.Run("wrap decryption error", func(t *testing.T) {
		_, err := DecryptFileFromPath(testFilePath, messageId, symKey)
		assert.ErrorIs(t, err, ErrorParseFileHeaderNoHeader)
	})

	err = os.RemoveAll("tmp/")
	assert.NoError(t, err)
}

func TestEncryptDecryptPerformance(t *testing.T) {
	testFileName := "random.fact"
	messageId := "00000000-0000-1000-a000-1d0000000000"

	symKey, err := symmetric_key.Generate()
	require.NoError(t, err)

	largePlainText, err := utils.GenerateRandomBytes(100 * 1024 * 1024)
	require.NoError(t, err)

	t.Run("encrypt / decrypt Bytes performance", func(t *testing.T) {
		t0 := time.Now()
		encrypted, err := EncryptBytes(largePlainText, testFileName, messageId, symKey)
		require.NoError(t, err)
		duration := time.Now().Sub(t0).Seconds()
		fmt.Printf("Encrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		t0 = time.Now()
		decrypted, err := DecryptBytes(encrypted, messageId, symKey)
		require.NoError(t, err)
		duration = time.Now().Sub(t0).Seconds()
		fmt.Printf("Decrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		assert.Equal(t, largePlainText, decrypted.FileContent)
	})

	t.Run("encrypt / decrypt Reader performance", func(t *testing.T) {
		clearTextReader := bytes.NewReader(largePlainText)
		t0 := time.Now()
		encryptedReader, err := EncryptReader(clearTextReader, testFileName, int64(len(largePlainText)), messageId, symKey)
		require.NoError(t, err)
		encrypted, err := io.ReadAll(encryptedReader)
		require.NoError(t, err)
		duration := time.Now().Sub(t0).Seconds()
		fmt.Printf("Encrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		cipherTextReader := bytes.NewReader(encrypted)
		t0 = time.Now()
		decryptedReader, err := DecryptReader(cipherTextReader, messageId, symKey)
		require.NoError(t, err)
		decrypted, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		duration = time.Now().Sub(t0).Seconds()
		fmt.Printf("Decrypt speed: %.2f MB/s\n", float64(len(largePlainText))/(1024*1024)/duration)

		assert.Equal(t, largePlainText, decrypted)
	})
}
