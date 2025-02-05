package encrypt_decrypt_file

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"go.mongodb.org/mongo-driver/bson"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	// ErrorTarFileNoFile is returned when session cannot decrypt the retrieved message key.
	ErrorTarFileNoFile = utils.NewSealdError("TAR_FILE_NO_FILE", "file cannot be nil")
	// ErrorEncryptFileNoSymKey is returned when no symkey is given at encryption
	ErrorEncryptFileNoSymKey = utils.NewSealdError("ENCRYPT_FILE_NO_SYMKEY", "encrypt file no symkey")
	// ErrorParseFileHeaderNoHeader is returned when the Seald header is not found at the beginning of the encrypted file
	ErrorParseFileHeaderNoHeader = utils.NewSealdError("PARSE_FILE_HEADER_NO_HEADER", "file does not include correct header")
	// ErrorParseFileHeaderInvalidHeaderBson is returned when BSON header is invalid
	ErrorParseFileHeaderInvalidHeaderBson = utils.NewSealdError("PARSE_FILE_HEADER_INVALID_HEADER_BSON", "bson header is invalid")
	// ErrorDecryptFileNoSymKey is returned when no symkey is given at decryption
	ErrorDecryptFileNoSymKey = utils.NewSealdError("DECRYPT_FILE_NO_SYMKEY", "decrypt file no symkey")
	// ErrorDecryptUnexpectedSessionId means that the file you are trying to decrypt does not match the sessionID of the session you are trying to use to decrypt it.
	ErrorDecryptUnexpectedSessionId = utils.NewSealdError("DECRYPT_UNEXPECTED_SESSION_ID", "retrieved device id does not match current device")
	// ErrorGetFreeFilenameNoFreeFilename is returned when no free filename found (up to 99)
	ErrorGetFreeFilenameNoFreeFilename = utils.NewSealdError("GET_FREE_FILENAME_NO_FREE_FILENAME", "unable to find a free filename")
)

func tarBytes(file []byte, filename string) ([]byte, error) {
	if file == nil {
		return nil, tracerr.Wrap(ErrorTarFileNoFile)
	}
	header := tar.Header{
		Name:     filename,
		Size:     int64(len(file)),
		Typeflag: tar.TypeReg,
		Mode:     0600,
	}

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&header); err != nil {
		return nil, tracerr.Wrap(err)
	}
	if _, err := writer.Write(file); err != nil {
		return nil, tracerr.Wrap(err)
	}
	if err := writer.Close(); err != nil {
		return nil, tracerr.Wrap(err)
	}
	return buf.Bytes(), nil
}

func tarReader(inputFile io.Reader, fileSize int64, filename string) (outputFile io.Reader, err error) {
	if inputFile == nil {
		return nil, tracerr.Wrap(ErrorTarFileNoFile)
	}

	outputReader, outputWriter := io.Pipe()
	go func() {
		defer outputWriter.Close() // Ensure the writer is closed at the end to signal EOF
		tarWriter := tar.NewWriter(outputWriter)
		defer tarWriter.Close() // Ensure tarWriter is closed to write the final tar data
		// create and write tar header
		header := tar.Header{
			Name:     filename,
			Size:     fileSize,
			Typeflag: tar.TypeReg,
			Mode:     0600,
		}
		err := tarWriter.WriteHeader(&header)
		if err != nil {
			_ = outputReader.CloseWithError(tracerr.Wrap(err))
			return
		}
		// Copy the file content into the tarWriter
		_, err = io.Copy(tarWriter, inputFile)
		if err != nil {
			_ = outputReader.CloseWithError(tracerr.Wrap(err))
			return
		}
	}()
	return outputReader, nil
}

func untarBytes(file []byte) ([]byte, string, error) {
	if file == nil {
		return nil, "", tracerr.Wrap(ErrorTarFileNoFile)
	}
	tarReader := tar.NewReader(bytes.NewReader(file))

	header, err := tarReader.Next()
	if err != nil {
		return nil, "", tracerr.Wrap(err)
	}
	fileBuff := make([]byte, header.Size)
	_, err = io.ReadFull(tarReader, fileBuff)
	if err != nil {
		return nil, "", tracerr.Wrap(err)
	}

	return fileBuff, header.FileInfo().Name(), nil
}

func untarReader(inputFile io.Reader) (fileSize int64, fileName string, outputFile io.Reader, err error) {
	if inputFile == nil {
		return 0, "", nil, tracerr.Wrap(ErrorTarFileNoFile)
	}
	tarReader := tar.NewReader(inputFile)

	header, err := tarReader.Next()
	if err != nil {
		return 0, "", nil, tracerr.Wrap(err)
	}

	return header.Size, header.FileInfo().Name(), tarReader, nil
}

func generateFileHeader(messageId string) ([]byte, error) {
	b64MessageId, err := utils.B64UUID(messageId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	header := common_models.EncryptedFileHeader{Version: "1", MessageId: b64MessageId}
	bsonHeader, err := bson.Marshal(header)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	bsonLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(bsonLength, uint32(len(bsonHeader)))

	output := bytes.Buffer{}
	output.WriteString("SEALD.IO_")
	output.Write(bsonLength)
	output.Write(bsonHeader)
	return output.Bytes(), nil
}

func ParseFileHeaderReader(fileReader io.Reader) (sessionId string, headerSize uint32, err error) {
	initString := make([]byte, 9)
	_, err = io.ReadFull(fileReader, initString) // "SEALD.IO_"
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", 0, tracerr.Wrap(err)
	}

	if !bytes.Equal(initString, []byte("SEALD.IO_")) {
		return "", 0, tracerr.Wrap(ErrorParseFileHeaderNoHeader)
	}

	bsonLength := make([]byte, 4)
	_, err = io.ReadFull(fileReader, bsonLength)
	if err != nil {
		return "", 0, tracerr.Wrap(err)
	}

	bsonHeaderLength := binary.LittleEndian.Uint32(bsonLength)
	headerBuff := make([]byte, bsonHeaderLength)
	_, err = io.ReadFull(fileReader, headerBuff)
	if err != nil {
		return "", 0, tracerr.Wrap(err)
	}

	var header common_models.EncryptedFileHeader
	err = bson.Unmarshal(headerBuff, &header)
	if err != nil {
		return "", 0, tracerr.Wrap(ErrorParseFileHeaderInvalidHeaderBson.AddDetails(err.Error()))
	}

	sessionId, err = utils.UnB64UUID(header.MessageId)
	if err != nil {
		return "", 0, tracerr.Wrap(err)
	}

	return sessionId, 9 + 4 + bsonHeaderLength, nil
}

func ParseFileHeaderBytes(file []byte) (sessionId string, headerSize uint32, err error) {
	fileReader := bytes.NewReader(file)
	sessionId, headerSize, err = ParseFileHeaderReader(fileReader)
	if err != nil {
		return "", 0, tracerr.Wrap(err)
	}
	return sessionId, headerSize, nil
}

func ParseFileHeaderFromPath(filePath string) (sessionId string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	defer file.Close()
	sessionId, _, err = ParseFileHeaderReader(file)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return sessionId, nil
}

func EncryptBytes(file []byte, filename string, messageId string, key *symmetric_key.SymKey) ([]byte, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorEncryptFileNoSymKey)
	}
	tarFile, err := tarBytes(file, filename)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	header, err := generateFileHeader(messageId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedTarFile, err := key.Encrypt(tarFile)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	output := append(header, encryptedTarFile...)

	return output, nil
}

func DecryptBytes(file []byte, expectedSessionId string, key *symmetric_key.SymKey) (*common_models.ClearFile, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorDecryptFileNoSymKey)
	}

	mid, headerSize, err := ParseFileHeaderBytes(file)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if mid != expectedSessionId {
		return nil, tracerr.Wrap(ErrorDecryptUnexpectedSessionId)
	}

	if int64(len(file))-int64(headerSize) <= 0 {
		return nil, tracerr.Wrap(io.ErrUnexpectedEOF)
	}

	clearTar, err := key.Decrypt(file[headerSize:])
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	clearData, clearFilename, err := untarBytes(clearTar)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	clearFile := common_models.ClearFile{Filename: clearFilename, SessionId: mid, FileContent: clearData}
	return &clearFile, nil
}

func EncryptReader(file io.Reader, filename string, fileSize int64, messageId string, key *symmetric_key.SymKey) (io.Reader, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorEncryptFileNoSymKey)
	}
	tarFile, err := tarReader(file, fileSize, filename)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	header, err := generateFileHeader(messageId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedTarFile, err := key.EncryptReader(tarFile)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return io.MultiReader(bytes.NewReader(header), encryptedTarFile), nil
}

func DecryptReader(file io.Reader, expectedSessionId string, key *symmetric_key.SymKey) (*common_models.ClearFileReader, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorDecryptFileNoSymKey)
	}

	mid, _, err := ParseFileHeaderReader(file)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if mid != expectedSessionId {
		return nil, tracerr.Wrap(ErrorDecryptUnexpectedSessionId)
	}

	clearTar, err := key.DecryptReader(file)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	clearFileSize, clearFilename, clearData, err := untarReader(clearTar)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	clearFile := common_models.ClearFileReader{Filename: clearFilename, SessionId: mid, Size: clearFileSize, FileContent: clearData}
	return &clearFile, nil
}

func getFreeFilePath(basePath string, wantedFilename string, wantedExt string) (string, error) {
	iteration := 0
	iterationString := ""
	for iteration <= 99 {
		iterationPath := path.Join(basePath, wantedFilename+iterationString+wantedExt)
		_, err := os.Stat(iterationPath)
		if err != nil {
			return iterationPath, nil
		}
		iteration++
		iterationString = fmt.Sprintf(" (%d)", iteration)
	}
	return "", tracerr.Wrap(ErrorGetFreeFilenameNoFreeFilename)
}

func EncryptFileFromPath(clearFilePath string, messageId string, key *symmetric_key.SymKey) (string, error) {
	filename := filepath.Base(clearFilePath)
	clearFile, err := os.Open(clearFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	defer clearFile.Close()
	stat, err := os.Stat(clearFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	encryptedFile, err := EncryptReader(clearFile, filename, stat.Size(), messageId, key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	directory, err := filepath.Abs(filepath.Dir(clearFilePath))
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	fileExt := filepath.Ext(filename)
	freeFilePath, err := getFreeFilePath(directory, strings.TrimSuffix(filename, fileExt), fileExt+".seald")
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	output, err := os.OpenFile(freeFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stat.Mode().Perm())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	defer output.Close()
	_, err = io.Copy(output, encryptedFile)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return freeFilePath, nil
}

func DecryptFileFromPath(encryptedFilePath string, expectedSessionId string, key *symmetric_key.SymKey) (outputPath string, err error) {
	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	defer encryptedFile.Close()

	clearFile, err := DecryptReader(encryptedFile, expectedSessionId, key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	directory, err := filepath.Abs(filepath.Dir(encryptedFilePath))
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	fileExt := filepath.Ext(clearFile.Filename)
	freeFilePath, err := getFreeFilePath(directory, strings.TrimSuffix(clearFile.Filename, fileExt), fileExt)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	stat, err := os.Stat(encryptedFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	output, err := os.OpenFile(freeFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stat.Mode().Perm())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	defer output.Close()
	_, err = io.Copy(output, clearFile)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return freeFilePath, nil
}
