package encrypt_decrypt_file

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/utils"
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
	// ErrorUnTarFileNoEOF is returned when no EOF is found during untar
	ErrorUnTarFileNoEOF = utils.NewSealdError("UNTAR_FILE_NO_EOF", "expected end of file, but did not get it")
	// ErrorEncryptFileNoSymKey is returned when no symkey is given at encryption
	ErrorEncryptFileNoSymKey = utils.NewSealdError("ENCRYPT_FILE_NO_SYMKEY", "encrypt file no symkey")
	// ErrorParseFileHeaderNoHeader is returned when the Seald header is not found at the beginning of the encrypted file
	ErrorParseFileHeaderNoHeader = utils.NewSealdError("PARSE_FILE_HEADER_NO_HEADER", "file does not include correct header")
	// ErrorParseFileHeaderIncorrectHeaderLength is returned when a malformed Seald header is found at the beginning of the encrypted file
	ErrorParseFileHeaderIncorrectHeaderLength = utils.NewSealdError("PARSE_FILE_HEADER_INCORRECT_HEADER_LENGTH", "unexpected end of file - bad header length")
	// ErrorDecryptFileNoSymKey is returned when no symkey is given at decryption
	ErrorDecryptFileNoSymKey = utils.NewSealdError("DECRYPT_FILE_NO_SYMKEY", "decrypt file no symkey")
	// ErrorDecryptFileUnexpectedEOF is returned when an unexpected EOF is found in the file
	ErrorDecryptFileUnexpectedEOF = utils.NewSealdError("DECRYPT_FILE_UNEXPECTED_EOF", "unexpected end of file - bad data length")
	// ErrorDecryptFileUntarUnexpectedEOF is returned when decrypted data is not a tar file
	ErrorDecryptFileUntarUnexpectedEOF = utils.NewSealdError("DECRYPT_FILE_UNTAR_UNEXPECTED_EOF", "unable to untar file after decryption")
	// ErrorGetFreeFilenameNoFreeFilename is returned when no free filename found (up to 99)
	ErrorGetFreeFilenameNoFreeFilename = utils.NewSealdError("GET_FREE_FILENAME_NO_FREE_FILENAME", "unable to find a free filename")
)

func TarFile(file []byte, filename string) ([]byte, error) {
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

func UnTarFile(file []byte) ([]byte, string, error) {
	tarReader := tar.NewReader(bytes.NewBuffer(file))

	header, err := tarReader.Next()
	if err != nil {
		return nil, "", tracerr.Wrap(err)
	}
	info := header.FileInfo()
	fileBuff := make([]byte, info.Size())
	_, err = tarReader.Read(fileBuff) // It returns (len, io.EOF) when it reaches the end of that file

	if err == nil {
		return nil, "", tracerr.Wrap(ErrorUnTarFileNoEOF)
	}
	if err != io.EOF {
		return nil, "", tracerr.Wrap(err)
	}

	return fileBuff, info.Name(), nil
}

func EncryptFile(file []byte, filename string, messageId string, key *symmetric_key.SymKey) ([]byte, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorEncryptFileNoSymKey)
	}
	tarFile, err := TarFile(file, filename)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

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

	encryptedTarFile, err := key.Encrypt(tarFile)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	output := bytes.Buffer{}
	output.WriteString("SEALD.IO_")
	output.Write(bsonLength)
	output.Write(bsonHeader)
	output.Write(encryptedTarFile)

	return output.Bytes(), nil
}

func ParseFileHeader(fileReader io.Reader) (string, error) {
	initString := make([]byte, 9)
	lenRead, err := fileReader.Read(initString) // "SEALD.IO_"
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	if lenRead != 9 || !bytes.Equal(initString, []byte("SEALD.IO_")) {
		return "", tracerr.Wrap(ErrorParseFileHeaderNoHeader)
	}

	bsonLength := make([]byte, 4)
	lenRead, err = fileReader.Read(bsonLength)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	if lenRead != 4 {
		return "", tracerr.Wrap(ErrorParseFileHeaderIncorrectHeaderLength)
	}

	headerBuff := make([]byte, binary.LittleEndian.Uint32(bsonLength))
	_, err = fileReader.Read(headerBuff)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	var header common_models.EncryptedFileHeader
	err = bson.Unmarshal(headerBuff, &header)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	mid, err := utils.UnB64UUID(header.MessageId)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return mid, nil
}

func DecryptFile(file []byte, key *symmetric_key.SymKey) (*common_models.ClearFile, error) {
	if key == nil {
		return nil, tracerr.Wrap(ErrorDecryptFileNoSymKey)
	}
	fileReader := bytes.NewReader(file)

	mid, err := ParseFileHeader(fileReader)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if fileReader.Len() == 0 {
		return nil, tracerr.Wrap(ErrorDecryptFileUnexpectedEOF)
	}

	dataBuff := make([]byte, fileReader.Len())
	_, err = fileReader.Read(dataBuff)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	clearTar, err := key.Decrypt(dataBuff)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	clearData, clearFilename, err := UnTarFile(clearTar)
	if err != nil {
		if err == io.EOF || err.Error() == "unexpected EOF" {
			// If we simply return EOF, it gives no intel of what happened.
			return nil, tracerr.Wrap(ErrorDecryptFileUntarUnexpectedEOF.AddDetails(err.Error()))
		}
		return nil, tracerr.Wrap(err)
	}

	clearFile := common_models.ClearFile{Filename: clearFilename, SessionId: mid, FileContent: clearData}
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
	clearFile, err := os.ReadFile(clearFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	encryptedFile, err := EncryptFile(clearFile, filename, messageId, key)
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
	stat, err := os.Stat(clearFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	err = os.WriteFile(freeFilePath, encryptedFile, stat.Mode())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return freeFilePath, nil
}

func DecryptFileFromPath(encryptedFilePath string, key *symmetric_key.SymKey) (string, error) {
	encryptedFile, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	clearFile, err := DecryptFile(encryptedFile, key)
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

	err = os.WriteFile(freeFilePath, clearFile.FileContent, stat.Mode())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return freeFilePath, nil
}
