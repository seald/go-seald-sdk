package react_native_seald_accelerator

import (
	"bytes"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"os"
	"path/filepath"
)

var (
	// ErrorEncryptFromUriNoWritePerm is returned when the SDK cannot write at the destination path
	ErrorEncryptFromUriNoWritePerm = utils.NewSealdError("RNACC_ENCRYPT_FROM_URI_NO_WRITE_PERM", "encrypt cannot write in destination folder")
	// ErrorDecryptFromUriNoWritePerm is returned when the SDK cannot write at the destination path
	ErrorDecryptFromUriNoWritePerm = utils.NewSealdError("RNACC_DECRYPT_FROM_URI_NO_WRITE_PERM", "decrypt cannot write in destination folder")
)

type ClearFile struct {
	Filename    string
	SessionId   string
	FileContent []byte
}

type ClearPath struct {
	Filename  string
	SessionId string
	Path      string
}

func EncryptFileFromSerializedSymKey(file []byte, filename string, messageId string, serializedSymKey []byte) ([]byte, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return encrypt_decrypt_file.EncryptFile(file, filename, messageId, &symKey)
}
func DecryptFileFromSerializedSymKey(file []byte, serializedSymKey []byte) (*ClearFile, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	cf, err := encrypt_decrypt_file.DecryptFile(file, &symKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &ClearFile{Filename: cf.Filename, SessionId: cf.SessionId, FileContent: cf.FileContent}, nil
}
func EncryptFileFromUriAndSerializedSymKey(fileUri string, filename string, messageId string, serializedSymKey []byte) (string, error) {
	clearByteArray, err := os.ReadFile(fileUri)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	basePath := filepath.Dir(fileUri)
	dirInfo, err := os.Stat(basePath)
	if dirInfo.Mode().Perm()&0o200 == 0 {
		return "", tracerr.Wrap(ErrorEncryptFromUriNoWritePerm)
	}

	encryptedData, err := EncryptFileFromSerializedSymKey(clearByteArray, filename, messageId, serializedSymKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	outputPath := filepath.Join(basePath, filename+".seald")
	err = os.WriteFile(outputPath, encryptedData, 0666)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return outputPath, nil
}

func DecryptFileFromUriAndSerializedSymKey(fileUri string, serializedSymKey []byte) (*ClearPath, error) {
	encryptedByteArray, err := os.ReadFile(fileUri)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	basePath := filepath.Dir(fileUri)
	dirInfo, err := os.Stat(basePath)
	if dirInfo.Mode().Perm()&0o200 == 0 {
		return nil, tracerr.Wrap(ErrorDecryptFromUriNoWritePerm)
	}

	decryptedFile, err := DecryptFileFromSerializedSymKey(encryptedByteArray, serializedSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	outputPath := filepath.Join(basePath, decryptedFile.Filename)
	err = os.WriteFile(outputPath, decryptedFile.FileContent, 0666)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// Return a ClearFile, with a path but without FileContent
	clearFile := ClearPath{Filename: decryptedFile.Filename, SessionId: decryptedFile.SessionId, Path: outputPath}
	return &clearFile, nil
}

func ParseFileUri(fileUri string) (string, error) {
	encryptedByteArray, err := os.ReadFile(fileUri)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	fileReader := bytes.NewReader(encryptedByteArray)

	mid, err := encrypt_decrypt_file.ParseFileHeader(fileReader)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return mid, nil
}
