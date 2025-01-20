package react_native_seald_accelerator

import (
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/ztrue/tracerr"
)

type ClearFile struct {
	Filename    string
	SessionId   string
	FileContent []byte
}

func EncryptFileFromSerializedSymKey(file []byte, filename string, messageId string, serializedSymKey []byte) ([]byte, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return encrypt_decrypt_file.EncryptBytes(file, filename, messageId, &symKey)
}
func DecryptFileFromSerializedSymKey(file []byte, expectedSessionId string, serializedSymKey []byte) (*ClearFile, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	cf, err := encrypt_decrypt_file.DecryptBytes(file, expectedSessionId, &symKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &ClearFile{Filename: cf.Filename, SessionId: cf.SessionId, FileContent: cf.FileContent}, nil
}
func EncryptFileFromUriAndSerializedSymKey(fileUri string, filename string, messageId string, serializedSymKey []byte) (string, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	outputPath, err := encrypt_decrypt_file.EncryptFileFromPath(fileUri, messageId, &symKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return outputPath, nil
}

func DecryptFileFromUriAndSerializedSymKey(fileUri string, expectedSessionId string, serializedSymKey []byte) (string, error) {
	symKey, err := symmetric_key.Decode(serializedSymKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	outputPath, err := encrypt_decrypt_file.DecryptFileFromPath(fileUri, expectedSessionId, &symKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return outputPath, nil
}

func ParseFileUri(fileUri string) (string, error) {
	mid, err := encrypt_decrypt_file.ParseFileHeaderFromPath(fileUri)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return mid, nil
}
