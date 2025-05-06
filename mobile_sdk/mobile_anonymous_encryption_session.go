package mobile_sdk

import (
	"github.com/seald/go-seald-sdk/anonymous_sdk"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

type MobileAnonymousEncryptionSession struct {
	SessionId string
	aes       *anonymous_sdk.AnonymousEncryptionSession
}

func mobileAnonymousEncryptionSessionFromCommon(aes *anonymous_sdk.AnonymousEncryptionSession) *MobileAnonymousEncryptionSession {
	return &MobileAnonymousEncryptionSession{
		aes:       aes,
		SessionId: aes.SessionId,
	}
}

func (maes *MobileAnonymousEncryptionSession) EncryptMessage(clearMessage string) (string, error) {
	res, err := maes.aes.EncryptMessage(clearMessage)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (maes *MobileAnonymousEncryptionSession) DecryptMessage(clearMessage string) (string, error) {
	res, err := maes.aes.DecryptMessage(clearMessage)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (maes *MobileAnonymousEncryptionSession) EncryptFile(clearFile []byte, filename string) ([]byte, error) {
	res, err := maes.aes.EncryptFile(clearFile, filename)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
func (maes *MobileAnonymousEncryptionSession) DecryptFile(encryptedFile []byte) (*ClearFile, error) {
	res, err := maes.aes.DecryptFile(encryptedFile)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &ClearFile{Filename: res.Filename, SessionId: res.SessionId, FileContent: res.FileContent}, nil
}

func (maes *MobileAnonymousEncryptionSession) EncryptFileFromURI(clearFileURI string) (string, error) {
	res, err := maes.aes.EncryptFileFromPath(clearFileURI)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (maes *MobileAnonymousEncryptionSession) DecryptFileFromURI(encryptedFileURI string) (string, error) {
	res, err := maes.aes.DecryptFileFromPath(encryptedFileURI)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
