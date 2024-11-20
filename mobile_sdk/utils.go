package mobile_sdk

import (
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

func ParseSessionIdFromFile(encryptedFilePath string) (string, error) {
	res, err := sdk.ParseSessionIdFromFile(encryptedFilePath)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func ParseSessionIdFromBytes(fileBytes []byte) (string, error) {
	res, err := sdk.ParseSessionIdFromBytes(fileBytes)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func ParseSessionIdFromMessage(message string) (string, error) {
	res, err := sdk.ParseSessionIdFromMessage(message)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
