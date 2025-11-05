package mobile_sdk

import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/anonymous_sdk"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

type MobileAnonymousSDK struct {
	aSDK *anonymous_sdk.AnonymousSDK
}

type AnonymousInitializeOptions struct {
	ApiURL              string
	AppId               string
	MaxParallelRequests int
	LogLevel            int8 // zerolog.Level
	LogNoColor          bool
	InstanceName        string
	Platform            string
}

func CreateAnonymousSDK(options *AnonymousInitializeOptions) *MobileAnonymousSDK {
	aSDK := anonymous_sdk.CreateAnonymousSDK(&anonymous_sdk.AnonymousInitializeOptions{
		ApiURL:              options.ApiURL,
		AppId:               options.AppId,
		MaxParallelRequests: options.MaxParallelRequests,
		LogLevel:            zerolog.Level(options.LogLevel),
		LogNoColor:          options.LogNoColor,
		InstanceName:        options.InstanceName,
		Platform:            options.Platform,
	})

	return &MobileAnonymousSDK{aSDK: aSDK}
}

func (maSDK MobileAnonymousSDK) CreateAnonymousEncryptionSession(encryptionToken string, getKeysToken string, recipients *StringArray, tmrRecipients *AnonymousTmrRecipientArray) (*MobileAnonymousEncryptionSession, error) {
	anonymousRecipients := &anonymous_sdk.Recipients{
		SealdIds:      recipients.getSlice(),
		TMRRecipients: tmrRecipients.getSlice(),
	}
	aes, err := maSDK.aSDK.CreateAnonymousEncryptionSession(encryptionToken, getKeysToken, anonymousRecipients)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileAnonymousEncryptionSessionFromCommon(aes), nil
}

func (maSDK MobileAnonymousSDK) DeserializeAnonymousEncryptionSession(serializedSession string) (*MobileAnonymousEncryptionSession, error) {
	aes, err := maSDK.aSDK.DeserializeAnonymousEncryptionSession(serializedSession)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileAnonymousEncryptionSessionFromCommon(aes), nil
}

func (maSDK MobileAnonymousSDK) RetrieveAnonymousEncryptionSessionWithSymEncKeyPassword(retrieveJWT string, sessionId string, symEncKeyId string, symEncKeyPassword string) (*MobileAnonymousEncryptionSession, error) {
	aes, err := maSDK.aSDK.RetrieveEncryptionSessionWithSymEncKeyPassword(retrieveJWT, sessionId, symEncKeyId, symEncKeyPassword)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileAnonymousEncryptionSessionFromCommon(aes), nil
}

func (maSDK MobileAnonymousSDK) RetrieveAnonymousEncryptionSessionWithSymEncKeyRawKeys(retrieveJWT string, sessionId string, symEncKeyId string, rawSecret string, rawSymKey []byte) (*MobileAnonymousEncryptionSession, error) {
	aes, err := maSDK.aSDK.RetrieveEncryptionSessionWithSymEncKeyRawKeys(retrieveJWT, sessionId, symEncKeyId, rawSecret, rawSymKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileAnonymousEncryptionSessionFromCommon(aes), nil
}
