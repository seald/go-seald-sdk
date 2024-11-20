package mobile_sdk

import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/ssks_password"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

type MobileSSKSPassword struct {
	ssks *ssks_password.PluginPassword
}

type SsksPasswordInitializeOptions struct {
	SsksURL      string
	AppId        string
	LogLevel     int8
	LogNoColor   bool
	InstanceName string
	Platform     string
}

func (mOpts SsksPasswordInitializeOptions) toGoOptions() *ssks_password.PluginPasswordInitializeOptions {
	return &ssks_password.PluginPasswordInitializeOptions{
		SsksURL:      mOpts.SsksURL,
		AppId:        mOpts.AppId,
		LogLevel:     zerolog.Level(mOpts.LogLevel),
		LogNoColor:   mOpts.LogNoColor,
		InstanceName: mOpts.InstanceName,
		Platform:     mOpts.Platform,
	}
}

func NewSSKSPasswordPlugin(options *SsksPasswordInitializeOptions) *MobileSSKSPassword {
	mSSKS := ssks_password.NewPluginPassword(options.toGoOptions())
	client := MobileSSKSPassword{
		ssks: mSSKS,
	}
	return &client
}

func (mSsksPassword *MobileSSKSPassword) SaveIdentityFromPassword(userId string, password string, identity []byte) (string, error) {
	res, err := mSsksPassword.ssks.SaveIdentityFromPassword(userId, password, identity)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSsksPassword *MobileSSKSPassword) SaveIdentityFromRawKeys(userId string, rawStorageKey string, rawEncryptionKey []byte, identity []byte) (string, error) {
	res, err := mSsksPassword.ssks.SaveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey, identity)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSsksPassword *MobileSSKSPassword) RetrieveIdentityFromPassword(userId string, password string) ([]byte, error) {
	res, err := mSsksPassword.ssks.RetrieveIdentityFromPassword(userId, password)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSsksPassword *MobileSSKSPassword) RetrieveIdentityFromRawKeys(userId string, rawStorageKey string, rawEncryptionKey []byte) ([]byte, error) {
	res, err := mSsksPassword.ssks.RetrieveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSsksPassword *MobileSSKSPassword) ChangeIdentityPassword(userId string, currentPassword string, newPassword string) (string, error) {
	res, err := mSsksPassword.ssks.ChangeIdentityPassword(userId, currentPassword, newPassword)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
