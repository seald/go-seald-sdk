package mobile_sdk

import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/ssks_tmr"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

type MobileSSKSTMR struct {
	ssks *ssks_tmr.PluginTMR
}

type SsksTMRInitializeOptions struct {
	SsksURL      string
	AppId        string
	LogLevel     int8
	LogNoColor   bool
	InstanceName string
	Platform     string
}

func (mOpts SsksTMRInitializeOptions) toGoOptions() *ssks_tmr.PluginTMRInitializeOptions {
	return &ssks_tmr.PluginTMRInitializeOptions{
		SsksURL:      mOpts.SsksURL,
		AppId:        mOpts.AppId,
		LogLevel:     zerolog.Level(mOpts.LogLevel),
		LogNoColor:   mOpts.LogNoColor,
		InstanceName: mOpts.InstanceName,
		Platform:     mOpts.Platform,
	}
}

type AuthFactor struct {
	Type  string `json:"type"` // 'EM' | 'SMS' no enum concept in GO, we should use a setter to ensure the value
	Value string `json:"value"`
}

func (mAF *AuthFactor) toCommon() *common_models.AuthFactor {
	return &common_models.AuthFactor{Type: mAF.Type, Value: mAF.Value}
}

func NewSSKSTMRPlugin(options *SsksTMRInitializeOptions) *MobileSSKSTMR {
	mSSKS := ssks_tmr.NewPluginTMR(options.toGoOptions())
	client := MobileSSKSTMR{
		ssks: mSSKS,
	}
	return &client
}

type SaveIdentityResponse struct {
	SsksId                 string
	AuthenticatedSessionId string
}

func (mSSKS *MobileSSKSTMR) SaveIdentity(sessionId string, authFactor *AuthFactor, challenge string, rawTMRSymKey []byte, identity []byte) (*SaveIdentityResponse, error) {
	res, err := mSSKS.ssks.SaveIdentity(sessionId, authFactor.toCommon(), challenge, rawTMRSymKey, identity)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &SaveIdentityResponse{
		SsksId:                 res.SsksId,
		AuthenticatedSessionId: res.AuthenticatedSessionId,
	}, nil
}

type RetrieveIdentityResponse struct {
	Identity               []byte
	ShouldRenewKey         bool
	AuthenticatedSessionId string
}

func (mSSKS *MobileSSKSTMR) RetrieveIdentity(sessionId string, authFactor *AuthFactor, challenge string, rawTMRSymKey []byte) (*RetrieveIdentityResponse, error) {
	retrievedIdentity, err := mSSKS.ssks.RetrieveIdentity(sessionId, authFactor.toCommon(), challenge, rawTMRSymKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &RetrieveIdentityResponse{
		Identity:               retrievedIdentity.Identity,
		ShouldRenewKey:         retrievedIdentity.ShouldRenewKey,
		AuthenticatedSessionId: retrievedIdentity.AuthenticatedSessionId,
	}, nil
}

type GetFactorTokenResponse struct {
	Token                  string
	AuthenticatedSessionId string
}

func (mSSKS *MobileSSKSTMR) GetFactorToken(sessionId string, authFactor *AuthFactor, challenge string) (*GetFactorTokenResponse, error) {
	retrievedToken, err := mSSKS.ssks.GetFactorToken(sessionId, authFactor.toCommon(), challenge)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &GetFactorTokenResponse{
		Token:                  retrievedToken.Token,
		AuthenticatedSessionId: retrievedToken.AuthenticatedSessionId,
	}, nil
}
