package test_utils

import (
	"encoding/json"
	"github.com/rs/zerolog"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/api_helper"
	"go-seald-sdk/common_models"
	"os"
	"time"
)

type SSKS2MRBackendApiClient struct {
	api_helper.ApiClient
}

func NewSSKS2MRBackendApiClient(keyStorageURL string, appId string, appKey string) *SSKS2MRBackendApiClient {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	ssksTMRbackendLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).With().Timestamp().Str("instance", "TMRBackend").Logger()
	client := SSKS2MRBackendApiClient{
		ApiClient: *api_helper.NewApiClient(keyStorageURL, []api_helper.Header{{Name: "X-SEALD-APPID", Value: appId}, {Name: "X-SEALD-APIKEY", Value: appKey}}, ssksTMRbackendLogger),
	}

	return &client
}

type ChallengeSendResponse struct {
	SessionId        string `json:"session_id"`
	MustAuthenticate bool   `json:"must_authenticate"`
}

func (apiClient *SSKS2MRBackendApiClient) ChallengeSend(userId string, authFactor *common_models.AuthFactor, createUser bool, forceAuth bool) (*ChallengeSendResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"user_id": userId,
		"auth_factor": map[string]interface{}{
			"type":  authFactor.Type,
			"value": authFactor.Value,
		},
		"create_user": createUser,
		"force_auth":  forceAuth,
		"template":    "<html><body>TEST CHALLENGE EMAIL</body></html>",
	})

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/tmr/back/challenge_send/",
		requestBody,
		nil,
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result ChallengeSendResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}
