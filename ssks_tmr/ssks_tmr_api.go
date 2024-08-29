package ssks_tmr

import (
	"encoding/json"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/api_helper"
	"go-seald-sdk/common_models"
)

type apiClient struct {
	api_helper.ApiClient
}

type challengeValidateResponse struct {
	NewSessionId string `json:"new_id"`
}

func (apiClient *apiClient) challengeValidate(challenge string, authFactor common_models.AuthFactor, sessionId string) (*challengeValidateResponse, error) {
	headers := []api_helper.Header{{Name: "X-SEALD-SESSION", Value: sessionId}}

	requestBody, err := json.Marshal(map[string]interface{}{
		"challenge":   challenge,
		"auth_factor": authFactor,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/tmr/front/challenge_validate/",
		requestBody,
		headers,
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result challengeValidateResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type pushResponse struct {
	Id string `json:"id"`
}

func (apiClient *apiClient) push(encryptedB64Data string, sessionId string) (*pushResponse, error) {
	headers := []api_helper.Header{{Name: "X-SEALD-SESSION", Value: sessionId}}

	requestBody, err := json.Marshal(map[string]interface{}{
		"data_b64": encryptedB64Data,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/tmr/front/push/",
		requestBody,
		headers,
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result pushResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type twoManRuleSearchResponse struct {
	EncryptedDataB64 string `json:"data_b64"`
	Authenticated    bool   `json:"authenticated"`
}

func (apiClient *apiClient) search(sessionId string) (*twoManRuleSearchResponse, error) {
	headers := []api_helper.Header{{Name: "X-SEALD-SESSION", Value: sessionId}}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/tmr/front/search/",
		nil,
		headers,
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result twoManRuleSearchResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type factorTokenResponse struct {
	FactorToken string `json:"factor_token"`
}

func (apiClient *apiClient) getFactorToken(authFactor *common_models.AuthFactor, sessionId string) (string, error) {
	headers := []api_helper.Header{{Name: "X-SEALD-SESSION", Value: sessionId}}

	requestBody, err := json.Marshal(map[string]interface{}{
		"auth_factor_type":  authFactor.Type,
		"auth_factor_value": authFactor.Value,
	})
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/tmr/front/get_factor_token/",
		requestBody,
		headers,
		200,
	)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	var result factorTokenResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return result.FactorToken, nil
}

type apiClientInterface interface {
	challengeValidate(challenge string, authFactor common_models.AuthFactor, sessionId string) (*challengeValidateResponse, error)
	push(encryptedB64Data string, sessionId string) (*pushResponse, error)
	search(sessionId string) (*twoManRuleSearchResponse, error)
	getFactorToken(authFactor *common_models.AuthFactor, sessionId string) (string, error)
}
