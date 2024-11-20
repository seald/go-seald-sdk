package ssks_password

import (
	"encoding/json"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/ztrue/tracerr"
)

type apiClient struct {
	api_helper.ApiClient
}

type pushResponse struct {
	Id string `json:"id"`
}

func (apiClient *apiClient) push(appId string, userId string, encryptedB64Data string, secret string) (*pushResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"app_id":   appId,
		"user_id":  userId,
		"secret":   secret,
		"data_b64": encryptedB64Data,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/push/",
		requestBody,
		nil,
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

type searchResponse struct {
	EncryptedDataB64 string `json:"data_b64"`
}

func (apiClient *apiClient) search(appId string, userId string, secret string) (*searchResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"app_id":  appId,
		"user_id": userId,
		"secret":  secret,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/search/",
		requestBody,
		nil,
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result searchResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type apiClientInterface interface {
	push(appId string, userId string, encryptedB64Data string, secret string) (*pushResponse, error)
	search(appId string, userId string, secret string) (*searchResponse, error)
}
