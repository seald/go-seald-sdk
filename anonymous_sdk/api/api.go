package api

import (
	"encoding/json"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/ztrue/tracerr"
	"strconv"
	"time"
)

type DeviceState string

const DEVICE_STATE_PENDING DeviceState = "U"
const DEVICE_STATE_VALIDATED DeviceState = "A"
const DEVICE_STATE_REVOKED DeviceState = "R"

type UserDevice struct {
	Id               string      `json:"id"`
	EncryptionPubKey string      `json:"encryption_pub_key"`
	SigningPubKey    string      `json:"signing_pub_key"`
	State            DeviceState `json:"state"`
	Created          time.Time   `json:"created"` // Go automagically marshalls / unmarshalls Times to RFC 3339
	Updated          time.Time   `json:"updated"`
}

type SigchainTransaction struct {
	Created     time.Time              `json:"created"`
	Hash        string                 `json:"hash"`
	Position    int                    `json:"position"`
	Transaction map[string]interface{} `json:"transaction"`
}

type Paginated struct {
	NbPage  int           `json:"nb_page"`
	Results []interface{} `json:"results"` // TODO: use generic starting with Go 1.18
}

type KeyFindResponse struct {
	NbPage  int          `json:"nb_page"`
	Results []UserDevice `json:"results"`
}

type SigchainFindResponse struct {
	NbPage  int                   `json:"nb_page"`
	Results []SigchainTransaction `json:"results"`
}

type MessageCreateResponse struct {
	Id string `json:"id"`
}

type TestGetAnonymousSDKUserResponse struct {
	BearduserId string `json:"bearduser_id"`
	DeviceId    string `json:"device_id"`
}

type EncryptedMessageKey struct {
	CreatedForKey     string `json:"created_for_key"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
	Token             string `json:"token"`
}

type ApiClient struct {
	api_helper.ApiClient
}

func (apiClient ApiClient) KeyFind(token string, userIds []string, page int) (*KeyFindResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"users_id": userIds,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/anonymous/key_find/?page="+strconv.Itoa(page),
		requestBody,
		[]api_helper.Header{{Name: "Authorization", Value: "Bearer " + token}},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result KeyFindResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

func (apiClient ApiClient) KeyFindAll(token string, userIds []string) ([]UserDevice, error) {
	var results []UserDevice
	page := 1
	hasNextPage := true
	for hasNextPage {
		resp, err := apiClient.KeyFind(token, userIds, page)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		results = append(results, resp.Results...)
		hasNextPage = page < resp.NbPage
		page++
	}
	return results, nil
}

func (apiClient ApiClient) SigchainFind(token string, userId string, page int) (*SigchainFindResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"user_id": userId,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/anonymous/sigchain_find/?page="+strconv.Itoa(page),
		requestBody,
		[]api_helper.Header{{Name: "Authorization", Value: "Bearer " + token}},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result SigchainFindResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

func (apiClient ApiClient) SigchainFindAll(token string, userId string) ([]SigchainTransaction, error) {
	var results []SigchainTransaction
	page := 1
	hasNextPage := true
	for hasNextPage {
		resp, err := apiClient.SigchainFind(token, userId, page)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		results = append(results, resp.Results...)
		hasNextPage = page < resp.NbPage
		page++
	}
	return results, nil
}

type TMRMessageKey struct {
	AuthFactorType  string `json:"auth_factor_type"`
	AuthFactorValue string `json:"auth_factor_value"`
	Token           string `json:"token"`
}
type MessageCreateRequest struct {
	EncryptedMessageKeys []*EncryptedMessageKey `json:"encrypted_message_keys"`
	TMRMessageKeys       []*TMRMessageKey       `json:"tmr_message_keys,omitempty"`
	Metadata             string                 `json:"metadata"`
}

func (apiClient ApiClient) MessageCreate(token string, request *MessageCreateRequest) (*MessageCreateResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/anonymous/message_create/",
		requestBody,
		[]api_helper.Header{{Name: "Authorization", Value: "Bearer " + token}},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result MessageCreateResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

func (apiClient ApiClient) TestGetAnonymousSDKUser(DebugApiSecret string) (*TestGetAnonymousSDKUserResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/devapi/get_anonymous_sdk_user",
		nil,
		[]api_helper.Header{{Name: "X-APIVIEW-SECRET", Value: DebugApiSecret}},
		200,
	)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result TestGetAnonymousSDKUserResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}
