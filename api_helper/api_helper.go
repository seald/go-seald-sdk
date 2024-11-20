package api_helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type ApiClient struct {
	client       *http.Client
	ApiURL       string
	SessionId    string
	CSRFToken    string
	ExtraHeaders []Header
	Logger       zerolog.Logger
}

type serverError struct {
	Code   string `json:"error_code"`
	Id     string `json:"error_id"`
	Detail string `json:"detail"`
}

type Header struct {
	Name  string
	Value string
}

func NewApiClient(apiUrl string, extraHeaders []Header, logger zerolog.Logger) *ApiClient {
	var url string
	if strings.HasSuffix(apiUrl, "/") {
		url = apiUrl[:len(apiUrl)-1]
	} else {
		url = apiUrl
	}

	return &ApiClient{
		client:       &http.Client{},
		ApiURL:       url,
		SessionId:    "",
		CSRFToken:    "",
		ExtraHeaders: extraHeaders,
		Logger:       logger,
	}
}

func (apiClient *ApiClient) MakeRequest(method string, url string, requestBody []byte, headers []Header, expectedStatusCode int) ([]byte, error) {
	if apiClient.client == nil {
		apiClient.client = &http.Client{}
	}

	var req *http.Request
	var err error
	if requestBody != nil {
		data := bytes.NewBuffer(requestBody)
		req, err = http.NewRequest(method, apiClient.ApiURL+url, data)
	} else {
		req, err = http.NewRequest(method, apiClient.ApiURL+url, nil) // cannot use a typed `nil`, otherwise it panics...
	}
	if err != nil {
		return nil, utils.APIError{Status: 0, Code: "REQUEST_ERROR", Details: err.Error(), Method: method, Url: req.URL.String()}
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	for i := 0; i < len(apiClient.ExtraHeaders); i++ {
		req.Header.Add(apiClient.ExtraHeaders[i].Name, apiClient.ExtraHeaders[i].Value)
	}

	for i := 0; i < len(headers); i++ {
		req.Header.Add(headers[i].Name, headers[i].Value)
	}

	if apiClient.SessionId != "" {
		req.Header.Add("X-HDR-Session-Id", apiClient.SessionId)
	}

	if apiClient.CSRFToken != "" {
		req.Header.Add("X-CSRFToken", apiClient.CSRFToken)
	}

	req.Header.Add("X-HDR-Method", "HDR")

	apiClient.Logger.Debug().Msg("API call: " + method + " " + req.URL.String())
	apiClient.Logger.Trace().Msg(fmt.Sprintf("Request body: %s", requestBody))
	resp, err := apiClient.client.Do(req)
	if err != nil {
		return nil, utils.APIError{Status: 0, Code: "NETWORK_ERROR", Details: err.Error(), Method: method, Url: req.URL.String()}
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalln(err)
		}
	}(resp.Body)
	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, utils.APIError{Status: 0, Code: "RESPONSE_READER_ERROR", Details: err.Error(), Method: method, Url: req.URL.String()}
	}

	sessionId := resp.Header.Get("X-HDR-Session-Id")

	if sessionId != "" {
		apiClient.SessionId = sessionId
	}

	CSRFToken := resp.Header.Get("X-HDR-CSRF-Token")

	if CSRFToken != "" {
		apiClient.Logger.Trace().Msg("New CSRF token set")
		apiClient.CSRFToken = CSRFToken
	}

	apiClient.Logger.Debug().Msg(fmt.Sprintf("Received response to %s %s, status code: %d", req.Method, req.URL.String(), resp.StatusCode))
	apiClient.Logger.Trace().Msg(fmt.Sprintf("Response body: %s", responseBody))
	if resp.StatusCode != expectedStatusCode {
		var responseServerError serverError
		err = json.Unmarshal(responseBody, &responseServerError)
		if err != nil || responseServerError.Code == "" {
			return nil, utils.APIError{Status: resp.StatusCode, Code: "UNKNOWN", Raw: string(responseBody), Method: method, Url: req.URL.String()}
		} else {
			return nil, utils.APIError{
				Status:  resp.StatusCode,
				Code:    responseServerError.Code,
				Id:      responseServerError.Id,
				Details: responseServerError.Detail,
				Url:     req.URL.String(),
				Method:  method,
				Raw:     string(responseBody),
			}
		}
	}

	return responseBody, nil
}
