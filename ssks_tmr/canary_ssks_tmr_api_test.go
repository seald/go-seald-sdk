package ssks_tmr

import (
	"encoding/json"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/ztrue/tracerr"
)

type canarySsksTMRApiClient struct {
	Client    apiClientInterface
	ToExecute map[string]func() ([]byte, error)
	Counter   map[string]int
}

func newCanarySsksTMRApiClient(client apiClientInterface) *canarySsksTMRApiClient {
	return &canarySsksTMRApiClient{Client: client, ToExecute: make(map[string]func() ([]byte, error)), Counter: make(map[string]int)}
}

func executeSsksTMRApiCanary[T any](c canarySsksTMRApiClient, funcName string) (*T, error) {
	c.Counter[funcName] += 1
	if c.ToExecute[funcName] != nil {
		res, err := c.ToExecute[funcName]()
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if res != nil {
			var response T
			err = json.Unmarshal(res, &response)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			return &response, nil
		}
	}
	return nil, nil
}

func (c canarySsksTMRApiClient) challengeValidate(challenge string, authFactor common_models.AuthFactor, sessionId string) (*challengeValidateResponse, error) {
	res, err := executeSsksTMRApiCanary[challengeValidateResponse](c, "challengeValidate")
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.challengeValidate(challenge, authFactor, sessionId)
}

func (c canarySsksTMRApiClient) push(encryptedB64Data string, sessionId string) (*pushResponse, error) {
	// The canary cannot emulate a successful api call
	res, err := executeSsksTMRApiCanary[pushResponse](c, "push")
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.push(encryptedB64Data, sessionId)
}

func (c canarySsksTMRApiClient) search(sessionId string) (*twoManRuleSearchResponse, error) {
	res, err := executeSsksTMRApiCanary[twoManRuleSearchResponse](c, "search")
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.search(sessionId)
}

func (c canarySsksTMRApiClient) getFactorToken(authFactor *common_models.AuthFactor, sessionId string) (string, error) {
	res, err := executeSsksTMRApiCanary[string](c, "getFactorToken")
	if err != nil {
		return "", err
	}
	if res != nil {
		return "", nil
	}
	return c.Client.getFactorToken(authFactor, sessionId)
}
