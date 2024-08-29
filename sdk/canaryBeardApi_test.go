package sdk

import (
	"encoding/json"
	"github.com/ztrue/tracerr"
)

func newCanaryBeardApiClient(client beardApiClientInterface) *canaryBeardApiClient {
	return &canaryBeardApiClient{Client: client, ToExecute: make(map[string]func(any) ([]byte, error)), Counter: make(map[string]int)}
}

func executeBeardApiCanary[U any](c canaryBeardApiClient, funcName string, request interface{}) (*U, error) {
	c.Counter[funcName] += 1
	if c.ToExecute[funcName] != nil {
		res, err := c.ToExecute[funcName](request)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if res != nil {
			var response U
			err = json.Unmarshal(res, &response)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			return &response, nil
		}
	}
	return nil, nil
}

type canaryBeardApiClient struct {
	Client    beardApiClientInterface
	ToExecute map[string]func(request any) ([]byte, error)
	Counter   map[string]int
}

func (c canaryBeardApiClient) renewGroupKey(request *renewGroupKeyRequest) (*renewGroupKeyResponse, error) {
	res, err := executeBeardApiCanary[renewGroupKeyResponse](c, "renewGroupKey", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.renewGroupKey(request)
}

func (c canaryBeardApiClient) removeGroupMembers(request *removeGroupMembersRequest) (*statusResponse, error) {
	res, err := executeBeardApiCanary[statusResponse](c, "removeGroupMembers", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.removeGroupMembers(request)
}

func (c canaryBeardApiClient) listGroupMembers(request *listGroupMembersRequest) (*listGroupMembersResponse, error) {
	res, err := executeBeardApiCanary[listGroupMembersResponse](c, "listGroupMembers", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.listGroupMembers(request)
}

func (c canaryBeardApiClient) addGroupMembers(request *addGroupMembersRequest) (*statusResponse, error) {
	res, err := executeBeardApiCanary[statusResponse](c, "addGroupMembers", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addGroupMembers(request)
}

func (c canaryBeardApiClient) createAccount(request *createAccountRequest) (*createAccountResponse, error) {
	res, err := executeBeardApiCanary[createAccountResponse](c, "createAccount", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.createAccount(request)
}

func (c canaryBeardApiClient) login(request *loginRequest) (*loginResponse, error) {
	res, err := executeBeardApiCanary[loginResponse](c, "login", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.login(request)
}

func (c canaryBeardApiClient) getChallenge() (*getChallengeResponse, error) {
	res, err := executeBeardApiCanary[getChallengeResponse](c, "getChallenge", nil)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.getChallenge()
}

func (c canaryBeardApiClient) heartbeat(_ *emptyInterface) (*statusResponse, error) {
	res, err := executeBeardApiCanary[statusResponse](c, "heartbeat", nil)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.heartbeat(nil)
}

func (c canaryBeardApiClient) teamStatus(_ *emptyInterface) (*teamStatusResponse, error) {
	res, err := executeBeardApiCanary[teamStatusResponse](c, "teamStatus", nil)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.teamStatus(nil)
}

func (c canaryBeardApiClient) addSigChainTransaction(request *addSigChainTransactionRequest) (*addSigChainTransactionResponse, error) {
	res, err := executeBeardApiCanary[addSigChainTransactionResponse](c, "addSigChainTransaction", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addSigChainTransaction(request)
}

func (c canaryBeardApiClient) search(request *searchRequest) (*searchResponse, error) {
	res, err := executeBeardApiCanary[searchResponse](c, "search", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.search(request)
}

func (c canaryBeardApiClient) createMessage(request *createMessageRequest) (*createMessageResponse, error) {
	res, err := executeBeardApiCanary[createMessageResponse](c, "createMessage", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.createMessage(request)
}

func (c canaryBeardApiClient) retrieveMessage(request *retrieveMessageRequest) (*retrieveMessageResponse, error) {
	res, err := executeBeardApiCanary[retrieveMessageResponse](c, "retrieveMessage", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.retrieveMessage(request)
}

func (c canaryBeardApiClient) retrieveMultipleMessages(request *retrieveMultipleMessagesRequest) (*retrieveMultipleMessagesResponse, error) {
	res, err := executeBeardApiCanary[retrieveMultipleMessagesResponse](c, "retrieveMultipleMessages", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.retrieveMultipleMessages(request)
}

func (c canaryBeardApiClient) addKey(request *addKeysRequest) (*AddKeysMultiStatusResponse, error) {
	res, err := executeBeardApiCanary[AddKeysMultiStatusResponse](c, "addKey", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addKey(request)
}

func (c canaryBeardApiClient) addKeyProxy(request *addKeyProxyRequest) (*proxyMessageRetrieved, error) {
	res, err := executeBeardApiCanary[proxyMessageRetrieved](c, "addKeyProxy", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addKeyProxy(request)
}

func (c canaryBeardApiClient) revokeRecipients(request *revokeRecipientsRequest) (*RevokeRecipientsResponse, error) {
	res, err := executeBeardApiCanary[RevokeRecipientsResponse](c, "revokeRecipients", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.revokeRecipients(request)
}

func (c canaryBeardApiClient) renewKeys(request *renewKeysRequest) (*renewKeysResponse, error) {
	res, err := executeBeardApiCanary[renewKeysResponse](c, "renewKeys", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.renewKeys(request)
}

func (c canaryBeardApiClient) retrieveSigchain(request *retrieveSigchainRequest) (*retrieveSigchainResponse, error) {
	res, err := executeBeardApiCanary[retrieveSigchainResponse](c, "retrieveSigchain", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.retrieveSigchain(request)
}

func (c canaryBeardApiClient) checkUsers(request *checkUsersRequest) (*checkUsersResponse, error) {
	res, err := executeBeardApiCanary[checkUsersResponse](c, "checkUsers", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.checkUsers(request)
}

func (c canaryBeardApiClient) addDevice(request *addDeviceRequest) (*addDeviceResponse, error) {
	res, err := executeBeardApiCanary[addDeviceResponse](c, "addDevice", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addDevice(request)
}

func (c canaryBeardApiClient) validateDevice(request *validateDeviceRequest) (*validateDeviceResponse, error) {
	res, err := executeBeardApiCanary[validateDeviceResponse](c, "validateDevice", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.validateDevice(request)
}

func (c canaryBeardApiClient) revokeDevice(request *revokeDeviceRequest) (*revokeDeviceResponse, error) {
	res, err := executeBeardApiCanary[revokeDeviceResponse](c, "revoke", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.revokeDevice(request)
}

func (c canaryBeardApiClient) verifyConnector(request *verifyConnectorRequest) (*verifyConnectorResponse, error) {
	res, err := executeBeardApiCanary[verifyConnectorResponse](c, "verifyConnector", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.verifyConnector(request)
}

func (c canaryBeardApiClient) pushJWT(request *pushJWTRequest) (*pushJWTResponse, error) {
	res, err := executeBeardApiCanary[pushJWTResponse](c, "pushJWT", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.pushJWT(request)
}

func (c canaryBeardApiClient) isAuthenticated() bool {
	return c.Client.isAuthenticated()
}

func (c canaryBeardApiClient) clear() {
	c.Client.clear()
}

func (c canaryBeardApiClient) createGroup(request *createGroupRequest) (*createGroupResponse, error) {
	res, err := executeBeardApiCanary[createGroupResponse](c, "createGroup", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.createGroup(request)
}

func (c canaryBeardApiClient) initGroupSigchain(request *initGroupSigchainRequest) (*statusResponse, error) {
	res, err := executeBeardApiCanary[statusResponse](c, "initGroupSigchain", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.initGroupSigchain(request)
}

func (c canaryBeardApiClient) listGroupDevices(request *listGroupDevicesRequest) (*listGroupDevicesResponse, error) {
	res, err := executeBeardApiCanary[listGroupDevicesResponse](c, "listGroupDevices", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.listGroupDevices(request)
}

func (c canaryBeardApiClient) setGroupAdmins(request *setGroupAdminsRequest) (*statusResponse, error) {
	res, err := executeBeardApiCanary[statusResponse](c, "setGroupAdmins", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.setGroupAdmins(request)
}

func (c canaryBeardApiClient) addConnector(request *addConnectorRequest) (*addConnectorResponse, error) {
	res, err := executeBeardApiCanary[addConnectorResponse](c, "addConnector", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addConnector(request)
}

func (c canaryBeardApiClient) validateConnector(request *validateConnectorRequest) (*validateConnectorResponse, error) {
	res, err := executeBeardApiCanary[validateConnectorResponse](c, "validateConnector", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.validateConnector(request)
}

func (c canaryBeardApiClient) removeConnector(request *removeConnectorRequest) (*removeConnectorResponse, error) {
	res, err := executeBeardApiCanary[removeConnectorResponse](c, "removeConnector", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.removeConnector(request)
}

func (c canaryBeardApiClient) listConnectors(_ *emptyInterface) (*listConnectorsResponse, error) {
	res, err := executeBeardApiCanary[listConnectorsResponse](c, "listConnectors", nil)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.listConnectors(nil)
}

func (c canaryBeardApiClient) retrieveConnector(request *retrieveConnectorRequest) (*retrieveConnectorResponse, error) {
	res, err := executeBeardApiCanary[retrieveConnectorResponse](c, "retrieveConnector", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.retrieveConnector(request)
}

func (c canaryBeardApiClient) missingMessageKeys(request *missingMessageKeyRequest) (*missingMessageKeyResponse, error) {
	res, err := executeBeardApiCanary[missingMessageKeyResponse](c, "missingMessageKeys", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.missingMessageKeys(request)
}

func (c canaryBeardApiClient) addMissingKeys(request *addMissingKeysRequest) (*addMissingKeysResponse, error) {
	res, err := executeBeardApiCanary[addMissingKeysResponse](c, "addMissingKeys", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addMissingKeys(request)
}

func (c canaryBeardApiClient) devicesMissingKeys(_ *emptyInterface) (*devicesMissingKeysApiResponse, error) {
	res, err := executeBeardApiCanary[devicesMissingKeysApiResponse](c, "devicesMissingKeys", nil)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.devicesMissingKeys(nil)
}

func (c canaryBeardApiClient) addTmrAccesses(request *addTmrAccessesRequest) (*AddTmrAccessesMultiStatusResponse, error) {
	res, err := executeBeardApiCanary[AddTmrAccessesMultiStatusResponse](c, "addTmrAccesses", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.addTmrAccesses(request)
}

func (c canaryBeardApiClient) listTmrAccesses(request *listTmrAccessesRequest) (*ListTmrAccessesResponse, error) {
	res, err := executeBeardApiCanary[ListTmrAccessesResponse](c, "listTmrAccesses", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.listTmrAccesses(request)
}

func (c canaryBeardApiClient) retrieveTmrAccesses(request *retrieveTmrAccessesRequest) (*retrieveTmrAccessesResponse, error) {
	res, err := executeBeardApiCanary[retrieveTmrAccessesResponse](c, "retrieveTmrAccesses", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.retrieveTmrAccesses(request)
}

func (c canaryBeardApiClient) convertTmrAccesses(request *convertTmrAccessesRequest) (*ConvertTmrAccessesResponse, error) {
	res, err := executeBeardApiCanary[ConvertTmrAccessesResponse](c, "convertTmrAccesses", request)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	return c.Client.convertTmrAccesses(request)
}
