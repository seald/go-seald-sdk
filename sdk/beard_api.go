package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/api_helper"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/common_models"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/utils"
	"golang.org/x/exp/maps"
	"strconv"
	"time"
)

type deviceState string

const (
	deviceStatePending   deviceState = "U"
	deviceStateValidated deviceState = "A"
	deviceStateRevoked   deviceState = "R"
)

var (
	ErrorApiAddKeyMultistatusRequired = utils.NewSealdError("API_ADD_KEY_MULTISTATUS_REQUIRED", "Must set MultiStatus to true")
	// ErrorNoTokenForYou is returned when trying to access a session for with the current user doesn't have a token
	ErrorNoTokenForYou = utils.NewSealdError("NO_TOKEN_FOR_YOU", "Can't decipher this session")
)

type beardApiClientInterface interface {
	isAuthenticated() bool
	clear()
	createAccount(*createAccountRequest) (*createAccountResponse, error)
	login(*loginRequest) (*loginResponse, error)
	getChallenge() (*getChallengeResponse, error)
	heartbeat(*emptyInterface) (*statusResponse, error)
	teamStatus(*emptyInterface) (*teamStatusResponse, error)
	addSigChainTransaction(request *addSigChainTransactionRequest) (*addSigChainTransactionResponse, error)
	search(request *searchRequest) (*searchResponse, error)
	createMessage(request *createMessageRequest) (*createMessageResponse, error)
	retrieveMessage(request *retrieveMessageRequest) (*retrieveMessageResponse, error)
	retrieveMultipleMessages(request *retrieveMultipleMessagesRequest) (*retrieveMultipleMessagesResponse, error)
	addKey(request *addKeysRequest) (*AddKeysMultiStatusResponse, error)
	addKeyProxy(request *addKeyProxyRequest) (*proxyMessageRetrieved, error)
	revokeRecipients(request *revokeRecipientsRequest) (*RevokeRecipientsResponse, error)
	renewKeys(request *renewKeysRequest) (*renewKeysResponse, error)
	retrieveSigchain(request *retrieveSigchainRequest) (*retrieveSigchainResponse, error)
	checkUsers(request *checkUsersRequest) (*checkUsersResponse, error)
	addDevice(request *addDeviceRequest) (*addDeviceResponse, error)
	validateDevice(request *validateDeviceRequest) (*validateDeviceResponse, error)
	revokeDevice(request *revokeDeviceRequest) (*revokeDeviceResponse, error)
	createGroup(request *createGroupRequest) (*createGroupResponse, error)
	initGroupSigchain(request *initGroupSigchainRequest) (*statusResponse, error)
	listGroupDevices(request *listGroupDevicesRequest) (*listGroupDevicesResponse, error)
	addGroupMembers(request *addGroupMembersRequest) (*statusResponse, error)
	listGroupMembers(request *listGroupMembersRequest) (*listGroupMembersResponse, error)
	removeGroupMembers(request *removeGroupMembersRequest) (*statusResponse, error)
	renewGroupKey(request *renewGroupKeyRequest) (*renewGroupKeyResponse, error)
	setGroupAdmins(request *setGroupAdminsRequest) (*statusResponse, error)
	verifyConnector(request *verifyConnectorRequest) (*verifyConnectorResponse, error)
	pushJWT(request *pushJWTRequest) (*pushJWTResponse, error)
	addConnector(request *addConnectorRequest) (*addConnectorResponse, error)
	validateConnector(request *validateConnectorRequest) (*validateConnectorResponse, error)
	removeConnector(removeConnectorRequest *removeConnectorRequest) (*removeConnectorResponse, error)
	listConnectors(*emptyInterface) (*listConnectorsResponse, error)
	retrieveConnector(retrieveConnectorRequest *retrieveConnectorRequest) (*retrieveConnectorResponse, error)
	missingMessageKeys(request *missingMessageKeyRequest) (*missingMessageKeyResponse, error)
	addMissingKeys(request *addMissingKeysRequest) (*addMissingKeysResponse, error)
	devicesMissingKeys(*emptyInterface) (*devicesMissingKeysApiResponse, error)
	addTmrAccesses(*addTmrAccessesRequest) (*AddTmrAccessesMultiStatusResponse, error)
	listTmrAccesses(*listTmrAccessesRequest) (*ListTmrAccessesResponse, error)
	retrieveTmrAccesses(*retrieveTmrAccessesRequest) (*retrieveTmrAccessesResponse, error)
	convertTmrAccesses(*convertTmrAccessesRequest) (*ConvertTmrAccessesResponse, error)
}

type emptyInterface struct{}

type statusResponse struct {
	Status string `json:"status"`
}

type encryptedMessageKey struct {
	CreatedForKey     string `json:"created_for_key"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
	Token             string `json:"token"`
}

type beardApiClient struct {
	api_helper.ApiClient
}

func (apiClient *beardApiClient) isAuthenticated() bool {
	return apiClient.SessionId != "" && apiClient.CSRFToken != ""
}

func (apiClient *beardApiClient) clear() {
	apiClient.SessionId = ""
	apiClient.CSRFToken = ""
}

type serializedUser struct {
	Id          string `json:"id"`
	DisplayName string `json:"display_name"`
}

type serializedDevice struct {
	DeviceName          string             `json:"device_name"`
	Id                  string             `json:"id"`
	EncryptionPublicKey *asymkey.PublicKey `json:"encryption_pub_key"`
	SigningPublicKey    *asymkey.PublicKey `json:"signing_pub_key"`
	State               deviceState        `json:"state"`
	Created             time.Time          `json:"created"`
	Updated             time.Time          `json:"updated"`
}

type createAccountRequest struct {
	EncryptionPublicKey string `json:"encryption_pub_key"`
	SigningPublicKey    string `json:"signing_pub_key"`
	DisplayName         string `json:"display_name"`
	DeviceName          string `json:"device_name"`
	SignupJWT           string `json:"additional_jwt"`
}

type createAccountResponse struct {
	Status              string                        `json:"status"`
	User                serializedUser                `json:"user"`
	DeviceId            string                        `json:"device_id"`
	DeviceData          serializedDevice              `json:"device_data"`
	Challenge           string                        `json:"challenge"`
	AdditionalJWTStatus serializedAdditionalJWTStatus `json:"additional_jwt_status"`
}

type serializedTeamJoined struct {
	Id string `json:"id"`
}

type apiConnectorData struct {
	Type    common_models.ConnectorType  `json:"type"` // 'EM' | 'AP'
	Value   string                       `json:"value"`
	Id      string                       `json:"id"`
	State   common_models.ConnectorState `json:"state"`
	SealdId string                       `json:"bearduser"` // rename the json key for beard API
}

func (connectorData *apiConnectorData) toCommonConnector() common_models.Connector {
	return common_models.Connector{
		SealdId: connectorData.SealdId,
		Type:    connectorData.Type,
		Value:   connectorData.Value,
		State:   connectorData.State,
		Id:      connectorData.Id,
	}
}

type serializedAdditionalJWTStatus struct {
	Status         string               `json:"status"`
	TeamJoined     serializedTeamJoined `json:"team_joined,omitempty"`
	ConnectorAdded apiConnectorData     `json:"connector_added,omitempty"`
	ErrorCode      string               `json:"error_code,omitempty"`
	Detail         string               `json:"detail,omitempty"`
}

func (apiClient *beardApiClient) createAccount(request *createAccountRequest) (*createAccountResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/user/",
		requestBody,
		[]api_helper.Header{},
		201,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result createAccountResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type loginRequest struct {
	UserId            string `json:"uid"`
	DeviceId          string `json:"device_id"`
	KeyId             string `json:"key_id"`
	SignedChallenge   string `json:"signed_challenge"`
	SigningPubkeyHash string `json:"signing_pubkey_hash,omitempty"`
}

type loginResponse struct {
	Status string `json:"status"`
}

func (apiClient *beardApiClient) login(request *loginRequest) (*loginResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/user/login/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result loginResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type teamStatusResponse struct {
	Status  string `json:"status"`
	Level   string `json:"level"`
	Active  bool   `json:"active"`
	Options []int  `json:"options"`
}

func (apiClient *beardApiClient) teamStatus(_ *emptyInterface) (*teamStatusResponse, error) { // this does not need any arg, but the autoLogin signature requires it
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/user/status/",
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result teamStatusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type getChallengeResponse struct {
	NextChallenge string `json:"next_chall"`
}

func (apiClient *beardApiClient) getChallenge() (*getChallengeResponse, error) {
	requestBody, err := json.Marshal(map[string]interface{}{})

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/user/create_challenge/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result getChallengeResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

func (apiClient *beardApiClient) heartbeat(_ *emptyInterface) (*statusResponse, error) { // this does not need any arg, but the autoLogin signature requires it
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/user/heartbeat/",
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result statusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type addSigChainTransactionRequest struct {
	TransactionData *sigchain.Block `json:"transaction_data"`
	IntegrityCheck  bool            `json:"integrity_check"`
}

type addSigChainTransactionResponse struct {
	Status string `json:"status"`
}

func (apiClient *beardApiClient) addSigChainTransaction(request *addSigChainTransactionRequest) (*addSigChainTransactionResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/sigchain/add_transaction/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result addSigChainTransactionResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type searchRequest struct {
	Type  common_models.ConnectorType `json:"type"`
	Value string                      `json:"value"`
}

type searchResponse struct {
	UserId           string `json:"user"`
	UserTeamDisabled bool   `json:"user_team_disabled"`
	SigchainLastHash string `json:"sigchain_last_hash"`
	// apiConnectorData TODO: allow connectors
	DisplayName string      `json:"display_name"`
	Status      string      `json:"status"`
	IsGroup     bool        `json:"is_group"`
	Keys        []apiDevice `json:"keys"`
}

type apiDevice struct {
	Id                  string             `json:"id"`
	EncryptionPublicKey *asymkey.PublicKey `json:"encryption_pub_key"`
	SigningPublicKey    *asymkey.PublicKey `json:"signing_pub_key"`
	State               deviceState        `json:"state"`
	Created             time.Time          `json:"created"`
	Updated             time.Time          `json:"updated"`
}

func (apiClient *beardApiClient) search(request *searchRequest) (*searchResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/user/search/",
		requestBody,
		[]api_helper.Header{},
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

type createMessageRequest struct {
	MetaData         string                      `json:"meta_data,omitempty"`
	AllowDownload    bool                        `json:"allow_download,omitempty"`
	NotForMe         bool                        `json:"not_for_me,omitempty"`
	MultiStatus      bool                        `json:"multistatus,omitempty"`
	Tokens           []encryptedMessageKey       `json:"tokens,omitempty"`
	SelfDestructDate *time.Time                  `json:"date,omitempty"`
	Rights           map[string]*RecipientRights `json:"rights"`
}

type createMessageResponse struct {
	Message string `json:"message"`
}

func (apiClient *beardApiClient) createMessage(request *createMessageRequest) (*createMessageResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/",
		requestBody,
		[]api_helper.Header{},
		201,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result createMessageResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type requestWithLookups[T any] interface {
	forceLookups() T
}

type retrieveMessageRequest struct {
	Id             string
	LookupProxyKey bool
	LookupGroupKey bool
}

type tokenRetrieved struct {
	KeyId             string `json:"key_id"`
	Token             string `json:"token"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
}

type proxyMessageRetrieved struct {
	Created        time.Time `json:"created"`
	CreatedById    string    `json:"created_by_id"`
	MessageId      string    `json:"message_id"`
	ProxyMessageId string    `json:"proxy_message_id"`
	Data           string    `json:"data"` // optional, only provided on message retrieve
	Revoked        bool      `json:"revoked"`
	RevokedDate    time.Time `json:"revoked_date"` // optional, only provided if revoked is true
	AclRead        bool      `json:"acl_read"`
	AclForward     bool      `json:"acl_forward"`
	AclRevoke      bool      `json:"acl_revoke"`
}

type proxyKeyInfo struct {
	ProxyMk                  *proxyMessageRetrieved `json:"proxy_mk"`
	EncryptedProxyMessageKey *tokenRetrieved        `json:"encrypted_proxy_message_key"`
}

type retrieveMessageResponse struct {
	OwnerId      string           `json:"owner"`
	MetaData     string           `json:"meta_data,omitempty"`
	Token        []tokenRetrieved `json:"token"`
	GroupId      string           `json:"group,omitempty"`
	ProxyKeyInfo *proxyKeyInfo    `json:"proxy_key_info,omitempty"`
}

func (apiClient *beardApiClient) retrieveMessage(request *retrieveMessageRequest) (*retrieveMessageResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/message/"+request.Id+"/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		[]byte{},
		[]api_helper.Header{},
		200,
	)

	if err != nil {
		var apiErr utils.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 && apiErr.Raw == "{\"model\":\"Message\"}" {
			return nil, tracerr.Wrap(ErrorNoTokenForYou)
		}
		return nil, tracerr.Wrap(err)
	}

	var result retrieveMessageResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type retrieveMultipleMessagesRequest struct {
	MessageIds     []string `json:"messages_ids"`
	LookupProxyKey bool     `json:"-"`
	LookupGroupKey bool     `json:"-"`
}

type retrieveMultipleMessagesMessage struct {
	EncryptedMessageKey *tokenRetrieved `json:"token,omitempty"`
	GroupId             string          `json:"group"`
	ProxyKeyInfo        *proxyKeyInfo   `json:"proxy_key_infos,omitempty"`
}

type retrieveMultipleMessagesResponse struct {
	Results map[string]*retrieveMultipleMessagesMessage `json:"results"`
}

func (apiClient *beardApiClient) retrieveMultipleMessages(request *retrieveMultipleMessagesRequest) (*retrieveMultipleMessagesResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/multiple_retrieve/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		requestBody,
		[]api_helper.Header{},
		200,
	)

	if err != nil {
		var apiErr utils.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 && apiErr.Raw == "{\"model\":\"Message\"}" {
			return nil, tracerr.Wrap(ErrorNoTokenForYou)
		}
		return nil, tracerr.Wrap(err)
	}

	var result retrieveMultipleMessagesResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type addKeysRequest struct {
	Id                   string                      `json:"-"`
	LookupProxyKey       bool                        `json:"-"`
	LookupGroupKey       bool                        `json:"-"`
	MultiStatus          bool                        `json:"multistatus"`
	EncryptedMessageKeys []encryptedMessageKey       `json:"tokens"`
	Rights               map[string]*RecipientRights `json:"rights"`
}

func (r *addKeysRequest) forceLookups() *addKeysRequest {
	return &addKeysRequest{
		Id:                   r.Id,
		LookupProxyKey:       true,
		LookupGroupKey:       true,
		MultiStatus:          r.MultiStatus,
		EncryptedMessageKeys: r.EncryptedMessageKeys,
		Rights:               r.Rights,
	}
}

// AddKeysMultiStatusResponse represents the server response when adding session keys for multiple recipients at once.
// It is a map between IDs of recipient's devices and results when trying to add the session key for said device.
type AddKeysMultiStatusResponse struct { // Used directly by the mobile wrapper
	Status map[string]AddKeysResponse `json:"status"`
}

// AddKeysResponse represents the result when trying to add a session key for one recipient's device.
type AddKeysResponse struct {
	StatusCode int         `json:"status"`
	Error      *BeardError `json:"error,omitempty"`
}

// BeardError represents an error returned by the server. It contains a specific Id and Code to determine the underlying reason.
type BeardError struct {
	Id   string `json:"id"`
	Code string `json:"code"`
}

func (apiClient *beardApiClient) addKey(request *addKeysRequest) (*AddKeysMultiStatusResponse, error) {
	if request.MultiStatus != true {
		return nil, tracerr.Wrap(ErrorApiAddKeyMultistatusRequired)
	}
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/"+request.Id+"/add_key/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		requestBody,
		[]api_helper.Header{},
		207,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result AddKeysMultiStatusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type addKeyProxyRequest struct {
	Id             string           `json:"-"`
	LookupProxyKey bool             `json:"-"`
	LookupGroupKey bool             `json:"-"`
	ProxyMessage   string           `json:"proxy_message"`
	Data           string           `json:"data"`
	Rights         *RecipientRights `json:"acl,omitempty"`
}

func (r *addKeyProxyRequest) forceLookups() *addKeyProxyRequest {
	return &addKeyProxyRequest{
		Id:             r.Id,
		LookupProxyKey: true,
		LookupGroupKey: true,
		ProxyMessage:   r.ProxyMessage,
		Data:           r.Data,
		Rights:         r.Rights,
	}
}

type addKeyProxyResponse struct {
	StatusCode string                 `json:"status"`
	Proxy      *proxyMessageRetrieved `json:"proxy_message_key"`
}

func (apiClient *beardApiClient) addKeyProxy(request *addKeyProxyRequest) (*proxyMessageRetrieved, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/"+request.Id+"/add_key_proxy/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result addKeyProxyResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return result.Proxy, nil
}

type revokeRecipientsRequest struct {
	MessageId      string   `json:"-"`
	LookupProxyKey bool     `json:"-"`
	LookupGroupKey bool     `json:"-"`
	UserIds        []string `json:"user_ids,omitempty"`
	ProxyMkIds     []string `json:"proxy_mk_ids,omitempty"`
	RevokeAll      string   `json:"revoke,omitempty"` // "all" | "others"
	// EntrustedRecipients []EntrustedRecipient `json:"entrusted_users,omitempty"`
}

func (r *revokeRecipientsRequest) forceLookups() *revokeRecipientsRequest {
	return &revokeRecipientsRequest{
		MessageId:      r.MessageId,
		LookupProxyKey: true,
		LookupGroupKey: true,
		UserIds:        r.UserIds,
		ProxyMkIds:     r.ProxyMkIds,
		RevokeAll:      r.RevokeAll,
	}
}

// RevokeRecipientsResponse represents the server response when trying to revoke recipients from a session.
// It contains UserIds, a map of the IDs of recipients you tried to revoke explicitly and the result for each one.
// It contains ProxyMkIds, a map of the IDs of ProxyMKs you tried to revoke explicitly and the result for each one.
// It also contains RevokeAll, which contains the results (in a similar format) for the recipients revoked when you try to revoke all the session's recipients.
type RevokeRecipientsResponse struct { // Used directly by the mobile wrapper
	UserIds    map[string]string `json:"user_ids"`
	ProxyMkIds map[string]string `json:"proxy_mk_ids"`
	RevokeAll  struct {
		UserIds    map[string]string `json:"user_ids"`
		ProxyMkIds map[string]string `json:"proxy_mk_ids"`
	} `json:"revoke_all"`
}

func (apiClient *beardApiClient) revokeRecipients(request *revokeRecipientsRequest) (*RevokeRecipientsResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/"+request.MessageId+"/revoke/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result RevokeRecipientsResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type renewKeysRequest struct {
	DeviceId                      string          `json:"-"`
	SerializedEncryptionPublicKey string          `json:"encryption_pub_key"`
	SerializedSigningPublicKey    string          `json:"signing_pub_key"`
	Transaction                   *sigchain.Block `json:"transaction"`
}

type renewKeysResponse struct {
	StatusCode string           `json:"status"`
	Device     serializedDevice `json:"device"`
}

func (apiClient *beardApiClient) renewKeys(request *renewKeysRequest) (*renewKeysResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/device/"+request.DeviceId+"/renew/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result renewKeysResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type retrieveSigchainRequest struct {
	UserId          string
	FromTransaction int
	PageSize        int
}

type wrappedBlock struct {
	Created     time.Time
	Hash        string
	Position    int
	Transaction *sigchain.Block
}

type retrieveSigchainApiResponse struct {
	Status  string
	NbPage  int
	Results []wrappedBlock
}
type retrieveSigchainResponse struct {
	Blocks []*sigchain.Block `json:"blocks"`
}

func (apiClient *beardApiClient) retrieveSigchain(request *retrieveSigchainRequest) (*retrieveSigchainResponse, error) {
	lastPage := 1000
	var transactions []*sigchain.Block

	pageSize := 100
	if request.PageSize != 0 {
		pageSize = request.PageSize
	}

	var fromTransaction string
	if request.FromTransaction != 0 {
		fromTransaction = fmt.Sprintf("&from=%d", request.FromTransaction)
	} else {
		fromTransaction = ""
	}
	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		responseBody, err := apiClient.MakeRequest(
			"GET",
			fmt.Sprintf("/api/sigchain/%s/?page=%d%s&page_size=%d", request.UserId, currentPage, fromTransaction, pageSize),
			[]byte{},
			[]api_helper.Header{},
			200,
		)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		var result retrieveSigchainApiResponse
		err = json.Unmarshal(responseBody, &result)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		lastPage = result.NbPage
		for _, wrappedBlock := range result.Results {
			transactions = append(transactions, wrappedBlock.Transaction)

		}
	}

	return &retrieveSigchainResponse{Blocks: transactions}, nil
}

type checkUsersRequest struct {
	Users []string `json:"users"`
}

type checkUsersResponse struct {
	Users map[string]string `json:"users"`
}

func (apiClient *beardApiClient) checkUsers(request *checkUsersRequest) (*checkUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/sigchain/check_users/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result checkUsersResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type addDeviceRequest struct {
	EncryptionPubKey *asymkey.PublicKey `json:"encryption_pub_key"`
	SigningPubKey    *asymkey.PublicKey `json:"signing_pub_key"`
	DeviceName       string             `json:"device_name"`
}

type addDeviceResponse struct {
	Status     string           `json:"status"`
	DeviceId   string           `json:"device_id"`
	DeviceData serializedDevice `json:"device_data"`
}

func (apiClient *beardApiClient) addDevice(request *addDeviceRequest) (*addDeviceResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/device/add_device/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result addDeviceResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type validateDeviceRequest struct {
	DeviceId        string          `json:"-"`
	TransactionData *sigchain.Block `json:"transaction_data"`
}

type validateDeviceResponse struct {
	Status     string           `json:"status"`
	DeviceData serializedDevice `json:"device_data"`
}

func (apiClient *beardApiClient) validateDevice(request *validateDeviceRequest) (*validateDeviceResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/device/%s/validate_pending_device/", request.DeviceId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result validateDeviceResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type revokeDeviceRequest struct {
	DeviceId        string          `json:"-"`
	TransactionData *sigchain.Block `json:"transaction_data"`
}

type revokeDeviceResponse struct {
	Status     string           `json:"status"`
	DeviceData serializedDevice `json:"device_data"`
}

func (apiClient *beardApiClient) revokeDevice(request *revokeDeviceRequest) (*revokeDeviceResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/device/%s/revoke_device/", request.DeviceId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result revokeDeviceResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type apiVerifyConnectorResponseConnector struct {
	Type    common_models.ConnectorType  `json:"type"` // 'EM' | 'AP'
	Value   string                       `json:"value"`
	Id      string                       `json:"id"`
	State   common_models.ConnectorState `json:"state"`
	SealdId string                       `json:"bearduser_id"` // rename the json key for beard API
}
type apiVerifyConnectorResponse struct {
	Results []apiVerifyConnectorResponseConnector `json:"results"`
}

type verifyConnectorResponse struct {
	Results []*common_models.Connector `json:"results"`
}

type verifyConnectorRequest struct {
	Connectors []*ConnectorTypeValue `json:"connectors"`
}

func (apiClient *beardApiClient) verifyConnector(connectorsToVerify *verifyConnectorRequest) (*verifyConnectorResponse, error) {
	requestBody, err := json.Marshal(connectorsToVerify)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/trustedconnector/verify/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var deserializedResult apiVerifyConnectorResponse
	err = json.Unmarshal(responseBody, &deserializedResult)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	result := &verifyConnectorResponse{}
	for _, c := range deserializedResult.Results {
		result.Results = append(result.Results, &common_models.Connector{Type: c.Type, Value: c.Value, SealdId: c.SealdId})
	}

	return result, nil
}

type addConnectorRequest struct {
	Type               common_models.ConnectorType `json:"type"`
	Value              string                      `json:"value"`
	PreValidationToken *utils.PreValidationToken   `json:"pre_validation,omitempty"`
}

type addConnectorResponse struct {
	Status        string            `json:"status"`
	PreValidated  bool              `json:"pre_validated"`
	ConnectorData *apiConnectorData `json:"connector_data"`
}

func (apiClient *beardApiClient) addConnector(addConnectorRequest *addConnectorRequest) (*addConnectorResponse, error) {
	requestBody, err := json.Marshal(addConnectorRequest)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/trustedconnector/add/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result addConnectorResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &result, nil
}

type validateConnectorRequest struct {
	ConnectorId string `json:"-"`
	Challenge   string `json:"data"`
}

type validateConnectorResponse struct {
	Status        string            `json:"status"`
	ConnectorData *apiConnectorData `json:"connector_data"`
}

func (apiClient *beardApiClient) validateConnector(addConnectorRequest *validateConnectorRequest) (*validateConnectorResponse, error) {
	requestBody, err := json.Marshal(addConnectorRequest)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/trustedconnector/%s/validate/", addConnectorRequest.ConnectorId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result validateConnectorResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type removeConnectorRequest struct {
	ConnectorId string
}

type removeConnectorResponse struct {
	Status        string            `json:"status"`
	ConnectorData *apiConnectorData `json:"connector_data"`
}

func (apiClient *beardApiClient) removeConnector(removeConnectorRequest *removeConnectorRequest) (*removeConnectorResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		fmt.Sprintf("/api/trustedconnector/%s/remove/", removeConnectorRequest.ConnectorId),
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result removeConnectorResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type listConnectorsResponse struct {
	Connectors []*apiConnectorData `json:"connectors"`
}

func (apiClient *beardApiClient) listConnectors(_ *emptyInterface) (*listConnectorsResponse, error) { // this does not need any arg, but the autoLogin signature requires it
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/trustedconnector/list/",
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result listConnectorsResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type retrieveConnectorRequest struct {
	ConnectorId string
}

type retrieveConnectorResponse struct {
	Status        string            `json:"status"`
	ConnectorData *apiConnectorData `json:"connector_data"`
}

func (apiClient *beardApiClient) retrieveConnector(retrieveConnectorRequest *retrieveConnectorRequest) (*retrieveConnectorResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		fmt.Sprintf("/api/trustedconnector/%s/", retrieveConnectorRequest.ConnectorId),
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result retrieveConnectorResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type pushJWTRequest struct {
	JWT string `json:"jwt"`
}

type pushJWTResponse struct {
	Status         string           `json:"status"`
	TeamJoined     string           `json:"team_joined,omitempty"`
	ConnectorAdded apiConnectorData `json:"connector_added,omitempty"`
}

func (apiClient *beardApiClient) pushJWT(request *pushJWTRequest) (*pushJWTResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/user/push_jwt/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result pushJWTResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type encryptedMessageKey2 struct { // 2, because there is another format for sending EMKs to the server in other cases...
	CreatedForKey     string `json:"created_for_key"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
	Key               string `json:"encrypted_message_key"`
}

type createGroupRequest struct {
	GroupName                     string                 `json:"group_name"`
	EncryptionPublicKey           string                 `json:"encrypt_pubkey"`
	SigningPublicKey              string                 `json:"signing_pubkey"`
	EncryptedEncryptionPrivateKey string                 `json:"encrypted_encryption_privkey"`
	EncryptedSigningPrivateKey    string                 `json:"encrypted_signing_privkey"`
	Members                       []string               `json:"members"`
	Admins                        []string               `json:"admins"`
	EncryptedMessageKeys          []encryptedMessageKey2 `json:"message_keys"`
}

type groupDeviceKey struct {
	Created                       time.Time `json:"created"`
	GeneratedByUserId             string    `json:"generated_by_user_id"`
	GroupId                       string    `json:"group_id"`
	MessageId                     string    `json:"message_id"`
	EncryptedEncryptionPrivateKey string    `json:"encrypted_encryption_privkey"`
	EncryptedSigningPrivateKey    string    `json:"encrypted_signing_privkey"`
	KeyExpirationDate             int64     `json:"key_expiration_date"`
}

type createGroupResponse struct {
	Group struct {
		Created            time.Time      `json:"created"`
		IsGroupInitialized bool           `json:"is_group_initialized"`
		BeardUser          serializedUser `json:"bearduser"`
		DeviceId           string         `json:"device_id"`
		PrimaryEmail       string         `json:"primary_email"`
	} `json:"group"`
	GroupDeviceKey groupDeviceKey `json:"groupdevicekey"`
}

func (apiClient *beardApiClient) createGroup(request *createGroupRequest) (*createGroupResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/group/",
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result createGroupResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type initGroupSigchainRequest struct {
	GroupId                string          `json:"-"`
	TransactionData        *sigchain.Block `json:"transaction_data"`
	TransactionDataMembers *sigchain.Block `json:"transaction_data_members"`
}

func (apiClient *beardApiClient) initGroupSigchain(request *initGroupSigchainRequest) (*statusResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/group/%s/init_sigchain/", request.GroupId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result statusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type listGroupDevicesRequest struct {
	GroupId      string
	AfterMessage string
}

type listGroupDevicesAPIResponse struct {
	Status  string
	NbPage  int
	Results []groupDeviceKey
}

type listGroupDevicesResponse struct {
	DeviceKeys []groupDeviceKey
}

func (apiClient *beardApiClient) listGroupDevices(request *listGroupDevicesRequest) (*listGroupDevicesResponse, error) {
	var afterMessage string
	if request.AfterMessage != "" {
		afterMessage = fmt.Sprintf("&after_message=%s", request.AfterMessage)
	} else {
		afterMessage = ""
	}

	lastPage := 1000
	var groupDevices []groupDeviceKey

	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		responseBody, err := apiClient.MakeRequest(
			"GET",
			fmt.Sprintf("/api/group/%s/groupdevices/?page=%d%s", request.GroupId, currentPage, afterMessage),
			[]byte{},
			[]api_helper.Header{},
			200,
		)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		var result listGroupDevicesAPIResponse
		err = json.Unmarshal(responseBody, &result)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		lastPage = result.NbPage
		groupDevices = append(groupDevices, result.Results...)
	}
	return &listGroupDevicesResponse{DeviceKeys: groupDevices}, nil
}

type listGroupMembersRequest struct {
	GroupId  string
	PageSize int
}

type apiGroupMember struct {
	DisplayName string `json:"display_name"`
	Id          string `json:"id"`
	IsAdmin     bool   `json:"is_admin"`
}

type listGroupMembersAPIResponse struct {
	Results []apiGroupMember `json:"results"`
	Status  string
	NbPage  int
}

type listGroupMembersResponse struct {
	GroupMember []apiGroupMember
}

func (apiClient *beardApiClient) listGroupMembers(request *listGroupMembersRequest) (*listGroupMembersResponse, error) {
	lastPage := 1000
	var groupMembers []apiGroupMember

	pageSize := 100
	if request.PageSize != 0 {
		pageSize = request.PageSize
	}

	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		responseBody, err := apiClient.MakeRequest(
			"GET",
			fmt.Sprintf("/api/group/%s/members/?page=%d&page_size=%d", request.GroupId, currentPage, pageSize),
			[]byte{},
			[]api_helper.Header{},
			200,
		)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		var result listGroupMembersAPIResponse
		err = json.Unmarshal(responseBody, &result)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		lastPage = result.NbPage
		groupMembers = append(groupMembers, result.Results...)
	}
	return &listGroupMembersResponse{GroupMember: groupMembers}, nil
}

type emkAndId struct {
	MessageId   string                 `json:"message_id"`
	MessageKeys []encryptedMessageKey2 `json:"message_keys"`
}

type addGroupMembersRequest struct {
	GroupId                        string                `json:"-"`
	EditedBeardUsersDeviceMessages map[string][]emkAndId `json:"edited_beardusers_device_messages"`
	TransactionDataMembers         *sigchain.Block       `json:"transaction_data_members"`
	AddedAdmins                    []string              `json:"added_admins"`
}

func (apiClient *beardApiClient) addGroupMembers(request *addGroupMembersRequest) (*statusResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/group/%s/members/", request.GroupId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result statusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type removeGroupMembersRequest struct {
	GroupId                string          `json:"-"`
	BeardUsersId           []string        `json:"beardusers_id"`
	TransactionDataMembers *sigchain.Block `json:"transaction_data_members"`
}

func (apiClient *beardApiClient) removeGroupMembers(request *removeGroupMembersRequest) (*statusResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"DELETE",
		fmt.Sprintf("/api/group/%s/members/", request.GroupId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result statusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type renewGroupKeyRequest struct {
	GroupId                    string                 `json:"-"`
	TransactionData            *sigchain.Block        `json:"transaction_data"`
	EncryptPubkey              string                 `json:"encrypt_pubkey"`
	SigningPubkey              string                 `json:"signing_pubkey"`
	EncryptedEncryptionPrivkey string                 `json:"encrypted_encryption_privkey"`
	EncryptedSigningPrivkey    string                 `json:"encrypted_signing_privkey"`
	MessageKeys                []encryptedMessageKey2 `json:"message_keys"`
}

type renewGroupKeyResponse struct {
	Group struct {
		Created   time.Time      `json:"created"`
		Bearduser serializedUser `json:"bearduser"`
		DeviceId  string         `json:"deviceId"`
	} `json:"group"`
	GroupDeviceKey groupDeviceKey `json:"groupdevicekey"`
}

func (apiClient *beardApiClient) renewGroupKey(request *renewGroupKeyRequest) (*renewGroupKeyResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/group/%s/renew/", request.GroupId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result renewGroupKeyResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type setGroupAdminsRequestElement struct {
	Id      string `json:"bearduser_id"`
	IsAdmin bool   `json:"is_admin"`
}

type setGroupAdminsRequest struct {
	GroupId string                         `json:"-"`
	Members []setGroupAdminsRequestElement `json:"members"`
}

func (apiClient *beardApiClient) setGroupAdmins(request *setGroupAdminsRequest) (*statusResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"PATCH",
		fmt.Sprintf("/api/group/%s/members/", request.GroupId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result statusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type missingMessageKeyRequest struct {
	DeviceId              string
	MaxResults            int
	ErrorIfNotProvisioned bool
}

type missingMessageKey struct {
	MessageId         string `json:"message_id"`
	Token             string `json:"token"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
}

type missingMessageKeysApiResponse struct {
	NbPage int                 `json:"nb_page"`
	Data   []missingMessageKey `json:"data"`
}

type missingMessageKeyResponse struct {
	MissingMessageKey []missingMessageKey
}

func (apiClient *beardApiClient) missingMessageKeys(request *missingMessageKeyRequest) (*missingMessageKeyResponse, error) {
	lastPage := 1000
	var missingMessageKey []missingMessageKey

	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		responseBody, err := apiClient.MakeRequest(
			"GET",
			fmt.Sprintf("/api/device/%s/missing_encrypted_message_keys/?page=%d&error_if_not_provisioned=%s", request.DeviceId, currentPage, strconv.FormatBool(request.ErrorIfNotProvisioned)),
			[]byte{},
			[]api_helper.Header{},
			200,
		)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		var result missingMessageKeysApiResponse
		err = json.Unmarshal(responseBody, &result)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		lastPage = result.NbPage
		missingMessageKey = append(missingMessageKey, result.Data...)

		if len(missingMessageKey) >= request.MaxResults {
			return &missingMessageKeyResponse{MissingMessageKey: missingMessageKey}, nil
		}
	}
	return &missingMessageKeyResponse{MissingMessageKey: missingMessageKey}, nil
}

type addMissingKeysRequest struct {
	DeviceId string                  `json:"-"`
	Keys     []reencryptedMessageKey `json:"keys"`
}

type addMissingKeysResponse struct {
	Success []string `json:"success"`
	Errors  []string `json:"errors"`
}

func (apiClient *beardApiClient) addMissingKeys(request *addMissingKeysRequest) (*addMissingKeysResponse, error) {
	requestBody, err := json.Marshal(request)

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	responseBody, err := apiClient.MakeRequest(
		"POST",
		fmt.Sprintf("/api/device/%s/add_encrypted_message_keys/", request.DeviceId),
		requestBody,
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result addMissingKeysResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type devicesMissingKeysApiResponse struct {
	DevicesMissingKeys map[string]any `json:"devices_missing_keys"`
}

func (apiClient *beardApiClient) devicesMissingKeys(_ *emptyInterface) (*devicesMissingKeysApiResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/device/devices_missing_keys/",
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var result devicesMissingKeysApiResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &result, nil
}

type tmrKey struct {
	Type  string `json:"auth_factor_type"`
	Value string `json:"auth_factor_value"`
	Token string `json:"token"`
}

type addTmrAccessesRequest struct {
	MessageId      string                      `json:"-"`
	LookupProxyKey bool                        `json:"-"`
	LookupGroupKey bool                        `json:"-"`
	TmrKeys        []*tmrKey                   `json:"tokens"`
	Rights         map[string]*RecipientRights `json:"rights"`
}

func (r *addTmrAccessesRequest) forceLookups() *addTmrAccessesRequest {
	return &addTmrAccessesRequest{
		MessageId:      r.MessageId,
		LookupProxyKey: true,
		LookupGroupKey: true,
		TmrKeys:        r.TmrKeys,
		Rights:         r.Rights,
	}
}

type AddedTmrAccessesError struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

type TmrAccesses struct {
	Id             string    `json:"id"`
	Created        time.Time `json:"created"`
	AuthFactorType string    `json:"auth_factor_type"`
	AclRead        bool      `json:"acl_read"`
	AclForward     bool      `json:"acl_forward"`
	AclRevoke      bool      `json:"acl_revoke"`
}

type AddTmrAccessesResponse struct {
	Status int                    `json:"status"`
	TmrKey *TmrAccesses           `json:"tmr_key"`
	Error  *AddedTmrAccessesError `json:"error"`
}

type AddTmrAccessesMultiStatusResponse struct {
	Status map[string]*AddTmrAccessesResponse `json:"status"`
}

func (apiClient *beardApiClient) addTmrAccesses(request *addTmrAccessesRequest) (*AddTmrAccessesMultiStatusResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/message/"+request.MessageId+"/add_key_tmr/"+
			"?lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		requestBody,
		[]api_helper.Header{},
		207,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result AddTmrAccessesMultiStatusResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type listTmrAccessesRequest struct {
	MessageId      string
	LookupProxyKey bool
	LookupGroupKey bool
	Page           int
}

func (r *listTmrAccessesRequest) forceLookups() *listTmrAccessesRequest {
	return &listTmrAccessesRequest{
		MessageId:      r.MessageId,
		LookupProxyKey: true,
		LookupGroupKey: true,
		Page:           r.Page,
	}
}

type ListTmrAccessesResponse struct {
	NbPage int            `json:"nb_page"`
	TmrMKs []*TmrAccesses `json:"tmr_mks"`
}

func (apiClient *beardApiClient) listTmrAccesses(request *listTmrAccessesRequest) (*ListTmrAccessesResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/message/"+request.MessageId+"/get_tmr_mks/"+
			fmt.Sprintf("?page=%d", request.Page)+
			"&lookup_proxy_key="+utils.Ternary(request.LookupProxyKey, "1", "0")+
			"&lookup_group_key="+utils.Ternary(request.LookupGroupKey, "1", "0"),
		[]byte{},
		[]api_helper.Header{},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result ListTmrAccessesResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}

type TmrAccessesConvertFilters struct {
	SessionId   string
	CreatedById string
	TmrAccessId string
}

type retrieveTmrAccessesRequest struct {
	TmrJWT             string
	TmrAccessesFilters *TmrAccessesConvertFilters
	Page               int
}

func (request *retrieveTmrAccessesRequest) getQueryParams() string {
	if request.TmrAccessesFilters == nil {
		return ""
	}
	return utils.Ternary(request.TmrAccessesFilters.TmrAccessId != "", "&id="+request.TmrAccessesFilters.TmrAccessId, "") +
		utils.Ternary(request.TmrAccessesFilters.CreatedById != "", "&created_by_id="+request.TmrAccessesFilters.CreatedById, "") +
		utils.Ternary(request.TmrAccessesFilters.SessionId != "", "&message_id="+request.TmrAccessesFilters.SessionId, "")
}

type retrievedTmrKey struct {
	Id          string `json:"id"`
	Data        string `json:"data"`
	MessageId   string `json:"message_id"`
	CreatedById string `json:"created_by_id"`
	AclRead     bool   `json:"acl_read"`
	AclForward  bool   `json:"acl_forward"`
	AclRevoke   bool   `json:"acl_revoke"`
}

type retrieveTmrAccessesResponse struct {
	NbPage          int                `json:"nb_page"`
	PaginationLimit int                `json:"pagination_limit"`
	TmrAccesses     []*retrievedTmrKey `json:"tmr_mks"`
}

func (apiClient *beardApiClient) retrieveTmrAccesses(request *retrieveTmrAccessesRequest) (*retrieveTmrAccessesResponse, error) {
	responseBody, err := apiClient.MakeRequest(
		"GET",
		"/api/tmr_keys/"+fmt.Sprintf("?page=%d", request.Page)+request.getQueryParams(),
		[]byte{},
		[]api_helper.Header{{Name: "AUTHORIZATION", Value: "Bearer " + request.TmrJWT}},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result retrieveTmrAccessesResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil

}

type tmrDeviceToken struct {
	CreatedForKeyId   string `json:"created_for_key_id"`
	CreatedForKeyHash string `json:"created_for_key_hash"`
	Token             string `json:"token"`
}

type tmrToken struct {
	TmrKeyId     string            `json:"tmr_key_id"`
	DeviceTokens []*tmrDeviceToken `json:"device_tokens"`
}

type convertTmrAccessesRequest struct {
	TmrJWT                string      `json:"-"`
	DeleteOnConvert       bool        `json:"delete_on_convert"`
	FullyConvertedTmrKeys []string    `json:"converted"`
	MessageTokens         []*tmrToken `json:"message_tokens"`
}

type ConvertedError struct {
	Status int `json:"status"`
	Error  struct {
		Code string `json:"code"`
		Id   string `json:"id"`
	} `json:"error"`
}

type ConvertTmrAccessesResponse struct {
	Status    string                     `json:"status"`
	Converted []string                   `json:"converted"`
	Errored   map[string]*ConvertedError `json:"errored"`
	Succeeded map[string][]string        `json:"succeeded"` // map values are array of string
}

func (alreadyKnown *ConvertTmrAccessesResponse) concatNextBatch(nextBatch *ConvertTmrAccessesResponse) *ConvertTmrAccessesResponse {
	alreadyKnown.Status = nextBatch.Status
	alreadyKnown.Converted = append(alreadyKnown.Converted, nextBatch.Converted...)
	if len(nextBatch.Errored) > 0 {
		maps.Copy(alreadyKnown.Errored, nextBatch.Errored)
	}
	for keyId, keyResult := range nextBatch.Succeeded {
		if len(alreadyKnown.Succeeded[keyId]) == 0 { // the value of the map is an array of length 0
			alreadyKnown.Succeeded[keyId] = keyResult
		} else {
			alreadyKnown.Succeeded[keyId] = append(alreadyKnown.Succeeded[keyId], keyResult...)
		}
	}
	return alreadyKnown
}

func (apiClient *beardApiClient) convertTmrAccesses(request *convertTmrAccessesRequest) (*ConvertTmrAccessesResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	responseBody, err := apiClient.MakeRequest(
		"POST",
		"/api/tmr_keys/convert/",
		requestBody,
		[]api_helper.Header{{Name: "AUTHORIZATION", Value: "Bearer " + request.TmrJWT}},
		200,
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result ConvertTmrAccessesResponse
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &result, nil
}
