// Package mobile_sdk is an internal wrapper, to help make the seald SDK compatible with mobile OSes. This is not meant to be used by end-users of the Seald SDK.
package mobile_sdk

import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"time"
)

const Version = utils.Version

type MobileSDK struct {
	sdk *sdk.State
}

// Need to redefine these structs, both because I need to change a few subtypes (time.duration into int in Milliseconds)
// and because gomobile apparently does not like the `type X = package.X` construct (the type itself is exposed correctly, but functions using it don't build)

type SdkInitializeOptions struct {
	ApiURL                    string
	AppId                     string
	KeySize                   int
	DatabasePath              string
	DatabaseEncryptionKey     []byte
	EncryptionSessionCacheTTL int64
	LogLevel                  int8
	LogNoColor                bool
	InstanceName              string
	Platform                  string
}

var (
	ErrorFileDbRequiresEncKeyMobile = utils.NewSealdError("MOBILE_FILE_DB_REQUIRES_ENC_KEY", "Using a file database requires encryption key : if you pass DatabasePath you must also pass DatabaseEncryptionKey - Mobile")
	ErrorFileDbInvalidKeyLength     = utils.NewSealdError("MOBILE_FILE_DB_INVALID_KEY_LENGTH", "DatabaseEncryptionKey must be a 64-byte buffer - Mobile")
)

func (mOpts SdkInitializeOptions) toGoOptions() (*sdk.InitializeOptions, error) {
	var storage sdk.Database
	if mOpts.DatabasePath == "" {
		storage = &sdk.MemoryStorage{}
	} else {
		if len(mOpts.DatabaseEncryptionKey) != 64 {
			return nil, utils.ToSerializableError(tracerr.Wrap(ErrorFileDbInvalidKeyLength))
		}
		if mOpts.DatabaseEncryptionKey == nil {
			return nil, utils.ToSerializableError(tracerr.Wrap(ErrorFileDbRequiresEncKeyMobile))
		}
		key, err := symmetric_key.Decode(mOpts.DatabaseEncryptionKey)
		if err != nil {
			return nil, utils.ToSerializableError(tracerr.Wrap(err))
		}

		storage = &sdk.FileStorage{
			EncryptionKey: key,
			DatabaseDir:   mOpts.DatabasePath,
		}
	}

	return &sdk.InitializeOptions{
		ApiURL:                    mOpts.ApiURL,
		AppId:                     mOpts.AppId,
		KeySize:                   mOpts.KeySize,
		EncryptionSessionCacheTTL: time.Duration(mOpts.EncryptionSessionCacheTTL) * time.Millisecond,
		LogLevel:                  zerolog.Level(mOpts.LogLevel),
		LogNoColor:                mOpts.LogNoColor,
		InstanceName:              mOpts.InstanceName,
		Platform:                  mOpts.Platform,
		Database:                  storage,
	}, nil
}

// SDK

func Initialize(options *SdkInitializeOptions) (*MobileSDK, error) {
	sdkOpts, err := options.toGoOptions()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	state, err := sdk.Initialize(sdkOpts)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	return &MobileSDK{sdk: state}, nil
}

func (mSDK MobileSDK) Close() error {
	err := mSDK.sdk.Close()
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

// Account

type PreGeneratedKeys struct {
	EncryptionKey string
	SigningKey    string
}

func (pgk *PreGeneratedKeys) toCommon() (*sdk.PreGeneratedKeys, error) {
	if pgk == nil {
		return nil, nil
	}
	encryptionKey, err := asymkey.PrivateKeyFromB64(pgk.EncryptionKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	signingKey, err := asymkey.PrivateKeyFromB64(pgk.SigningKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &sdk.PreGeneratedKeys{EncryptionKey: encryptionKey, SigningKey: signingKey}, nil
}

func PreGeneratedKeysFromPKCS1DER(encryptionKey []byte, signingKey []byte) (*PreGeneratedKeys, error) {
	decodedEncryptionKey, err := asymkey.PrivateKeyDecodePKCS1DER(encryptionKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	decodedSigningKey, err := asymkey.PrivateKeyDecodePKCS1DER(signingKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	pgk := PreGeneratedKeys{
		EncryptionKey: decodedEncryptionKey.ToB64(),
		SigningKey:    decodedSigningKey.ToB64(),
	}
	return &pgk, nil
}

type CreateAccountOptions struct {
	DisplayName      string
	DeviceName       string
	SignupJWT        string
	ExpireAfter      int64
	PreGeneratedKeys *PreGeneratedKeys
}

type AccountInfo struct {
	UserId        string
	DeviceId      string
	DeviceExpires int64
}

func accountInfoFromCommon(accountInfo *sdk.AccountInfo) *AccountInfo {
	var deviceExpires int64 = 0
	if accountInfo.DeviceExpires != nil {
		deviceExpires = accountInfo.DeviceExpires.Unix()
	}
	return &AccountInfo{
		UserId:        accountInfo.UserId,
		DeviceId:      accountInfo.DeviceId,
		DeviceExpires: deviceExpires,
	}
}

func (mSDK MobileSDK) CreateAccount(options *CreateAccountOptions) (*AccountInfo, error) {
	pgk, err := options.PreGeneratedKeys.toCommon()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	accountInfo, err := mSDK.sdk.CreateAccount(&sdk.CreateAccountOptions{
		DisplayName:      options.DisplayName,
		DeviceName:       options.DeviceName,
		SignupJWT:        options.SignupJWT,
		ExpireAfter:      time.Duration(options.ExpireAfter) * time.Millisecond,
		PreGeneratedKeys: pgk,
	})
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return accountInfoFromCommon(accountInfo), nil
}

func (mSDK MobileSDK) GetCurrentAccountInfo() *AccountInfo {
	accountInfo := mSDK.sdk.GetCurrentAccountInfo()
	if accountInfo == nil {
		return nil
	}
	return accountInfoFromCommon(accountInfo)
}

func (mSDK MobileSDK) UpdateCurrentDevice() error {
	err := mSDK.sdk.UpdateCurrentDevice()
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

func (mSDK MobileSDK) PrepareRenew(preGeneratedKeys *PreGeneratedKeys) ([]byte, error) {
	pgk, err := preGeneratedKeys.toCommon()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	preparedRenewal, err := mSDK.sdk.PrepareRenew(sdk.PrepareRenewOptions{
		PreGeneratedKeys: pgk,
	})
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return preparedRenewal, nil

}

type RenewKeysOptions struct {
	ExpireAfter      int64
	PreGeneratedKeys *PreGeneratedKeys
	PreparedRenewal  []byte
}

func (mSDK MobileSDK) RenewKeys(options *RenewKeysOptions) error {
	pgk, err := options.PreGeneratedKeys.toCommon()
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	err = mSDK.sdk.RenewKeys(sdk.RenewKeysOptions{
		ExpireAfter:      time.Duration(options.ExpireAfter) * time.Millisecond,
		PreGeneratedKeys: pgk,
		PreparedRenewal:  options.PreparedRenewal,
	})
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

type CreateSubIdentityOptions struct {
	DeviceName       string
	ExpireAfter      int64
	PreGeneratedKeys *PreGeneratedKeys
}

type CreateSubIdentityResponse struct {
	DeviceId  string
	BackupKey []byte
}

func (mSDK MobileSDK) CreateSubIdentity(options *CreateSubIdentityOptions) (*CreateSubIdentityResponse, error) { // Response is well transpiled
	pgk, err := options.PreGeneratedKeys.toCommon()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	res, err := mSDK.sdk.CreateSubIdentity(&sdk.CreateSubIdentityOptions{
		DeviceName:       options.DeviceName,
		ExpireAfter:      time.Duration(options.ExpireAfter) * time.Millisecond,
		PreGeneratedKeys: pgk,
	})
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &CreateSubIdentityResponse{DeviceId: res.DeviceId, BackupKey: res.BackupKey}, nil
}

func (mSDK MobileSDK) ImportIdentity(identity []byte) error {
	err := mSDK.sdk.ImportIdentity(identity)
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

func (mSDK MobileSDK) ExportIdentity() ([]byte, error) {
	res, err := mSDK.sdk.ExportIdentity()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSDK MobileSDK) PushJWT(jwt string) error {
	err := mSDK.sdk.PushJWT(jwt)
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

func (mSDK MobileSDK) Heartbeat() error {
	err := mSDK.sdk.Heartbeat()
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

// Groups

func (mSDK MobileSDK) CreateGroup(groupName string, members *StringArray, admins *StringArray, preGeneratedKeys *PreGeneratedKeys) (string, error) {
	pgk, err := preGeneratedKeys.toCommon()
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	res, err := mSDK.sdk.CreateGroup(groupName, members.getSlice(), admins.getSlice(), pgk)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
func (mSDK MobileSDK) AddGroupMembers(groupId string, membersToAdd *StringArray, adminsToSet *StringArray) error {
	err := mSDK.sdk.AddGroupMembers(groupId, membersToAdd.getSlice(), adminsToSet.getSlice())
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}
func (mSDK MobileSDK) RemoveGroupMembers(groupId string, membersToRemove *StringArray) error {
	err := mSDK.sdk.RemoveGroupMembers(groupId, membersToRemove.getSlice())
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}
func (mSDK MobileSDK) RenewGroupKey(groupId string, preGeneratedKeys *PreGeneratedKeys) error {
	pgk, err := preGeneratedKeys.toCommon()
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	err = mSDK.sdk.RenewGroupKey(groupId, pgk)
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}
func (mSDK MobileSDK) SetGroupAdmins(groupId string, addToAdmins *StringArray, removeFromAdmins *StringArray) error {
	err := mSDK.sdk.SetGroupAdmins(groupId, addToAdmins.getSlice(), removeFromAdmins.getSlice())
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}
func (mSDK MobileSDK) ShouldRenewGroup(groupId string) (bool, error) {
	res, err := mSDK.sdk.ShouldRenewGroup(groupId)
	if err != nil {
		return false, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (mSDK MobileSDK) CreateGroupTMRTemporaryKey(groupId string, authFactor *AuthFactor, isAdmin bool, rawOverEncryptionKey []byte) (*GroupTMRTemporaryKey, error) {
	res, err := mSDK.sdk.CreateGroupTMRTemporaryKey(groupId, authFactor.toCommon(), isAdmin, rawOverEncryptionKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	return groupTMRTemporaryKeyFromCommon(res), nil
}

func (mSDK MobileSDK) ListGroupTMRTemporaryKeys(groupId string, page int, all bool) (*ListedGroupTMRTemporaryKeys, error) {
	res, err := mSDK.sdk.ListGroupTMRTemporaryKeys(groupId, page, all)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	return groupListTMRTemporaryKeyFromCommon(res), nil
}

func (mSDK MobileSDK) DeleteGroupTMRTemporaryKey(groupId string, temporaryKeyId string) error {
	err := mSDK.sdk.DeleteGroupTMRTemporaryKey(groupId, temporaryKeyId)
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}

	return nil
}

func (mSDK MobileSDK) SearchGroupTMRTemporaryKeys(groupId string, opts *SearchGroupTMRTemporaryKeysOpts) (*ListedGroupTMRTemporaryKeys, error) {
	res, err := mSDK.sdk.SearchGroupTMRTemporaryKeys(groupId, opts.toCommon())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	return groupListTMRTemporaryKeyFromCommon(res), nil
}

func (mSDK MobileSDK) ConvertGroupTMRTemporaryKey(groupId string, temporaryKeyId string, tmrJWT string, rawOverEncryptionKey []byte, deleteOnConvert bool) error {
	err := mSDK.sdk.ConvertGroupTMRTemporaryKey(groupId, temporaryKeyId, tmrJWT, rawOverEncryptionKey, deleteOnConvert)
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}

	return nil
}

// EncryptionSession

func (mSDK MobileSDK) CreateEncryptionSession(recipients *RecipientsWithRightsArray, metadata string, useCache bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.CreateEncryptionSession(
		recipients.getSlice(),
		sdk.CreateEncryptionSessionOptions{UseCache: useCache, Metadata: metadata},
	)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}
func (mSDK MobileSDK) RetrieveEncryptionSession(messageId string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.RetrieveEncryptionSession(messageId, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}
func (mSDK MobileSDK) RetrieveEncryptionSessionFromMessage(message string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.RetrieveEncryptionSessionFromMessage(message, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}
func (mSDK MobileSDK) RetrieveEncryptionSessionFromFile(fileUri string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.RetrieveEncryptionSessionFromFile(fileUri, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}
func (mSDK MobileSDK) RetrieveEncryptionSessionFromBytes(fileBytes []byte, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.RetrieveEncryptionSessionFromBytes(fileBytes, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}

func (mSDK MobileSDK) RetrieveEncryptionSessionByTmr(tmrJWT string, sessionId string, overEncryptionKey []byte, tmrAccessesFilters *TmrAccessesRetrievalFilters, tryIfMultiple bool, useCache bool) (*MobileEncryptionSession, error) {
	es, err := mSDK.sdk.RetrieveEncryptionSessionByTmr(tmrJWT, sessionId, overEncryptionKey, tmrAccessesFilters.toCommon(), tryIfMultiple, useCache)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionFromCommon(es), nil
}

func (mSDK MobileSDK) RetrieveMultipleEncryptionSessions(sessionIds *StringArray, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*MobileEncryptionSessionArray, error) {
	array, err := mSDK.sdk.RetrieveMultipleEncryptionSessions(sessionIds.getSlice(), useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return mobileEncryptionSessionArrayFromCommon(array), nil
}

// Connectors

func (mSDK MobileSDK) GetSealdIdsFromConnectors(connectorTypeValues *ConnectorTypeValueArray) (*StringArray, error) {
	sealdIds, err := mSDK.sdk.GetSealdIdsFromConnectors(connectorTypeValues.getSlice())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return sliceToStringArray(sealdIds), nil
}
func (mSDK MobileSDK) GetConnectorsFromSealdId(sealdId string) (*ConnectorsArray, error) {
	connectorsArray, err := mSDK.sdk.GetConnectorsFromSealdId(sealdId)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	ca := &ConnectorsArray{}
	for _, el := range connectorsArray {
		ca = ca.Add(connectorFromCommon(&el))
	}
	return ca, nil
}

type PreValidationToken struct {
	DomainValidationKeyId string
	Nonce                 string
	Token                 string
}

func (t *PreValidationToken) toCommon() *utils.PreValidationToken {
	if t == nil {
		return nil
	}
	return &utils.PreValidationToken{DomainValidationKeyId: t.DomainValidationKeyId, Nonce: t.Nonce, Token: t.Token}
}

func (mSDK MobileSDK) AddConnector(value string, connectorType string, preValidationToken *PreValidationToken) (*Connector, error) {
	res, err := mSDK.sdk.AddConnector(
		value,
		common_models.ConnectorType(connectorType),
		preValidationToken.toCommon(),
	)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return connectorFromCommon(res), nil
}
func (mSDK MobileSDK) ValidateConnector(connectorId string, challenge string) (*Connector, error) {
	res, err := mSDK.sdk.ValidateConnector(connectorId, challenge)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return connectorFromCommon(res), nil
}
func (mSDK MobileSDK) RemoveConnector(connectorId string) (*Connector, error) {
	res, err := mSDK.sdk.RemoveConnector(connectorId)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return connectorFromCommon(res), nil
}
func (mSDK MobileSDK) ListConnectors() (*ConnectorsArray, error) {
	connectorsArray, err := mSDK.sdk.ListConnectors()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	ca := &ConnectorsArray{}
	for _, el := range connectorsArray {
		ca = ca.Add(connectorFromCommon(&el))
	}
	return ca, nil
}
func (mSDK MobileSDK) RetrieveConnector(connectorId string) (*Connector, error) {
	res, err := mSDK.sdk.RetrieveConnector(connectorId)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return connectorFromCommon(res), nil
}

// Reencrypt

type MassReencryptOptions struct {
	Retries                  int
	RetrieveBatchSize        int
	WaitBetweenRetries       int64
	WaitProvisioning         bool
	WaitProvisioningTime     int64
	WaitProvisioningTimeMax  int64
	WaitProvisioningTimeStep int64
	WaitProvisioningRetries  int
	ForceLocalAccountUpdate  bool
}

func (o MassReencryptOptions) toCommon() sdk.MassReencryptOptions {
	return sdk.MassReencryptOptions{
		Retries:                  o.Retries,
		RetrieveBatchSize:        o.RetrieveBatchSize,
		WaitBetweenRetries:       time.Duration(o.WaitBetweenRetries) * time.Millisecond,
		WaitProvisioning:         o.WaitProvisioning,
		WaitProvisioningTime:     time.Duration(o.WaitProvisioningTime) * time.Millisecond,
		WaitProvisioningTimeMax:  time.Duration(o.WaitProvisioningTimeMax) * time.Millisecond,
		WaitProvisioningTimeStep: time.Duration(o.WaitProvisioningTimeStep) * time.Millisecond,
		WaitProvisioningRetries:  o.WaitProvisioningRetries,
		ForceLocalAccountUpdate:  o.ForceLocalAccountUpdate,
	}
}

type MassReencryptResponse struct {
	Reencrypted int
	Failed      int
}

func (mSDK MobileSDK) MassReencrypt(deviceId string, options *MassReencryptOptions) (*MassReencryptResponse, error) {
	reencrypted, failed, err := mSDK.sdk.MassReencrypt(deviceId, options.toCommon())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &MassReencryptResponse{Reencrypted: reencrypted, Failed: failed}, nil
}

func (mSDK MobileSDK) DevicesMissingKeys(forceLocalAccountUpdate bool) (*DevicesMissingKeysArray, error) {
	response, err := mSDK.sdk.DevicesMissingKeys(forceLocalAccountUpdate)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return devicesMissingKeysArrayFromCommon(response), nil
}

// Contact

type GetSigchainResponse struct {
	Hash     string
	Position int
}

func (mSDK MobileSDK) GetSigchainHash(userId string, position int) (*GetSigchainResponse, error) {
	resp, err := mSDK.sdk.GetSigchainHash(userId, position)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &GetSigchainResponse{Hash: resp.Hash, Position: resp.Position}, nil
}

type CheckSigchainResponse struct {
	Found        bool
	Position     int
	LastPosition int
}

func (mSDK MobileSDK) CheckSigchainHash(userId string, sigchainHash string, position int) (*CheckSigchainResponse, error) {
	resp, err := mSDK.sdk.CheckSigchainHash(userId, sigchainHash, position)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &CheckSigchainResponse{Found: resp.Found, Position: resp.Position, LastPosition: resp.LastPosition}, nil
}

func (mSDK MobileSDK) ConvertTmrAccesses(tmrJWT string, overEncryptionKey []byte, conversionFilters *TmrAccessesConvertFilters, deleteOnConvert bool) (*ConvertTmrAccessesResponse, error) {
	resp, err := mSDK.sdk.ConvertTmrAccesses(tmrJWT, overEncryptionKey, conversionFilters.toCommon(), deleteOnConvert)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return convertTmrAccessesResponseFromCommon(resp), nil
}
