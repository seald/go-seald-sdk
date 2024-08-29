package sdk

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/exported_identity"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/utils"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

var (
	// ErrorCreateAccountNoTeam is returned when a JWT without the join team claim is used to create an account
	ErrorCreateAccountNoTeam = utils.NewSealdError("CREATE_ACCOUNT_NO_TEAM", "cannot create account with JWT that does not allow to join team")
	// ErrorPushJWTUnexpectedJoinTeam is returned when pushing JWT to join a team, account must already have one
	ErrorPushJWTUnexpectedJoinTeam = utils.NewSealdError("PUSH_JWT_UNEXPECTED_JOIN_TEAM", "cannot join team")
	// ErrorCurrentDeviceSigchainNotFound is returned when the sigchain for the current device could not be found
	ErrorCurrentDeviceSigchainNotFound = utils.NewSealdError("CURRENT_DEVICE_SIGCHAIN_NOT_FOUND", "cannot find the sigchain for the current device")
	// ErrorRevokeUnknownDevice is returned when the specified device could not be found
	ErrorRevokeUnknownDevice = utils.NewSealdError("REVOKE_UNKNOWN_DEVICE", "cannot find the specified device")
	// ErrorPreRenewalWrongCurrentKey is returned when the pre-renewal used for RenewKeys() does not include the current device private key
	ErrorPreRenewalWrongCurrentKey = utils.NewSealdError("PRE_RENEWAL_WRONG_CURRENT_KEY", "The pre-renewal you are trying to use is invalid, or is not associated to this account.")
)

// AccountInfo is returned when calling State.CreateAccount or State.GetCurrentAccountInfo, containing information about the local account.
type AccountInfo struct {
	// UserId is the ID of the current user for this SDK instance.
	UserId string
	// DeviceId is the ID of the current device for this SDK instance.
	DeviceId string
	// DeviceExpires is the date at which the current device keys expire. For continued operation, renew your device keys before this date. `nil` if it is not known locally: use State.UpdateCurrentDevice to retrieve it.
	DeviceExpires *time.Time
}

// PreGeneratedKeys allows to pass pre-generated asym keys for functions that need to generated keys.
type PreGeneratedKeys struct {
	EncryptionKey *asymkey.PrivateKey
	SigningKey    *asymkey.PrivateKey
}

// CreateAccountOptions is the options object for State.CreateAccount.
type CreateAccountOptions struct {
	// DisplayName is an optional name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user. Optional.
	DisplayName string
	// DeviceName is an optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
	DeviceName string
	// SignupJWT is the JWT to allow this SDK instance to create an account. Required.
	SignupJWT string
	// ExpireAfter is the duration during which this device key will be valid without renewal. Optional, defaults to 5 years. Maximum is 5 years.
	ExpireAfter time.Duration
	// PreGeneratedKeys allows you to pass pre-generated keys
	PreGeneratedKeys *PreGeneratedKeys
}

// CreateAccount creates a new Seald SDK account for this Seald SDK instance.
// This function can only be called if the current SDK instance does not have an account yet.
func (state *State) CreateAccount(options *CreateAccountOptions) (*AccountInfo, error) {
	state.locks.currentDeviceLock.Lock()
	defer state.locks.currentDeviceLock.Unlock()
	err := state.checkSdkState(false)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	state.logger.Debug().Msg("Creating a new account...")
	state.logger.Trace().Interface("opts", options).Msg("Create options")
	err = utils.CheckValidJWT(options.SignupJWT)
	if err != nil { // the regexp itself failed
		return nil, tracerr.Wrap(err)
	}

	var encryptionKeyPair *asymkey.PrivateKey
	var signingKeyPair *asymkey.PrivateKey
	if options.PreGeneratedKeys == nil {
		state.logger.Trace().Msg("CreateAccount: Generating keys...")
		encryptionKeyPair, signingKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("CreateAccount: Using pre-generated keys.")
		encryptionKeyPair = options.PreGeneratedKeys.EncryptionKey
		signingKeyPair = options.PreGeneratedKeys.SigningKey
	}

	encryptionPublicKey := encryptionKeyPair.Public()
	signingPublicKey := signingKeyPair.Public()

	user, err := state.apiClient.createAccount( // No autologin because, well, we are creating the account
		&createAccountRequest{
			EncryptionPublicKey: encryptionPublicKey.ToB64(),
			SigningPublicKey:    signingPublicKey.ToB64(),
			DisplayName:         options.DisplayName,
			DeviceName:          options.DeviceName,
			SignupJWT:           options.SignupJWT,
		},
	)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if user.AdditionalJWTStatus.Status != "success" { // should never happen
		return nil, tracerr.Errorf("JWT error code %s with detail %s", user.AdditionalJWTStatus.ErrorCode, user.AdditionalJWTStatus.Detail)
	}

	if user.AdditionalJWTStatus.TeamJoined.Id == "" { // should never happen
		return nil, tracerr.Wrap(ErrorCreateAccountNoTeam)
	}

	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_CREATE,
		OperationEncryptionKey: encryptionPublicKey,
		OperationSigningKey:    signingPublicKey,
		OperationDeviceId:      user.DeviceId,
		ExpireAfter:            options.ExpireAfter,
		SigningKey:             signingKeyPair,
		Position:               0,
		PreviousHash:           "",
		SignerDeviceId:         user.DeviceId,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	deviceExpires := time.Unix(block.Transaction.ExpireAt, 0)
	state.storage.currentDevice.set(currentDevice{
		UserId:                   user.User.Id,
		DeviceId:                 user.DeviceId,
		EncryptionPrivateKey:     encryptionKeyPair,
		SigningPrivateKey:        signingKeyPair,
		OldEncryptionPrivateKeys: []*asymkey.PrivateKey{},
		OldSigningPrivateKeys:    []*asymkey.PrivateKey{},
		DeviceExpires:            &deviceExpires,
	})

	err = state.login(user.Challenge)
	if err != nil {
		state.logger.Warn().Msg("Unable to log to newly created account.")
		state.storage.currentDevice.set(currentDevice{})
		return nil, tracerr.Wrap(err)
	}

	if user.AdditionalJWTStatus.ConnectorAdded.Value != "" {
		state.logger.Debug().Msg(fmt.Sprintf("Adding connector to local DB %s", user.AdditionalJWTStatus.ConnectorAdded.Value))
		err = state.storage.connectors.set(user.AdditionalJWTStatus.ConnectorAdded.toCommonConnector())
		if err != nil {
			state.storage.currentDevice.set(currentDevice{})
			return nil, tracerr.Wrap(err)
		}
	}

	_, err = handleLocked(state, autoLogin(state, state.apiClient.addSigChainTransaction), 3)(&addSigChainTransactionRequest{TransactionData: block, IntegrityCheck: true})
	if err != nil {
		state.storage.currentDevice.set(currentDevice{})
		return nil, tracerr.Wrap(err)
	}

	state.logger.Debug().Msg("Set current device...")
	state.storage.contacts.set(contact{
		Id:      user.User.Id,
		IsGroup: false,
		Devices: []*device{
			{
				Id:            user.DeviceId,
				SigningKey:    signingPublicKey,
				EncryptionKey: encryptionPublicKey,
			},
		},
		Sigchain: sigchain.Sigchain{Blocks: []*sigchain.Block{block}},
	})

	err = state.saveCurrentDevice()
	if err != nil {
		state.storage.currentDevice.set(currentDevice{})
		return nil, tracerr.Wrap(err)
	}

	err = state.saveContacts()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = state.saveConnectors()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	currentUser := state.storage.currentDevice.get()
	return &AccountInfo{
		UserId:        currentUser.UserId,
		DeviceId:      currentUser.DeviceId,
		DeviceExpires: &deviceExpires,
	}, nil
}

// GetCurrentAccountInfo returns information about the current account, or nil if there is none.
func (state *State) GetCurrentAccountInfo() *AccountInfo {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	currentDevice := state.storage.currentDevice.get()
	if currentDevice.UserId == "" || currentDevice.DeviceId == "" {
		return nil
	}
	return &AccountInfo{
		UserId:        currentDevice.UserId,
		DeviceId:      currentDevice.DeviceId,
		DeviceExpires: currentDevice.DeviceExpires,
	}
}

// PrepareRenewOptions is the options object for PrepareRenew.
type PrepareRenewOptions struct {
	// PreGeneratedKeys allows you to pass pre-generated keys
	PreGeneratedKeys *PreGeneratedKeys
}

// PrepareRenew prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew
func (state *State) PrepareRenew(options PrepareRenewOptions) ([]byte, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	currentDevice := state.storage.currentDevice.get()

	var newEncryptionKeyPair *asymkey.PrivateKey
	var newSigningKeyPair *asymkey.PrivateKey
	if options.PreGeneratedKeys == nil {
		state.logger.Trace().Msg("PrepareRenew: Generating keys...")
		newEncryptionKeyPair, newSigningKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("PrepareRenew: Using pre-generated keys.")
		newEncryptionKeyPair = options.PreGeneratedKeys.EncryptionKey
		newSigningKeyPair = options.PreGeneratedKeys.SigningKey
	}

	preparedRenew := exported_identity.ExportedIdentity{
		UserId:                      currentDevice.UserId,
		KeyId:                       currentDevice.DeviceId,
		EncryptionKey:               currentDevice.EncryptionPrivateKey,
		SigningKey:                  currentDevice.SigningPrivateKey,
		NewEncryptionKey:            newEncryptionKeyPair,
		NewSigningKey:               newSigningKeyPair,
		SerializedOldEncryptionKeys: currentDevice.OldEncryptionPrivateKeys,
		SerializedOldSigningKeys:    currentDevice.OldSigningPrivateKeys,
	}

	preparedRenewBuffer, err := bson.Marshal(preparedRenew)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return preparedRenewBuffer, nil
}

// RenewKeysOptions is the options object for State.RenewKeys.
type RenewKeysOptions struct {
	// ExpireAfter is the duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years. Maximum is 5 years.
	ExpireAfter time.Duration
	// PreGeneratedKeys allows you to pass pre-generated keys
	PreGeneratedKeys *PreGeneratedKeys
	// PreparedRenewal Optional. A prepared renewal created using PrepareRenew.
	PreparedRenewal []byte
}

// RenewKeys renews the keys of the current device, extending their validity.
// If the current device has expired, you will need to call RenewKeys before you are able to do anything else.
//
// In order to avoid any failure, we recommand to first use PrepareRenew, then save the prepared renewal on SSKS,
// and finally call `sdk.renewKey({ preparedRenewal })`.
//
// Warning: if the identity of the current device is stored externally, for example on SSKS,
// you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
func (state *State) RenewKeys(options RenewKeysOptions) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	currentDevice := state.storage.currentDevice.get()
	state.locks.contactsLockGroup.Lock(currentDevice.UserId)
	defer state.locks.contactsLockGroup.Unlock(currentDevice.UserId)

	var encryptionKeyPair *asymkey.PrivateKey
	var signingKeyPair *asymkey.PrivateKey
	if options.PreparedRenewal != nil {
		var preparedRenew exported_identity.ExportedIdentity
		err = bson.Unmarshal(options.PreparedRenewal, &preparedRenew)
		if err != nil {
			return tracerr.Wrap(err)
		}
		if !bytes.Equal(preparedRenew.EncryptionKey.Encode(), currentDevice.EncryptionPrivateKey.Encode()) || !bytes.Equal(preparedRenew.SigningKey.Encode(), currentDevice.SigningPrivateKey.Encode()) {
			return tracerr.Wrap(ErrorPreRenewalWrongCurrentKey)
		}
		encryptionKeyPair = preparedRenew.NewEncryptionKey
		signingKeyPair = preparedRenew.NewSigningKey
	} else if options.PreGeneratedKeys == nil {
		state.logger.Trace().Msg("RenewKeys: Generating keys...")
		encryptionKeyPair, signingKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("RenewKeys: Using pre-generated keys.")
		encryptionKeyPair = options.PreGeneratedKeys.EncryptionKey
		signingKeyPair = options.PreGeneratedKeys.SigningKey
	}

	encryptionPublicKey := encryptionKeyPair.Public()
	signingPublicKey := signingKeyPair.Public()

	self, err := state.getUpdatedContactUnlocked(currentDevice.UserId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
		OperationEncryptionKey: encryptionPublicKey,
		OperationSigningKey:    signingPublicKey,
		OperationDeviceId:      currentDevice.DeviceId,
		ExpireAfter:            options.ExpireAfter,
		SigningKey:             currentDevice.SigningPrivateKey,
		Position:               lastBlock.Transaction.Position + 1,
		PreviousHash:           lastBlock.Signature.Hash,
		SignerDeviceId:         currentDevice.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	_, err = handleLocked(state, autoLogin(state, state.apiClient.renewKeys), 3)(&renewKeysRequest{
		DeviceId:                      currentDevice.DeviceId,
		SerializedEncryptionPublicKey: encryptionPublicKey.ToB64(),
		SerializedSigningPublicKey:    signingPublicKey.ToB64(),
		Transaction:                   block,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	deviceExpires := time.Unix(block.Transaction.ExpireAt, 0)
	currentDevice.OldEncryptionPrivateKeys = append(currentDevice.OldEncryptionPrivateKeys, currentDevice.EncryptionPrivateKey)
	currentDevice.OldSigningPrivateKeys = append(currentDevice.OldSigningPrivateKeys, currentDevice.SigningPrivateKey)
	currentDevice.EncryptionPrivateKey = encryptionKeyPair
	currentDevice.SigningPrivateKey = signingKeyPair
	currentDevice.DeviceExpires = &deviceExpires
	state.storage.currentDevice.set(currentDevice)

	err = state.saveCurrentDevice()
	if err != nil {
		return tracerr.Wrap(err)
	}

	self.Sigchain.Blocks = append(self.Sigchain.Blocks, block)
	currentContactDevice := self.getDevice(currentDevice.DeviceId)
	currentContactDevice.SigningKey = signingPublicKey
	currentContactDevice.EncryptionKey = encryptionPublicKey
	state.storage.contacts.set(*self)

	err = state.saveContacts()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// CreateSubIdentityOptions is the options object for State.CreateSubIdentity.
type CreateSubIdentityOptions struct {
	// DeviceName is an optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
	DeviceName string
	// ExpireAfter is the duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years. Maximum is 5 years.
	ExpireAfter time.Duration
	// PreGeneratedKeys allows you to pass pre-generated keys
	PreGeneratedKeys *PreGeneratedKeys
}

// CreateSubIdentityResponse is the response object for State.CreateSubIdentity.
type CreateSubIdentityResponse struct {
	// DeviceId is the ID of the newly created device.
	DeviceId string
	// BackupKey is the identity export of the newly created sub-identity.
	BackupKey []byte
}

// CreateSubIdentity creates a new sub-identity, or new device, for the current user account.
// After creating this new device, you will probably want to call State.MassReencrypt,
// so that the newly created device will be able to decrypt EncryptionSession s previously created for this account.
func (state *State) CreateSubIdentity(options *CreateSubIdentityOptions) (*CreateSubIdentityResponse, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	currentDevice := state.storage.currentDevice.get()
	state.locks.contactsLockGroup.Lock(currentDevice.UserId)
	defer state.locks.contactsLockGroup.Unlock(currentDevice.UserId)

	var encryptionKeyPair *asymkey.PrivateKey
	var signingKeyPair *asymkey.PrivateKey
	if options.PreGeneratedKeys == nil {
		state.logger.Trace().Msg("CreateSubIdentity: Generating keys...")
		encryptionKeyPair, signingKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("CreateSubIdentity: Using pre-generated keys.")
		encryptionKeyPair = options.PreGeneratedKeys.EncryptionKey
		signingKeyPair = options.PreGeneratedKeys.SigningKey
	}

	encryptionPublicKey := encryptionKeyPair.Public()
	signingPublicKey := signingKeyPair.Public()

	self, err := state.getUpdatedContactUnlocked(currentDevice.UserId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	addDeviceResponse, err := autoLogin(state, state.apiClient.addDevice)(&addDeviceRequest{
		EncryptionPubKey: encryptionPublicKey,
		SigningPubKey:    signingPublicKey,
		DeviceName:       options.DeviceName,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_CREATE,
		OperationEncryptionKey: encryptionPublicKey,
		OperationSigningKey:    signingPublicKey,
		OperationDeviceId:      addDeviceResponse.DeviceId,
		ExpireAfter:            options.ExpireAfter,
		SigningKey:             currentDevice.SigningPrivateKey,
		Position:               lastBlock.Transaction.Position + 1,
		PreviousHash:           lastBlock.Signature.Hash,
		SignerDeviceId:         currentDevice.DeviceId,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	_, err = handleLocked(state, autoLogin(state, state.apiClient.validateDevice), 3)(&validateDeviceRequest{
		DeviceId:        addDeviceResponse.DeviceId,
		TransactionData: block,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	self.Sigchain.Blocks = append(self.Sigchain.Blocks, block)
	self.Devices = append(self.Devices, &device{
		Id:            addDeviceResponse.DeviceId,
		SigningKey:    signingPublicKey,
		EncryptionKey: encryptionPublicKey,
	})
	state.storage.contacts.set(*self)

	err = state.saveContacts()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	bkp := exported_identity.ExportedIdentity{UserId: currentDevice.UserId, KeyId: addDeviceResponse.DeviceId, EncryptionKey: encryptionKeyPair, SigningKey: signingKeyPair}

	b, e := bson.Marshal(bkp)
	if e != nil {
		return nil, tracerr.Wrap(err)
	}

	return &CreateSubIdentityResponse{
		DeviceId:  addDeviceResponse.DeviceId,
		BackupKey: b,
	}, nil
}

// RevokeSubIdentity revokes an existing sub-identity, or device, for the current user account.
// After revoking this device, you will not be able to use it anymore.
func (state *State) RevokeSubIdentity(deviceId string) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}

	currentDevice := state.storage.currentDevice.get()
	state.locks.contactsLockGroup.Lock(currentDevice.UserId)
	defer state.locks.contactsLockGroup.Unlock(currentDevice.UserId)

	self, err := state.getUpdatedContactUnlocked(currentDevice.UserId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

	deviceToRevoke := self.getDevice(deviceId)
	if deviceToRevoke == nil {
		return tracerr.Wrap(ErrorRevokeUnknownDevice)
	}

	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_REVOKE,
		OperationEncryptionKey: deviceToRevoke.EncryptionKey,
		OperationSigningKey:    deviceToRevoke.SigningKey,
		OperationDeviceId:      deviceId,
		SigningKey:             currentDevice.SigningPrivateKey,
		Position:               lastBlock.Transaction.Position + 1,
		PreviousHash:           lastBlock.Signature.Hash,
		SignerDeviceId:         currentDevice.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	_, err = handleLocked(state, autoLogin(state, state.apiClient.revokeDevice), 3)(&revokeDeviceRequest{
		DeviceId:        deviceId,
		TransactionData: block,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	self.Sigchain.Blocks = append(self.Sigchain.Blocks, block)
	var newDevices []*device
	for _, d := range self.Devices {
		if d.Id != deviceId {
			newDevices = append(newDevices, d)
		}
	}
	self.Devices = newDevices
	state.storage.contacts.set(*self)

	err = state.saveContacts()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

func (state *State) updateCurrentDeviceUnlocked() error {
	currentDevice := state.storage.currentDevice.get()
	// search to update contact
	contact, err := state.searchUnlocked(currentDevice.UserId, true, true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// parse sigchain from freshly retrieved updated contact
	checkResult, err := sigchain.CheckSigchainTransactions(contact.Sigchain, false)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// get current device from sigchain
	currentDeviceSigchain, found := checkResult.KnownKeys[currentDevice.DeviceId]
	if !found {
		return tracerr.Wrap(ErrorCurrentDeviceSigchainNotFound)
	}
	// update DeviceExpires from this
	deviceExpires := time.Unix(currentDeviceSigchain.ExpireAt, 0)
	currentDevice.DeviceExpires = &deviceExpires
	state.storage.currentDevice.set(currentDevice)

	// save current device
	err = state.saveCurrentDevice()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// UpdateCurrentDevice updates the locally known information about the current device.
// You should never have to call this manually, except if you getting `nil` in AccountInfo.DeviceExpires,
// which can happen if migrating from an older version of the SDK,
// or if the internal call to UpdateCurrentDevice failed when calling ImportIdentity.
func (state *State) UpdateCurrentDevice() error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()

	currentDevice := state.storage.currentDevice.get()
	state.locks.contactsLockGroup.Lock(currentDevice.UserId)
	defer state.locks.contactsLockGroup.Unlock(currentDevice.UserId)

	err := state.updateCurrentDeviceUnlocked()
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

func (state *State) importAndUpdateDevice(device currentDevice) error {

	state.storage.currentDevice.set(device)

	err := state.saveCurrentDevice()
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Lock contact as we're using the underlying searchUnlocked function that assumes all locks are already taken
	state.locks.contactsLockGroup.Lock(device.UserId)
	defer state.locks.contactsLockGroup.Unlock(device.UserId)
	err = state.updateCurrentDeviceUnlocked()
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

// ImportIdentity loads an identity export into the current SDK instance.
// This function can only be called if the current SDK instance does not have an account yet.
func (state *State) ImportIdentity(identity []byte) error {
	state.locks.currentDeviceLock.Lock()
	defer state.locks.currentDeviceLock.Unlock()
	err := state.checkSdkState(false)
	if err != nil {
		return tracerr.Wrap(err)
	}

	var bkp exported_identity.ExportedIdentity
	err = bson.Unmarshal(identity, &bkp)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if bkp.NewEncryptionKey != nil {
		state.logger.Trace().Msg("ImportIdentity: import prepared renewal")

		preparedDevice := currentDevice{
			UserId:                   bkp.UserId,
			DeviceId:                 bkp.KeyId,
			EncryptionPrivateKey:     bkp.NewEncryptionKey,
			SigningPrivateKey:        bkp.NewSigningKey,
			OldEncryptionPrivateKeys: append(bkp.SerializedOldEncryptionKeys, bkp.EncryptionKey),
			OldSigningPrivateKeys:    append(bkp.SerializedOldSigningKeys, bkp.SigningKey),
			// cannot set ExpireAfter here, counting on the UpdateCurrentDevice
		}
		err = state.importAndUpdateDevice(preparedDevice)

		// Inverted err logic:
		// If no error with the new device => everything is fine, simply return
		if err == nil {
			return nil
		}

		// A login error should fail with LOGIN_WRONG_SIGNING_PUBKEY_HASH if the pubKey hash has been sent.
		// Let's catch both to be future-proof.
		if !errors.Is(err, utils.APIError{Status: 406, Code: "LOGIN_WRONG_SIGNING_PUBKEY_HASH"}) && !errors.Is(err, utils.APIError{Status: 403, Code: "AUTHENTICATION_FAILED"}) {
			state.logger.Trace().Msg("ImportIdentity: unexpected error.")
			return tracerr.Wrap(err)
		}
		state.logger.Trace().Msg("ImportIdentity: authentication error. Import non-renew key.")
	}

	cd := currentDevice{
		UserId:                   bkp.UserId,
		DeviceId:                 bkp.KeyId,
		EncryptionPrivateKey:     bkp.EncryptionKey,
		SigningPrivateKey:        bkp.SigningKey,
		OldEncryptionPrivateKeys: bkp.SerializedOldEncryptionKeys,
		OldSigningPrivateKeys:    bkp.SerializedOldSigningKeys,
		// cannot set ExpireAfter here, counting on the UpdateCurrentDevice
	}
	err = state.importAndUpdateDevice(cd)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// ExportIdentity exports the current device as an identity export.
func (state *State) ExportIdentity() ([]byte, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	currentDevice := state.storage.currentDevice.get()

	bkp := exported_identity.ExportedIdentity{
		UserId:                      currentDevice.UserId,
		KeyId:                       currentDevice.DeviceId,
		EncryptionKey:               currentDevice.EncryptionPrivateKey,
		SigningKey:                  currentDevice.SigningPrivateKey,
		NewEncryptionKey:            nil,
		NewSigningKey:               nil,
		SerializedOldEncryptionKeys: currentDevice.OldEncryptionPrivateKeys,
		SerializedOldSigningKeys:    currentDevice.OldSigningPrivateKeys,
	}

	b, e := bson.Marshal(bkp)
	if e != nil {
		return nil, tracerr.Wrap(e)
	}

	return b, nil
}

// PushJWT pushes a given JWT to the Seald server, for example to add a connector to the current account.
func (state *State) PushJWT(jwt string) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckValidJWT(jwt)
	if err != nil {
		return tracerr.Wrap(err)
	}

	result, err := autoLogin(state, state.apiClient.pushJWT)(&pushJWTRequest{JWT: jwt})
	if err != nil {
		return tracerr.Wrap(err)
	}

	if result.TeamJoined != "" {
		return tracerr.Wrap(ErrorPushJWTUnexpectedJoinTeam)
	}

	if result.ConnectorAdded.Value != "" {
		state.logger.Debug().Str("type", string(result.ConnectorAdded.Type)).Str("value", result.ConnectorAdded.Value).Msg("JWT has added connector")
		c := result.ConnectorAdded.toCommonConnector()
		err = state.storage.connectors.set(c)
		if err != nil {
			return tracerr.Wrap(err)
		}
	}

	return nil
}

// Heartbeat just calls the Seald server, without doing anything.
// This may be used for example to verify that the current instance has a valid identity.
func (state *State) Heartbeat() error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	_, err = autoLogin(state, state.apiClient.heartbeat)(nil)
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}
