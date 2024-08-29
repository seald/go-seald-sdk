package sdk

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/utils"
	"time"
)

var (
	// ErrorInvalidDeviceId is returned when the given device id is not a valid UUIDv4
	ErrorInvalidDeviceId = utils.NewSealdError("INVALID_DEVICE_ID", "given device id is invalid (must be UUIDv4)")
	// ErrorUnknownDevice is returned when a device with the given device id could not be found. You may want to retry with MassReencryptOptions.ForceLocalAccountUpdate set to true.
	ErrorUnknownDevice = utils.NewSealdError("UNKNOWN_DEVICE", "could not find device with given device id")
	// ErrorConvertTmrAccessCannotDecrypt is returned decryption of retrieved TMR access failed
	ErrorConvertTmrAccessCannotDecrypt = utils.NewSealdError("TMR_ACCESS_CANNOT_DECRYPT_ON_CONVERT", "Cannot decrypt found TMR accesses. Provided `overEncryptionKeyBytes` is probably incorrect.")
)

type reencryptedMessageKey struct {
	MessageId           string `json:"message_id"`
	CreatedForKeyHash   string `json:"created_for_key_hash"`
	EncryptedMessageKey string `json:"token"`
}

// MassReencryptOptions options for MassReencrypt function.
// You probably do not want to instantiate a MassReencryptOptions object yourself. Instead, use NewMassReencryptOptions
// then change the settings you want to change from defaults.
type MassReencryptOptions struct {
	Retries                  int           // Number of times to retry. Defaults to 3
	RetrieveBatchSize        int           // Default to 1000
	WaitBetweenRetries       time.Duration // Time to wait between retries. Defaults to 3 seconds
	WaitProvisioning         bool          // Whether to wait for provisioning (new behaviour) or not. Defaults to true
	WaitProvisioningTime     time.Duration // Time to wait if device is not provisioned on the server yet. The actual wait time will be increased on subsequent tries, by `waitProvisioningTimeStep`, up to `waitProvisioningTimeMax` Defaults to 5 seconds
	WaitProvisioningTimeMax  time.Duration // Maximum time to wait if device is not provisioned on the server yet. Defaults to 10 seconds
	WaitProvisioningTimeStep time.Duration // Amount to increase the time to wait if device is not provisioned on the server yet. Defaults to 1 second
	WaitProvisioningRetries  int           // Maximum number of tries to check if the device is provisioned yet. Defaults to 100
	ForceLocalAccountUpdate  bool          // Whether to update the local account before trying the reencryption. Defaults to false
}

// NewMassReencryptOptions instantiates a MassReencryptOptions object and sets the defaults.
func NewMassReencryptOptions() MassReencryptOptions {
	mr := MassReencryptOptions{}
	mr.Retries = 3
	mr.RetrieveBatchSize = 1000
	mr.WaitBetweenRetries = 3 * time.Second
	mr.WaitProvisioning = true
	mr.WaitProvisioningTime = 5 * time.Second
	mr.WaitProvisioningTimeMax = 10 * time.Second
	mr.WaitProvisioningTimeStep = 1 * time.Second
	mr.WaitProvisioningRetries = 100
	mr.ForceLocalAccountUpdate = false
	return mr
}

func (state *State) getBatchOfMissingKeys(deviceId string, options MassReencryptOptions) (*[]missingMessageKey, error) {
	req := &missingMessageKeyRequest{
		DeviceId:              deviceId,
		MaxResults:            options.RetrieveBatchSize,
		ErrorIfNotProvisioned: options.WaitProvisioning,
	}

	missingMessageKeys, err := autoLogin(state, state.apiClient.missingMessageKeys)(req)
	if err != nil {
		if errors.Is(err, utils.APIError{Status: 406, Code: "DEVICE_NOT_PROVISIONED_YET"}) && options.WaitProvisioning && options.WaitProvisioningRetries > 0 {
			time.Sleep(options.WaitProvisioningTime)
			nextIterationOptions := options
			nextIterationOptions.WaitProvisioningTime = utils.Min(options.WaitProvisioningTime+options.WaitProvisioningTimeStep, options.WaitProvisioningTimeMax)
			nextIterationOptions.WaitProvisioningRetries = options.WaitProvisioningRetries - 1
			return state.getBatchOfMissingKeys(deviceId, nextIterationOptions)
		} else {
			return nil, tracerr.Wrap(err)
		}
	}
	return &missingMessageKeys.MissingMessageKey, nil
}

func reencryptMissingKeyBatch(privateKeysHashMap map[string]*asymkey.PrivateKey, missingKeysBatch *[]missingMessageKey, reencryptForPublicKey *asymkey.PublicKey) ([]reencryptedMessageKey, int, error) {
	var failed = 0
	var reencrypted []reencryptedMessageKey
	for _, missingMsgKey := range *missingKeysBatch {
		b64Token, err := base64.StdEncoding.DecodeString(utils.S64toB64(missingMsgKey.Token))
		if err != nil {
			return reencrypted, failed, tracerr.Wrap(err)
		}
		var decrypted []byte
		// not using decryptMessageKey, because the types do not match exactly,
		// but also (and mainly) to avoid re-computing the private key hashes for each message key we have to reencrypt
		if missingMsgKey.CreatedForKeyHash != "" {
			privateKeyForToken := privateKeysHashMap[missingMsgKey.CreatedForKeyHash]
			if privateKeyForToken == nil {
				failed++
				continue
			} else {
				decrypted, err = privateKeyForToken.Decrypt(b64Token)
				if err != nil {
					failed++
					continue
				}
			}
		} else {
			for _, privateKeyToTry := range privateKeysHashMap {
				decrypted, err = privateKeyToTry.Decrypt(b64Token)
				if err == nil {
					break
				}
			}
			if len(decrypted) == 0 {
				failed++
				continue
			}
		}
		reencryptedToken, err := reencryptForPublicKey.Encrypt(decrypted)
		if err != nil {
			return nil, failed, tracerr.Wrap(err)
		}
		reencrypted = append(reencrypted, reencryptedMessageKey{
			MessageId:           missingMsgKey.MessageId,
			CreatedForKeyHash:   reencryptForPublicKey.GetHash(),
			EncryptedMessageKey: base64.StdEncoding.EncodeToString(reencryptedToken),
		})
	}

	return reencrypted, failed, nil
}

func (state *State) getAndReencryptBatch(deviceId string, privateKeysHashMap map[string]*asymkey.PrivateKey, reencryptForPublicKey *asymkey.PublicKey, options MassReencryptOptions) (int, int, error) {
	// Get a batch of missing keys
	missingMessageKeysBatch, err := state.getBatchOfMissingKeys(deviceId, options)
	if err != nil {
		return 0, 0, tracerr.Wrap(err)
	}
	if len(*missingMessageKeysBatch) == 0 {
		return 0, 0, nil
	}

	// Reencrypt batch of missing keys
	reencrypted, failed, err := reencryptMissingKeyBatch(privateKeysHashMap, missingMessageKeysBatch, reencryptForPublicKey)

	// Send reencrypted missing keys batch
	pageSize := 100 // TODO: use a global maxPageSize like goatee?
	for _, reencryptedPage := range utils.ChunkSlice[reencryptedMessageKey](reencrypted, pageSize) {
		_, err = autoLogin(state, state.apiClient.addMissingKeys)(&addMissingKeysRequest{
			DeviceId: deviceId,
			Keys:     reencryptedPage,
		})
		if err != nil {
			return 0, len(reencryptedPage), tracerr.Wrap(err)
		}
	}

	return len(reencrypted), failed, nil
}

func (state *State) iterMassReencryptBatches(deviceId string, privateKeysHashMap map[string]*asymkey.PrivateKey, reencryptForPublicKey *asymkey.PublicKey, options MassReencryptOptions) (int, int, error) {
	totalReencrypted := 0
	totalFailed := 0
	shouldWaitProvisioning := true
	for true {
		nextIterationOptions := options
		nextIterationOptions.WaitProvisioning = shouldWaitProvisioning                   // We wait for the first batch, then the provisioning is done
		nextIterationOptions.RetrieveBatchSize = options.RetrieveBatchSize + totalFailed // adding failed here to avoid the whole batch being filled with previously failed keys
		newlyReencrypted, newlyFailed, err := state.getAndReencryptBatch(deviceId, privateKeysHashMap, reencryptForPublicKey, nextIterationOptions)
		totalReencrypted += newlyReencrypted
		totalFailed += newlyFailed
		if err != nil {
			return totalReencrypted, totalFailed, tracerr.Wrap(err)
		}
		if newlyReencrypted+newlyFailed < nextIterationOptions.RetrieveBatchSize {
			break
		}
		shouldWaitProvisioning = false
	}

	return totalReencrypted, totalFailed, nil
}

func (state *State) massReencrypt(deviceId string, privateKeysHashMap map[string]*asymkey.PrivateKey, reencryptForPublicKey *asymkey.PublicKey, options MassReencryptOptions) (int, int, error) {
	reencrypted, failed, err := state.iterMassReencryptBatches(deviceId, privateKeysHashMap, reencryptForPublicKey, options)
	if err != nil {
		if options.Retries > 0 {
			time.Sleep(options.WaitBetweenRetries)
			nextIterationOptions := options
			nextIterationOptions.Retries = nextIterationOptions.Retries - 1
			newlyReencrypted, newlyFailed, err := state.massReencrypt(deviceId, privateKeysHashMap, reencryptForPublicKey, nextIterationOptions)
			reencrypted += newlyReencrypted
			failed += newlyFailed
			return reencrypted, failed, err // No error wrapping for a cleaner error stack (recursive function)
		} else {
			return reencrypted, failed, tracerr.Wrap(err)
		}
	}

	return reencrypted, failed, nil
}

// MassReencrypt retrieves, re-encrypts, and adds missing keys for a certain device.
func (state *State) MassReencrypt(deviceId string, options MassReencryptOptions) (reencrypted int, failed int, e error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return 0, 0, tracerr.Wrap(err)
	}
	if !utils.IsUUID(deviceId) {
		return 0, 0, tracerr.Wrap(ErrorInvalidDeviceId)
	}
	currentDevice := state.storage.currentDevice.get()

	// Getting the updated local user
	localUser, err := state.search(currentDevice.UserId, options.ForceLocalAccountUpdate)
	if err != nil {
		return 0, 0, tracerr.Wrap(err)
	}
	// Finding the device we want
	var reencryptForPublicKey *asymkey.PublicKey
	for _, d := range localUser.Devices {
		if d.Id == deviceId {
			reencryptForPublicKey = d.EncryptionKey
			break
		}
	}
	if reencryptForPublicKey == nil {
		return 0, 0, tracerr.Wrap(ErrorUnknownDevice)
	}

	// Pre-computing the hash map of private keys once for reencryptMissingKeyBatch
	privateKeysHashMap := make(map[string]*asymkey.PrivateKey)
	privateKeysHashMap[currentDevice.EncryptionPrivateKey.Public().GetHash()] = currentDevice.EncryptionPrivateKey
	for _, privateKey := range currentDevice.OldEncryptionPrivateKeys {
		privateKeysHashMap[privateKey.Public().GetHash()] = privateKey
	}

	return state.massReencrypt(deviceId, privateKeysHashMap, reencryptForPublicKey, options)
}

// DeviceMissingKeys represents a device of the current account which is missing some keys, and for which you probably want to call State.MassReencrypt.
type DeviceMissingKeys struct {
	// DeviceId is the ID of the device which is missing some keys.
	DeviceId string
}

// DevicesMissingKeys lists which of the devices of the current account are missing keys,
// so you can call MassReencrypt for them.
func (state *State) DevicesMissingKeys(forceLocalAccountUpdate bool) ([]DeviceMissingKeys, error) {
	currentDevice := state.storage.currentDevice.get()

	localUser, err := state.search(currentDevice.UserId, forceLocalAccountUpdate)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if len(localUser.Devices) <= 1 {
		return nil, nil
	}

	missing, err := state.apiClient.devicesMissingKeys(nil)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var result []DeviceMissingKeys
	for deviceId := range missing.DevicesMissingKeys {
		state.logger.Trace().Str("deviceId", deviceId).Msg("Device missing keys")
		result = append(result, DeviceMissingKeys{DeviceId: deviceId})
	}

	return result, nil
}

// ConvertTmrAccesses convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
// All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKeyBytes`.
func (state *State) ConvertTmrAccesses(tmrJWT string, overEncryptionKeyBytes []byte, convertAccessesFilters *TmrAccessesConvertFilters, deleteOnConvert bool) (*ConvertTmrAccessesResponse, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	currentDevice := state.storage.currentDevice.get()

	// Getting the updated local user
	localUser, err := state.search(currentDevice.UserId, true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Debug().Interface("convertAccessesFilters", convertAccessesFilters).Bool("deleteOnConvert", deleteOnConvert).Msg("ConvertTmrAccesses: Converting TMR accesses with options")

	var tmrKeyConverted = &ConvertTmrAccessesResponse{}
	tmrKeyConverted.Errored = make(map[string]*ConvertedError)
	tmrKeyConverted.Succeeded = make(map[string][]string)

	for true {
		currentPage := 1
		response, err := autoLogin(state, state.apiClient.retrieveTmrAccesses)(&retrieveTmrAccessesRequest{
			TmrJWT:             tmrJWT,
			TmrAccessesFilters: convertAccessesFilters,
			Page:               currentPage,
		})
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		lastPage := response.NbPage
		tmrKeysToConvert := response.TmrAccesses
		paginationLimit := response.PaginationLimit // we can push a total of `paginationLimit` tokens
		state.logger.Debug().Int("Length", len(tmrKeysToConvert)).Int("lastPage", response.NbPage).Int("paginationLimit", paginationLimit).Msg("ConvertTmrAccesses: Retrieved page of tmrMks.")

		if len(tmrKeysToConvert) == 0 {
			break
		}

		tmrKeysToC := paginationLimit / len(localUser.Devices)
		nTmrKeysToConvert := utils.Ternary(tmrKeysToC > 1, tmrKeysToC, 1)
		nPagesToConvert := nTmrKeysToConvert / len(tmrKeysToConvert) // how many pages we need (even if this is 0, we already have the first page)
		if nTmrKeysToConvert%len(tmrKeysToConvert) != 0 {
			nPagesToConvert = nPagesToConvert + 1
		}

		state.logger.Debug().Int("nTmrKeysToConvert", nTmrKeysToConvert).Int("nPagesToConvert", nPagesToConvert).Msg("ConvertTmrAccesses page params")

		// We already have a page, so `currentPage` starts at 2
		for currentPage = 2; currentPage <= nPagesToConvert && currentPage <= lastPage; currentPage++ {
			state.logger.Debug().Int("currentPage", currentPage).Msg("ConvertTmrAccesses: getting additional page")
			nextPage, err := autoLogin(state, state.apiClient.retrieveTmrAccesses)(&retrieveTmrAccessesRequest{
				TmrJWT:             tmrJWT,
				TmrAccessesFilters: convertAccessesFilters,
				Page:               currentPage,
			})
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			tmrKeysToConvert = append(tmrKeysToConvert, nextPage.TmrAccesses...)
		}
		currentPage-- // `currentPage` went over by one compared to the last page we actually retrieved, so we decrement by one

		if nTmrKeysToConvert < len(tmrKeysToConvert) { // if there are more TmrKeys than necessary
			state.logger.Trace().Msg(fmt.Sprintf("ConvertTmrAccesses: limiting length of keys to convert from %d to %d", len(tmrKeysToConvert), nTmrKeysToConvert))
			tmrKeysToConvert = tmrKeysToConvert[:nTmrKeysToConvert] // slice to limit to only those we are actually going to convert
			currentPage--                                           // and reduce `currentPage` by one, as the last page retrieved won't be entirely handled, so we have to reduce before checking if we have finished `lastPage`
		}
		nConverted := 0
		var messageTokens []*tmrToken
		var fullyConvertedTmrKeys []string

		overEncryptionKey, err := symmetric_key.Decode(overEncryptionKeyBytes)

		// iterate over tmrKeys to convert them
		for _, tmrKey := range tmrKeysToConvert {
			state.logger.Trace().Msg(fmt.Sprintf("ConvertTmrAccesses: converting key %s", tmrKey.Id))
			encryptedKey, err := base64.StdEncoding.DecodeString(tmrKey.Data)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			decrypted, err := overEncryptionKey.Decrypt(encryptedKey)
			if err != nil {
				if errors.Is(err, symmetric_key.ErrorDecryptMacMismatch) {
					return nil, tracerr.Wrap(ErrorConvertTmrAccessCannotDecrypt)
				}
				return nil, tracerr.Wrap(err)
			}

			var deviceTokens []*tmrDeviceToken
			for deviceIndex, userDevice := range localUser.Devices { // iterate over user devices
				token, err := userDevice.EncryptionKey.Encrypt(decrypted) // reencrypt the message key for the current device
				if err != nil {
					return nil, tracerr.Wrap(err)
				}
				deviceTok := &tmrDeviceToken{CreatedForKeyId: userDevice.Id, CreatedForKeyHash: userDevice.EncryptionKey.GetHash(), Token: base64.StdEncoding.EncodeToString(token)}
				deviceTokens = append(deviceTokens, deviceTok)
				nConverted++
				if deviceIndex == len(localUser.Devices)-1 {
					state.logger.Trace().Msg(fmt.Sprintf("ConvertTmrAccesses: fully converted key %s", tmrKey.Id))
					fullyConvertedTmrKeys = append(fullyConvertedTmrKeys, tmrKey.Id)
				}
				if nConverted >= paginationLimit { // if this newly converted key makes us reach the pagination limit (only applicable if we have more devices than the pagination limit)
					messTok := &tmrToken{TmrKeyId: tmrKey.Id, DeviceTokens: deviceTokens}
					messageTokens = append(messageTokens, messTok)

					state.logger.Trace().Msg("sendTmrAccessConvertedBatch: Sending batch of converted tokens...")
					batchResult, err := autoLogin(state, state.apiClient.convertTmrAccesses)(&convertTmrAccessesRequest{
						TmrJWT:                tmrJWT,
						DeleteOnConvert:       deleteOnConvert,
						FullyConvertedTmrKeys: fullyConvertedTmrKeys,
						MessageTokens:         messageTokens,
					})
					if err != nil {
						return nil, tracerr.Wrap(err)
					}
					state.logger.Trace().Msg("sendTmrAccessConvertedBatch: Sent batch successfully.")

					tmrKeyConverted.concatNextBatch(batchResult)
					deviceTokens = []*tmrDeviceToken{} // and reset everything, as this was all just sent
					messageTokens = []*tmrToken{}
					fullyConvertedTmrKeys = []string{}
					nConverted = 0
				}
			}
			if len(deviceTokens) > 0 {
				messageTokens = append(messageTokens, &tmrToken{TmrKeyId: tmrKey.Id, DeviceTokens: deviceTokens}) // if there are encrypted deviceTokens left, add them to the batch
			}
		}
		state.logger.Trace().Msg("ConvertTmrAccesses: finished converting keys batch")
		if len(messageTokens) > 0 { // if there is anything left, send it
			state.logger.Trace().Msg("sendTmrAccessConvertedBatch: Sending last batch of converted tokens...")
			batchResult, err := autoLogin(state, state.apiClient.convertTmrAccesses)(&convertTmrAccessesRequest{
				TmrJWT:                tmrJWT,
				DeleteOnConvert:       deleteOnConvert,
				FullyConvertedTmrKeys: fullyConvertedTmrKeys,
				MessageTokens:         messageTokens,
			})
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			state.logger.Trace().Msg("sendTmrAccessConvertedBatch: Sent batch successfully.")
			tmrKeyConverted.concatNextBatch(batchResult)
		}

		if currentPage >= lastPage {
			break // if `currentPage` is last, nothing left to do
		}
	}
	return tmrKeyConverted, nil
}
