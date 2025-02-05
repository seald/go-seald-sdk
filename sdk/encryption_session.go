package sdk

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/messages"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

var (
	// ErrorSessionCannotDecryptEncMK is returned when session cannot decrypt the retrieved message key.
	ErrorSessionCannotDecryptEncMK = utils.NewSealdError("SESSION_CANNOT_DECRYPT_ENC_MK", "cannot decrypt message key")
	// ErrorSessionUnexpectedGroupDeviceId means the server responded with a group device ID which does not match the device ID of the group in question.
	ErrorSessionUnexpectedGroupDeviceId = utils.NewSealdError("SESSION_UNEXPECTED_GROUP_DEVICE_ID", "retrieved device id does not match current group")
	// ErrorSessionCannotDecryptEncMKWithGroup is returned when the session cannot decrypt the retrieved message key with this group.
	ErrorSessionCannotDecryptEncMKWithGroup = utils.NewSealdError("SESSION_CANNOT_DECRYPT_ENC_MK_WITH_GROUP", "cannot decrypt message key with group")
	// ErrorSessionRetrievedUnexpectedNumEncMK means the server responded with an unexpected number of EncryptedMessageKeys when trying to retrieve the key for this session.
	ErrorSessionRetrievedUnexpectedNumEncMK = utils.NewSealdError("SESSION_RETRIEVE_UNEXPECTED_NUM_ENC_MK", "retrieved multiple or no encrypted message keys while expecting exactly one")
	// ErrorSessionNotRetrievedUnexpectedly means that the server unexpectedly did not return one of the sessions when trying to retrieve multiple sessions.
	ErrorSessionNotRetrievedUnexpectedly = utils.NewSealdError("SESSION_NOT_RETRIEVED_UNEXPECTEDLY", "the server unexpectedly did not return one of the sessions when trying to retrieve multiple sessions")
	// ErrorSessionUnexpectedDeviceId means the server responded with a device ID which does not match you current device.
	ErrorSessionUnexpectedDeviceId = utils.NewSealdError("SESSION_UNEXPECTED_DEVICE_ID", "retrieved device id does not match current device")
	// ErrorRetrieveEncryptionSessionInvalidMessageId is returned when trying to retrieve an encryption session with an invalid message id.
	ErrorRetrieveEncryptionSessionInvalidMessageId = utils.NewSealdError("RETRIEVE_ENCRYPTION_SESSION_INVALID_MESSAGE_ID", "invalid message id")
	// ErrorUnknownUserId is returned when a given recipient id is unknown.
	ErrorUnknownUserId = utils.NewSealdError("UNKNOWN_USER_ID", "recipients unknown user id")
	// ErrorAddKeySerializer is returned when failing to create EMKs for all recipients
	ErrorAddKeySerializer = utils.NewSealdError("ErrorAddKeySerializer", "Failed to create message for all recipients")
	// ErrorFailedCreated is returned when failing to create an EMK for a recipient
	ErrorFailedCreated = utils.NewSealdError("ErrorFailedCreated", "Failed to create message for a recipient")
	// ErrorRetrieveEncryptionSessionByTmrAccessNotFound is returned when no TMR access was found.
	ErrorRetrieveEncryptionSessionByTmrAccessNotFound = utils.NewSealdError("TMR_ACCESS_NOT_FOUND", "Could not find requested TMR access")
	// ErrorRetrieveEncryptionSessionByTmrAccessTooManyAccesses  is returned when expecting one TMR access, but multiple accesses are found.
	ErrorRetrieveEncryptionSessionByTmrAccessTooManyAccesses = utils.NewSealdError("MULTIPLE_TMR_ACCESS_FOUND", "Found multiple TMR accesses matching. Try filtering or use `tryIfMultiple`")
	// ErrorRetrieveEncryptionSessionByTmrAccessCannotDecrypt is returned when decryption of all retrieved TMR access failed
	ErrorRetrieveEncryptionSessionByTmrAccessCannotDecrypt = utils.NewSealdError("TMR_ACCESS_CANNOT_DECRYPT_ON_RETRIEVE", "Cannot decrypt found TMR accesses. Provided `overEncryptionKey` is probably incorrect.")
	// ErrorAddTMRAccessUnexpectedResponse is returned when an unexpected response was given by the server
	ErrorAddTMRAccessUnexpectedResponse = utils.NewSealdError("TMR_ACCESS_UNEXPECTED_RESPONSE", "The server did not return a response for the given authentication factor")
	// ErrorAddTMRAccessCreateError is returned when failing to create a TMR access
	ErrorAddTMRAccessCreateError = utils.NewSealdError("TMR_ACCESS_ERROR", "The server failed to create the TMR access")
)

// The EncryptionSession struct represents an encryption session, with which you can then encrypt / decrypt multiple messages.
type EncryptionSession struct {
	state *State
	// Id is the ID of this EncryptionSession.
	Id string
	// Key represents the SymKey of this EncryptionSession. For advanced use only.
	Key *symmetric_key.SymKey
	// RetrievalDetails stores details about how this session was retrieved: through a group, a proxy, or directly
	RetrievalDetails EncryptionSessionRetrievalDetails
}

type encryptMessageKeyOutput struct {
	Keys     []encryptedMessageKey
	NotForMe bool
}

func (state *State) encryptMessageKey(key *symmetric_key.SymKey, recipients []string) (*encryptMessageKeyOutput, error) {
	var tokens []encryptedMessageKey
	notForMe := true
	updatedContacts, _, err := state.getUpdatedContacts(recipients)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	currentDevice := state.storage.currentDevice.get()
	for _, c := range updatedContacts {
		if c.Id == currentDevice.UserId {
			notForMe = false
		}

		for _, device := range c.Devices {
			emk, err := device.EncryptionKey.Encrypt(key.Encode())
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			tokens = append(tokens, encryptedMessageKey{Token: base64.StdEncoding.EncodeToString(emk), CreatedForKey: device.Id, CreatedForKeyHash: device.EncryptionKey.GetHash()})
		}
	}
	return &encryptMessageKeyOutput{tokens, notForMe}, nil
}

type CreateEncryptionSessionOptions struct {
	UseCache bool
	Metadata string
}

// CreateEncryptionSession creates an encryption session, and returns the associated EncryptionSession instance,
// with which you can then encrypt / decrypt multiple messages.
// Warning : if you want to be able to retrieve the session later,
// you must put your own UserId in the recipients argument.
func (state *State) CreateEncryptionSession(recipientsWithRights []*RecipientWithRights, options CreateEncryptionSessionOptions) (*EncryptionSession, error) {
	recipientsIds, recipientsRightsMap := getRecipientIdsAndMap(recipientsWithRights)
	state.logger.Trace().Interface("recipients", recipientsIds).Msg("Calling CreateEncryptionSession")
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// TODO: metadata & stuff like that
	currentDevice := state.storage.currentDevice.get()
	key, err := symmetric_key.Generate()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	keys, err := state.encryptMessageKey(key, recipientsIds)
	if err != nil {
		var apiErr utils.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 && apiErr.Raw == "{\"model\":\"BeardUser\"}" {
			return nil, tracerr.Wrap(ErrorUnknownUserId)
		}
		return nil, tracerr.Wrap(err)
	}

	// TODO : max number of tokens in request
	response, err := autoLogin(state, state.apiClient.createMessage)(&createMessageRequest{
		Tokens:   keys.Keys,
		NotForMe: keys.NotForMe,
		Rights:   recipientsRightsMap,
		MetaData: options.Metadata,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if len(response.FailedCreatedForKey) > 0 {
		return nil, tracerr.Wrap(ErrorFailedCreated)
	}
	if response.AddKeySerializerErrors != nil && len(response.AddKeySerializerErrors.Tokens) > 0 {
		return nil, tracerr.Wrap(ErrorAddKeySerializer)
	}

	retrievalDetails := EncryptionSessionRetrievalDetails{Flow: EncryptionSessionRetrievalCreated}
	if utils.SliceIncludes(recipientsIds, currentDevice.UserId) && options.UseCache {
		state.storage.encryptionSessionsCache.Set(response.Message, *key, retrievalDetails)
		err = state.saveEncryptionSessions()
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	}

	res := EncryptionSession{Id: response.Message, Key: key, state: state, RetrievalDetails: retrievalDetails}
	state.logger.Trace().Interface("res", res).Msg("Response from CreateEncryptionSession")
	return &res, nil
}

func decryptMessageKey(encMK tokenRetrieved, device privateDevice) (*symmetric_key.SymKey, error) {
	encryptionKeys := device.getEncryptionKeys()

	encryptedKey, err := base64.StdEncoding.DecodeString(utils.S64toB64(encMK.Token))
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var decryptedKey []byte
	if encMK.CreatedForKeyHash != "" {
		// if there is an `encMK.CreatedForKeyHash` :
		// it's easy, just look for the key with matching hash
		for _, pk := range encryptionKeys {
			if encMK.CreatedForKeyHash == pk.Public().GetHash() {
				decryptedKey, err = pk.Decrypt(encryptedKey)
				if err != nil {
					return nil, tracerr.Wrap(err)
				}
				break
			}
		}
	} else {
		// if there isn't, we have to try decrypting with each key, until one works
		for _, pk := range encryptionKeys {
			decryptedKey, err = pk.Decrypt(encryptedKey)
			if err != nil { // TODO: test for correct error, for stricter check
				//if err.Error() != "The error we expect when it's a bad key" {
				//	return nil, tracerr.Wrap(err)
				//} else {
				continue
				//}
			}
			break
		}
	}
	if decryptedKey != nil {
		key, err := symmetric_key.Decode(decryptedKey)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		return &key, nil
	} else {
		return nil, tracerr.Wrap(ErrorSessionCannotDecryptEncMK)
	}
}

func (state *State) decryptMessageKeyWithGroup(groupId string, encMK tokenRetrieved, forceUpdate bool) (*symmetric_key.SymKey, error) {
	group := state.storage.groups.get(groupId)
	updated := false
	if group == nil || forceUpdate {
		// Get updated info about group
		_, err := state.getUpdatedContactUnlocked(groupId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		group = state.storage.groups.get(groupId)
		if group == nil {
			return nil, tracerr.Wrap(ErrorGroupsNotMember)
		}
		updated = true
	}

	if encMK.KeyId != group.DeviceId {
		return nil, tracerr.Wrap(ErrorSessionUnexpectedGroupDeviceId)
	}

	// try retrieving the encryption key with the known group
	key, err := decryptMessageKey(encMK, group)
	if err != nil && !errors.Is(err, ErrorSessionCannotDecryptEncMK) {
		return nil, tracerr.Wrap(err)
	}

	if key != nil { // if we have a key, return it
		return key, nil
	} else if !updated { // if we don't have it, and the group wasn't just updated, retry with forceUpdate=true
		return state.decryptMessageKeyWithGroup(groupId, encMK, true)
	} else {
		return nil, tracerr.Wrap(ErrorSessionCannotDecryptEncMKWithGroup)
	}
}

// RetrieveEncryptionSessionFromFile retrieves an encryption session from an encrypted filepath, and returns the associated
// EncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (state *State) RetrieveEncryptionSessionFromFile(encryptedFilePath string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*EncryptionSession, error) {
	mid, err := ParseSessionIdFromFile(encryptedFilePath)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	es, err := state.RetrieveEncryptionSession(mid, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return es, nil
}

// RetrieveEncryptionSessionFromBytes retrieves an encryption session from a file []byte, and returns the associated
// EncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (state *State) RetrieveEncryptionSessionFromBytes(fileBytes []byte, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*EncryptionSession, error) {
	mid, err := ParseSessionIdFromBytes(fileBytes)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	es, err := state.RetrieveEncryptionSession(mid, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return es, nil
}

// RetrieveEncryptionSessionFromMessage retrieves an encryption session from a seald message, and returns the associated
// EncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (state *State) RetrieveEncryptionSessionFromMessage(message string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*EncryptionSession, error) {
	mid, err := ParseSessionIdFromMessage(message)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	es, err := state.RetrieveEncryptionSession(mid, useCache, lookupProxyKey, lookupGroupKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return es, nil
}

func (state *State) retrieveKeyByTmr(tmrJWT string, overEncryptionKey *symmetric_key.SymKey, filters *TmrAccessesConvertFilters, tryIfMultiple bool) (*symmetric_key.SymKey, error) {
	lastPage := 1000
	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		state.logger.Trace().Interface("filters", filters).Bool("tryIfMultiple", tryIfMultiple).Int("page", currentPage).Msg(fmt.Sprintf("retrieveKeyByTmr: Retrieving TMR access with options"))
		response, err := autoLogin(state, state.apiClient.retrieveTmrAccesses)(&retrieveTmrAccessesRequest{
			TmrJWT:             tmrJWT,
			TmrAccessesFilters: filters,
			Page:               currentPage,
		})
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if len(response.TmrAccesses) == 0 {
			return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionByTmrAccessNotFound)
		}
		if len(response.TmrAccesses) > 1 && !tryIfMultiple {
			return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionByTmrAccessTooManyAccesses)
		}
		state.logger.Trace().Msg(fmt.Sprintf("retrieveKeyByTmr: Retrieved %d TMR Message Keys for message %s.", len(response.TmrAccesses), filters.SessionId))

		lastPage = response.NbPage
		for _, tmrKey := range response.TmrAccesses {
			state.logger.Trace().Msg(fmt.Sprintf("retrieveKeyByTmr: Decrypting tmrMK %s...", tmrKey.Id))
			b64Data, err := base64.StdEncoding.DecodeString(tmrKey.Data)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			sessionKeyBuff, err := overEncryptionKey.Decrypt(b64Data)
			if err != nil && errors.Is(err, symmetric_key.ErrorDecryptMacMismatch) {
				state.logger.Trace().Msg(fmt.Sprintf("retrieveKeyByTmr: Could not decrypt tmrMK %s with given overEncryptionKey", tmrKey.Id))
			} else if err != nil {
				return nil, tracerr.Wrap(err)
			}
			sessionSymKey, err := symmetric_key.Decode(sessionKeyBuff)
			if err != nil {
				return nil, tracerr.Wrap(err)
			} else {
				state.logger.Trace().Msg(fmt.Sprintf("retrieveKeyByTmr: Decrypted tmrMK %s successfully", tmrKey.Id))
				return &sessionSymKey, nil
			}
		}
		if currentPage > lastPage {
			return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionByTmrAccessCannotDecrypt)
		}
	}
	// This path should never be reached. The depagination for loop should either found an access, or throw.
	return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionByTmrAccessCannotDecrypt)
}

type TmrAccessesRetrievalFilters struct {
	CreatedById string
	TmrAccessId string
}

// RetrieveEncryptionSessionByTmr retrieves an EncryptionSession with Two Man Rule.
// If your Auth Factor has multiple TMR accesses for this message ID, you have to specify filters,
// or set `tryIfMultiple` to `true`.
func (state *State) RetrieveEncryptionSessionByTmr(tmrJWT string, sessionId string, overEncryptionKeyBytes []byte, retrievalFilters *TmrAccessesRetrievalFilters, tryIfMultiple bool, useCache bool) (*EncryptionSession, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if !utils.IsUUID(sessionId) {
		return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionInvalidMessageId)
	}
	if useCache {
		state.locks.cacheLockGroup.Lock(sessionId)
		defer state.locks.cacheLockGroup.Unlock(sessionId)
		retrieveSession, err := state.storage.encryptionSessionsCache.get(sessionId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if retrieveSession != nil {
			return &EncryptionSession{Id: sessionId, Key: retrieveSession.Symkey, state: state, RetrievalDetails: retrieveSession.RetrievalDetails}, nil
		}
	}

	jwtFilters := &TmrAccessesConvertFilters{
		SessionId: sessionId,
	}
	if retrievalFilters != nil {
		jwtFilters.CreatedById = retrievalFilters.CreatedById
		jwtFilters.TmrAccessId = retrievalFilters.TmrAccessId
	}

	overEncryptionKey, err := symmetric_key.Decode(overEncryptionKeyBytes)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	sessionSymKey, err := state.retrieveKeyByTmr(tmrJWT, &overEncryptionKey, jwtFilters, tryIfMultiple)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	retrievalDetails := EncryptionSessionRetrievalDetails{Flow: EncryptionSessionRetrievalViaTmrAccess}

	if useCache {
		state.storage.encryptionSessionsCache.Set(sessionId, *sessionSymKey, retrievalDetails)
		err = state.saveEncryptionSessions()
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	}
	session := EncryptionSession{Id: sessionId, Key: sessionSymKey, state: state, RetrievalDetails: retrievalDetails}
	state.logger.Debug().Interface("session", session).Msg("RetrieveEncryptionSession returning encryption session")
	return &session, nil
}

// RetrieveEncryptionSession retrieves an encryption session with the sessionId, and returns the associated
// EncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (state *State) RetrieveEncryptionSession(sessionId string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) (*EncryptionSession, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if !utils.IsUUID(sessionId) {
		return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionInvalidMessageId)
	}
	if useCache {
		state.locks.cacheLockGroup.Lock(sessionId)
		defer state.locks.cacheLockGroup.Unlock(sessionId)
		retrieveSession, err := state.storage.encryptionSessionsCache.get(sessionId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if retrieveSession != nil {
			return &EncryptionSession{Id: sessionId, Key: retrieveSession.Symkey, state: state, RetrievalDetails: retrieveSession.RetrievalDetails}, nil
		}
	}
	response, err := autoLogin(state, state.apiClient.retrieveMessage)(&retrieveMessageRequest{
		Id:             sessionId,
		LookupProxyKey: lookupProxyKey,
		LookupGroupKey: lookupGroupKey,
	})

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if !((len(response.Token) == 1 && response.ProxyKeyInfo == nil) || (len(response.Token) == 0 && response.ProxyKeyInfo != nil)) {
		return nil, tracerr.Wrap(ErrorSessionRetrievedUnexpectedNumEncMK)
	}

	var key *symmetric_key.SymKey
	var retrievalDetails EncryptionSessionRetrievalDetails

	// we are retrieving the session based on a group we belong to
	if lookupGroupKey && response.GroupId != "" {
		state.logger.Debug().Str("SessionId", sessionId).Str("GroupId", response.GroupId).Msg("Retrieving session via group")
		key, err = state.decryptMessageKeyWithGroup(response.GroupId, response.Token[0], false)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		retrievalDetails = EncryptionSessionRetrievalDetails{
			Flow:    EncryptionSessionRetrievalViaGroup,
			GroupId: response.GroupId,
		}
	} else if lookupProxyKey && response.ProxyKeyInfo != nil {
		state.logger.Debug().Str("SessionId", sessionId).Str("ProxySessionId", response.ProxyKeyInfo.ProxyMk.ProxyMessageId).Msg("Retrieving session via proxy")
		encryptedKey, err := base64.StdEncoding.DecodeString(utils.S64toB64(response.ProxyKeyInfo.ProxyMk.Data))
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		currentDevice := state.storage.currentDevice.get()
		if response.ProxyKeyInfo.EncryptedProxyMessageKey.KeyId != currentDevice.DeviceId {
			return nil, tracerr.Wrap(ErrorSessionUnexpectedDeviceId)
		}

		proxyKey, err := decryptMessageKey(*response.ProxyKeyInfo.EncryptedProxyMessageKey, currentDevice)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		decryptedKey, err := proxyKey.Decrypt(encryptedKey)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		keyObj, err := symmetric_key.Decode(decryptedKey)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		key = &keyObj
		retrievalDetails = EncryptionSessionRetrievalDetails{
			Flow:           EncryptionSessionRetrievalViaProxy,
			ProxySessionId: response.ProxyKeyInfo.ProxyMk.ProxyMessageId,
		}
	} else { // we are retrieving the session with an EncMK directly for us
		encMK := response.Token[0]

		state.logger.Debug().Str("SessionId", sessionId).Msg("Retrieving session as direct recipient")
		currentDevice := state.storage.currentDevice.get()
		if encMK.KeyId != currentDevice.DeviceId {
			return nil, tracerr.Wrap(ErrorSessionUnexpectedDeviceId)
		}

		key, err = decryptMessageKey(encMK, currentDevice)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		retrievalDetails = EncryptionSessionRetrievalDetails{
			Flow: EncryptionSessionRetrievalDirect,
		}
	}

	if useCache {
		state.storage.encryptionSessionsCache.Set(sessionId, *key, retrievalDetails)
		err = state.saveEncryptionSessions()
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
	}
	session := EncryptionSession{Id: sessionId, Key: key, state: state, RetrievalDetails: retrievalDetails}
	state.logger.Debug().Interface("session", session).Msg("RetrieveEncryptionSession returning encryption session")
	return &session, nil
}

// RetrieveMultipleEncryptionSessions retrieves multiple encryption sessions with a slice of sessionIds, and returns a
// slice of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
// The returned Slice of EncryptionSession instances is in the same order as the input slice.
func (state *State) RetrieveMultipleEncryptionSessions(sessionIds []string, useCache bool, lookupProxyKey bool, lookupGroupKey bool) ([]*EncryptionSession, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	for _, sessionId := range sessionIds {
		if !utils.IsUUID(sessionId) {
			return nil, tracerr.Wrap(ErrorRetrieveEncryptionSessionInvalidMessageId.AddDetails(sessionId))
		}
	}

	state.logger.Debug().Interface("sessionIds", sessionIds).Bool("useCache", useCache).Bool("lookupProxyKey", lookupProxyKey).Bool("lookupGroupKey", lookupGroupKey).Msg("Calling RetrieveMultipleEncryptionSessions")

	results := make([]*EncryptionSession, len(sessionIds)) // Slice to hold the results
	var nonCachedSessionIds []string                       // sessionIds that were not retrieved from the cache

	// get what we can from the cache
	if useCache {
		state.locks.cacheLockGroup.LockMultiple(sessionIds)
		defer state.locks.cacheLockGroup.UnlockMultiple(sessionIds)
		for i, sessionId := range sessionIds {
			retrieveSession, err := state.storage.encryptionSessionsCache.get(sessionId)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			if retrieveSession != nil {
				state.logger.Debug().Str("sessionId", sessionId).Msg("RetrieveMultipleEncryptionSessions: session found in cache")
				results[i] = &EncryptionSession{Id: sessionId, Key: retrieveSession.Symkey, state: state, RetrievalDetails: retrieveSession.RetrievalDetails}
			} else {
				nonCachedSessionIds = append(nonCachedSessionIds, sessionId)
			}
		}
	} else {
		nonCachedSessionIds = sessionIds
	}

	// if there is nothing else to retrieve, let's return early
	if len(nonCachedSessionIds) == 0 {
		state.logger.Debug().Interface("results", results).Msg("RetrieveMultipleEncryptionSessions: nothing left to retrieve, returning")
		return results, nil
	}

	// retrieve all that's left from the API
	state.logger.Debug().Interface("nonCachedSessionIds", nonCachedSessionIds).Msg("RetrieveMultipleEncryptionSessions: calling retrieveMultipleMessages API")
	response, err := autoLogin(state, state.apiClient.retrieveMultipleMessages)(&retrieveMultipleMessagesRequest{
		MessageIds:     nonCachedSessionIds,
		LookupProxyKey: lookupProxyKey,
		LookupGroupKey: lookupGroupKey,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	sessionsMap := make(map[string]*EncryptionSession)
	for sessionId, sessionResponse := range response.Results { // TODO: parallelize this?
		var key *symmetric_key.SymKey
		var retrievalDetails EncryptionSessionRetrievalDetails
		state.logger.Debug().Str("SessionId", sessionId).Interface("sessionResponse", sessionResponse).Msg("RetrieveMultipleEncryptionSessions: parsing response for session")

		// we are retrieving the session based on a group we belong to
		if lookupGroupKey && sessionResponse.GroupId != "" {
			state.logger.Debug().Str("SessionId", sessionId).Str("GroupId", sessionResponse.GroupId).Msg("RetrieveMultipleEncryptionSessions: retrieving session via group")
			key, err = state.decryptMessageKeyWithGroup(sessionResponse.GroupId, *sessionResponse.EncryptedMessageKey, false)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			retrievalDetails = EncryptionSessionRetrievalDetails{
				Flow:    EncryptionSessionRetrievalViaGroup,
				GroupId: sessionResponse.GroupId,
			}
		} else if lookupProxyKey && sessionResponse.ProxyKeyInfo != nil {
			state.logger.Debug().Str("SessionId", sessionId).Str("ProxySessionId", sessionResponse.ProxyKeyInfo.ProxyMk.ProxyMessageId).Msg("RetrieveMultipleEncryptionSessions: retrieving session via proxy")
			encryptedKey, err := base64.StdEncoding.DecodeString(utils.S64toB64(sessionResponse.ProxyKeyInfo.ProxyMk.Data))
			if err != nil {
				return nil, tracerr.Wrap(err)
			}

			currentDevice := state.storage.currentDevice.get()
			if sessionResponse.ProxyKeyInfo.EncryptedProxyMessageKey.KeyId != currentDevice.DeviceId {
				return nil, tracerr.Wrap(ErrorSessionUnexpectedDeviceId)
			}

			proxyKey, err := decryptMessageKey(*sessionResponse.ProxyKeyInfo.EncryptedProxyMessageKey, currentDevice)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}

			decryptedKey, err := proxyKey.Decrypt(encryptedKey)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}

			keyObj, err := symmetric_key.Decode(decryptedKey)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			key = &keyObj
			retrievalDetails = EncryptionSessionRetrievalDetails{
				Flow:           EncryptionSessionRetrievalViaProxy,
				ProxySessionId: sessionResponse.ProxyKeyInfo.ProxyMk.ProxyMessageId,
			}
		} else { // we are retrieving the session with an EncMK directly for us
			state.logger.Debug().Str("SessionId", sessionId).Msg("RetrieveMultipleEncryptionSessions: retrieving session as direct recipient")
			currentDevice := state.storage.currentDevice.get()
			if sessionResponse.EncryptedMessageKey.KeyId != currentDevice.DeviceId {
				return nil, tracerr.Wrap(ErrorSessionUnexpectedDeviceId)
			}

			key, err = decryptMessageKey(*sessionResponse.EncryptedMessageKey, currentDevice)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			retrievalDetails = EncryptionSessionRetrievalDetails{
				Flow: EncryptionSessionRetrievalDirect,
			}
		}

		if useCache {
			state.storage.encryptionSessionsCache.Set(sessionId, *key, retrievalDetails)
			err = state.saveEncryptionSessions()
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}
		session := EncryptionSession{Id: sessionId, Key: key, state: state, RetrievalDetails: retrievalDetails}
		state.logger.Debug().Interface("session", session).Msg("RetrieveMultipleEncryptionSessions found encryption session")
		sessionsMap[sessionId] = &session
	}
	state.logger.Debug().Interface("sessionsMap", sessionsMap).Msg("RetrieveMultipleEncryptionSessions: finished retrieving sessions")

	// populate the results array with the retrieved sessions
	for i, sessionId := range sessionIds {
		if results[i] == nil {
			session := sessionsMap[sessionId]
			if session == nil {
				return nil, tracerr.Wrap(ErrorSessionNotRetrievedUnexpectedly.AddDetails(sessionId))
			}
			results[i] = session
		}
	}
	state.logger.Debug().Interface("results", results).Msg("RetrieveMultipleEncryptionSessions: returning results")
	return results, nil
}

// AddRecipients adds new recipients to this session.
// These recipients will be able to read all encrypted messages of this session.
func (encryptionSession *EncryptionSession) AddRecipients(recipientsWithRights []*RecipientWithRights) (*AddKeysMultiStatusResponse, error) {
	recipientsIds, recipientsRightsMap := getRecipientIdsAndMap(recipientsWithRights)
	keys, err := encryptionSession.state.encryptMessageKey(encryptionSession.Key, recipientsIds)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.addKey))(&addKeysRequest{
		Id:                   encryptionSession.Id,
		LookupProxyKey:       encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey:       encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		MultiStatus:          true,
		EncryptedMessageKeys: keys.Keys,
		Rights:               recipientsRightsMap,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return response, nil
}

// AddProxySession adds a proxy session as a recipient of this session.
// Any recipient of the proxy session will also be able to retrieve this session.
// The current user has to be a direct recipient of the proxy session.
// If `rights` is nil, it defaults to `Read: true, Forward: true, Revoke: false`.
func (encryptionSession *EncryptionSession) AddProxySession(proxySessionId string, rights *RecipientRights) error {
	encryptionSession.state.logger.Debug().Str("SessionId", encryptionSession.Id).Str("ProxySessionId", proxySessionId).Msg("Adding proxy session")
	// no need to use lookupProxyKey / lookupGroupKey here, as user must be a direct recipient of the proxy session
	proxySession, err := encryptionSession.state.RetrieveEncryptionSession(proxySessionId, true, false, false)
	if err != nil {
		return tracerr.Wrap(err)
	}

	data, err := proxySession.Key.Encrypt(encryptionSession.Key.Encode())
	if err != nil {
		return tracerr.Wrap(err)
	}

	if rights == nil {
		rights = &RecipientRights{
			Read:    true,
			Forward: true,
			Revoke:  false,
		}
	}

	_, err = handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.addKeyProxy))(&addKeyProxyRequest{
		Id:             encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		ProxyMessage:   proxySessionId,
		Data:           base64.StdEncoding.EncodeToString(data),
		Rights:         rights,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// RevokeRecipients revoke some recipients or proxy sessions from this session.
// If you want to revoke all recipients, see RevokeAll instead.
// If you want to revoke all recipients besides yourself, see RevokeOthers.
func (encryptionSession *EncryptionSession) RevokeRecipients(recipientsIds []string, proxySessionsIds []string) (*RevokeRecipientsResponse, error) {
	if len(recipientsIds) == 0 && len(proxySessionsIds) == 0 {
		encryptionSession.state.logger.Log().Msg("RevokeRecipients called with nothing, bailing.")
		return &RevokeRecipientsResponse{}, nil
	}
	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.revokeRecipients))(&revokeRecipientsRequest{
		MessageId:      encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		UserIds:        recipientsIds,
		ProxyMkIds:     proxySessionsIds,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	retrieveES, err := encryptionSession.state.storage.encryptionSessionsCache.get(encryptionSession.Id)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	currentDevice := encryptionSession.state.storage.currentDevice.get()
	if retrieveES != nil {
		if utils.SliceIncludes(recipientsIds, currentDevice.UserId) ||
			(retrieveES.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup && utils.SliceIncludes(recipientsIds, retrieveES.RetrievalDetails.GroupId)) ||
			(retrieveES.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy && utils.SliceIncludes(proxySessionsIds, retrieveES.RetrievalDetails.ProxySessionId)) {
			encryptionSession.state.storage.encryptionSessionsCache.delete(encryptionSession.Id)
			err = encryptionSession.state.saveEncryptionSessions()
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}
	}
	return response, nil
}

// RevokeAll revokes this session entirely.
func (encryptionSession *EncryptionSession) RevokeAll() (*RevokeRecipientsResponse, error) {
	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.revokeRecipients))(&revokeRecipientsRequest{
		MessageId:      encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		RevokeAll:      "all",
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	encryptionSession.state.storage.encryptionSessionsCache.delete(encryptionSession.Id)
	err = encryptionSession.state.saveEncryptionSessions()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return response, nil
}

// RevokeOthers revokes all recipients, except yourself as a direct recipient, from this session.
func (encryptionSession *EncryptionSession) RevokeOthers() (*RevokeRecipientsResponse, error) {
	// revoke on API
	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.revokeRecipients))(&revokeRecipientsRequest{
		MessageId:      encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		RevokeAll:      "others",
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	// if there is a cache of this session, and it comes from group or proxy, remove it from cache
	retrieveES, err := encryptionSession.state.storage.encryptionSessionsCache.get(encryptionSession.Id)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if retrieveES != nil {
		if retrieveES.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup || retrieveES.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy {
			encryptionSession.state.storage.encryptionSessionsCache.delete(encryptionSession.Id)
			err = encryptionSession.state.saveEncryptionSessions()
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}
	}
	return response, nil
}

// EncryptMessage encrypts a clear-text string into an encrypted message, for the recipients of this session.
func (encryptionSession *EncryptionSession) EncryptMessage(clearMessage string) (string, error) {
	sealdMessage, err := messages.EncryptMessage(clearMessage, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return sealdMessage, nil
}

// DecryptMessage decrypts an encrypted message string into the corresponding clear-text string.
func (encryptionSession *EncryptionSession) DecryptMessage(encryptedMessage string) (string, error) {
	clearMessage, err := messages.DecryptMessage(encryptedMessage, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return clearMessage, nil
}

// EncryptFile encrypts a clear-text file into an encrypted file, for the recipients of this session.
func (encryptionSession *EncryptionSession) EncryptFile(clearFile []byte, filename string) ([]byte, error) {
	sealdFile, err := encrypt_decrypt_file.EncryptBytes(clearFile, filename, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return sealdFile, nil
}

// DecryptFile decrypts an encrypted file into the corresponding clear-text file.
func (encryptionSession *EncryptionSession) DecryptFile(encryptedFile []byte) (*common_models.ClearFile, error) {
	clearFile, err := encrypt_decrypt_file.DecryptBytes(encryptedFile, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return clearFile, nil
}

// EncryptFileFromPath encrypts a clear-text file into an encrypted file, for the recipients of this session.
// Returns the path of the encrypted file.
// The encrypted file will be created alongside the clear one, in the same directory, with the same name,
// and a `.seald` extension added.
// If a file already exist with that name, a numeric suffix will be added (up to 99).
func (encryptionSession *EncryptionSession) EncryptFileFromPath(clearFilePath string) (string, error) {
	encryptionSession.state.logger.Debug().Str("clearFilePath", clearFilePath).Msg("EncryptFileFromPath encrypting...")
	sealdFile, err := encrypt_decrypt_file.EncryptFileFromPath(clearFilePath, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptionSession.state.logger.Debug().Str("sealdFile", sealdFile).Msg("EncryptFileFromPath encrypted")
	return sealdFile, nil
}

// DecryptFileFromPath decrypts an encrypted file into the corresponding clear-text file.
// Returns the path of the decrypted file.
// The clear file will be created alongside the encrypted one, in the same directory.
// The output file will be named with the name it had at encryption.
// If a file already exist with that name, a numeric suffix will be added (up to 99).
func (encryptionSession *EncryptionSession) DecryptFileFromPath(encryptedFilePath string) (string, error) {
	encryptionSession.state.logger.Debug().Str("encryptedFilePath", encryptedFilePath).Msg("DecryptFileFromPath decrypting...")
	clearFilePath, err := encrypt_decrypt_file.DecryptFileFromPath(encryptedFilePath, encryptionSession.Id, encryptionSession.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptionSession.state.logger.Debug().Str("clearFilePath", clearFilePath).Msg("DecryptFileFromPath decrypted")
	return clearFilePath, nil
}

type TmrRecipientWithRights struct {
	AuthFactor        *common_models.AuthFactor
	Rights            *RecipientRights
	OverEncryptionKey []byte
}

// AddTmrAccess adds a 2-man-rule access to an existing EncryptionSession
func (encryptionSession *EncryptionSession) AddTmrAccess(tmrRecipient *TmrRecipientWithRights) (string, error) {
	recipientSymKey, err := symmetric_key.Decode(tmrRecipient.OverEncryptionKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptedData, err := recipientSymKey.Encrypt(encryptionSession.Key.Encode())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	overEncryptionKey := &tmrKey{Type: tmrRecipient.AuthFactor.Type, Value: tmrRecipient.AuthFactor.Value, Token: base64.StdEncoding.EncodeToString(encryptedData)}

	var tmrRights = make(map[string]*RecipientRights)
	if tmrRecipient.Rights != nil {
		tmrRights[tmrRecipient.AuthFactor.Value] = tmrRecipient.Rights
	}

	request := &addTmrAccessesRequest{
		MessageId:      encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		TmrKeys:        []*tmrKey{overEncryptionKey},
		Rights:         tmrRights,
	}
	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.addTmrAccesses))(request)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	if response.Status[tmrRecipient.AuthFactor.Value] == nil {
		return "", tracerr.Wrap(ErrorAddTMRAccessUnexpectedResponse)
	}
	if response.Status[tmrRecipient.AuthFactor.Value].Status != 200 {
		return "", tracerr.Wrap(ErrorAddTMRAccessCreateError.AddDetails(fmt.Sprintf("Status: %s, Code: %s", response.Status[tmrRecipient.AuthFactor.Value].Error.Status, response.Status[tmrRecipient.AuthFactor.Value].Error.Code)))
	}

	return response.Status[tmrRecipient.AuthFactor.Value].TmrKey.Id, nil
}

// AddMultipleTmrAccesses adds multiple 2-man-rule accesses to an existing EncryptionSession
func (encryptionSession *EncryptionSession) AddMultipleTmrAccesses(recipients []*TmrRecipientWithRights) (*AddTmrAccessesMultiStatusResponse, error) {
	var tmrKeys []*tmrKey
	var tmrRights = make(map[string]*RecipientRights)
	for _, tmrRecipient := range recipients {
		recipientSymKey, err := symmetric_key.Decode(tmrRecipient.OverEncryptionKey)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		encryptedData, err := recipientSymKey.Encrypt(encryptionSession.Key.Encode())
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		rKey := &tmrKey{Type: tmrRecipient.AuthFactor.Type, Value: tmrRecipient.AuthFactor.Value, Token: base64.StdEncoding.EncodeToString(encryptedData)}

		tmrKeys = append(tmrKeys, rKey)
		if tmrRecipient.Rights != nil {
			tmrRights[tmrRecipient.AuthFactor.Value] = tmrRecipient.Rights
		}
	}

	request := &addTmrAccessesRequest{
		MessageId:      encryptionSession.Id,
		LookupProxyKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaProxy,
		LookupGroupKey: encryptionSession.RetrievalDetails.Flow == EncryptionSessionRetrievalViaGroup,
		TmrKeys:        tmrKeys,
		Rights:         tmrRights,
	}
	response, err := handleMultipleAcl(encryptionSession.state, autoLogin(encryptionSession.state, encryptionSession.state.apiClient.addTmrAccesses))(request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return response, nil
}
