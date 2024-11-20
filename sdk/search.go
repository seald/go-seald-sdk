package sdk

import (
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

var (
	// ErrorSigchainRetrievedEmpty is returned when the retrieved sigchain has zero blocks
	ErrorSigchainRetrievedEmpty = utils.NewSealdError("SIGCHAIN_RETRIEVED_EMPTY", "sigchain retrieved empty")
	// ErrorSigchainForked is returned when there is an incoherence between the sigchain known locally and the one from the server
	ErrorSigchainForked = utils.NewSealdError("SIGCHAIN_FORKED", "sigchain forked")
)

var (
	// ErrorSigchainUnexpectedRetrievedLastHash is returned when the retrieved sigchain differ from different API endpoint
	ErrorSigchainUnexpectedRetrievedLastHash = utils.NewSealdError("SIGCHAIN_UNEXPECTED_RETRIEVED_LAST_HASH", "sigchain retrieved from server does not match retrieved user last sigchain hash")
)

// searchUnlocked is the internal function to perform the search without locking
func (state *State) searchUnlocked(value string, forceUpdate bool, recursive bool) (*contact, error) {
	state.logger.Trace().Str("id", value).Msg("Search: searching for user")
	currentDevice := state.storage.currentDevice.get()
	// Local search
	localContact := state.storage.contacts.get(value)
	fromTransaction := 0

	state.logger.Trace().Str("id", value).Interface("localContact", localContact).Msg("Search: local contact")

	if localContact != nil {
		if !forceUpdate {
			state.logger.Trace().Str("id", value).Msg("Search: no forceUpdate => returning localContact early")
			return localContact, nil
		}
		fromTransaction = localContact.Sigchain.GetLastBlock().Transaction.Position
	}

	blocks, err := handleLocked(state, autoLogin(state, state.apiClient.retrieveSigchain), 3)(&retrieveSigchainRequest{UserId: value, FromTransaction: fromTransaction})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if len(blocks.Blocks) == 0 {
		return nil, tracerr.Wrap(ErrorSigchainRetrievedEmpty)
	}

	var userSigchain = sigchain.Sigchain{}

	if localContact != nil {
		if localContact.Sigchain.GetLastBlock().Signature.Hash != blocks.Blocks[0].Signature.Hash { // first block retrieved is last block of the locally known sigchain
			return nil, tracerr.Wrap(ErrorSigchainForked)
		}
		if len(blocks.Blocks) == 1 {
			// sigchain is unchanged, localDatabase is fine, no further verification is needed
			return localContact, nil
		} else {
			// sigchain has been changed, further verification is needed
			userSigchain.Blocks = append(userSigchain.Blocks, localContact.Sigchain.Blocks...)
			userSigchain.Blocks = append(userSigchain.Blocks, blocks.Blocks[1:]...)
		}
	} else {
		userSigchain.Blocks = blocks.Blocks // sigchain has been fully retrieved
	}

	checkResult, err := sigchain.CheckSigchainTransactions(userSigchain, false)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	response, err := autoLogin(state, state.apiClient.search)(&searchRequest{Type: common_models.ConnectorTypeSealdId, Value: value})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if response.SigchainLastHash != blocks.Blocks[len(blocks.Blocks)-1].Signature.Hash {
		// sigchain has changed during update. Start again.
		if recursive {
			return state.searchUnlocked(value, forceUpdate, false)
		} else {
			return nil, tracerr.Wrap(ErrorSigchainUnexpectedRetrievedLastHash)
		}
	}

	var devices []*device

	if response.UserTeamDisabled {
		state.storage.contacts.delete(response.UserId)
		err = state.saveContacts()
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		if response.IsGroup && state.storage.groups.get(response.UserId) != nil { // if we were a group member, let's delete the group data
			state.storage.groups.delete(response.UserId)
			err = state.saveGroups()
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}

		return nil, nil
	}
	for _, userKey := range response.Keys {
		if userKey.State == deviceStateValidated {
			devices = append(devices, &device{
				Id:            userKey.Id,
				SigningKey:    userKey.SigningPublicKey,
				EncryptionKey: userKey.EncryptionPublicKey,
			})
		}
	}

	err = checkKeyringMatchesSigChain(checkResult, devices)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	c := contact{
		Id:       response.UserId,
		IsGroup:  response.IsGroup,
		Sigchain: userSigchain,
		Devices:  devices,
	}

	state.storage.contacts.set(c)
	err = state.saveContacts()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// Update group keys and members
	if c.IsGroup {
		state.logger.Trace().Str("id", value).Msg("Search: contact is a group, trying group update")
		isMember := false
		for mId := range checkResult.KnownMembers {
			if mId == currentDevice.UserId {
				isMember = true
				break
			}
		}
		state.logger.Trace().Str("id", value).Bool("isMember", isMember).Msg("Search: is member ?")
		if isMember {
			err = state.retrieveGroupKeys(c.Id, c.Devices[0].Id)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			_, err := state.retrieveGroupInfo(&c)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		} else if state.storage.groups.get(c.Id) != nil {
			// if we used to be a member but aren't anymore, we must delete the group info
			state.storage.groups.delete(response.UserId)
			err = state.saveGroups()
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}
	}

	return &c, nil
}

// Search function looks if the user exist in the local database, check if it needs to be updated, then return an up-to-date contact.
func (state *State) search(value string, forceUpdate bool) (*contact, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	// Lock contact
	state.locks.contactsLockGroup.Lock(value)
	defer state.locks.contactsLockGroup.Unlock(value)

	return state.searchUnlocked(value, forceUpdate, true)
}
