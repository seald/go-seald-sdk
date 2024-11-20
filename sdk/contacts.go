package sdk

import (
	"fmt"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"time"
)

var (
	// ErrorContactsContactRemoved is returned when trying to update a contact which was removed.
	ErrorContactsContactRemoved = utils.NewSealdError("CONTACTS_CONTACT_REMOVED", "trying to update a removed contact")
	// ErrorContactsGroupDeviceExpiresMigrationEmptyKeys is returned when trying to retrieve group keys from the server but the server unexpectedly does not return any.
	ErrorContactsGroupDeviceExpiresMigrationEmptyKeys = utils.NewSealdError("CONTACTS_GROUP_DEVICEEXPIRES_MIGRATION_EMPTY_KEYS", "group keys cannot be empty")
	// ErrorContactsSigchainOutOfRange is returned when an illegal sigchain index was requested.
	ErrorContactsSigchainOutOfRange = utils.NewSealdError("CONTACTS_SIGCHAIN_OUT_OF_RANGE", "Sigchain index out of range")
)

func (state *State) getUpdatedContactsUnlocked(userIds []string) ([]*contact, int, error) {
	var updatedContacts []*contact
	removedContacts := 0

	state.logger.Trace().Interface("userIds", userIds).Msg("Calling GetUpdatedContacts")
	var localContacts []*contact
	var newContactsIds []string
	for _, userId := range userIds {
		lc := state.storage.contacts.get(userId)
		if lc != nil {
			localContacts = append(localContacts, lc)
		} else {
			newContactsIds = append(newContactsIds, userId)
		}
	}
	// For locally known contact, we checkUsers and update only if needed
	pageSize := 10
	for _, usersPage := range utils.ChunkSlice[*contact](localContacts, pageSize) {
		var usersPageIds []string
		for _, user := range usersPage {
			usersPageIds = append(usersPageIds, user.Id)
		}
		usersLastSigchainHashes, err := autoLogin(state, state.apiClient.checkUsers)(&checkUsersRequest{Users: usersPageIds})
		if err != nil {
			return nil, 0, tracerr.Wrap(err)
		}

		for _, localUser := range usersPage {
			if localUser.Sigchain.GetLastBlock().Signature.Hash != usersLastSigchainHashes.Users[localUser.Id] {
				updatedUser, err := state.searchUnlocked(localUser.Id, true, true)
				if err != nil {
					return nil, 0, tracerr.Wrap(err)
				}
				if updatedUser != nil {
					state.logger.Trace().Interface("id", localUser.Id).Msg("GetUpdatedContacts: user updated")
					updatedContacts = append(updatedContacts, updatedUser)
				} else {
					state.logger.Trace().Interface("id", localUser.Id).Msg("GetUpdatedContacts: user removed")
					removedContacts++
				}
			} else {
				// Handle migration from when we don't know the DeviceExpires
				if localUser.IsGroup {
					group_ := state.storage.groups.get(localUser.Id)
					if group_ != nil && group_.DeviceExpires.IsZero() { // We need to migrate
						// To migrate we need to retrieve a key to get its KeyExpirationDate. Let's retrieve only one key, for optimization.
						lastKnownMessage := ""       // If there is are no OldKeys, set lastKnownMessage to empty : we will only get one key anyway.
						if len(group_.OldKeys) > 0 { // If there are OldKeys, set lastKnownMessage is to the most recent OldKey so we get only CurrentKey.
							lastKnownMessage = group_.OldKeys[len(group_.OldKeys)-1].MessageId
						}
						keys, err := autoLogin(state, state.apiClient.listGroupDevices)(&listGroupDevicesRequest{GroupId: localUser.Id, AfterMessage: lastKnownMessage})
						if err != nil {
							return nil, 0, tracerr.Wrap(err)
						}
						if len(keys.DeviceKeys) == 0 {
							return nil, 0, tracerr.Wrap(ErrorContactsGroupDeviceExpiresMigrationEmptyKeys)
						}
						group_.DeviceExpires = time.Unix(keys.DeviceKeys[0].KeyExpirationDate, 0)

						state.storage.groups.set(*group_)
						err = state.saveGroups()
						if err != nil {
							return nil, 0, tracerr.Wrap(err)
						}
						// migration is done
					}
				}
				updatedContacts = append(updatedContacts, localUser)
			}
		}
	}

	// Dealing with new users
	for _, newUserId := range newContactsIds {
		newUser, err := state.searchUnlocked(newUserId, true, true)
		if err != nil {
			return nil, 0, tracerr.Wrap(err)
		}
		if newUser != nil {
			state.logger.Trace().Interface("id", newUserId).Msg("GetUpdatedContacts: added new contact")
			updatedContacts = append(updatedContacts, newUser)
		} else {
			removedContacts++
		}
	}

	state.logger.Trace().Interface("updatedContacts", updatedContacts).Msg("GetUpdatedContacts: done")
	return updatedContacts, removedContacts, nil
}

// getUpdatedContacts takes a slice of seald IDs, updates the corresponding users if necessary,
// and returns a slice of contact s, as well as the number of contacts which were deleted because they are revoked.
func (state *State) getUpdatedContacts(userIds []string) ([]*contact, int, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, 0, tracerr.Wrap(err)
	}
	// Check inputs are valid
	err = utils.CheckUUIDSlice(userIds)
	if err != nil {
		return nil, 0, tracerr.Wrap(err)
	}
	err = utils.CheckSliceUnique(userIds)
	if err != nil {
		return nil, 0, tracerr.Wrap(err)
	}

	// Lock the contacts in question to avoid parallel updates
	state.locks.contactsLockGroup.LockMultiple(userIds)
	defer state.locks.contactsLockGroup.UnlockMultiple(userIds)

	return state.getUpdatedContactsUnlocked(userIds)
}

func (state *State) getUpdatedContactUnlocked(userId string) (*contact, error) {
	contactSlice, removed, err := state.getUpdatedContactsUnlocked([]string{userId})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if removed > 0 || len(contactSlice) != 1 {
		return nil, tracerr.Wrap(ErrorContactsContactRemoved)
	}
	return contactSlice[0], nil
}

type GetSigchainResponse struct {
	Hash     string
	Position int
}

// GetSigchainHash return a user's sigchain transaction hash at index `position`.
func (state *State) GetSigchainHash(userId string, position int) (*GetSigchainResponse, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(userId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Str("userId", userId).Msg("GetSigchainHash: get updated user...")
	// Lock the contacts in question to avoid parallel updates
	state.locks.contactsLockGroup.Lock(userId)
	defer state.locks.contactsLockGroup.Unlock(userId)
	updatedContact, err := state.getUpdatedContactUnlocked(userId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if position < 0 {
		lastBlock := updatedContact.Sigchain.GetLastBlock()
		state.logger.Trace().Str("Hash", lastBlock.Signature.Hash).Msg("GetSigchainHash: return last hash")
		return &GetSigchainResponse{Hash: lastBlock.Signature.Hash, Position: lastBlock.Transaction.Position}, nil
	} else {
		if position >= len(updatedContact.Sigchain.Blocks) {
			return nil, tracerr.Wrap(ErrorContactsSigchainOutOfRange.AddDetails(fmt.Sprintf("Requested: \"%d\", sigchain length: \"%d\"", position, len(updatedContact.Sigchain.Blocks))))
		}
		posBlock := updatedContact.Sigchain.Blocks[position]
		state.logger.Trace().Int("position", position).Str("Hash", posBlock.Signature.Hash).Msg("GetSigchainHash: return last hash")
		return &GetSigchainResponse{Hash: posBlock.Signature.Hash, Position: posBlock.Transaction.Position}, nil
	}
}

type CheckSigchainResponse struct {
	Found        bool
	Position     int
	LastPosition int
}

// CheckSigchainHash verify if the given `expectedHash` is included in the recipient `userId` sigchain.
// Use the `position` option to check the hash of a specific sigchain transaction.
// Set `position` to -1 to check if the hash exist in the sigchain.
func (state *State) CheckSigchainHash(userId string, expectedHash string, position int) (*CheckSigchainResponse, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(userId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Str("userId", userId).Msg("CheckSigchainHash: get updated user...")
	// Lock the contacts in question to avoid parallel updates
	state.locks.contactsLockGroup.Lock(userId)
	defer state.locks.contactsLockGroup.Unlock(userId)
	updatedContact, err := state.getUpdatedContactUnlocked(userId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Int("Sigchain length", len(updatedContact.Sigchain.Blocks)).Msg("CheckSigchainHash: user updated.")
	if position < 0 {
		state.logger.Trace().Str("expectedHash", expectedHash).Msg("CheckSigchainHash: looking for `expectedHash` anywhere in the sigchain...")
		for i := 0; i < len(updatedContact.Sigchain.Blocks); i++ {
			if updatedContact.Sigchain.Blocks[i].Signature.Hash == expectedHash {
				state.logger.Trace().Msg("CheckSigchainHash: hash found")
				return &CheckSigchainResponse{Found: true, Position: i, LastPosition: len(updatedContact.Sigchain.Blocks) - 1}, nil
			}
		}
		state.logger.Trace().Msg("CheckSigchainHash: hash *NOT* found")
		return &CheckSigchainResponse{Found: false, LastPosition: len(updatedContact.Sigchain.Blocks) - 1}, nil
	} else {
		state.logger.Trace().Msg(fmt.Sprintf("CheckSigchainHash: looking for hash \"%s\", at position \"%d\"", expectedHash, position))
		if position >= len(updatedContact.Sigchain.Blocks) {
			return nil, tracerr.Wrap(ErrorContactsSigchainOutOfRange.AddDetails(fmt.Sprintf("Requested: \"%d\", sigchain length: \"%d\"", position, len(updatedContact.Sigchain.Blocks))))
		}
		if updatedContact.Sigchain.Blocks[position].Signature.Hash == expectedHash {
			state.logger.Trace().Msg("CheckSigchainHash: hash found")
			return &CheckSigchainResponse{Found: true, Position: position, LastPosition: len(updatedContact.Sigchain.Blocks) - 1}, nil
		} else {
			state.logger.Trace().Msg("CheckSigchainHash: hash *NOT* found")
			return &CheckSigchainResponse{Found: false, LastPosition: len(updatedContact.Sigchain.Blocks) - 1}, nil
		}
	}
}
