package sdk

import (
	"encoding/base64"
	"errors"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"sort"
	"time"
)

var (
	// ErrorGroupsUserUnregistered means this account is not initialized.
	ErrorGroupsUserUnregistered = utils.NewSealdError("GROUPS_USER_UNREGISTERED", "unregistered")
	// ErrorGroupsNotAdmin means this account is not an admin of this group.
	ErrorGroupsNotAdmin = utils.NewSealdError("GROUPS_NOT_ADMIN", "not admin")
	// ErrorGroupsNotMember means this account is not a member of this group.
	ErrorGroupsNotMember = utils.NewSealdError("GROUPS_NOT_MEMBER", "not member")
	// ErrorGroupsCreateSelfNotAdmin means this account is not an admin of the group you are trying to create.
	ErrorGroupsCreateSelfNotAdmin = utils.NewSealdError("GROUPS_CREATE_SELF_NOT_ADMIN", "current user not admin")
	// ErrorGroupsCreateAdminNotMember means one of the admins of the group you are trying to create is not among the members.
	ErrorGroupsCreateAdminNotMember = utils.NewSealdError("GROUPS_CREATE_ADMIN_NOT_MEMBER", "admin not member when creating group")
	// ErrorGroupsMemberDifferFromSigchain means the retrieved list of group members does not correspond to the retrieved Sigchain of this group.
	// This group is probably corrupted. contact Seald support.
	ErrorGroupsMemberDifferFromSigchain = utils.NewSealdError("GROUPS_MEMBERS_DIFFER_FROM_SIGCHAIN", "group members differ from sigchain")
	// ErrorGroupsAddMembersAlreadyInGroup means the user you are trying to add is already in the group.
	ErrorGroupsAddMembersAlreadyInGroup = utils.NewSealdError("GROUPS_ADD_MEMBERS_ALREADY_IN_GROUP", "already in group")
	// ErrorGroupsAddMembersAdminNotMember means the admin you are trying to add is not among the members you are trying to add.
	ErrorGroupsAddMembersAdminNotMember = utils.NewSealdError("GROUPS_ADD_MEMBERS_ADMIN_NOT_MEMBER", "admin not member when adding members")
	// ErrorGroupsRemoveMembersNotInGroup means the user you are trying to remove is not in the group.
	ErrorGroupsRemoveMembersNotInGroup = utils.NewSealdError("GROUPS_REMOVE_MEMBERS_NOT_IN_GROUP", "not in group")
	// ErrorGroupsRetrievedUnexpectedNumEncMK means the server responded with an unexpected number of EncryptedMessageKeys when trying to retrieve the key for this group device.
	ErrorGroupsRetrievedUnexpectedNumEncMK = utils.NewSealdError("GROUPS_RETRIEVED_UNEXPECTED_NUM_ENC_MK", "retrieved multiple or no encrypted message keys while expecting exactly one")
	// ErrorGroupsUnexpectedGroupMessage means the server responded with a group message, not a direct one, which is forbidden.
	ErrorGroupsUnexpectedGroupMessage = utils.NewSealdError("GROUPS_UNEXPECTED_GROUP_MESSAGE", "retrieved token is for a group")
	// ErrorGroupsUnexpectedDeviceId means the server responded with a device ID which does not match you current device.
	ErrorGroupsUnexpectedDeviceId = utils.NewSealdError("GROUPS_UNEXPECTED_DEVICE_ID", "retrieved device id does not match current device")
	// ErrorGroupsSetAdminsAddedNotMember means one of the user you are trying to add to group admins is not a group member.
	ErrorGroupsSetAdminsAddedNotMember = utils.NewSealdError("GROUPS_SET_ADMINS_ADDED_NOT_MEMBER", "one of the users you are trying to add to admins is not a group member")
	// ErrorGroupsSetAdminsRemovedNotMember means one of the user you are trying to remove from group admins is not a group member.
	ErrorGroupsSetAdminsRemovedNotMember = utils.NewSealdError("GROUPS_SET_ADMINS_REMOVED_NOT_MEMBER", "one of the users you are trying to remove from admins is not a group member")
	// ErrorGroupsAddMembersRevokedUser is returned when trying to add a revoked user as group member
	ErrorGroupsAddMembersRevokedUser = utils.NewSealdError("GROUPS_ADD_MEMBERS_REVOKED_USER", "cannot add a revoked user as group member")
	// ErrorGroupsRetrieveInfoNoGroup is returned when updating a group that does not exist in the local database
	ErrorGroupsRetrieveInfoNoGroup = utils.NewSealdError("GROUPS_RETRIEVE_INFO_NO_GROUP", "updating group unknown locally")
	// ErrorGroupsGroupCannotBeMember is returned when trying to set a group as a member of itself
	ErrorGroupsGroupCannotBeMember = utils.NewSealdError("GROUPS_GROUP_CANNOT_BE_MEMBER", "group cannot be a member of itself")
	// ErrorGroupsRenewGroupKeyCannotDecryptTMRTempKey is returned when we cannot decrypt a group TMR temporary SymKey with the group device
	ErrorGroupsRenewGroupKeyCannotDecryptTMRTempKey = utils.NewSealdError("GROUPS_GROUP_RENEW_KEY_CANNOT_DECRYPT_TMR_TEMP_KEY", "Cannot decrypt a group TMR temporary SymKey with this group device")
)

// CreateGroup creates a group, and returns the created group's ID.
// admins must also be members.
// admins must include yourself.
func (state *State) CreateGroup(groupName string, members []string, admins []string, preGeneratedKeys *PreGeneratedKeys) (string, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	// Validating inputs
	currentDevice := state.storage.currentDevice.get()
	currentUserId := currentDevice.UserId
	if currentUserId == "" {
		return "", tracerr.Wrap(ErrorGroupsUserUnregistered)
	}

	if !utils.SliceIncludes(admins, currentUserId) {
		return "", tracerr.Wrap(ErrorGroupsCreateSelfNotAdmin)
	}
	for _, admin := range admins {
		if !utils.SliceIncludes(members, admin) {
			return "", tracerr.Wrap(ErrorGroupsCreateAdminNotMember)
		}
	}
	// No need to lock, as the group does not exist yet

	// Generating group keys
	var encryptionKeyPair *asymkey.PrivateKey
	var signingKeyPair *asymkey.PrivateKey
	if preGeneratedKeys == nil {
		state.logger.Trace().Msg("CreateGroup: Generating keys...")
		encryptionKeyPair, signingKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return "", tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("CreateGroup: Using pre-generated keys.")
		encryptionKeyPair = preGeneratedKeys.EncryptionKey
		signingKeyPair = preGeneratedKeys.SigningKey
	}

	encryptionPublicKey := encryptionKeyPair.Public()
	signingPublicKey := signingKeyPair.Public()

	// Encrypting group keys with a sym key
	key, err := symmetric_key.Generate()
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptedEncryptionPrivateKey, err := key.Encrypt(encryptionKeyPair.Encode())
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptedSigningPrivateKey, err := key.Encrypt(signingKeyPair.Encode())
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	// Encrypting sym key for members
	keys, err := state.encryptMessageKey(key, members)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	var keys2 []encryptedMessageKey2

	for _, k := range keys.Keys {
		keys2 = append(keys2, encryptedMessageKey2{Key: k.Token, CreatedForKey: k.CreatedForKey, CreatedForKeyHash: k.CreatedForKeyHash})
	}

	// Creating group on API
	group_, err := autoLogin(state, state.apiClient.createGroup)(&createGroupRequest{
		GroupName:                     groupName,
		EncryptionPublicKey:           encryptionPublicKey.ToB64(),
		SigningPublicKey:              signingPublicKey.ToB64(),
		EncryptedEncryptionPrivateKey: base64.StdEncoding.EncodeToString(encryptedEncryptionPrivateKey),
		EncryptedSigningPrivateKey:    base64.StdEncoding.EncodeToString(encryptedSigningPrivateKey),
		Members:                       members,
		Admins:                        admins,
		EncryptedMessageKeys:          keys2,
	})

	if err != nil {
		return "", tracerr.Wrap(err)
	}

	groupId := group_.Group.BeardUser.Id

	// define createdAt here instead of relying on the default in CreateSigchainTransaction so that we can
	// compute the exact value of expireAt, in order to save it in the model
	createdAt := time.Now()

	// Generating sigchain transactions
	block1, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_CREATE,
		OperationEncryptionKey: encryptionPublicKey,
		OperationSigningKey:    signingPublicKey,
		OperationDeviceId:      group_.Group.DeviceId,
		ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
		SigningKey:             signingKeyPair,
		Position:               0,
		PreviousHash:           "",
		SignerDeviceId:         group_.Group.DeviceId,
		CreatedAt:              &createdAt,
	})

	if err != nil {
		return "", tracerr.Wrap(err)
	}

	block2, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:     sigchain.SIGCHAIN_OPERATION_MEMBERS,
		OperationMembers:  &members,
		OperationDeviceId: group_.Group.DeviceId,
		SigningKey:        signingKeyPair,
		Position:          1,
		PreviousHash:      block1.Signature.Hash,
		SignerDeviceId:    group_.Group.DeviceId,
		CreatedAt:         &createdAt,
	})

	if err != nil {
		return "", tracerr.Wrap(err)
	}

	// Sending sigchain to API
	_, err = handleLocked(state, autoLogin(state, state.apiClient.initGroupSigchain), 3)(&initGroupSigchainRequest{
		GroupId:                groupId,
		TransactionData:        block1,
		TransactionDataMembers: block2,
	})

	if err != nil {
		return "", tracerr.Wrap(err)
	}

	// Storing newly created group
	var newGroupMembers []groupMember
	for _, member := range members {
		newGroupMembers = append(newGroupMembers, groupMember{
			Id:      member,
			IsAdmin: utils.SliceIncludes(admins, member),
		})
	}
	expireAt := time.Unix(createdAt.Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix(), 0) // keep only the unix timestamp part (no sub-second precision)
	state.storage.groups.set(group{
		Id:       groupId,
		DeviceId: group_.Group.DeviceId,
		CurrentKey: groupKey{
			MessageId:            group_.GroupDeviceKey.MessageId,
			SigningPrivateKey:    signingKeyPair,
			EncryptionPrivateKey: encryptionKeyPair,
		},
		Members:       newGroupMembers,
		DeviceExpires: expireAt,
	})

	state.storage.contacts.set(contact{
		Id:      groupId,
		IsGroup: true,
		Sigchain: sigchain.Sigchain{
			Blocks: []*sigchain.Block{block1, block2},
		},
		Devices: []*device{
			{
				Id:            group_.Group.DeviceId,
				EncryptionKey: encryptionPublicKey,
				SigningKey:    signingPublicKey,
			},
		},
	})

	err = state.saveGroups()
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	err = state.saveContacts()
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return groupId, nil
}

// retrieveMessageKeyDirectOnly retrieves messageKey without trying to decrypt them via a group.
// Some functions that deal with groups do this, instead of using RetrieveEncryptionSession,
// to avoid entering an infinite loop.
func (state *State) retrieveMessageKeyDirectOnly(messageId string) (*symmetric_key.SymKey, error) {
	response, err := autoLogin(state, state.apiClient.retrieveMessage)(&retrieveMessageRequest{
		Id: messageId,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if response.GroupId != "" {
		return nil, tracerr.Wrap(ErrorGroupsUnexpectedGroupMessage)
	}
	if len(response.Token) != 1 {
		return nil, tracerr.Wrap(ErrorGroupsRetrievedUnexpectedNumEncMK)
	}
	encMK := response.Token[0]
	currentDevice := state.storage.currentDevice.get()
	if encMK.KeyId != currentDevice.DeviceId {
		return nil, tracerr.Wrap(ErrorGroupsUnexpectedDeviceId)
	}
	messageKey, err := decryptMessageKey(encMK, currentDevice)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return messageKey, nil
}

func (state *State) retrieveGroupKeys(groupId string, deviceId string) error {
	// No lock here : it's an internal function, the lock would be higher in the stack
	lastKnownMessage := ""
	group_ := state.storage.groups.get(groupId)

	if group_ != nil {
		lastKnownMessage = group_.CurrentKey.MessageId
	} else {
		group_ = &group{Id: groupId, DeviceId: deviceId}
	}

	keys, err := autoLogin(state, state.apiClient.listGroupDevices)(&listGroupDevicesRequest{GroupId: groupId, AfterMessage: lastKnownMessage})
	if err != nil {
		return tracerr.Wrap(err)
	}

	var groupKeys []groupKey

	for _, key := range keys.DeviceKeys {
		messageKey, err := state.retrieveMessageKeyDirectOnly(key.MessageId)
		if err != nil {
			return tracerr.Wrap(err)
		}

		// using retrieved messageKey to decrypt group key
		encryptionKeyPair, err := decryptPrivateKey(messageKey, key.EncryptedEncryptionPrivateKey)
		if err != nil {
			return tracerr.Wrap(err)
		}
		signingKeyPair, err := decryptPrivateKey(messageKey, key.EncryptedSigningPrivateKey)
		if err != nil {
			return tracerr.Wrap(err)
		}
		groupKeys = append(groupKeys, groupKey{MessageId: key.MessageId, EncryptionPrivateKey: encryptionKeyPair, SigningPrivateKey: signingKeyPair})
	}

	if len(groupKeys) == 0 {
		return nil
	}

	// groupKeys is a slice of the keys that we don't know yet
	// The last key in the array is the newest one : it is the current key
	currentKey := groupKeys[len(groupKeys)-1]
	var oldKeys []groupKey
	oldKeys = append(oldKeys, group_.OldKeys...)       // We keep the oldKeys we already know
	if group_.CurrentKey.EncryptionPrivateKey != nil { // If we know a CurrentKey, it becomes an old key
		oldKeys = append(oldKeys, group_.CurrentKey) //
	}
	oldKeys = append(oldKeys, groupKeys[0:len(groupKeys)-1]...) // All keys before the last one are old keys

	group_.CurrentKey = currentKey
	group_.OldKeys = oldKeys
	group_.DeviceExpires = time.Unix(keys.DeviceKeys[0].KeyExpirationDate, 0)

	state.storage.groups.set(*group_)
	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

func (state *State) retrieveGroupInfo(groupUser *contact) (*group, error) {
	// No lock here : it's an internal function, the lock would be higher in the stack
	members, err := autoLogin(state, state.apiClient.listGroupMembers)(&listGroupMembersRequest{GroupId: groupUser.Id})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var _membersIds []string
	for _, block := range groupUser.Sigchain.Blocks {
		if block.Transaction.Operation.Type == sigchain.SIGCHAIN_OPERATION_MEMBERS {
			_membersIds = *block.Transaction.Operation.Members
		}
	}

	membersIds := utils.SliceMap(members.GroupMember, func(e apiGroupMember) string { return e.Id })

	if !utils.SliceSameMembers(_membersIds, membersIds) {
		return nil, tracerr.Wrap(ErrorGroupsMemberDifferFromSigchain)
	}

	group := state.storage.groups.get(groupUser.Id)
	if group == nil {
		return nil, tracerr.Wrap(ErrorGroupsRetrieveInfoNoGroup)
	}
	storageMembers := utils.SliceMap(members.GroupMember, func(e apiGroupMember) groupMember { return groupMember{Id: e.Id, IsAdmin: e.IsAdmin} })
	group.Members = storageMembers

	// If we were revoked from the group, ensure that we delete the group private keys
	currentDevice := state.storage.currentDevice.get()
	if !group.isMember(currentDevice.UserId) {
		state.storage.groups.delete(groupUser.Id)
	}

	state.storage.groups.set(*group)
	err = state.saveGroups()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return group, nil
}

func (state *State) isGroupAdmin(group *group) (bool, error) {
	currentDevice := state.storage.currentDevice.get()
	currentUserId := currentDevice.UserId
	if currentUserId == "" {
		return false, tracerr.Wrap(ErrorGroupsUserUnregistered)
	}

	isAdmin, err := group.isAdmin(currentUserId)
	if err != nil && !errors.Is(err, ErrorMemberNotInGroup) {
		return false, tracerr.Wrap(err)
	}
	if err != nil || !isAdmin { // err is ErrorMemberNotInGroup, or user is not admin => update the group
		groupUser := state.storage.contacts.get(group.Id)
		updatedGroup, err := state.retrieveGroupInfo(groupUser)
		if err != nil {
			return false, tracerr.Wrap(err)
		}
		isAdmin, err = updatedGroup.isAdmin(currentUserId)
		if err != nil {
			return false, tracerr.Wrap(err)
		}
	}
	return isAdmin, nil
}

func (state *State) checkGroupAdmin(group *group) error {
	isAdmin, err := state.isGroupAdmin(group)
	if err != nil {
		return tracerr.Wrap(err)
	}
	if isAdmin {
		return nil
	} else {
		return tracerr.Wrap(ErrorGroupsNotAdmin)
	}
}

const graceDelay = 6 * 30 * 24 * time.Hour // 6 months

// ShouldRenewGroup returns a boolean that indicates whether or not this group should be renewed.
// Returns true if the current user is an admin of the group and the group expires in less than 6 months, false otherwise.
func (state *State) ShouldRenewGroup(groupId string) (bool, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return false, tracerr.Wrap(err)
	}
	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return false, tracerr.Wrap(err)
	}

	maxExpiration := time.Now().Add(graceDelay)

	state.logger.Trace().Str("groupId", groupId).Interface("maxExpiration", maxExpiration).Msg("ShouldRenewGroup: called")

	group := state.storage.groups.get(groupId)
	if group != nil {
		if group.DeviceExpires.After(maxExpiration) {
			// we know the group, and we already know it expires after grace delay: this shouldn't be reduced, so we should be good
			state.logger.Trace().Str("groupId", groupId).Interface("deviceExpires", group.DeviceExpires).Msg("ShouldRenewGroup: group already known, with long device expiration => returning false")
			return false, nil
		} else {
			state.logger.Trace().Str("groupId", groupId).Interface("deviceExpires", group.DeviceExpires).Msg("ShouldRenewGroup: group already known, but with short device expiration => updating the group, to check if it was already renewed")
		}
	} else {
		state.logger.Trace().Str("groupId", groupId).Msg("ShouldRenewGroup: group not known => retrieving the group")
	}
	// getUpdatedContactUnlocked handles both update & retrieve
	_, err = state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return false, tracerr.Wrap(err)
	}
	group = state.storage.groups.get(groupId)
	if group == nil {
		return false, tracerr.Wrap(ErrorGroupsNotMember)
	}

	// if current user is not admin, they can't renew, so return false
	isAdmin, err := state.isGroupAdmin(group)
	if err != nil {
		return false, tracerr.Wrap(err)
	}
	if !isAdmin {
		state.logger.Trace().Str("groupId", groupId).Msg("ShouldRenewGroup: current user not group admin => cannot renew")
		return false, nil
	}

	// finally, last step: actual result if is the known expiration (after update) is before maxExpiration
	shouldRenew := group.DeviceExpires.Before(maxExpiration)
	state.logger.Trace().Str("groupId", groupId).Interface("deviceExpires", group.DeviceExpires).Bool("shouldRenew", shouldRenew).Msg("ShouldRenewGroup: group retrieved")
	return shouldRenew, nil
}

// AddGroupMembers adds members to a group.
// Can only be done by a group administrator.
// Can also specify which of these newly added group members should also be admins.
func (state *State) AddGroupMembers(groupId string, membersToAdd []string, adminsToSet []string) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckUUIDSlice(membersToAdd)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckUUIDSlice(adminsToSet)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if adminsToSet == nil {
		adminsToSet = []string{}
	}
	for _, admin := range adminsToSet {
		if !utils.SliceIncludes(membersToAdd, admin) {
			return tracerr.Wrap(ErrorGroupsAddMembersAdminNotMember.AddDetails(admin))
		}
	}
	if utils.SliceIncludes(membersToAdd, groupId) {
		return tracerr.Wrap(ErrorGroupsGroupCannotBeMember)
	}

	// Lock group user
	state.locks.contactsLockGroup.Lock(groupId)
	defer state.locks.contactsLockGroup.Unlock(groupId)

	// Get updated info about group
	groupUser, err := state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	group := state.storage.groups.get(groupId)
	if group == nil {
		return tracerr.Wrap(ErrorGroupsNotMember)
	}

	// Check that we are allowed to do this
	err = state.checkGroupAdmin(group)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Update members to add (we will need it to generate keys for them)
	usersToAdd, removed, err := state.getUpdatedContacts(membersToAdd)
	if err != nil {
		return tracerr.Wrap(err)
	}
	if removed > 0 {
		return tracerr.Wrap(ErrorGroupsAddMembersRevokedUser) // TODO: add context
	}

	// Creating the new list of members
	membersSet := utils.Set[string]{}
	var newMembers []string

	for _, member := range group.Members {
		membersSet.Add(member.Id)
		newMembers = append(newMembers, member.Id)
	}

	for _, member := range membersToAdd {
		if membersSet.Has(member) {
			return tracerr.Wrap(ErrorGroupsAddMembersAlreadyInGroup.AddDetails(member))
		}
		newMembers = append(newMembers, member)
	}

	// Generating sigchain transaction with the new members list
	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:     sigchain.SIGCHAIN_OPERATION_MEMBERS,
		OperationMembers:  &newMembers,
		OperationDeviceId: group.DeviceId,
		SigningKey:        group.CurrentKey.SigningPrivateKey,
		Position:          groupUser.Sigchain.GetLastBlock().Transaction.Position + 1,
		PreviousHash:      groupUser.Sigchain.GetLastBlock().Signature.Hash,
		SignerDeviceId:    group.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Generating keys for the new members
	keysToAdd := make(map[string][]emkAndId)

	groupKeys := []groupKey{group.CurrentKey}
	if group.OldKeys != nil {
		groupKeys = append(groupKeys, group.OldKeys...)
	}

	for _, groupKey := range groupKeys {
		messageKey, err := state.retrieveMessageKeyDirectOnly(groupKey.MessageId)
		if err != nil {
			return tracerr.Wrap(err)
		}

		for _, user := range usersToAdd {
			emkAndId := emkAndId{MessageId: groupKey.MessageId}
			for _, device := range user.Devices {
				encryptedMessageKey, err := device.EncryptionKey.Encrypt(messageKey.Encode())
				if err != nil {
					return tracerr.Wrap(err)
				}
				emkAndId.MessageKeys = append(
					emkAndId.MessageKeys,
					encryptedMessageKey2{
						Key:               base64.StdEncoding.EncodeToString(encryptedMessageKey),
						CreatedForKey:     device.Id,
						CreatedForKeyHash: device.EncryptionKey.GetHash(),
					},
				)
			}
			keysToAdd[user.Id] = append(keysToAdd[user.Id], emkAndId) // we can just `append` to nil even if it is not initialized yet, it does not matter (as nil is equivalent to an empty slice)
		}
	}

	// Sending API request
	_, err = handleLocked(state, autoLogin(state, state.apiClient.addGroupMembers), 3)(&addGroupMembersRequest{
		GroupId:                        groupId,
		EditedBeardUsersDeviceMessages: keysToAdd,
		TransactionDataMembers:         block,
		AddedAdmins:                    adminsToSet,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Saving new members locally
	for _, member := range membersToAdd {
		isAdmin := utils.SliceIncludes(adminsToSet, member)
		group.Members = append(group.Members, groupMember{Id: member, IsAdmin: isAdmin})
	}
	state.storage.groups.set(*group)
	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// RemoveGroupMembers removes members from the group.
// Can only be done by a group administrator.
// You should call `RenewGroupKey` after this.
func (state *State) RemoveGroupMembers(groupId string, membersToRemove []string) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckUUIDSlice(membersToRemove)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Lock group user
	state.locks.contactsLockGroup.Lock(groupId)
	defer state.locks.contactsLockGroup.Unlock(groupId)

	// Get updated info about group
	groupUser, err := state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	group := state.storage.groups.get(groupId)
	if group == nil {
		return tracerr.Wrap(ErrorGroupsNotMember)
	}

	// Check that we are allowed to do this
	err = state.checkGroupAdmin(group)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Generating the list of members to remove
	membersToRemoveSet := utils.Set[string]{}
	newMembers := make([]string, 0) // If everybody is removed, newMembers will be an empty array. To avoid it to be omitted at transaction serialization, or serialized to "null", the array must be allocated.

	for _, member := range membersToRemove {
		membersToRemoveSet.Add(member)
	}

	for _, member := range group.Members {
		if !membersToRemoveSet.Has(member.Id) {
			newMembers = append(newMembers, member.Id)
		} else {
			membersToRemoveSet.Remove(member.Id)
		}
	}

	if len(membersToRemoveSet) != 0 {
		return tracerr.Wrap(ErrorGroupsRemoveMembersNotInGroup)
	}

	// Generating sigchain transaction
	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:     sigchain.SIGCHAIN_OPERATION_MEMBERS,
		OperationMembers:  &newMembers,
		OperationDeviceId: group.DeviceId,
		SigningKey:        group.CurrentKey.SigningPrivateKey,
		Position:          groupUser.Sigchain.GetLastBlock().Transaction.Position + 1,
		PreviousHash:      groupUser.Sigchain.GetLastBlock().Signature.Hash,
		SignerDeviceId:    group.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Sending API request
	_, err = handleLocked(state, autoLogin(state, state.apiClient.removeGroupMembers), 3)(&removeGroupMembersRequest{
		GroupId:                groupId,
		TransactionDataMembers: block,
		BeardUsersId:           membersToRemove,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Saving new members locally
	var newGroupMembers []groupMember
	for _, member := range group.Members {
		if !utils.SliceIncludes(membersToRemove, member.Id) {
			newGroupMembers = append(newGroupMembers, member)
		}
	}
	group.Members = newGroupMembers
	state.storage.groups.set(*group)
	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

func decryptPrivateKey(messageKey *symmetric_key.SymKey, b64EncryptedPrivateKey string) (*asymkey.PrivateKey, error) {
	encryptedPrivateKey, err := base64.StdEncoding.DecodeString(b64EncryptedPrivateKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	privateKeyBytes, err := messageKey.Decrypt(encryptedPrivateKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	pKey, err := asymkey.PrivateKeyDecode(privateKeyBytes)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return pKey, nil
}

// RenewGroupKey renews the group's private key.
// Can only be done by a group administrator.
// Should be called after removing members from the group.
func (state *State) RenewGroupKey(groupId string, preGeneratedKeys *PreGeneratedKeys) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Lock group user
	state.locks.contactsLockGroup.Lock(groupId)
	defer state.locks.contactsLockGroup.Unlock(groupId)

	state.logger.Trace().Str("groupId", groupId).Msg("RenewGroupKey: called")

	// Get updated info about group
	groupUser, err := state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	group := state.storage.groups.get(groupId)
	if group == nil {
		return tracerr.Wrap(ErrorGroupsNotMember)
	}
	state.logger.Trace().Str("groupId", groupId).Interface("deviceExpires", group.DeviceExpires).Msg("RenewGroupKey: retrieved group")

	// Check that we are allowed to do this
	err = state.checkGroupAdmin(group)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Generating new keys
	var encryptionKeyPair *asymkey.PrivateKey
	var signingKeyPair *asymkey.PrivateKey
	if preGeneratedKeys == nil {
		state.logger.Trace().Msg("RenewGroupKey: Generating keys...")
		encryptionKeyPair, signingKeyPair, err = generateKeyPair(state.options.KeySize)
		if err != nil {
			return tracerr.Wrap(err)
		}
	} else {
		state.logger.Trace().Msg("RenewGroupKey: Using pre-generated keys.")
		encryptionKeyPair = preGeneratedKeys.EncryptionKey
		signingKeyPair = preGeneratedKeys.SigningKey
	}
	encryptionPublicKey := encryptionKeyPair.Public()
	signingPublicKey := signingKeyPair.Public()

	key, err := symmetric_key.Generate()
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Encrypting new asym keys with new sym key
	encryptedEncryptionPrivateKey, err := key.Encrypt(encryptionKeyPair.Encode())
	if err != nil {
		return tracerr.Wrap(err)
	}
	encryptedSigningPrivateKey, err := key.Encrypt(signingKeyPair.Encode())
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Encrypting the new sym key for all members
	var membersId []string
	for _, member := range group.Members {
		membersId = append(membersId, member.Id)
	}

	keys, err := state.encryptMessageKey(key, membersId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	var keys2 []encryptedMessageKey2

	for _, k := range keys.Keys {
		keys2 = append(keys2, encryptedMessageKey2{Key: k.Token, CreatedForKey: k.CreatedForKey, CreatedForKeyHash: k.CreatedForKeyHash})
	}

	// List all group TMR temporary keys that need to be reencrypted
	state.logger.Trace().Msg("RenewGroupKey: Listing group TMR temporary keys...")
	temporaryKeysToConvert, err := state.listGTMRK(groupId, 1, true, true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	state.logger.Trace().Int("nbr to convert", len(temporaryKeysToConvert.Keys)).Msg("RenewGroupKey: Got group TMR temporary keys to convert")

	reencryptedTempKeys := make(map[string]gTMRTKRenewed)
	for _, keyToConvert := range temporaryKeysToConvert.Keys {
		encryptedSymKeyGroupBytes, err := base64.StdEncoding.DecodeString(keyToConvert.EncryptedSymKeyGroup)
		if err != nil {
			return tracerr.Wrap(err)
		}
		symKeySignatureBytes, err := base64.StdEncoding.DecodeString(keyToConvert.SymKeySignature)
		if err != nil {
			return tracerr.Wrap(err)
		}

		var symKeyBytes []byte
		symKeyBytes, err = group.CurrentKey.EncryptionPrivateKey.Decrypt(encryptedSymKeyGroupBytes)
		if err != nil {
			state.logger.Error().Msg("RenewGroupKey: Cannot decrypt retrived symKey.")
			return tracerr.Wrap(ErrorGroupsRenewGroupKeyCannotDecryptTMRTempKey.AddDetails(err.Error()))
		}
		err = group.CurrentKey.SigningPrivateKey.Public().Verify(symKeyBytes, symKeySignatureBytes)
		if err != nil {
			return tracerr.Wrap(err)
		}

		symKey, err := symmetric_key.Decode(symKeyBytes)
		if err != nil {
			return tracerr.Wrap(err)
		}

		reencryptedKeyBytes, err := symKey.Encrypt(key.Encode())
		if err != nil {
			return tracerr.Wrap(err)
		}
		symkeySignatureBuff, err := group.CurrentKey.SigningPrivateKey.Sign(symKey.Encode())
		if err != nil {
			return tracerr.Wrap(err)
		}
		renewedEncryptedSymKeyBytes, err := group.CurrentKey.EncryptionPrivateKey.Public().Encrypt(symKey.Encode())
		if err != nil {
			return tracerr.Wrap(err)
		}
		reencryptedTempKeys[keyToConvert.Id] = gTMRTKRenewed{
			Data:                 base64.StdEncoding.EncodeToString(reencryptedKeyBytes),
			Signature:            base64.StdEncoding.EncodeToString(symkeySignatureBuff),
			EncryptedSymkeyGroup: base64.StdEncoding.EncodeToString(renewedEncryptedSymKeyBytes),
		}
	}
	state.logger.Trace().Msg("RenewGroupKey: All group TMR temporary keys converted")

	state.logger.Trace().Str("groupId", groupId).Msg("RenewGroupKey: Generating sigchain transaction")
	// Generating sigchain transaction
	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
		OperationEncryptionKey: encryptionPublicKey,
		OperationSigningKey:    signingPublicKey,
		OperationDeviceId:      group.DeviceId,
		ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
		SigningKey:             group.CurrentKey.SigningPrivateKey,
		Position:               groupUser.Sigchain.GetLastBlock().Transaction.Position + 1,
		PreviousHash:           groupUser.Sigchain.GetLastBlock().Signature.Hash,
		SignerDeviceId:         group.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Sending API request
	groupRenewal, err := handleLocked(state, autoLogin(state, state.apiClient.renewGroupKey), 3)(&renewGroupKeyRequest{
		GroupId:                    groupId,
		TransactionData:            block,
		EncryptPubkey:              encryptionPublicKey.ToB64(),
		SigningPubkey:              signingPublicKey.ToB64(),
		EncryptedEncryptionPrivkey: base64.StdEncoding.EncodeToString(encryptedEncryptionPrivateKey),
		EncryptedSigningPrivkey:    base64.StdEncoding.EncodeToString(encryptedSigningPrivateKey),
		MessageKeys:                keys2,
		GroupTMRTemporaryKeys:      reencryptedTempKeys,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Update locally known group
	group.OldKeys = append(group.OldKeys, group.CurrentKey)
	group.CurrentKey = groupKey{
		MessageId:            groupRenewal.GroupDeviceKey.MessageId,
		SigningPrivateKey:    signingKeyPair,
		EncryptionPrivateKey: encryptionKeyPair,
	}
	group.DeviceExpires = time.Unix(groupRenewal.GroupDeviceKey.KeyExpirationDate, 0)
	state.storage.groups.set(*group)

	groupUser.Sigchain.Blocks = append(groupUser.Sigchain.Blocks, block)
	groupUser.Devices[0].SigningKey = signingPublicKey
	groupUser.Devices[0].EncryptionKey = encryptionPublicKey
	state.storage.contacts.set(*groupUser)

	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}

	err = state.saveContacts()
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.logger.Trace().Str("groupId", groupId).Interface("deviceExpires", group.DeviceExpires).Msg("RenewGroupKey: group keys renewed")

	return nil
}

// SetGroupAdmins adds some existing group members to the group admins, and/or removes admin status from some existing group admins.
// Can only be done by a group administrator.
func (state *State) SetGroupAdmins(groupId string, addToAdmins []string, removeFromAdmins []string) error {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckUUIDSlice(addToAdmins)
	if err != nil {
		return tracerr.Wrap(err)
	}
	err = utils.CheckUUIDSlice(removeFromAdmins)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Lock group user
	state.locks.contactsLockGroup.Lock(groupId)
	defer state.locks.contactsLockGroup.Unlock(groupId)

	// Get updated info about group
	_, err = state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}
	group := state.storage.groups.get(groupId)
	if group == nil {
		return tracerr.Wrap(ErrorGroupsNotMember)
	}

	// Check that we are allowed to do this
	err = state.checkGroupAdmin(group)
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Create the array to hold what we are going to send to the server
	var membersToChange []setGroupAdminsRequestElement

	currentMembers := utils.SliceMap(group.Members, func(member groupMember) string { return member.Id })

	// For each member we want to add to admins, check if they are in current members,
	// if they are already admin, and if all is good add them to the array
	for _, newAdminId := range addToAdmins {
		if !utils.SliceIncludes(currentMembers, newAdminId) {
			return tracerr.Wrap(ErrorGroupsSetAdminsAddedNotMember)
		}
		membersToChange = append(membersToChange, setGroupAdminsRequestElement{Id: newAdminId, IsAdmin: true})
	}

	// For each member we want to remove from admins, check if they are in current members,
	// and if all is good add them to the array
	for _, removedAdminId := range removeFromAdmins {
		if !utils.SliceIncludes(currentMembers, removedAdminId) {
			return tracerr.Wrap(ErrorGroupsSetAdminsRemovedNotMember)
		}
		membersToChange = append(membersToChange, setGroupAdminsRequestElement{Id: removedAdminId, IsAdmin: false})
	}

	// Send the array to server
	// TODO: paginate (warning: will have to put the current user in the last page)
	_, err = autoLogin(state, state.apiClient.setGroupAdmins)(&setGroupAdminsRequest{
		GroupId: groupId,
		Members: membersToChange,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	// Saving new admins locally
	var newMembers []groupMember
	for _, oldMember := range group.Members {
		for _, modifiedMember := range membersToChange {
			if modifiedMember.Id == oldMember.Id {
				oldMember.IsAdmin = modifiedMember.IsAdmin
			}
		}
		newMembers = append(newMembers, oldMember)
	}
	group.Members = newMembers
	state.storage.groups.set(*group)
	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

type ListedGroupTMRTemporaryKeys struct {
	NbPage int
	Keys   []*GroupTMRTemporaryKey
}

func (state *State) listGTMRK(groupId string, page int, all bool, full bool) (*ListedGroupTMRTemporaryKeys, error) {
	state.logger.Trace().Bool("all", all).Bool("full", full).Str("groupId", groupId).Int("page", page).Msg("listGTMRK: listing group TMR temp keys...")
	lastPage := utils.Ternary(all, 1000, utils.Ternary(page > 1, page, 1))

	res := &ListedGroupTMRTemporaryKeys{
		NbPage: lastPage,
	}
	for currentPage := utils.Ternary(page > 1, page, 1); currentPage <= lastPage; currentPage++ {
		result, err := autoLogin(state, state.apiClient.listGroupTMRTemporaryKeys)(&listGroupTMRTemporaryKeysRequest{
			GroupId: groupId,
			Page:    currentPage,
			Full:    full,
		})
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		lastPage = utils.Ternary(all, result.NbPage, currentPage)
		res.NbPage = result.NbPage
		res.Keys = append(res.Keys, result.Results...)
	}

	return res, nil

}

// ListGroupTMRTemporaryKeys list a group TMR temporary key.
// If `all` set to true, list all pages after `page`
func (state *State) ListGroupTMRTemporaryKeys(groupId string, page int, all bool) (*ListedGroupTMRTemporaryKeys, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return state.listGTMRK(groupId, page, all, false)
}

// CreateGroupTMRTemporaryKey create a group TMR temporary key.
func (state *State) CreateGroupTMRTemporaryKey(groupId string, authFactor *common_models.AuthFactor, isAdmin bool, rawOverEncryptionKey []byte) (*GroupTMRTemporaryKey, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Str("groupId", groupId).Msg("Calling CreateGroupTMRTemporaryKey...")

	// Lock group user
	state.locks.contactsLockGroup.Lock(groupId)
	defer state.locks.contactsLockGroup.Unlock(groupId)

	// Validate inputs
	err = utils.CheckUUID(groupId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckAuthFactor(authFactor)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	// Doing it early to validate arg value
	overEncryptionTMRSymKey, err := symmetric_key.Decode(rawOverEncryptionKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// Get updated info about group
	_, err = state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	group := state.storage.groups.get(groupId)
	if group == nil {
		return nil, tracerr.Wrap(ErrorGroupsNotMember)
	}

	// Check that we are allowed to do this
	err = state.checkGroupAdmin(group)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Msg("CreateGroupTMRTemporaryKey: Generating new temporary symKey")
	symKey, err := symmetric_key.Generate()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedSymKeyRoekBytes, err := overEncryptionTMRSymKey.Encrypt(symKey.Encode())
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedSymKeyGroupBytes, err := group.CurrentKey.EncryptionPrivateKey.Public().Encrypt(symKey.Encode())
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	symkeySignatureBuff, err := group.CurrentKey.SigningPrivateKey.Sign(symKey.Encode())
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	state.logger.Trace().Msg("CreateGroupTMRTemporaryKey: All key instantiated. Generating userDevicesMessages...")
	// generating userDevicesMessages
	var groupKeys []groupKey
	if group.OldKeys != nil {
		groupKeys = append(groupKeys, group.OldKeys...)
	}
	groupKeys = append(groupKeys, group.CurrentKey)

	var encGroupDeviceKeys = make(map[string]string)
	for _, groupKey := range groupKeys {
		messageKey, err := state.retrieveMessageKeyDirectOnly(groupKey.MessageId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		tokenBuff, err := symKey.Encrypt(messageKey.Encode())
		encGroupDeviceKeys[groupKey.MessageId] = base64.StdEncoding.EncodeToString(tokenBuff)
	}

	result, err := autoLogin(state, state.apiClient.createGroupTMRTemporaryKey)(&createGroupTMRTemporaryKeyRequest{
		GroupId:              groupId,
		IsAdmin:              isAdmin,
		AuthFactorType:       authFactor.Type,
		AuthFactorValue:      authFactor.Value,
		EncryptedSymKeyRoek:  base64.StdEncoding.EncodeToString(encryptedSymKeyRoekBytes),
		EncryptedSymKeyGroup: base64.StdEncoding.EncodeToString(encryptedSymKeyGroupBytes),
		SymkeySignature:      base64.StdEncoding.EncodeToString(symkeySignatureBuff),
		EncGroupDeviceKeys:   encGroupDeviceKeys,
	})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return result, nil
}

// DeleteGroupTMRTemporaryKey delete a groupTMRTemporaryKey
func (state *State) DeleteGroupTMRTemporaryKey(groupId string, temporaryKeyId string) error {
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}
	_, err = autoLogin(state, state.apiClient.deleteGroupTMRTemporaryKey)(&deleteGroupTMRTemporaryKeyRequest{
		GroupId:        groupId,
		TemporaryKeyId: temporaryKeyId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

type SearchGroupTMRTemporaryKeysOpts struct {
	GroupId string
	Page    int
	All     bool
}

// SearchGroupTMRTemporaryKeys search group TMR temporary keys that this tmrJWT could convert
func (state *State) SearchGroupTMRTemporaryKeys(tmrJWT string, opts *SearchGroupTMRTemporaryKeysOpts) (*ListedGroupTMRTemporaryKeys, error) {
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	state.logger.Trace().Interface("opts", opts).Msg("Calling SearchGroupTMRTemporaryKeys")
	if opts == nil {
		opts = &SearchGroupTMRTemporaryKeysOpts{}
	}

	lastPage := utils.Ternary(opts.All, 1000, utils.Ternary(opts.Page > 1, opts.Page, 1))
	res := &ListedGroupTMRTemporaryKeys{
		NbPage: lastPage,
	}
	for currentPage := utils.Ternary(opts.Page > 1, opts.Page, 1); currentPage <= lastPage; currentPage++ {
		state.logger.Trace().Int("currentPage", currentPage).Msg("SearchGroupTMRTemporaryKeys: fetching next page...")
		result, err := autoLogin(state, state.apiClient.searchGroupTMRTemporaryKeys)(&searchGroupTMRTemporaryKeysRequest{
			TmrJWT:  tmrJWT,
			GroupId: opts.GroupId,
			Page:    currentPage,
		})
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		lastPage = utils.Ternary(opts.All, result.NbPage, currentPage)
		res.NbPage = result.NbPage
		res.Keys = append(res.Keys, result.Results...)
	}

	return res, nil
}

// ConvertGroupTMRTemporaryKey convert group TMR temporary key to a group membership.
func (state *State) ConvertGroupTMRTemporaryKey(groupId string, temporaryKeyId string, tmrJWT string, rawOverEncryptionKey []byte, deleteOnConvert bool) error {
	err := state.checkSdkState(true)
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.logger.Trace().Str("groupId", groupId).Str("temporaryKeyId", temporaryKeyId).Msg("Calling ConvertGroupTMRTemporaryKey")
	lastPage := 1000
	var gtmrk *gtmrtk
	var messagesToConvert []*groupDeviceKeyData
	for currentPage := 1; currentPage <= lastPage; currentPage++ {
		result, err := autoLogin(state, state.apiClient.getGroupTMRTemporaryKey)(&getGroupTMRTemporaryKeyRequest{
			GroupId:        groupId,
			TemporaryKeyId: temporaryKeyId,
			TmrJWT:         tmrJWT,
			Page:           currentPage,
		})
		if err != nil {
			return tracerr.Wrap(err)
		}

		lastPage = result.NbPage
		gtmrk = result.Gtmrtk
		messagesToConvert = append(messagesToConvert, result.Results...)
	}
	state.logger.Trace().Int("messagesToConvert len:", len(messagesToConvert)).Msg("ConvertGroupTMRTemporaryKey: got messages to convert")

	overEncryptionTMRSymKey, err := symmetric_key.Decode(rawOverEncryptionKey)
	if err != nil {
		return tracerr.Wrap(err)
	}

	encryptedSymKeyRoekBytes, err := base64.StdEncoding.DecodeString(gtmrk.EncryptedSymKeyRoek)
	if err != nil {
		return err
	}
	symKeyBytes, err := overEncryptionTMRSymKey.Decrypt(encryptedSymKeyRoekBytes)
	if err != nil {
		return err
	}
	symKey, err := symmetric_key.Decode(symKeyBytes)
	if err != nil {
		return err
	}

	state.logger.Trace().Msg("ConvertGroupTMRTemporaryKey: start converting keys")
	var convertedKey []emkAndId
	var groupKeys []groupKey
	var keyExpireAt []time.Time
	// Make sure messagesToConvert are sorted, the oldest first, the most recent last.
	sort.Slice(messagesToConvert, func(i, j int) bool {
		return messagesToConvert[i].GroupDeviceKey.Created.Before(messagesToConvert[j].GroupDeviceKey.Created)
	})
	for _, keyToConvert := range messagesToConvert {
		dataBuff, err := base64.StdEncoding.DecodeString(keyToConvert.Data)
		if err != nil {
			return err
		}
		messageKeyBuff, err := symKey.Decrypt(dataBuff)
		if err != nil {
			return err
		}
		messageKey, err := symmetric_key.Decode(messageKeyBuff)
		if err != nil {
			return err
		}

		encEncPrivKBytes, err := base64.StdEncoding.DecodeString(keyToConvert.GroupDeviceKey.EncryptedEncryptionPrivateKey)
		if err != nil {
			return err
		}
		clearEncPrivKey, err := messageKey.Decrypt(encEncPrivKBytes)
		if err != nil {
			return err
		}

		encSigPrivKBytes, err := base64.StdEncoding.DecodeString(keyToConvert.GroupDeviceKey.EncryptedSigningPrivateKey)
		if err != nil {
			return err
		}
		clearSigPrivKey, err := messageKey.Decrypt(encSigPrivKBytes)
		if err != nil {
			return err
		}

		encKey, err := asymkey.PrivateKeyDecode(clearEncPrivKey)
		if err != nil {
			return err
		}
		sigKey, err := asymkey.PrivateKeyDecode(clearSigPrivKey)
		if err != nil {
			return err
		}
		keyPair := groupKey{
			MessageId:            keyToConvert.GroupDeviceKey.MessageId,
			EncryptionPrivateKey: encKey,
			SigningPrivateKey:    sigKey,
		}
		groupKeys = append(groupKeys, keyPair)
		keyExpireAt = append(keyExpireAt, time.Unix(int64(keyToConvert.GroupDeviceKey.KeyExpirationDate), 0))

		userDevices := state.storage.contacts.get(state.storage.currentDevice.get().UserId)
		var convertedEMK []encryptedMessageKey2
		for _, uDevice := range userDevices.Devices {
			emk, err := uDevice.EncryptionKey.Encrypt(messageKeyBuff)
			if err != nil {
				return err
			}
			emkB64 := base64.StdEncoding.EncodeToString(emk)
			convertedEMK = append(convertedEMK, encryptedMessageKey2{
				Key:               utils.B64toS64(emkB64),
				CreatedForKey:     uDevice.Id,
				CreatedForKeyHash: uDevice.EncryptionKey.GetHash(),
			})
		}

		convertedKey = append(convertedKey, emkAndId{
			MessageId:   keyToConvert.GroupDeviceKey.MessageId,
			MessageKeys: convertedEMK,
		})
	}
	state.logger.Trace().Msg("ConvertGroupTMRTemporaryKey: finished keys conversion")

	// Get updated info about group
	groupContact, err := state.getUpdatedContactUnlocked(groupId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.logger.Trace().Interface("groupContact", groupContact).Msg("ConvertGroupTMRTemporaryKey: retrieveGroupInfo...")

	members, err := autoLogin(state, state.apiClient.listGroupMembers)(&listGroupMembersRequest{GroupId: groupId})
	if err != nil {
		return tracerr.Wrap(err)
	}
	var newMembers []groupMember
	var newMembersIds []string
	for _, member := range members.GroupMember {
		newMembersIds = append(newMembersIds, member.Id)
		newMembers = append(newMembers, groupMember{Id: member.Id, IsAdmin: member.IsAdmin})
	}
	newMembers = append(newMembers, groupMember{Id: state.storage.currentDevice.get().UserId, IsAdmin: gtmrk.IsAdmin})
	newMembersIds = append(newMembersIds, state.storage.currentDevice.get().UserId)

	state.logger.Trace().Interface("members", members).Msg("ConvertGroupTMRTemporaryKey: Creating groupUser...")
	groupUser := group{
		Id:            groupId,
		DeviceId:      groupContact.Devices[0].Id,
		CurrentKey:    groupKeys[len(groupKeys)-1],
		Members:       newMembers,
		DeviceExpires: keyExpireAt[len(keyExpireAt)-1],
		OldKeys:       groupKeys[:len(groupKeys)-1],
	}

	state.logger.Trace().Msg("ConvertGroupTMRTemporaryKey: create sigchain transaction")
	// Generating sigchain transaction with the new members list
	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:     sigchain.SIGCHAIN_OPERATION_MEMBERS,
		OperationMembers:  &newMembersIds,
		OperationDeviceId: groupUser.DeviceId,
		SigningKey:        groupUser.CurrentKey.SigningPrivateKey,
		Position:          groupContact.Sigchain.GetLastBlock().Transaction.Position + 1,
		PreviousHash:      groupContact.Sigchain.GetLastBlock().Signature.Hash,
		SignerDeviceId:    groupUser.DeviceId,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}
	groupSigchain := sigchain.Sigchain{
		Blocks: append(groupContact.Sigchain.Blocks, block),
	}
	checkResult, err := sigchain.CheckSigchainTransactions(groupSigchain, false)
	if err != nil {
		return tracerr.Wrap(err)
	}
	groupDevices := []*device{
		{
			Id:            groupUser.DeviceId,
			EncryptionKey: groupKeys[len(groupKeys)-1].EncryptionPrivateKey.Public(),
			SigningKey:    groupKeys[len(groupKeys)-1].SigningPrivateKey.Public(),
		},
	}
	err = checkKeyringMatchesSigChain(checkResult, groupDevices)
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.logger.Trace().Msg("ConvertGroupTMRTemporaryKey: api call and save.")
	keysToAdd := make(map[string][]emkAndId)
	keysToAdd[state.storage.currentDevice.get().UserId] = convertedKey
	_, err = autoLogin(state, state.apiClient.convertGroupTMRTemporaryKey)(&convertGroupTMRTemporaryKeyRequest{
		GroupId:                groupId,
		TemporaryKeyId:         temporaryKeyId,
		TmrJWT:                 tmrJWT,
		DeleteOnConvert:        deleteOnConvert,
		UserDevicesMessages:    keysToAdd,
		TransactionDataMembers: block,
	})
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.storage.groups.set(groupUser)
	state.storage.contacts.set(contact{
		Id:       groupId,
		IsGroup:  true,
		Sigchain: groupSigchain,
		Devices:  groupDevices,
	})

	err = state.saveGroups()
	if err != nil {
		return tracerr.Wrap(err)
	}

	err = state.saveContacts()
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}
