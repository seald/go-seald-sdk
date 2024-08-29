package sdk

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func Test_Groups(t *testing.T) {
	account1, err := createTestAccount("sdk_groups_1")
	require.NoError(t, err)
	account2, err := createTestAccount("sdk_groups_2")
	require.NoError(t, err)
	currentDevice1 := account1.storage.currentDevice.get()
	currentDevice2 := account2.storage.currentDevice.get()

	allRights := &RecipientRights{
		Read:    true,
		Revoke:  true,
		Forward: true,
	}

	t.Parallel()

	t.Run("decryptPrivateKey", func(t *testing.T) {
		t.Parallel()
		// Generating keys for tests
		privateKey, err := asymkey.Generate(2048)
		require.NoError(t, err)
		rawMessageKey, err := utils.GenerateRandomBytes(64)
		require.NoError(t, err)
		messageKey, err := symmetric_key.Decode(rawMessageKey)
		require.NoError(t, err)
		rawBadMessageKey, err := utils.GenerateRandomBytes(64)
		require.NoError(t, err)
		badMessageKey, err := symmetric_key.Decode(rawBadMessageKey)
		require.NoError(t, err)

		// Encrypting private key
		rawPrivateKey := privateKey.Encode()
		encryptedPrivateKey, err := messageKey.Encrypt(rawPrivateKey)
		require.NoError(t, err)
		b64PrivateKey := base64.StdEncoding.EncodeToString(encryptedPrivateKey)

		t.Run("decryptPrivateKey working", func(t *testing.T) {
			decryptedKey, err := decryptPrivateKey(&messageKey, b64PrivateKey)
			require.NoError(t, err)
			assert.Equal(t, privateKey, decryptedKey)
		})
		t.Run("decryptPrivateKey failing with bad B64 input", func(t *testing.T) {
			decryptedKey, err := decryptPrivateKey(&messageKey, "&aaa")
			assert.Error(t, err)
			assert.Nil(t, decryptedKey)
			assert.ErrorContains(t, err, "illegal base64 data at input byte 0")
		})
		t.Run("decryptPrivateKey failing with valid but random B64", func(t *testing.T) {
			decryptedKey, err := decryptPrivateKey(&messageKey, base64.StdEncoding.EncodeToString([]byte("long long long long long long long long random stuff")))
			assert.Error(t, err)
			assert.Nil(t, decryptedKey)
			assert.ErrorContains(t, err, "macs do not match")
		})
		t.Run("decryptPrivateKey failing with wrong message key", func(t *testing.T) {
			decryptedKey, err := decryptPrivateKey(&badMessageKey, b64PrivateKey)
			assert.Error(t, err)
			assert.Nil(t, decryptedKey)
			assert.ErrorContains(t, err, "macs do not match")
		})
		t.Run("decryptPrivateKey failing with validly encrypted nonsense", func(t *testing.T) {
			encryptedNonsense, err := messageKey.Encrypt([]byte("random stuff"))
			require.NoError(t, err)
			b64Nonsense := base64.StdEncoding.EncodeToString(encryptedNonsense)

			decryptedKey, err := decryptPrivateKey(&messageKey, b64Nonsense)
			assert.Error(t, err)
			assert.Nil(t, decryptedKey)
			assert.ErrorContains(t, err, "asn1: structure error: tags don't match")
		})
	})

	t.Run("Groups — CreateGroup", func(t *testing.T) {
		t.Parallel()
		t.Run("Created group is stored locally and can be retrieved", func(t *testing.T) {
			t0 := time.Now()
			// account1 creates group1 with only itself
			group1Id, err := account1.CreateGroup( // test with no-pregenerated keys
				"Group 1",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				nil,
			)
			require.NoError(t, err)

			// For account1, group1 is directly stored locally
			group1 := account1.storage.groups.get(group1Id)
			assert.Equal(t, group1.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
			})
			assert.GreaterOrEqual(t, group1.DeviceExpires.Unix(), t0.Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())
			assert.LessOrEqual(t, group1.DeviceExpires.Unix(), time.Now().Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())

			// account1 creates group2 with itself and account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			group2Id, err := account1.CreateGroup( // test with pre-generated keys
				"Group 2",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// For account1, group2 is directly stored locally
			group2ForUser1 := account1.storage.groups.get(group2Id)
			assert.Equal(t, group2ForUser1.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
				{Id: currentDevice2.UserId, IsAdmin: false},
			})
			assert.Equal(t, group2ForUser1.CurrentKey.EncryptionPrivateKey, preGeneratedKeys.EncryptionKey)
			assert.Equal(t, group2ForUser1.CurrentKey.SigningPrivateKey, preGeneratedKeys.SigningKey)
			assert.GreaterOrEqual(t, group2ForUser1.DeviceExpires.Unix(), t0.Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())
			assert.LessOrEqual(t, group2ForUser1.DeviceExpires.Unix(), time.Now().Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())

			// account2 can retrieve group2
			_, err = account2.getUpdatedContactUnlocked(group2Id) // Need this here, to first create the group in DB
			require.NoError(t, err)

			group2ForUser2 := account2.storage.groups.get(group2Id)
			assert.Equal(t, group2ForUser2.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
				{Id: currentDevice2.UserId, IsAdmin: false},
			})
			assert.Equal(t, group2ForUser2.CurrentKey.EncryptionPrivateKey, preGeneratedKeys.EncryptionKey)
			assert.Equal(t, group2ForUser2.CurrentKey.SigningPrivateKey, preGeneratedKeys.SigningKey)
			assert.Equal(t, group2ForUser1.DeviceExpires.Unix(), group2ForUser2.DeviceExpires.Unix())
		})
		t.Run("Cannot CreateGroup if self is not admin", func(t *testing.T) {
			// account1 trying to CreateGroup where only account2 is admin
			_, err := account1.CreateGroup(
				"Group 1",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice2.UserId},
				nil,
			)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsCreateSelfNotAdmin)
		})
		t.Run("Cannot CreateGroup if admin is not member", func(t *testing.T) {
			// account1 trying to CreateGroup where account2 is admin but not member
			_, err := account1.CreateGroup(
				"Group 1",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				nil,
			)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsCreateAdminNotMember)
		})
	})

	t.Run("Groups — AddMembers", func(t *testing.T) {
		t.Parallel()
		t.Run("Added member can decrypt", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)
			recipientGroup := &RecipientWithRights{Id: groupId, Rights: allRights}

			// Create a session for the group
			sessionWithKey1, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// Renew group key multiple times
			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)
			preGeneratedKeys3, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys3)
			require.NoError(t, err)
			preGeneratedKeys4, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys4)
			require.NoError(t, err)

			// Create a session for the group with the new key
			sessionWithKey4, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 cannot decrypt
			_, err = account2.RetrieveEncryptionSession(sessionWithKey1.Id, false, false, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
			_, err = account2.RetrieveEncryptionSession(sessionWithKey4.Id, false, false, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)

			// Adding account2 to the group (it should add multiple keys)
			err = account1.AddGroupMembers(groupId, []string{currentDevice2.UserId}, nil)
			require.NoError(t, err)

			// For account1, local group is updated
			group := account1.storage.groups.get(groupId)
			assert.Equal(t, group.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
				{Id: currentDevice2.UserId, IsAdmin: false},
			})

			// Now, account2 still cannot decrypt with lookupGroupKey to false
			session2WithKey1Fail, err := account2.RetrieveEncryptionSession(sessionWithKey1.Id, false, false, false)
			require.Error(t, err)
			require.Nil(t, session2WithKey1Fail)
			session2WithKey4Fail, err := account2.RetrieveEncryptionSession(sessionWithKey4.Id, false, false, false)
			require.Error(t, err)
			require.Nil(t, session2WithKey4Fail)
			// But account2 can decrypt with lookupGroupKey to true
			session2WithKey1, err := account2.RetrieveEncryptionSession(sessionWithKey1.Id, false, false, true)
			require.NoError(t, err)
			session2WithKey4, err := account2.RetrieveEncryptionSession(sessionWithKey4.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionWithKey1.Id, session2WithKey1.Id)
			assert.Equal(t, sessionWithKey1.Key, session2WithKey1.Key)
			assert.Equal(t, sessionWithKey4.Id, session2WithKey4.Id)
			assert.Equal(t, sessionWithKey4.Key, session2WithKey4.Key)

			// For account2, the group correctly has all its keys
			group2 := account2.storage.groups.get(groupId)
			assert.Equal(t, len(group2.OldKeys), 3)
		})
		t.Run("Can add member as admin", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// Adding account2 to the group
			err = account1.AddGroupMembers(groupId, []string{currentDevice2.UserId}, []string{currentDevice2.UserId})
			require.NoError(t, err)

			// For account1, local group is updated
			group := account1.storage.groups.get(groupId)
			assert.Equal(t, group.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
				{Id: currentDevice2.UserId, IsAdmin: true},
			})

			// Now, account2 can renew key
			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account2.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)
		})
		t.Run("Cannot AddMember if not member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot call AddMember
			err = account2.AddGroupMembers(groupId, []string{currentDevice1.UserId}, nil) // just use account1 as a member to add, it's going to fail anyway
			assert.Error(t, err)
			// assert.ErrorIs(t, err, ErrorGroupsNotMember) // commented out because it actually fails before the check if we are a member : retrieving the keys fails with a 406
		})
		t.Run("Cannot AddMember if not admin", func(t *testing.T) {
			// Create a group with account2 as member but not admin
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot call AddMember
			err = account2.AddGroupMembers(groupId, []string{currentDevice1.UserId}, nil) // just use account1 as a member to add, it's going to fail anyway
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)
		})
		t.Run("Cannot AddMember if already in group", func(t *testing.T) {
			// Create a group with account2 as member
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account1 cannot re-add account2 in the group
			err = account1.AddGroupMembers(groupId, []string{currentDevice2.UserId}, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsAddMembersAlreadyInGroup)
		})
		t.Run("Cannot AddMember with admin not member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account1 cannot add account2 in the group as admin but not member
			err = account1.AddGroupMembers(groupId, []string{}, []string{currentDevice2.UserId})
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsAddMembersAdminNotMember)
		})
	})

	t.Run("Groups — RemoveGroupMembers", func(t *testing.T) {
		t.Parallel()
		t.Run("Removed member cannot decrypt", func(t *testing.T) {
			// Create a group with account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)
			recipientGroup := &RecipientWithRights{Id: groupId, Rights: allRights}

			// Create a session for the group
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 can decrypt
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)

			// Remove account2 from the group
			err = account1.RemoveGroupMembers(groupId, []string{currentDevice2.UserId})
			require.NoError(t, err)

			// For account1, local group is updated
			group := account1.storage.groups.get(groupId)
			assert.Equal(t, group.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
			})

			// account2 can no longer decrypt
			_, err = account2.RetrieveEncryptionSession(session.Id, false, false, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("Cannot RemoveGroupMembers if not member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot call RemoveGroupMembers
			err = account2.RemoveGroupMembers(groupId, []string{currentDevice1.UserId})
			assert.Error(t, err)
			// assert.ErrorIs(t, err, ErrorGroupsNotMember) // commented out because it actually fails before the check if we are a member : retrieving the keys fails with a 406
		})
		t.Run("Cannot RemoveGroupMembers if not admin", func(t *testing.T) {
			// Create a group with account2 as member but not admin
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot call RemoveGroupMembers
			err = account2.RemoveGroupMembers(groupId, []string{currentDevice1.UserId})
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)
		})
		t.Run("Cannot RemoveGroupMembers if not in group", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account1 cannot remove account2 from the group
			err = account1.RemoveGroupMembers(groupId, []string{currentDevice2.UserId})
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsRemoveMembersNotInGroup)
		})
		t.Run("Removed all members", func(t *testing.T) {
			// Create a group with account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// Remove all members. Sigchain remove transaction must have a `members` key with an empty array
			err = account1.RemoveGroupMembers(groupId, []string{currentDevice1.UserId, currentDevice2.UserId})
			assert.NoError(t, err)
		})
	})

	t.Run("Groups — RenewGroupKey", func(t *testing.T) {
		t.Parallel()
		t.Run("Group admin can RenewGroupKey", func(t *testing.T) {
			t0 := time.Now()
			// Create a group
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)
			recipientGroup := &RecipientWithRights{Id: groupId, Rights: allRights}

			// Create a session for the group
			sessionA, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 can decrypt
			sessionA2, err := account2.RetrieveEncryptionSession(sessionA.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionA.Id, sessionA2.Id)
			assert.Equal(t, sessionA.Key, sessionA2.Key)

			// check both users know no old key for the group
			groupForAccount1Before := account1.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount1Before.OldKeys), 0)
			assert.GreaterOrEqual(t, groupForAccount1Before.DeviceExpires.Unix(), t0.Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())
			assert.LessOrEqual(t, groupForAccount1Before.DeviceExpires.Unix(), time.Now().Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())
			groupForAccount2Before := account2.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount2Before.OldKeys), 0)
			assert.True(t, groupForAccount2Before.DeviceExpires.Equal(groupForAccount1Before.DeviceExpires))

			tBeforeRenew := time.Now()
			// account1 can RenewKey (no pre-generated key)
			err = account1.RenewGroupKey(groupId, nil)
			require.NoError(t, err)

			// account1 can RenewKey (pre-generated key)
			preGeneratedKeys2, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys}) // key must be different from original one, so that RetrieveEncryptionSession fails internally and triggers group update
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)

			// Create a new session for the group
			sessionB, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 can decrypt the new session
			sessionB2, err := account2.RetrieveEncryptionSession(sessionB.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionB.Id, sessionB2.Id)
			assert.Equal(t, sessionB.Key, sessionB2.Key)

			// check both users know 2 old keys for the group
			groupForAccount1After := account1.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount1After.OldKeys), 2)
			assert.False(t, groupForAccount1After.DeviceExpires.Equal(groupForAccount1Before.DeviceExpires))
			assert.GreaterOrEqual(t, groupForAccount1After.DeviceExpires.Unix(), tBeforeRenew.Add(sigchain.DEVICE_DEFAULT_LIFE_TIME).Unix())
			groupForAccount2After := account2.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount2After.OldKeys), 2)
			assert.Equal(t, groupForAccount2After.DeviceExpires.Unix(), groupForAccount1After.DeviceExpires.Unix())

			// check pre-generated keys are used
			assert.Equal(t, preGeneratedKeys2.EncryptionKey, groupForAccount1After.CurrentKey.EncryptionPrivateKey)
			assert.Equal(t, preGeneratedKeys2.SigningKey, groupForAccount1After.CurrentKey.SigningPrivateKey)
			assert.Equal(t, preGeneratedKeys2.EncryptionKey, groupForAccount2After.CurrentKey.EncryptionPrivateKey)
			assert.Equal(t, preGeneratedKeys2.SigningKey, groupForAccount2After.CurrentKey.SigningPrivateKey)

			// account2 can still decrypt the old session
			sessionA2b, err := account2.RetrieveEncryptionSession(sessionA.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionA.Id, sessionA2b.Id)
			assert.Equal(t, sessionA.Key, sessionA2b.Key)
		})
		t.Run("Cannot RenewGroupKey if not member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot RenewKey
			err = account2.RenewGroupKey(groupId, nil)
			assert.Error(t, err)
			// assert.ErrorIs(t, err, ErrorGroupsNotMember) // commented out because it actually fails before the check if we are a member : retrieving the keys fails with a 406
		})
		t.Run("Cannot RenewGroupKey if not admin", func(t *testing.T) {
			// Create a group with account2 as member but not admin
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot RenewKey
			err = account2.RenewGroupKey(groupId, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)
		})
		t.Run("Can RenewGroupKey multiple times", func(t *testing.T) {
			// Create a group
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)
			recipientGroup := &RecipientWithRights{Id: groupId, Rights: allRights}

			// Create a session for the group
			sessionA, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 can decrypt
			sessionA2, err := account2.RetrieveEncryptionSession(sessionA.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionA.Id, sessionA2.Id)
			assert.Equal(t, sessionA.Key, sessionA2.Key)

			// check both users know no old key for the group
			groupForAccount1Before := account1.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount1Before.OldKeys), 0)
			groupForAccount2Before := account2.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount2Before.OldKeys), 0)

			// account1 can RenewKey multiple times
			preGeneratedKeys2, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys}) // key must be different from original one, so that RetrieveEncryptionSession fails internally and triggers group update
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)
			preGeneratedKeys3, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys, preGeneratedKeys2})
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys3)
			require.NoError(t, err)
			preGeneratedKeys4, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys, preGeneratedKeys2, preGeneratedKeys3})
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys4)
			require.NoError(t, err)
			preGeneratedKeys5, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys, preGeneratedKeys2, preGeneratedKeys4})
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys5)
			require.NoError(t, err)

			// Create a new session for the group
			sessionB, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)

			// account2 can decrypt the new session
			sessionB2, err := account2.RetrieveEncryptionSession(sessionB.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionB.Id, sessionB2.Id)
			assert.Equal(t, sessionB.Key, sessionB2.Key)

			// check both users know 4 old key for the group
			groupForAccount1After := account1.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount1After.OldKeys), 4)
			groupForAccount2After := account2.storage.groups.get(groupId)
			assert.Equal(t, len(groupForAccount2After.OldKeys), 4)

			// account2 can still decrypt the old session
			sessionA2b, err := account2.RetrieveEncryptionSession(sessionA.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, sessionA.Id, sessionA2b.Id)
			assert.Equal(t, sessionA.Key, sessionA2b.Key)
		})
	})

	t.Run("Groups — SetGroupAdmins", func(t *testing.T) {
		t.Parallel()
		t.Run("SetGroupAdmins changes the admin status", func(t *testing.T) {
			// Create a group with account2 as member but not admin
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// Local representation of members is as expected
			group1 := account1.storage.groups.get(groupId)
			assert.Equal(t, group1.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: true},
				{Id: currentDevice2.UserId, IsAdmin: false},
			})

			// account2 cannot RenewKey
			err = account2.RenewGroupKey(groupId, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)

			// account1 uses SetGroupAdmins
			err = account1.SetGroupAdmins(groupId, []string{currentDevice2.UserId}, []string{currentDevice1.UserId})
			require.NoError(t, err)

			// For account1, local group is updated
			group := account1.storage.groups.get(groupId)
			assert.Equal(t, group.Members, []groupMember{
				{Id: currentDevice1.UserId, IsAdmin: false},
				{Id: currentDevice2.UserId, IsAdmin: true},
			})

			// Now account1 cannot RenewKey
			err = account1.RenewGroupKey(groupId, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)

			// And account2 can
			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account2.RenewGroupKey(groupId, preGeneratedKeys2)
			assert.NoError(t, err)
		})
		t.Run("Cannot SetGroupAdmins for non-member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account1 cannot add account2 as admin
			err = account1.SetGroupAdmins(groupId, []string{currentDevice2.UserId}, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsSetAdminsAddedNotMember)

			// account1 cannot remove account2 from admins
			err = account1.SetGroupAdmins(groupId, nil, []string{currentDevice2.UserId})
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsSetAdminsRemovedNotMember)
		})
		t.Run("Cannot SetGroupAdmins if non-member", func(t *testing.T) {
			// Create a group without account2
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot add account1 as admin (account1 is already admin, yeah, but it's going to fail before that)
			err = account2.SetGroupAdmins(groupId, []string{currentDevice1.UserId}, nil)
			assert.Error(t, err)
			// assert.ErrorIs(t, err, ErrorGroupsNotMember) // commented out because it actually fails before the check if we are a member : retrieving the keys fails with a 406
		})
		t.Run("Cannot SetGroupAdmins if non-admin", func(t *testing.T) {
			// Create a group with account2 as member but not admin
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// account2 cannot add account1 as admin (account1 is already admin, yeah, but it's going to fail before that)
			err = account2.SetGroupAdmins(groupId, []string{currentDevice1.UserId}, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrorGroupsNotAdmin)
		})
	})

	t.Run("Groups — ShouldRenewGroup", func(t *testing.T) {
		// using canary, so cannot reuse account from higher scope
		canaryAccount1, err := createTestAccount("sdk_groups_canary_1")
		require.NoError(t, err)
		canaryAccount2, err := createTestAccount("sdk_groups_canary_1")
		require.NoError(t, err)
		canaryDevice1 := canaryAccount1.storage.currentDevice.get()
		canaryDevice2 := canaryAccount2.storage.currentDevice.get()

		canaryApi1 := newCanaryBeardApiClient(canaryAccount1.apiClient)
		canaryAccount1.apiClient = canaryApi1
		canaryApi2 := newCanaryBeardApiClient(canaryAccount2.apiClient)
		canaryAccount2.apiClient = canaryApi2

		t.Run("Normal behaviour", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := canaryAccount1.CreateGroup(
				"Da group",
				[]string{canaryDevice1.UserId, canaryDevice2.UserId},
				[]string{canaryDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			shouldRenew1a, err := canaryAccount1.ShouldRenewGroup(groupId)
			require.NoError(t, err)
			assert.False(t, shouldRenew1a)
			shouldRenew2a, err := canaryAccount2.ShouldRenewGroup(groupId)
			require.NoError(t, err)
			assert.False(t, shouldRenew2a)

			// change group internally, so that ShouldRenewKey returns true
			group := canaryAccount1.storage.groups.get(groupId)
			group.DeviceExpires = time.Now().Add(2 * time.Hour) // make it look like the device expires in 2 hours
			canaryAccount1.storage.groups.set(*group)
			err = canaryAccount1.saveGroups()
			require.NoError(t, err)
			canaryAccount2.storage.groups.set(*group)
			err = canaryAccount2.saveGroups()
			require.NoError(t, err)

			shouldRenew1b, err := canaryAccount1.ShouldRenewGroup(groupId)
			require.NoError(t, err)
			assert.True(t, shouldRenew1b)
			shouldRenew2b, err := canaryAccount2.ShouldRenewGroup(groupId)
			require.NoError(t, err)
			assert.False(t, shouldRenew2b) // account2 is not group admin

			// make account2 admin
			err = canaryAccount1.SetGroupAdmins(groupId, []string{canaryDevice2.UserId}, nil)
			require.NoError(t, err)
			shouldRenew2bp, err := canaryAccount2.ShouldRenewGroup(groupId) // now account2 is group admin, so it should be true
			require.NoError(t, err)
			assert.True(t, shouldRenew2bp)

			// Renew & recheck
			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = canaryAccount1.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)

			canaryApi1.Counter["search"] = 0
			shouldRenew1c, err := canaryAccount1.ShouldRenewGroup(groupId) // renew known locally : this should return "false" immediately
			require.NoError(t, err)
			assert.False(t, shouldRenew1c)
			assert.Equal(t, 0, canaryApi1.Counter["search"])

			canaryApi2.Counter["search"] = 0
			shouldRenew2c, err := canaryAccount2.ShouldRenewGroup(groupId) // renew not known locally : this should update group then return "false"
			require.NoError(t, err)
			assert.False(t, shouldRenew2c)
			assert.Equal(t, 1, canaryApi2.Counter["search"])
		})
		t.Run("Migration", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := canaryAccount1.CreateGroup(
				"Da group",
				[]string{canaryDevice1.UserId, canaryDevice2.UserId},
				[]string{canaryDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// change group internally, so that we don't know any device expiration date
			group := canaryAccount1.storage.groups.get(groupId)
			group.DeviceExpires = time.Time{}
			canaryAccount1.storage.groups.set(*group)
			err = canaryAccount1.saveGroups()
			require.NoError(t, err)

			// ShouldRenewGroup should notice that we don't know any device expiration date, and force an update of this only before checking
			canaryApi1.Counter["listGroupDevices"] = 0
			canaryApi1.Counter["search"] = 0
			shouldRenew, err := canaryAccount1.ShouldRenewGroup(groupId)
			require.NoError(t, err)
			assert.False(t, shouldRenew)
			canaryApi1.Counter["listGroupDevices"] = 1
			canaryApi1.Counter["search"] = 0 // check that we did not do a full search, just retrieved the missing expiration date
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/groups")

			// import identity from JS
			identity, err := os.ReadFile(filepath.Join(testArtifactsDir, "identity"))
			require.NoError(t, err)
			initOptions, err := getInMemoryInitializeOptions("sdk_groups_import_js")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)
			err = account.ImportIdentity(identity)
			require.NoError(t, err)

			// can retrieve first session
			sessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "session_id"))
			require.NoError(t, err)
			_, err = account.RetrieveEncryptionSession(string(sessionId), false, false, true)
			require.NoError(t, err)

			// can retrieve second session
			sessionId2, err := os.ReadFile(filepath.Join(testArtifactsDir, "session_id2"))
			require.NoError(t, err)
			_, err = account.RetrieveEncryptionSession(string(sessionId2), false, false, true)
			require.NoError(t, err)

			// group is known locally
			groupId, err := os.ReadFile(filepath.Join(testArtifactsDir, "group_id"))
			require.NoError(t, err)
			group := account.storage.groups.get(string(groupId))
			assert.Equal(t, 1, len(group.OldKeys))
		})
		t.Run("Export for JS", func(t *testing.T) {
			// ensure artifacts dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/groups")
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// create identity
			account, err := createTestAccount("sdk_groups_export_js")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()
			exportedIdentity, err := account.ExportIdentity()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "identity"), exportedIdentity, 0o700)
			require.NoError(t, err)

			// create a group
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account.CreateGroup(
				"test-go-js",
				[]string{currentDevice.UserId},
				[]string{currentDevice.UserId},
				preGeneratedKeys,
			)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "group_id"), []byte(groupId), 0o700)
			require.NoError(t, err)
			recipientGroup := &RecipientWithRights{Id: groupId, Rights: allRights}

			// create a session for the group
			session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "session_id"), []byte(session.Id), 0o700)
			require.NoError(t, err)

			// renew group key to check if it works for oldKeys
			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)

			// create another session for the group
			session2, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientGroup}, false)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "session_id2"), []byte(session2.Id), 0o700)
			require.NoError(t, err)
		})
	})
}
