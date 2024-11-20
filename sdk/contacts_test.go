package sdk

import (
	"fmt"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ztrue/tracerr"
	"strconv"
	"testing"
	"time"
)

func TestState_GetUpdatedContacts(t *testing.T) {
	var accounts []*State
	var accountsIds []string

	// Generate some test users. checkUsers is paginated by 10.
	for i := 0; i < 7; i++ {
		acc, err := createTestAccount("sdk_get_updated_contacts_" + strconv.Itoa(i))
		require.NoError(t, err)
		currentDevice := acc.storage.currentDevice.get()
		accounts = append(accounts, acc)
		accountsIds = append(accountsIds, currentDevice.UserId)
	}
	currentDevice0 := accounts[0].storage.currentDevice.get()
	currentDevice1 := accounts[1].storage.currentDevice.get()

	// More test users, but users that we can revoke easily
	for i := 0; i < 7; i++ {
		preGeneratedKeys, err := getPreGeneratedKeys()
		require.NoError(t, err)
		groupId, err := accounts[0].CreateGroup(
			fmt.Sprintf("Group %d", i),
			[]string{currentDevice0.UserId},
			[]string{currentDevice0.UserId},
			preGeneratedKeys,
		)
		require.NoError(t, err)
		accountsIds = append(accountsIds, groupId)
	}

	t.Run("search new contacts, check known users, remove revoked ones.", func(t *testing.T) {
		canaryAccount, err := createTestAccount("sdk_get_updated_contacts_search")
		require.NoError(t, err)
		canaryApi := newCanaryBeardApiClient(canaryAccount.apiClient)
		canaryAccount.apiClient = canaryApi

		// canaryAccount know no one. So no user to check, only new one to search for.
		contacts, removed, err := canaryAccount.getUpdatedContacts(accountsIds[:11])
		require.NoError(t, err)
		assert.Equal(t, 11, len(contacts))
		assert.Equal(t, 0, removed)
		assert.Equal(t, 0, canaryApi.Counter["checkUsers"]) // No user to check, as we know no one yet
		assert.Equal(t, 11, canaryApi.Counter["search"])    // Search all 13 contacts

		// Someone we locally know have an update
		preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(accounts[5])})
		require.NoError(t, err)
		err = accounts[5].RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
		require.NoError(t, err)

		// canaryAccount know the first 11 users, but one had a key renewal.
		contacts, removed, err = canaryAccount.getUpdatedContacts(accountsIds[:13])
		require.NoError(t, err)
		assert.Equal(t, 13, len(contacts))
		assert.Equal(t, 0, removed)
		assert.Equal(t, 2, canaryApi.Counter["checkUsers"]) // 11 users in local DB => check 2 pages
		assert.Equal(t, 14, canaryApi.Counter["search"])    // 11 previous call, + 2 new this time + 1 update

		// Generating 2 revoked users. One that we know locally, one unknown yet.
		err = accounts[0].RemoveGroupMembers(accountsIds[13], []string{currentDevice0.UserId})
		require.NoError(t, err)
		err = accounts[0].RemoveGroupMembers(accountsIds[9], []string{currentDevice0.UserId})
		require.NoError(t, err)

		time.Sleep(2 * time.Second) // revoke on beard is async
		for i := 0; i <= 10; i++ {
			contacts, removed, err = canaryAccount.getUpdatedContacts(accountsIds) // all 14 users
			require.NoError(t, err)
			if removed == 2 {
				assert.Equal(t, 12, len(contacts))
				assert.Equal(t, 4, canaryApi.Counter["checkUsers"]) //  2 pages + 2 previous calls
				assert.Equal(t, 16, canaryApi.Counter["search"])    // 14 previous call, + 2 search for revoked users
				break
			} else {
				if i == 10 {
					t.Fatal("Groups were still not revoked after 10 retries.")
				}
				t.Log("Groups were not revoked yet, retrying...")
				time.Sleep(2 * time.Second)
			}
		}
	})

	t.Run("Test API errors", func(t *testing.T) {
		t.Parallel()
		t.Run("input validator", func(t *testing.T) {
			_, _, err := accounts[0].getUpdatedContacts([]string{"not-an-uuid"})
			assert.ErrorIs(t, err, utils.ErrorInvalidUUIDSlice)
		})
		t.Run("Test API checkUsers", func(t *testing.T) {
			canaryAccount, err := createTestAccount("sdk_get_updated_contacts_errors1")
			assert.NoError(t, err)
			canaryApi := newCanaryBeardApiClient(canaryAccount.apiClient)
			canaryAccount.apiClient = canaryApi

			canaryApi.ToExecute["checkUsers"] = func(_ any) ([]byte, error) {
				return nil, tracerr.Wrap(test_utils.ErrorSyntheticTestError)
			}
			// First we search the contact, so it's in the local DB
			_, err = canaryAccount.search(currentDevice0.UserId, true)
			require.NoError(t, err)

			_, _, err = canaryAccount.getUpdatedContacts([]string{currentDevice0.UserId})
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})
		t.Run("Test API search", func(t *testing.T) {
			canaryAccount, err := createTestAccount("sdk_get_updated_contacts_errors2")
			assert.NoError(t, err)
			canaryApi := newCanaryBeardApiClient(canaryAccount.apiClient)
			canaryAccount.apiClient = canaryApi

			// Add accounts[1] to local database
			_, err = canaryAccount.search(currentDevice1.UserId, true)
			assert.NoError(t, err)
			preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(accounts[1])})
			require.NoError(t, err)
			err = accounts[1].RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
			assert.NoError(t, err)

			canaryApi.ToExecute["search"] = func(_ any) ([]byte, error) {
				return nil, tracerr.Wrap(test_utils.ErrorSyntheticTestError)
			}
			// Search for an unknown user
			_, _, err = canaryAccount.getUpdatedContacts([]string{currentDevice0.UserId})
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			//Search for a known user that need to be updated
			_, _, err = canaryAccount.getUpdatedContacts([]string{currentDevice1.UserId})
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})

		t.Run("get/check sigchain hash", func(t *testing.T) {
			sdk, err := createTestAccount("sdk_get_updated_contacts_errors2")
			sdkId := sdk.storage.currentDevice.get().UserId

			preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(sdk)})
			for i := 0; i < 2; i++ {
				err = sdk.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
				require.NoError(t, err)
			}

			updatedContactSlice, _, err := sdk.getUpdatedContacts([]string{sdkId})
			require.NoError(t, err)
			sdkSigchainBlocks := updatedContactSlice[0].Sigchain.Blocks

			sdkLastHash, err := accounts[0].GetSigchainHash(sdkId, -1)
			assert.NoError(t, err)
			assert.Equal(t, 2, sdkLastHash.Position)
			assert.Equal(t, sdkSigchainBlocks[2].Signature.Hash, sdkLastHash.Hash)
			sdkHashAtPos2, err := accounts[0].GetSigchainHash(sdkId, 2)
			assert.NoError(t, err)
			assert.Equal(t, 2, sdkHashAtPos2.Position)
			assert.Equal(t, sdkLastHash.Hash, sdkHashAtPos2.Hash)

			for i := 0; i < len(sdkSigchainBlocks); i++ {
				sdkIndexHash, err := accounts[0].GetSigchainHash(sdkId, i)
				assert.NoError(t, err)
				assert.Equal(t, sdkSigchainBlocks[i].Signature.Hash, sdkIndexHash.Hash)

				checked, err := accounts[0].CheckSigchainHash(sdkId, sdkIndexHash.Hash, -1)
				assert.NoError(t, err)
				assert.True(t, checked.Found)
				assert.Equal(t, i, checked.Position)
				assert.Equal(t, len(sdkSigchainBlocks)-1, checked.LastPosition)

				checkedWithIndex, err := accounts[0].CheckSigchainHash(sdkId, sdkIndexHash.Hash, 1)
				assert.NoError(t, err)
				assert.Equal(t, i == 1, checkedWithIndex.Found)
			}
			invalidCheck, err := accounts[0].CheckSigchainHash(sdkId, "badHash", -1)
			assert.NoError(t, err)
			assert.False(t, invalidCheck.Found)

			checkBadPos, err := accounts[0].CheckSigchainHash(sdkId, sdkHashAtPos2.Hash, 1)
			assert.NoError(t, err)
			assert.False(t, checkBadPos.Found)

			_, err = accounts[0].GetSigchainHash(sdkId, 40)
			assert.ErrorIs(t, err, ErrorContactsSigchainOutOfRange)

			_, err = accounts[0].CheckSigchainHash(sdkId, "", 40)
			assert.ErrorIs(t, err, ErrorContactsSigchainOutOfRange)
		})
	})
}
