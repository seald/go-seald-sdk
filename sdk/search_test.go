package sdk

import (
	"encoding/json"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ztrue/tracerr"
	"testing"
	"time"
)

func TestBeardApiClient_Search(t *testing.T) {
	t.Parallel()
	t.Run("Search — Network failures", func(t *testing.T) {
		t.Parallel()
		t.Run("Search for a user with network failure on retrieveSigchain", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_fail_net11")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_fail_net12")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account2.apiClient)

			account2.apiClient = canaryApi
			canaryApi.ToExecute["retrieveSigchain"] = test_utils.SyntheticErrorCallback

			_, err = account2.search(currentDevice1.UserId, true)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			_, err = account2.search(currentDevice1.UserId, false)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})

		t.Run("search for a user with network failure on search", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_fail_net21")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_fail_net22")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()
			currentDevice2 := account2.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account2.apiClient)

			account2.apiClient = canaryApi
			canaryApi.ToExecute["search"] = test_utils.SyntheticErrorCallback

			_, err = account2.search(currentDevice1.UserId, false)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			_, err = account2.search(currentDevice1.UserId, true)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			_, err = account2.search(currentDevice2.UserId, false)
			assert.NoError(t, err) // user is known locally, no API request is made

			_, err = account2.search(currentDevice2.UserId, true)
			assert.NoError(t, err) // user is known locally and sigchain is up-to-date
		})
	})

	t.Run("Search — normal cases", func(t *testing.T) {
		t.Run("Search for self - force update == false", func(t *testing.T) {
			account, err := createTestAccount("sdk_search_self")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account.apiClient)

			account.apiClient = canaryApi

			contact, err := account.search(currentDevice.UserId, false)
			assert.NoError(t, err)
			assert.NotNil(t, contact)

			assert.Equal(t, 0, canaryApi.Counter["search"])

			assert.ElementsMatch(t, account.storage.contacts.get(currentDevice.UserId).Devices, contact.Devices)
			assert.Equal(t, account.storage.contacts.get(currentDevice.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account.storage.contacts.get(currentDevice.UserId).Id, contact.Id)
			assert.Equal(t, currentDevice.UserId, contact.Id)
			assert.Equal(t, 1, len(contact.Devices))
			assert.Equal(t, currentDevice.DeviceId, contact.Devices[0].Id)
			assert.Equal(t, currentDevice.EncryptionPrivateKey.Public(), contact.Devices[0].EncryptionKey)
			assert.Equal(t, currentDevice.SigningPrivateKey.Public(), contact.Devices[0].SigningKey)
			assert.Equal(t, 1, len(account.storage.contacts.all()))
		})

		t.Run("Search for self - force update == true", func(t *testing.T) {
			account, err := createTestAccount("sdk_search_self_force")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account.apiClient)

			account.apiClient = canaryApi

			contact, err := account.search(currentDevice.UserId, true)
			assert.NoError(t, err)
			assert.NotNil(t, contact)

			assert.Equal(t, 0, canaryApi.Counter["search"])

			assert.ElementsMatch(t, account.storage.contacts.get(currentDevice.UserId).Devices, contact.Devices)
			assert.Equal(t, account.storage.contacts.get(currentDevice.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account.storage.contacts.get(currentDevice.UserId).Id, contact.Id)
			assert.Equal(t, currentDevice.UserId, contact.Id)
			assert.Equal(t, 1, len(contact.Devices))
			assert.Equal(t, currentDevice.DeviceId, contact.Devices[0].Id)
			assert.Equal(t, currentDevice.EncryptionPrivateKey.Public(), contact.Devices[0].EncryptionKey)
			assert.Equal(t, currentDevice.SigningPrivateKey.Public(), contact.Devices[0].SigningKey)
			assert.Equal(t, 1, len(account.storage.contacts.all()))
		})

		t.Run("Search for another user - force update == true", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_other_force1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_other_force2")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account2.apiClient)

			account2.apiClient = canaryApi

			contact, err := account2.search(currentDevice1.UserId, true)
			assert.NoError(t, err)
			assert.NotNil(t, contact)

			assert.Equal(t, 1, canaryApi.Counter["search"])
			assert.ElementsMatch(t, account2.storage.contacts.get(currentDevice1.UserId).Devices, contact.Devices)
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Id, contact.Id)
			assert.Equal(t, currentDevice1.UserId, contact.Id)
			assert.Equal(t, 1, len(contact.Devices))
			assert.Equal(t, currentDevice1.DeviceId, contact.Devices[0].Id)
			assert.Equal(t, currentDevice1.EncryptionPrivateKey.Public(), contact.Devices[0].EncryptionKey)
			assert.Equal(t, currentDevice1.SigningPrivateKey.Public(), contact.Devices[0].SigningKey)
			assert.Equal(t, 2, len(account2.storage.contacts.all()))
		})

		t.Run("Search for another user - force update == false", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_other1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_other2")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()

			contact, err := account2.search(currentDevice1.UserId, false)
			assert.NoError(t, err)
			assert.NotNil(t, contact)
			assert.ElementsMatch(t, account2.storage.contacts.get(currentDevice1.UserId).Devices, contact.Devices)
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Id, contact.Id)
			assert.Equal(t, currentDevice1.UserId, contact.Id)
			assert.Equal(t, 1, len(contact.Devices))
			assert.Equal(t, currentDevice1.DeviceId, contact.Devices[0].Id)
			assert.Equal(t, currentDevice1.EncryptionPrivateKey.Public(), contact.Devices[0].EncryptionKey)
			assert.Equal(t, currentDevice1.SigningPrivateKey.Public(), contact.Devices[0].SigningKey)
			assert.Equal(t, 2, len(account2.storage.contacts.all()))
		})

		t.Run("Search for a known user that got updated", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_known1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_known2")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account2.apiClient)

			account2.apiClient = canaryApi

			_, err = account2.search(currentDevice1.UserId, true)
			assert.NoError(t, err)

			assert.Equal(t, 1, canaryApi.Counter["search"])
			assert.Equal(t, 1, canaryApi.Counter["retrieveSigchain"])

			_, err = account1.CreateSubIdentity(&CreateSubIdentityOptions{DeviceName: "Device_2", ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
			assert.NoError(t, err)

			contact, err := account2.search(currentDevice1.UserId, false)
			assert.NoError(t, err)

			assert.Equal(t, 1, canaryApi.Counter["search"])
			assert.Equal(t, 1, canaryApi.Counter["retrieveSigchain"])

			contact, err = account2.search(currentDevice1.UserId, true)
			assert.NoError(t, err)
			assert.NotNil(t, contact)

			assert.Equal(t, 2, canaryApi.Counter["retrieveSigchain"])
			assert.Equal(t, 2, canaryApi.Counter["search"]) // retrieveSigchain return no new block => sigchain is unchanged => no search

			assert.ElementsMatch(t, account2.storage.contacts.get(currentDevice1.UserId).Devices, contact.Devices)
			assert.Equal(t, account1.storage.contacts.get(currentDevice1.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account1.storage.contacts.get(currentDevice1.UserId).Id, contact.Id)
			assert.Equal(t, 2, len(account2.storage.contacts.all()))
		})

		t.Run("Search for a known user that got revoked", func(t *testing.T) {
			account, err := createTestAccount("sdk_search_revoked")
			assert.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account.CreateGroup(
				"You won't last a minute!",
				[]string{currentDevice.UserId},
				[]string{currentDevice.UserId},
				preGeneratedKeys,
			)
			assert.NoError(t, err)

			groupUser, err := account.search(groupId, true)
			require.NoError(t, err)
			require.NotNil(t, groupUser.Id)
			assert.Equal(t, groupId, groupUser.Id)

			err = account.RemoveGroupMembers(groupId, []string{currentDevice.UserId})
			require.NoError(t, err)

			assert.Equal(t, account.storage.contacts.get(groupId).Id, groupId)
			groupUser, err = account.search(groupId, false)
			require.NoError(t, err)
			require.NotNil(t, groupUser.Id)
			assert.Equal(t, groupId, groupUser.Id)
			assert.Equal(t, groupId, account.storage.contacts.get(groupId).Id)

			time.Sleep(2 * time.Second) // Group revocation is async on beard
			for i := 0; i <= 10; i++ {
				groupUser, err = account.search(groupId, true)
				require.NoError(t, err)
				if groupUser == nil {
					assert.Nil(t, account.storage.contacts.get(groupId)) // Deleted from local database
					break
				} else {
					if i == 10 {
						t.Fatal("Group was still not revoked after 10 retries.")
					}
					t.Log("Group was not revoked yet, retrying...")
					time.Sleep(2 * time.Second)
				}
			}
		})

		t.Run("Search for another user - sigchain update during search", func(t *testing.T) {
			account1, err := createTestAccount("sdk_search_other_force1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_other_force2")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()

			canaryApi := newCanaryBeardApiClient(account2.apiClient)

			account2.apiClient = canaryApi
			canaryApi.ToExecute["search"] = func(request any) ([]byte, error) {
				if canaryApi.Counter["search"] == 1 {
					var req = request.(*searchRequest)
					resp, err := canaryApi.Client.search(req)
					require.NoError(t, err)
					resp.SigchainLastHash = "aHashThatIsNotTheLastOne"
					return json.Marshal(resp)
				}
				return nil, nil
			}

			// the first call to `/search/` is intercepted by the canaryAPI, to return a bad `sigchainLastHash`
			// Later, when we will compare the hash from `sigchainLastHash` and the last hash retrieved from the sigchain, we know that the user has been update on beard.
			// This should trigger a recursive call on `fullUpdateDefaultUser`. Hence, a second call to `/search/` API endoint.
			contact, err := account2.search(currentDevice1.UserId, true)
			assert.NoError(t, err)
			assert.NotNil(t, contact)

			assert.Equal(t, 2, canaryApi.Counter["search"])
			assert.ElementsMatch(t, account2.storage.contacts.get(currentDevice1.UserId).Devices, contact.Devices)
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Sigchain, contact.Sigchain)
			assert.Equal(t, account1.storage.contacts.get(currentDevice1.UserId).Sigchain, contact.Sigchain) // Check that this is the 'good' sigchain that has been returned.
			assert.Equal(t, account2.storage.contacts.get(currentDevice1.UserId).Id, contact.Id)
			assert.Equal(t, currentDevice1.UserId, contact.Id)
			assert.Equal(t, 1, len(contact.Devices))
			assert.Equal(t, currentDevice1.DeviceId, contact.Devices[0].Id)
			assert.Equal(t, currentDevice1.EncryptionPrivateKey.Public(), contact.Devices[0].EncryptionKey)
			assert.Equal(t, currentDevice1.SigningPrivateKey.Public(), contact.Devices[0].SigningKey)
			assert.Equal(t, 2, len(account2.storage.contacts.all()))

			// We need to add a transaction to account1, otherwise the search will not update.
			preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(account1)})
			require.NoError(t, err)
			err = account1.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
			require.NoError(t, err)

			canaryApi.ToExecute["search"] = func(request any) ([]byte, error) {
				var req = request.(*searchRequest)
				resp, err := canaryApi.Client.search(req)
				require.NoError(t, err)
				resp.SigchainLastHash = "aHashThatIsNotTheLastOne"
				return json.Marshal(resp)
			}
			_, err = account2.search(currentDevice1.UserId, true)
			require.ErrorIs(t, err, ErrorSigchainUnexpectedRetrievedLastHash)
			assert.Equal(t, 4, canaryApi.Counter["search"]) // previous value +2
		})
	})

	t.Run("Search — error cases", func(t *testing.T) {
		t.Parallel()
		t.Run("Search for a user with a different sigchain in local", func(t *testing.T) {
			t.Parallel()
			account, err := createTestAccount("sdk_search_fail_sigchain_different")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			// START -- RENEW KEYS WITHOUT SENDING BLOCKS TO BEARD
			encryptionKeyPair, err := asymkey.Generate(account.options.KeySize)
			require.NoError(t, err)
			signingKeyPair, err := asymkey.Generate(account.options.KeySize)
			require.NoError(t, err)
			encryptionPublicKey := encryptionKeyPair.Public()
			signingPublicKey := signingKeyPair.Public()

			self := account.storage.contacts.get(currentDevice.UserId)

			lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

			block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
				OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
				OperationEncryptionKey: encryptionPublicKey,
				OperationSigningKey:    signingPublicKey,
				OperationDeviceId:      currentDevice.DeviceId,
				ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
				SigningKey:             currentDevice.SigningPrivateKey,
				Position:               lastBlock.Transaction.Position + 1,
				PreviousHash:           lastBlock.Signature.Hash,
				SignerDeviceId:         currentDevice.DeviceId,
			})

			require.NoError(t, err)

			oldEncryptionPrivateKeys := append(currentDevice.OldEncryptionPrivateKeys, currentDevice.EncryptionPrivateKey)
			oldSigningPrivateKeys := append(currentDevice.OldSigningPrivateKeys, currentDevice.SigningPrivateKey)

			currentDevice.EncryptionPrivateKey = encryptionKeyPair
			currentDevice.SigningPrivateKey = signingKeyPair
			currentDevice.OldEncryptionPrivateKeys = oldEncryptionPrivateKeys
			currentDevice.OldSigningPrivateKeys = oldSigningPrivateKeys

			account.storage.currentDevice.set(currentDevice)
			err = account.saveCurrentDevice()
			require.NoError(t, err)

			self.Sigchain.Blocks = append(self.Sigchain.Blocks, block)
			selfDevice := self.getDevice(currentDevice.DeviceId)

			selfDevice.SigningKey = signingPublicKey
			selfDevice.EncryptionKey = encryptionPublicKey

			account.storage.contacts.set(*self)
			err = account.saveContacts()
			require.NoError(t, err)
			// END -- RENEW KEYS WITHOUT SENDING BLOCKS TO BEARD

			_, err = account.search(currentDevice.UserId, true)

			assert.ErrorIs(t, err, ErrorSigchainRetrievedEmpty)
		})

		t.Run("Search for a user with a forked sigchain in local", func(t *testing.T) {
			t.Parallel()
			account, err := createTestAccount("sdk_search_fail_sigchain_forked")
			require.NoError(t, err)
			accountCopy := account // Duplicating local state
			currentDevice := account.storage.currentDevice.get()

			// START -- CREATE SUB_IDENTITY WITHOUT SAVING LOCALLY
			encryptionKeyPair, err := asymkey.Generate(accountCopy.options.KeySize)
			require.NoError(t, err)

			encryptionPublicKey := encryptionKeyPair.Public()

			signingKeyPair, err := asymkey.Generate(accountCopy.options.KeySize)
			require.NoError(t, err)

			signingPublicKey := signingKeyPair.Public()

			self, err := accountCopy.search(currentDevice.UserId, true)
			require.NoError(t, err)
			assert.NotNil(t, self)

			addDeviceResponse, err := accountCopy.apiClient.addDevice(&addDeviceRequest{
				EncryptionPubKey: encryptionPublicKey,
				SigningPubKey:    signingPublicKey,
				DeviceName:       "Device_2",
			})

			require.NoError(t, err)

			lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

			block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
				OperationType:          sigchain.SIGCHAIN_OPERATION_CREATE,
				OperationEncryptionKey: encryptionPublicKey,
				OperationSigningKey:    signingPublicKey,
				OperationDeviceId:      addDeviceResponse.DeviceId,
				ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
				SigningKey:             currentDevice.SigningPrivateKey,
				Position:               lastBlock.Transaction.Position + 1,
				PreviousHash:           lastBlock.Signature.Hash,
				SignerDeviceId:         currentDevice.DeviceId,
			})

			require.NoError(t, err)

			_, err = accountCopy.apiClient.validateDevice(&validateDeviceRequest{
				DeviceId:        addDeviceResponse.DeviceId,
				TransactionData: block,
			})

			require.NoError(t, err)

			// END -- CREATE SUB_IDENTITY WITHOUT SAVING LOCALLY

			// START -- RENEW KEYS WITHOUT SENDING BLOCKS TO BEARD
			encryptionKeyPair, err = asymkey.Generate(account.options.KeySize)
			require.NoError(t, err)
			signingKeyPair, err = asymkey.Generate(account.options.KeySize)
			require.NoError(t, err)
			encryptionPublicKey = encryptionKeyPair.Public()
			signingPublicKey = signingKeyPair.Public()

			self = account.storage.contacts.get(currentDevice.UserId)

			lastBlock = self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

			block, err = sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
				OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
				OperationEncryptionKey: encryptionPublicKey,
				OperationSigningKey:    signingPublicKey,
				OperationDeviceId:      currentDevice.DeviceId,
				ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
				SigningKey:             currentDevice.SigningPrivateKey,
				Position:               lastBlock.Transaction.Position + 1,
				PreviousHash:           lastBlock.Signature.Hash,
				SignerDeviceId:         currentDevice.DeviceId,
			})

			require.NoError(t, err)

			oldEncryptionPrivateKeys := append(currentDevice.OldEncryptionPrivateKeys, currentDevice.EncryptionPrivateKey)
			oldSigningPrivateKeys := append(currentDevice.OldSigningPrivateKeys, currentDevice.SigningPrivateKey)

			currentDevice.EncryptionPrivateKey = encryptionKeyPair
			currentDevice.SigningPrivateKey = signingKeyPair
			currentDevice.OldEncryptionPrivateKeys = oldEncryptionPrivateKeys
			currentDevice.OldSigningPrivateKeys = oldSigningPrivateKeys

			account.storage.currentDevice.set(currentDevice)
			err = account.saveCurrentDevice()
			require.NoError(t, err)

			self.Sigchain.Blocks = append(self.Sigchain.Blocks, block)
			selfDevice := self.getDevice(currentDevice.DeviceId)

			selfDevice.SigningKey = signingPublicKey
			selfDevice.EncryptionKey = encryptionPublicKey

			account.storage.contacts.set(*self)
			err = account.saveContacts()
			require.NoError(t, err)
			// END -- RENEW KEYS WITHOUT SENDING BLOCKS TO BEARD

			_, err = account.search(currentDevice.UserId, true)

			assert.ErrorIs(t, err, ErrorSigchainForked)
		})

		t.Run("Search for a user and receiving invalid sigchain", func(t *testing.T) {
			t.Parallel()
			account1, err := createTestAccount("sdk_search_fail_sigchain_invalid1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_fail_sigchain_invalid2")
			require.NoError(t, err)
			currentDevice2 := account2.storage.currentDevice.get()

			encryptionKeyPair, err := asymkey.Generate(account2.options.KeySize)
			require.NoError(t, err)

			signingKeyPair, err := asymkey.Generate(account2.options.KeySize)
			require.NoError(t, err)

			encryptionPublicKey := encryptionKeyPair.Public()
			signingPublicKey := signingKeyPair.Public()

			self, err := account2.search(currentDevice2.UserId, true)
			require.NoError(t, err)
			assert.NotNil(t, self)

			lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

			block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
				OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
				OperationEncryptionKey: encryptionPublicKey,
				OperationSigningKey:    signingPublicKey,
				OperationDeviceId:      currentDevice2.DeviceId,
				ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
				SigningKey:             currentDevice2.SigningPrivateKey,
				Position:               lastBlock.Transaction.Position + 1,
				PreviousHash:           lastBlock.Signature.Hash,
				SignerDeviceId:         currentDevice2.DeviceId,
			})

			block.Signature.SignatureString = "notavalidsignature"

			canaryApi := newCanaryBeardApiClient(account1.apiClient)

			account1.apiClient = canaryApi

			f := func(_ any) ([]byte, error) {
				var blocks []*sigchain.Block
				copy(blocks, self.Sigchain.Blocks)
				blocks = append(blocks, block)
				blocksResponse := retrieveSigchainResponse{Blocks: blocks}
				return json.Marshal(blocksResponse)
			}

			canaryApi.ToExecute["retrieveSigchain"] = f

			_, err = account1.search(currentDevice2.UserId, true)
			assert.EqualError(t, err, "INVALID_SIGCHAIN_TRANSACTION_SIGNATURE_MALFORMED")
		})

		t.Run("Search for a user and receiving sigchain that does not match keyring", func(t *testing.T) {
			t.Parallel()
			account1, err := createTestAccount("sdk_search_fail_sigchain_not_match1")
			require.NoError(t, err)
			account2, err := createTestAccount("sdk_search_fail_sigchain_not_match2")
			require.NoError(t, err)
			currentDevice2 := account2.storage.currentDevice.get()

			encryptionKeyPair, err := asymkey.Generate(account2.options.KeySize)
			require.NoError(t, err)

			signingKeyPair, err := asymkey.Generate(account2.options.KeySize)
			require.NoError(t, err)

			encryptionPublicKey := encryptionKeyPair.Public()
			signingPublicKey := signingKeyPair.Public()

			self, err := account2.search(currentDevice2.UserId, true)
			require.NoError(t, err)
			assert.NotNil(t, self)

			lastBlock := self.Sigchain.Blocks[len(self.Sigchain.Blocks)-1]

			block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
				OperationType:          sigchain.SIGCHAIN_OPERATION_RENEWAL,
				OperationEncryptionKey: encryptionPublicKey,
				OperationSigningKey:    signingPublicKey,
				OperationDeviceId:      currentDevice2.DeviceId,
				ExpireAfter:            sigchain.DEVICE_DEFAULT_LIFE_TIME,
				SigningKey:             currentDevice2.SigningPrivateKey,
				Position:               lastBlock.Transaction.Position + 1,
				PreviousHash:           lastBlock.Signature.Hash,
				SignerDeviceId:         currentDevice2.DeviceId,
			})

			_, err = autoLogin(account2, account2.apiClient.addSigChainTransaction)(&addSigChainTransactionRequest{TransactionData: block, IntegrityCheck: false})
			require.NoError(t, err)

			_, err = account1.search(currentDevice2.UserId, true)
			assert.ErrorIs(t, err, ErrorSigchainIntegrityEncryptionKeyHash)
		})
	})

	t.Run("Search — IO failure", func(t *testing.T) {
		account1, err := createTestAccount("sdk_search_fail_io1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_search_fail_io2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()

		canaryStorage := newCanaryFileStorage(account2.options.Database)

		account2.options.Database = canaryStorage

		canaryStorage.ToExecute["WriteContacts"] = func() error {
			return tracerr.Wrap(test_utils.ErrorSyntheticTestError)
		}

		_, err = account2.search(currentDevice1.UserId, true)
		assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
	})

}
