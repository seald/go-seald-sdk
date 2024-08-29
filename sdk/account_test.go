package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const invalidJWT = "ccccccccciJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqb2luX3RlYW0iOnRydWUsImNvbm5lY3Rvcl9hZGQiOnt9LCJzY29wZXMiOlszXSwiaWF0IjoxNjY1NDgzNzE0LCJpc3MiOiIwMDAwMDAwMC0wMDAwLTEwMDAtYTAwMC03ZWEzMDAwMDAwMTkifQ.OOhXWj-IoHFhUyF_Xj-LUDXqBdMnphDUDjUs3OgvhUQ"

func Test_SDKAccount(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)

	t.Parallel()
	t.Run("check SDK state before functions", func(t *testing.T) {
		t.Parallel()
		initOptions, err := getInMemoryInitializeOptions("sdk_account_check_state")
		require.NoError(t, err)
		sdk, err := Initialize(initOptions)
		require.NoError(t, err)

		err = sdk.checkSdkState(true)
		assert.ErrorIs(t, err, ErrorRequireAccount)

		// Check some functions that need a valid account
		err = sdk.PushJWT("absolutely valid JWT string")
		assert.ErrorIs(t, err, ErrorRequireAccount)
		err = sdk.AddGroupMembers("groupId", []string{"userId"}, []string{"userId"})
		assert.ErrorIs(t, err, ErrorRequireAccount)
		_, err = sdk.search("userId", false)
		assert.ErrorIs(t, err, ErrorRequireAccount)
		_, _, err = sdk.getUpdatedContacts([]string{"userId"})
		assert.ErrorIs(t, err, ErrorRequireAccount)

		// Create an account
		claims := test_utils.Claims{
			Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
			JoinTeam: true,
		}
		jwt, err := test_utils.GetJWT(claims)
		require.NoError(t, err)
		options := &CreateAccountOptions{
			DisplayName: "Dadada",
			DeviceName:  "Dididi",
			SignupJWT:   jwt,
			ExpireAfter: time.Hour * 24 * 365 * 5,
		}
		_, err = sdk.CreateAccount(options)
		require.NoError(t, err)

		err = sdk.checkSdkState(true)
		assert.NoError(t, err)

		// Check functions that need no account
		_, err = sdk.CreateAccount(options)
		assert.ErrorIs(t, err, ErrorRequireNoAccount)
		err = sdk.ImportIdentity([]byte{})
		assert.ErrorIs(t, err, ErrorRequireNoAccount)

		// Close SDK
		err = sdk.Close()

		// Check that nothing works after SDK has been closed
		_, err = sdk.CreateAccount(options)
		assert.ErrorIs(t, err, ErrorSdkClosed)
		err = sdk.ImportIdentity([]byte{})
		assert.ErrorIs(t, err, ErrorSdkClosed)
		err = sdk.PushJWT("absolutely valid JWT string")
		assert.ErrorIs(t, err, ErrorSdkClosed)
		err = sdk.AddGroupMembers("groupId", []string{"userId"}, []string{"userId"})
		assert.ErrorIs(t, err, ErrorSdkClosed)
		_, err = sdk.search("userId", false)
		assert.ErrorIs(t, err, ErrorSdkClosed)
		_, _, err = sdk.getUpdatedContacts([]string{"userId"})
		assert.ErrorIs(t, err, ErrorSdkClosed)
	})

	t.Run("CreateAccount", func(t *testing.T) {
		t.Parallel()
		t.Run("CreateAccount with persistent DB", func(t *testing.T) {
			initOptions, err := getInitializeOptions("testDB_sdk_create_persistent", true, "sdk_account_create_account")
			require.NoError(t, err)
			accountState, err := Initialize(&InitializeOptions{ // manually pass InitializeOptions without KeySize to check that it defaults to 4096
				ApiURL:       initOptions.ApiURL,
				Database:     initOptions.Database,
				AppId:        credentials.AppId,
				InstanceName: initOptions.InstanceName,
				Platform:     "go-tests",
				LogLevel:     zerolog.TraceLevel,
			})
			require.NoError(t, err)

			canaryApi := newCanaryBeardApiClient(accountState.apiClient)
			accountState.apiClient = canaryApi

			claims := test_utils.Claims{
				Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
				JoinTeam: true,
			}

			jwt, err := test_utils.GetJWT(claims)
			require.NoError(t, err)

			options := CreateAccountOptions{
				DisplayName: "Dadada",
				DeviceName:  "Dididi",
				SignupJWT:   jwt,
				ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME,
			}

			accountInfoBefore := accountState.GetCurrentAccountInfo()
			assert.Nil(t, accountInfoBefore)

			accountInfo, err := accountState.CreateAccount(&options) // not using pre-generated keys, to test that it works
			require.NoError(t, err)
			assert.NotNil(t, accountInfo.UserId)
			assert.NotNil(t, accountInfo.DeviceId)
			require.NotNil(t, accountInfo.DeviceExpires)
			assert.True(t, accountInfo.DeviceExpires.After(time.Now().Add(options.ExpireAfter-time.Hour)))
			assert.True(t, accountInfo.DeviceExpires.Before(time.Now().Add(options.ExpireAfter+time.Hour)))
			accountInfoAfter := accountState.GetCurrentAccountInfo()
			require.NotNil(t, accountInfoAfter)
			assert.Equal(t, accountInfo.UserId, accountInfoAfter.UserId)
			assert.Equal(t, accountInfo.DeviceId, accountInfoAfter.DeviceId)
			assert.True(t, accountInfo.DeviceExpires.Equal(*accountInfoAfter.DeviceExpires))
			currentDevice := accountState.storage.currentDevice.get()
			assert.NotNil(t, currentDevice.UserId)
			assert.NotNil(t, currentDevice.DeviceId)
			assert.NotNil(t, currentDevice.EncryptionPrivateKey)
			assert.NotNil(t, currentDevice.SigningPrivateKey)
			assert.NotNil(t, currentDevice.OldEncryptionPrivateKeys)
			assert.NotNil(t, currentDevice.OldSigningPrivateKeys)
			assert.NotNil(t, currentDevice.DeviceExpires)
			assert.Equal(t, accountInfo.UserId, currentDevice.UserId)
			assert.Equal(t, accountInfo.DeviceId, currentDevice.DeviceId)
			assert.True(t, accountInfo.DeviceExpires.Equal(*currentDevice.DeviceExpires))

			assert.Equal(t, 4096, currentDevice.EncryptionPrivateKey.BitLen())
			assert.Equal(t, 4096, currentDevice.SigningPrivateKey.BitLen())

			assert.Equal(t, 0, len(currentDevice.OldEncryptionPrivateKeys))
			assert.Equal(t, 0, len(currentDevice.OldSigningPrivateKeys))

			assert.Equal(t, 1, canaryApi.Counter["login"])
			assert.Equal(t, 0, canaryApi.Counter["getChallenge"]) // check that login after account creation correctly used the challenge provided by the account create

			assert.Equal(t, 1, len(accountState.storage.contacts.all()))

			c := accountState.storage.contacts.get(currentDevice.UserId)

			assert.Equal(t, c.Id, currentDevice.UserId)
			assert.Equal(t, 1, len(c.Devices))
			assert.Equal(t, c.Devices[0].Id, currentDevice.DeviceId)
			assert.Equal(t, c.Devices[0].EncryptionKey, currentDevice.EncryptionPrivateKey.Public())
			assert.Equal(t, c.Devices[0].SigningKey, currentDevice.SigningPrivateKey.Public())

			transactionCheck, err := sigchain.CheckSigchainTransactions(c.Sigchain, false)
			require.NoError(t, err)
			err = checkKeyringMatchesSigChain(transactionCheck, c.Devices)
			require.NoError(t, err)

			err = accountState.Close()
			require.NoError(t, err)

			// accountState2 reload local DB
			accountState2, err := Initialize(initOptions)
			require.NoError(t, err)
			currentDevice2 := accountState2.storage.currentDevice.get()
			assert.Equal(t, currentDevice.UserId, currentDevice2.UserId)
			assert.Equal(t, currentDevice.DeviceId, currentDevice2.DeviceId)
			assert.Equal(t, currentDevice.EncryptionPrivateKey, currentDevice2.EncryptionPrivateKey)
			assert.Equal(t, currentDevice.SigningPrivateKey, currentDevice2.SigningPrivateKey)
			assert.True(t, currentDevice.DeviceExpires.Equal(*currentDevice2.DeviceExpires))
			assert.Equal(t, 0, len(currentDevice2.OldEncryptionPrivateKeys))
			assert.Equal(t, 0, len(currentDevice2.OldSigningPrivateKeys))

			assert.Equal(t, 1, len(accountState2.storage.contacts.all()))

			contact2 := accountState2.storage.contacts.get(currentDevice2.UserId)

			assert.Equal(t, contact2.Id, currentDevice.UserId)
			assert.Equal(t, 1, len(contact2.Devices))
			assert.Equal(t, contact2.Devices[0].Id, currentDevice.DeviceId)
			assert.Equal(t, contact2.Devices[0].EncryptionKey, currentDevice.EncryptionPrivateKey.Public())
			assert.Equal(t, contact2.Devices[0].SigningKey, currentDevice.SigningPrivateKey.Public())

			transactionCheck2, err := sigchain.CheckSigchainTransactions(contact2.Sigchain, false)
			require.NoError(t, err)
			err = checkKeyringMatchesSigChain(transactionCheck2, contact2.Devices)
			require.NoError(t, err)
		})

		t.Run("Must have a valid JWT", func(t *testing.T) {
			initOptions, err := getInMemoryInitializeOptions("sdk_account_valid_jwt")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)

			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			options := CreateAccountOptions{
				DisplayName:      "Dadada",
				DeviceName:       "Dididi",
				SignupJWT:        "not a valid JWT",
				ExpireAfter:      time.Hour * 24 * 365 * 5,
				PreGeneratedKeys: preGeneratedKeys,
			}
			_, err = account.CreateAccount(&options)
			assert.ErrorIs(t, err, utils.ErrorInvalidJWT)

			// JWT that match the regexp, but will be rejected by the server
			options = CreateAccountOptions{
				DisplayName:      "Dadada",
				DeviceName:       "Dididi",
				SignupJWT:        invalidJWT,
				ExpireAfter:      time.Hour * 24 * 365 * 5,
				PreGeneratedKeys: preGeneratedKeys,
			}
			_, err = account.CreateAccount(&options)
			assert.ErrorIs(t, err, utils.APIError{Status: 403, Code: "INVALID_JWT"})

			var apiError utils.APIError
			errors.As(err, &apiError)
			// APIError Is() does not compare Details, Method, Url. So we cannot use assert.ErrorIs
			assert.Equal(t, apiError.Method, "POST")
			assert.Equal(t, apiError.Url, credentials.ApiUrl+"api/user/")

		})

		t.Run("Create account JWT must have join team", func(t *testing.T) {
			initOptions, err := getInMemoryInitializeOptions("sdk_account_jwt_join")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)

			nonce, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			userCustomId := fmt.Sprintf("myid-%s@%s", nonce[:10], credentials.AppId)
			claims := test_utils.Claims{
				Scopes:       []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam, test_utils.PermissionAddConnector},
				JoinTeam:     false,
				ConnectorAdd: test_utils.ConnectorAdd{Type: "AP", Value: userCustomId},
			}

			jwt, err := test_utils.GetJWT(claims)
			require.NoError(t, err)

			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			options := CreateAccountOptions{
				DisplayName:      "Dadada",
				DeviceName:       "Dididi",
				SignupJWT:        jwt,
				ExpireAfter:      time.Hour * 24 * 365 * 5,
				PreGeneratedKeys: preGeneratedKeys,
			}
			_, err = account.CreateAccount(&options)
			assert.ErrorIs(t, err, utils.APIError{Status: 406, Code: "INVALID_JWT_NO_TEAM"})
		})

		t.Run("Adding a connector with JWT", func(t *testing.T) {
			initOptions, err := getInMemoryInitializeOptions("sdk_account_jwt_connector")
			require.NoError(t, err)
			accountWithConnector, err := Initialize(initOptions)
			require.NoError(t, err)
			nonce, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			userCustomId := fmt.Sprintf("myid-%s@%s", nonce[:10], credentials.AppId)
			claims := test_utils.Claims{
				Scopes:       []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
				JoinTeam:     true,
				ConnectorAdd: test_utils.ConnectorAdd{Type: "AP", Value: userCustomId},
			}

			jwt, err := test_utils.GetJWT(claims)
			require.NoError(t, err)
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			options := CreateAccountOptions{
				DisplayName:      "Dadada",
				DeviceName:       "Dididi",
				SignupJWT:        jwt,
				ExpireAfter:      time.Hour * 24 * 365 * 5,
				PreGeneratedKeys: preGeneratedKeys,
			}
			_, err = accountWithConnector.CreateAccount(&options)
			require.NoError(t, err)
			currentDevice := accountWithConnector.storage.currentDevice.get()
			c, err := accountWithConnector.storage.connectors.getByValue(userCustomId, "AP")
			require.NoError(t, err)
			assert.Equal(t, userCustomId, c.Value)
			assert.Equal(t, common_models.ConnectorType("AP"), c.Type)
			assert.Equal(t, currentDevice.UserId, c.SealdId)
		})

		t.Run("pre-generated keys", func(t *testing.T) {
			initOptions, err := getInMemoryInitializeOptions("sdk_account_pregenerated")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)

			jwt, err := test_utils.GetJWT(test_utils.Claims{
				Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
				JoinTeam: true,
			})
			require.NoError(t, err)

			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)

			options := CreateAccountOptions{
				DisplayName:      "Dadada",
				DeviceName:       "Dididi",
				SignupJWT:        jwt,
				ExpireAfter:      time.Hour * 24 * 365 * 5,
				PreGeneratedKeys: preGeneratedKeys,
			}
			_, err = account.CreateAccount(&options)
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()
			assert.Equal(t, currentDevice.EncryptionPrivateKey, preGeneratedKeys.EncryptionKey)
			assert.Equal(t, currentDevice.SigningPrivateKey, preGeneratedKeys.SigningKey)
		})
	})

	t.Run("renewKeys", func(t *testing.T) {
		accountState, err := createTestAccount("sdk_account_renew")
		require.NoError(t, err)

		// RenewKeys without pre-generated keys
		err = accountState.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
		require.NoError(t, err)

		currentDevice := accountState.storage.currentDevice.get()
		assert.Equal(t, 1, len(currentDevice.OldEncryptionPrivateKeys))
		assert.Equal(t, 1, len(currentDevice.OldSigningPrivateKeys))
		assert.NotEqual(t, (currentDevice.OldEncryptionPrivateKeys)[0], currentDevice.EncryptionPrivateKey)
		assert.NotEqual(t, (currentDevice.OldSigningPrivateKeys)[0], currentDevice.SigningPrivateKey)
		require.NotNil(t, currentDevice.DeviceExpires)
		assert.True(t, currentDevice.DeviceExpires.After(time.Now().Add(sigchain.DEVICE_DEFAULT_LIFE_TIME-time.Hour)))
		assert.True(t, currentDevice.DeviceExpires.Before(time.Now().Add(sigchain.DEVICE_DEFAULT_LIFE_TIME+time.Hour)))

		c := accountState.storage.contacts.get(currentDevice.UserId)
		checkResult, err := sigchain.CheckSigchainTransactions(c.Sigchain, false)
		require.NoError(t, err)

		err = checkKeyringMatchesSigChain(checkResult, c.Devices)
		require.NoError(t, err)

		// RenewKeys with pre-generated keys
		preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(accountState)})
		require.NoError(t, err)
		err = accountState.RenewKeys(RenewKeysOptions{ExpireAfter: 10 * time.Hour, PreGeneratedKeys: preGeneratedKeys})
		require.NoError(t, err)

		currentDevice2 := accountState.storage.currentDevice.get()
		assert.Equal(t, 2, len(currentDevice2.OldEncryptionPrivateKeys))
		assert.Equal(t, 2, len(currentDevice2.OldSigningPrivateKeys))
		assert.Equal(t, preGeneratedKeys.EncryptionKey, currentDevice2.EncryptionPrivateKey)
		assert.Equal(t, preGeneratedKeys.SigningKey, currentDevice2.SigningPrivateKey)
		assert.True(t, currentDevice2.DeviceExpires.After(time.Now().Add(10*time.Hour-time.Hour)))
		assert.True(t, currentDevice2.DeviceExpires.Before(time.Now().Add(10*time.Hour+time.Hour)))

		c2 := accountState.storage.contacts.get(currentDevice.UserId)
		checkResult2, err := sigchain.CheckSigchainTransactions(c2.Sigchain, false)
		require.NoError(t, err)

		err = checkKeyringMatchesSigChain(checkResult2, c2.Devices)
		require.NoError(t, err)
	})

	t.Run("PrepareRenewKeys", func(t *testing.T) {
		accountState, err := createTestAccount("sdk_account_prepare_renew")
		require.NoError(t, err)

		preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(accountState)})
		require.NoError(t, err)

		preparedRenewal, err := accountState.PrepareRenew(PrepareRenewOptions{PreGeneratedKeys: preGeneratedKeys})
		require.NoError(t, err)
		currentDeviceBefore := accountState.storage.currentDevice.get()

		initOptFailImport, err := getInMemoryInitializeOptions("sdk_account_prepare_renew")
		require.NoError(t, err)
		failImportSDK, err := Initialize(initOptFailImport)
		require.NoError(t, err)

		failImportCanaryApi := newCanaryBeardApiClient(failImportSDK.apiClient)
		failImportSDK.apiClient = failImportCanaryApi
		failImportCanaryApi.ToExecute["retrieveSigchain"] = func(request any) ([]byte, error) {
			return nil, tracerr.Wrap(utils.APIError{Status: 500, Code: "canary error"})
		}

		err = failImportSDK.ImportIdentity(preparedRenewal)
		require.ErrorIs(t, err, utils.APIError{Status: 500, Code: "canary error"})

		initOptImport, err := getInMemoryInitializeOptions("sdk_account_prepare_renew")
		require.NoError(t, err)
		firstImportSDK, err := Initialize(initOptImport)
		require.NoError(t, err)

		firstImportCanaryApi := newCanaryBeardApiClient(firstImportSDK.apiClient)
		firstImportSDK.apiClient = firstImportCanaryApi

		// Import should try the new key, then rollback and import the current one.
		err = firstImportSDK.ImportIdentity(preparedRenewal)
		require.NoError(t, err)
		firstImportDevice := firstImportSDK.storage.currentDevice.get()
		assert.Equal(t, firstImportDevice.EncryptionPrivateKey, currentDeviceBefore.EncryptionPrivateKey)
		assert.Equal(t, firstImportDevice.SigningPrivateKey, currentDeviceBefore.SigningPrivateKey)
		assert.Equal(t, 1, firstImportCanaryApi.Counter["search"])

		err = accountState.RenewKeys(RenewKeysOptions{ExpireAfter: 10 * time.Hour, PreparedRenewal: preparedRenewal})
		require.NoError(t, err)

		currentDeviceAfter := accountState.storage.currentDevice.get()
		assert.Equal(t, 1, len(currentDeviceAfter.OldEncryptionPrivateKeys))
		assert.Equal(t, 1, len(currentDeviceAfter.OldSigningPrivateKeys))
		assert.Equal(t, preGeneratedKeys.EncryptionKey, currentDeviceAfter.EncryptionPrivateKey)
		assert.Equal(t, preGeneratedKeys.SigningKey, currentDeviceAfter.SigningPrivateKey)
		assert.True(t, currentDeviceAfter.DeviceExpires.After(time.Now().Add(10*time.Hour-time.Hour)))
		assert.True(t, currentDeviceAfter.DeviceExpires.Before(time.Now().Add(10*time.Hour+time.Hour)))

		contact := accountState.storage.contacts.get(currentDeviceAfter.UserId)
		checkResult, err := sigchain.CheckSigchainTransactions(contact.Sigchain, false)
		require.NoError(t, err)

		err = checkKeyringMatchesSigChain(checkResult, contact.Devices)
		require.NoError(t, err)

		// Import the preparedRenewal once it has been renewed.
		initOptRenewedImport, err := getInMemoryInitializeOptions("sdk_account_prepare_renew")
		require.NoError(t, err)
		renewedImportSDK, err := Initialize(initOptRenewedImport)
		require.NoError(t, err)

		err = renewedImportSDK.ImportIdentity(preparedRenewal)
		require.NoError(t, err)
		renewedImportDevice := renewedImportSDK.storage.currentDevice.get()
		assert.Equal(t, 1, len(renewedImportDevice.OldEncryptionPrivateKeys))
		assert.Equal(t, 1, len(renewedImportDevice.OldSigningPrivateKeys))
		assert.Equal(t, preGeneratedKeys.EncryptionKey, renewedImportDevice.EncryptionPrivateKey)
		assert.Equal(t, preGeneratedKeys.SigningKey, renewedImportDevice.SigningPrivateKey)

	})

	t.Run("CreateSubIdentity/RevokeSubIdentity", func(t *testing.T) {
		// Create device1
		device1, err := createTestAccount("sdk_account_subidentity1")
		require.NoError(t, err)

		// device1 retrieves contact of itself (for assertions)
		currentDevice := device1.storage.currentDevice.get()
		self := device1.storage.contacts.get(currentDevice.UserId)
		assert.Equal(t, 1, len(self.Devices))

		// device1 creates sub-identity for device2
		subIdentityResponse, err := device1.CreateSubIdentity(&CreateSubIdentityOptions{DeviceName: "test", ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
		require.NoError(t, err)

		// check that device 1 now knows 2 devices
		self = device1.storage.contacts.get(currentDevice.UserId)
		assert.Equal(t, 2, len(self.Devices))

		// instantiate device2 and import sub-identity
		initOptions2, err := getInMemoryInitializeOptions("sdk_account_subidentity2")
		require.NoError(t, err)
		device2, err := Initialize(initOptions2)
		require.NoError(t, err)
		err = device2.ImportIdentity(subIdentityResponse.BackupKey)
		require.NoError(t, err)

		// verify that device2's currentDevice is as expected
		currentDevice2 := device2.storage.currentDevice.get()
		assert.Equal(t, currentDevice2.UserId, currentDevice.UserId)
		assert.NotEqual(t, currentDevice.DeviceId, currentDevice2.DeviceId)
		assert.NotEqual(t, currentDevice.EncryptionPrivateKey, currentDevice2.EncryptionPrivateKey)
		assert.NotEqual(t, currentDevice.SigningPrivateKey, currentDevice2.SigningPrivateKey)
		assert.Equal(t, 0, len(currentDevice2.OldEncryptionPrivateKeys))
		assert.Equal(t, 0, len(currentDevice2.OldSigningPrivateKeys))

		assert.Equal(t, 1, len(device1.storage.contacts.all()))

		// device2 gets contact of itself to check that it matches with device1's
		contact2 := device1.storage.contacts.get(currentDevice2.UserId)

		assert.Equal(t, contact2.Id, currentDevice.UserId)
		assert.Equal(t, 2, len(contact2.Devices))
		assert.ElementsMatch(t, contact2.Devices, self.Devices)

		// device2 does heartbeat
		err = device2.Heartbeat()
		require.NoError(t, err)

		// device1 revokes device2
		err = device1.RevokeSubIdentity(subIdentityResponse.DeviceId)
		require.NoError(t, err)

		// check that device 1 now knows only 1 device again
		self = device1.storage.contacts.get(currentDevice.UserId)
		assert.Equal(t, 1, len(self.Devices))

		// device2 cannot heartbeat anymore
		err = device2.Heartbeat()
		assert.ErrorIs(t, err, utils.APIError{Status: 403, Code: "KEY_REVOKED"})
	})

	t.Run("ExportIdentity/ImportIdentity", func(t *testing.T) {
		account1, err := createTestAccount("sdk_account_export_import1")
		require.NoError(t, err)

		currentDevice := account1.storage.currentDevice.get()
		self := account1.storage.contacts.get(currentDevice.UserId)

		bkp, err := account1.ExportIdentity()
		require.NoError(t, err)

		initOptions2, err := getInMemoryInitializeOptions("sdk_account_export_import2")
		require.NoError(t, err)
		account2, err := Initialize(initOptions2)
		require.NoError(t, err)

		err = account2.ImportIdentity(bkp)
		require.NoError(t, err)
		currentDevice2 := account2.storage.currentDevice.get()

		assert.Equal(t, currentDevice.UserId, currentDevice2.UserId)
		assert.Equal(t, currentDevice.DeviceId, currentDevice2.DeviceId)
		assert.Equal(t, currentDevice.EncryptionPrivateKey, currentDevice2.EncryptionPrivateKey)
		assert.Equal(t, currentDevice.SigningPrivateKey, currentDevice2.SigningPrivateKey)
		assert.NotNil(t, currentDevice2.DeviceExpires)
		assert.True(t, currentDevice.DeviceExpires.Equal(*currentDevice2.DeviceExpires))
		assert.Equal(t, 0, len(currentDevice2.OldEncryptionPrivateKeys))
		assert.Equal(t, 0, len(currentDevice2.OldSigningPrivateKeys))

		assert.Equal(t, 1, len(account1.storage.contacts.all()))

		contact2 := account1.storage.contacts.get(currentDevice2.UserId)

		assert.Equal(t, contact2.Id, currentDevice.UserId)
		assert.Equal(t, 1, len(contact2.Devices))
		assert.ElementsMatch(t, contact2.Devices, self.Devices)
	})

	t.Run("UpdateCurrentDevice", func(t *testing.T) {
		account1, err := createTestAccount("sdk_account_update_current_device")
		require.NoError(t, err)

		// fake remove DeviceExpire to simulate migration
		currentDevice := account1.storage.currentDevice.get()
		deviceExpireBefore := currentDevice.DeviceExpires
		currentDevice.DeviceExpires = nil
		account1.storage.currentDevice.set(currentDevice)
		err = account1.saveCurrentDevice()
		require.NoError(t, err)

		currentAccountInfoBefore := account1.GetCurrentAccountInfo()
		assert.Nil(t, currentAccountInfoBefore.DeviceExpires)

		err = account1.UpdateCurrentDevice()
		currentAccountInfoAfter := account1.GetCurrentAccountInfo()
		assert.NotNil(t, currentAccountInfoAfter.DeviceExpires)
		assert.True(t, deviceExpireBefore.Equal(*currentAccountInfoAfter.DeviceExpires))
	})

	t.Run("PushJWT", func(t *testing.T) {
		account, err := createTestAccount("sdk_account_push_jwt")
		require.NoError(t, err)

		nonce, err := utils.GenerateRandomNonce()
		require.NoError(t, err)
		t.Run("can push connectors", func(t *testing.T) {

			userCustomId := fmt.Sprintf("myid-%s@%s", nonce[:10], credentials.AppId)
			claims := test_utils.Claims{
				Scopes:       []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam, test_utils.PermissionAddConnector},
				ConnectorAdd: test_utils.ConnectorAdd{Type: "AP", Value: userCustomId},
			}

			jwt, err := test_utils.GetJWT(claims)
			require.NoError(t, err)
			err = account.PushJWT(jwt)
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()
			c, err := account.storage.connectors.getByValue(userCustomId, "AP")
			require.NoError(t, err)
			assert.Equal(t, userCustomId, c.Value)
			assert.Equal(t, common_models.ConnectorType("AP"), c.Type)
			assert.Equal(t, currentDevice.UserId, c.SealdId)
		})
		t.Run("cannot push invalid connectors", func(t *testing.T) {
			err = account.PushJWT("")
			assert.ErrorIs(t, err, utils.ErrorInvalidJWT)
			err = account.PushJWT("notAValidJwt")
			assert.ErrorIs(t, err, utils.ErrorInvalidJWT)
			err = account.PushJWT(invalidJWT)
			assert.ErrorIs(t, err, utils.APIError{Status: 403, Code: "INVALID_JWT"})
		})
		t.Run("Push JWT to join team, with already a team", func(t *testing.T) {
			joinTeamClaims := test_utils.Claims{
				Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
				JoinTeam: true,
			}
			joinTeamJWT, err := test_utils.GetJWT(joinTeamClaims)
			require.NoError(t, err)

			err = account.PushJWT(joinTeamJWT)
			assert.ErrorIs(t, err, utils.APIError{Status: 406, Code: "ALREADY_IN_TEAM"})
		})
	})

	t.Run("Hearbeat", func(t *testing.T) {
		account, err := createTestAccount("sdk_account_heartbeat")
		require.NoError(t, err)

		err = account.Heartbeat()
		assert.NoError(t, err)
	})

	t.Run("autoLogin", func(t *testing.T) {
		account, err := createTestAccount("sdk_account_autologin")
		require.NoError(t, err)

		originalApi, ok := account.apiClient.(*beardApiClient)
		require.True(t, ok)
		canaryApi := newCanaryBeardApiClient(originalApi)
		account.apiClient = canaryApi

		// user is already logged in : this shouldn't call the login
		err = account.Heartbeat()
		require.NoError(t, err)

		assert.Equal(t, 0, canaryApi.Counter["login"])
		assert.Equal(t, 0, canaryApi.Counter["getChallenge"])
		assert.Equal(t, 1, canaryApi.Counter["heartbeat"])

		// manually clear the login state
		originalApi.SessionId = ""
		originalApi.CSRFToken = ""

		// user is not logged in : this should call login then heartbeat
		err = account.Heartbeat()
		require.NoError(t, err)

		assert.Equal(t, 1, canaryApi.Counter["login"])
		assert.Equal(t, 1, canaryApi.Counter["getChallenge"])
		assert.Equal(t, 2, canaryApi.Counter["heartbeat"])

		// user is logged in again : this shouldn't call the login
		err = account.Heartbeat()
		require.NoError(t, err)

		assert.Equal(t, 1, canaryApi.Counter["login"])
		assert.Equal(t, 1, canaryApi.Counter["getChallenge"])
		assert.Equal(t, 3, canaryApi.Counter["heartbeat"])

		// manually corrupt the login state
		originalApi.SessionId = "bad session ID"

		// user thinks it is logged in : this should try heartbeat, then login, then heartbeat again
		err = account.Heartbeat()
		require.NoError(t, err)

		assert.Equal(t, 2, canaryApi.Counter["login"])
		assert.Equal(t, 2, canaryApi.Counter["getChallenge"])
		assert.Equal(t, 5, canaryApi.Counter["heartbeat"])

		// Error when invalid auth challenge
		canaryApi.ToExecute["getChallenge"] = func(_ any) ([]byte, error) {
			return json.Marshal(getChallengeResponse{NextChallenge: "bad challenge"})
		}
		originalApi.SessionId = ""
		originalApi.CSRFToken = ""
		err = account.Heartbeat()
		assert.ErrorIs(t, err, utils.ErrorInvalidAuthChallenge)
		var sealdError utils.SealdError
		require.ErrorAs(t, err, &sealdError)
		require.Equal(t, sealdError.Details, "bad challenge")
	})

	t.Run("handleLocked", func(t *testing.T) {
		account, err := createTestAccount("sdk_account_handle_locked")
		require.NoError(t, err)

		canaryApi := newCanaryBeardApiClient(account.apiClient)
		account.apiClient = canaryApi
		canaryApi.ToExecute["initGroupSigchain"] = func(request any) ([]byte, error) {
			if canaryApi.Counter["initGroupSigchain"] == 3 {
				var req = request.(*initGroupSigchainRequest)
				resp, err := canaryApi.Client.initGroupSigchain(req)
				require.NoError(t, err)
				return json.Marshal(resp)
			}
			return nil, tracerr.Wrap(utils.APIError{Status: 423, Code: ""})
		}

		preGeneratedKeys, err := getPreGeneratedKeys()
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		_, err = account.CreateGroup( // test with no-pregenerated keys
			"Group 1",
			[]string{currentDevice.UserId},
			[]string{currentDevice.UserId},
			preGeneratedKeys,
		)
		require.NoError(t, err)
		assert.Equal(t, 3, canaryApi.Counter["initGroupSigchain"])
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/account")

			// reading identity data
			rawSealdId, err := os.ReadFile(filepath.Join(testArtifactsDir, "seald_id"))
			require.NoError(t, err)
			sealdId := string(rawSealdId)
			rawDeviceId, err := os.ReadFile(filepath.Join(testArtifactsDir, "device_id"))
			require.NoError(t, err)
			deviceId := string(rawDeviceId)

			// can import identity from JS
			identity, err := os.ReadFile(filepath.Join(testArtifactsDir, "exported_identity"))
			require.NoError(t, err)
			initOptions, err := getInMemoryInitializeOptions("sdk_account_import_js1")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)
			err = account.ImportIdentity(identity)
			require.NoError(t, err)

			// imported identity is as expected
			currentDevice := account.storage.currentDevice.get()
			assert.Equal(t, sealdId, currentDevice.UserId)
			assert.Equal(t, deviceId, currentDevice.DeviceId)
			assert.Equal(t, 3, len(currentDevice.OldEncryptionPrivateKeys))
			assert.Equal(t, 3, len(currentDevice.OldSigningPrivateKeys))

			// imported identity works
			err = account.Heartbeat()
			require.NoError(t, err)

			// can import sub-identity from JS
			subIdentity, err := os.ReadFile(filepath.Join(testArtifactsDir, "sub_identity"))
			require.NoError(t, err)
			initOptions2, err := getInMemoryInitializeOptions("sdk_account_import_js2")
			require.NoError(t, err)
			account2, err := Initialize(initOptions2)
			require.NoError(t, err)
			err = account2.ImportIdentity(subIdentity)
			require.NoError(t, err)

			// imported sub-identity is as expected
			rawSubDeviceId, err := os.ReadFile(filepath.Join(testArtifactsDir, "sub_device_id"))
			require.NoError(t, err)
			subDeviceId := string(rawSubDeviceId)
			currentDevice2 := account2.storage.currentDevice.get()
			assert.Equal(t, sealdId, currentDevice2.UserId)
			assert.Equal(t, subDeviceId, currentDevice2.DeviceId)
			assert.Equal(t, 0, len(currentDevice2.OldEncryptionPrivateKeys))
			assert.Equal(t, 0, len(currentDevice2.OldSigningPrivateKeys))

			// imported sub-identity works
			err = account2.Heartbeat()
			require.NoError(t, err)
		})
		t.Run("Export for JS", func(t *testing.T) {
			// ensure artifacts dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/account")
			err = os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)
			// create identity
			account, err := createTestAccount("sdk_account_export_js")
			require.NoError(t, err)
			originalAccountKeys := stateToPreGenerated(account)

			// write identity data
			currentDevice := account.storage.currentDevice.get()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "seald_id"), []byte(currentDevice.UserId), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "device_id"), []byte(currentDevice.DeviceId), 0o700)
			require.NoError(t, err)

			// renew key a few times, so that key export is more complex
			preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{originalAccountKeys})
			require.NoError(t, err)
			err = account.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
			require.NoError(t, err)
			preGeneratedKeys2, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{originalAccountKeys, preGeneratedKeys})
			require.NoError(t, err)
			err = account.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys2})
			require.NoError(t, err)
			preGeneratedKeys3, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{originalAccountKeys, preGeneratedKeys, preGeneratedKeys2})
			require.NoError(t, err)
			err = account.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys3})
			require.NoError(t, err)

			// export identity
			exportedIdentity, err := account.ExportIdentity()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "exported_identity"), exportedIdentity, 0o700)
			require.NoError(t, err)

			// sub identity
			subIdentityResponse, err := account.CreateSubIdentity(&CreateSubIdentityOptions{DeviceName: "test", ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "sub_identity"), subIdentityResponse.BackupKey, 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "sub_device_id"), []byte(subIdentityResponse.DeviceId), 0o700)
			require.NoError(t, err)
		})
	})
}
