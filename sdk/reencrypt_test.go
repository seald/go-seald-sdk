package sdk

import (
	"errors"
	"fmt"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ztrue/tracerr"
	"testing"
	"time"
)

var deviceNameIndex = 0

func makeNewDevice(t *testing.T, device *State, instanceName string) *State {
	deviceName := fmt.Sprintf("device-%d", deviceNameIndex)
	deviceNameIndex++
	subIdentityResponse, err := device.CreateSubIdentity(&CreateSubIdentityOptions{DeviceName: deviceName, ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
	require.NoError(t, err)

	initOptionsDevice2, err := getInMemoryInitializeOptions(instanceName)
	require.NoError(t, err)
	device2, err := Initialize(initOptionsDevice2)
	require.NoError(t, err)

	err = device2.ImportIdentity(subIdentityResponse.BackupKey)
	require.NoError(t, err)

	return device2
}

func TestState_MassReencrypt(t *testing.T) {
	t.Skip("too long")
	// First, we create an account with messages to reencrypt.
	// We need multiple pages of keys, so we create 220 messages:
	// 110 for the initial private key, then we renew keys, then 110 others for the renewed key.
	// Each following test will reencrypt those messages keys for a new device of this account.
	device1, err := createTestAccount("sdk_reencrypt_1")
	require.NoError(t, err)
	currentDevice := device1.storage.currentDevice.get()
	allRights := &RecipientRights{
		Read:    true,
		Revoke:  true,
		Forward: true,
	}
	recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}

	var sessions []*EncryptionSession

	for i := 0; i < 110; i++ {
		es, err := device1.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
		require.NoError(t, err)
		sessions = append(sessions, es)
	}

	preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(device1)})
	require.NoError(t, err)
	err = device1.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
	require.NoError(t, err)

	for i := 0; i < 110; i++ {
		es, err := device1.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
		require.NoError(t, err)
		sessions = append(sessions, es)
	}

	// Generate massReencrypt options for tests
	massReencryptOptions := NewMassReencryptOptions()
	massReencryptOptions.WaitBetweenRetries = 250 * time.Millisecond // For quicker tests
	massReencryptOptions.RetrieveBatchSize = 100                     // So we have 3 batches

	t.Parallel()
	t.Run("Basic test", func(t *testing.T) {
		// CheckMissingKeys finds nothing
		missingBefore, err := device1.DevicesMissingKeys(false)
		assert.Empty(t, missingBefore)

		newDevice := makeNewDevice(t, device1, "sdk_reencrypt_new_basic")
		newCurrentDevice := newDevice.storage.currentDevice.get()

		// New device doesn't have a token yet.
		_, err = newDevice.RetrieveEncryptionSession(sessions[0].Id, false, false, false)
		assert.ErrorIs(t, err, utils.APIError{Status: 410, Code: "NO_TOKEN"})

		// CheckMissingKeys finds the new device
		missingDuring, err := device1.DevicesMissingKeys(false)
		assert.Equal(t, 1, len(missingDuring))
		assert.Equal(t, newCurrentDevice.DeviceId, missingDuring[0].DeviceId)

		// First device reencrypts for the new one.
		reencrypted, failed, err := device1.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)
		assert.Equal(t, 220, reencrypted)
		assert.Equal(t, 0, failed)

		// New device have a key for all messages.
		for i := 0; i < 22; i++ { // No need to test all, just some of each reencryption pages
			_, err = newDevice.RetrieveEncryptionSession(sessions[i*10].Id, false, false, false)
			require.NoError(t, err)
		}

		// Check that no message is left to reencrypt
		reencrypted, failed, err = device1.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)
		assert.Equal(t, reencrypted, 0)
		assert.Equal(t, failed, 0)

		// CheckMissingKeys finds nothing again
		missingAfter, err := device1.DevicesMissingKeys(false)
		assert.Empty(t, missingAfter)
	})

	t.Run("invalid arguments", func(t *testing.T) {
		badDevice, err := createTestAccount("sdk_reencrypt_invalid_args")
		require.NoError(t, err)

		_, _, err = badDevice.MassReencrypt("not an UUIDv4", massReencryptOptions)
		assert.ErrorIs(t, err, ErrorInvalidDeviceId)
	})

	t.Run("api error", func(t *testing.T) {
		canaryDevice := makeNewDevice(t, device1, "sdk_reencrypt_api_error1")
		canaryCurrentDevice := canaryDevice.storage.currentDevice.get()
		_, _, err = device1.MassReencrypt(canaryCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)

		newDevice := makeNewDevice(t, canaryDevice, "sdk_reencrypt_api_error2")
		newCurrentDevice := newDevice.storage.currentDevice.get()

		canaryApi := newCanaryBeardApiClient(canaryDevice.apiClient)
		canaryDevice.apiClient = canaryApi

		canaryApi.ToExecute["addMissingKeys"] = func(_ any) ([]byte, error) {
			return nil, tracerr.New("synthetic error addMissingKeys")
		}
		_, _, err = canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		assert.EqualError(t, err, "synthetic error addMissingKeys")

		canaryApi.ToExecute["missingMessageKeys"] = func(_ any) ([]byte, error) {
			return nil, tracerr.New("synthetic error missingMessageKeys")
		}
		_, _, err = canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		assert.EqualError(t, err, "synthetic error missingMessageKeys")
	})

	t.Run("retries getMissingKeys", func(t *testing.T) {
		// We need a device that will reencrypt with a canaryAPI (canaryDevice), and a device to reencrypt for newDevice.
		canaryDevice := makeNewDevice(t, device1, "sdk_reencrypt_retries_get1")
		canaryCurrentDevice := canaryDevice.storage.currentDevice.get()
		_, _, err = device1.MassReencrypt(canaryCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)

		// Device needing mass-reencrypt
		newDevice := makeNewDevice(t, canaryDevice, "sdk_reencrypt_retries_get2")
		newCurrentDevice := newDevice.storage.currentDevice.get()

		canaryApi := newCanaryBeardApiClient(canaryDevice.apiClient)
		canaryDevice.apiClient = canaryApi

		// Ensure provisioning is done so MassReencrypt API call will succeed at first try. We need it for canary counter.
		provisionningReq := &missingMessageKeyRequest{
			DeviceId:              newCurrentDevice.DeviceId,
			MaxResults:            100,
			ErrorIfNotProvisioned: true,
		}
		provisioningDone := false
		for i := 0; i < 30; i++ {
			_, err := canaryApi.Client.missingMessageKeys(provisionningReq)
			if err == nil {
				provisioningDone = true
				break
			}
			if !errors.Is(err, utils.APIError{Status: 406, Code: "DEVICE_NOT_PROVISIONED_YET"}) {
				break
			}
		}
		assert.True(t, provisioningDone)

		MissingMessageKeysCounter := 0
		canaryApi.ToExecute["missingMessageKeys"] = func(_ any) ([]byte, error) {
			MissingMessageKeysCounter++
			if MissingMessageKeysCounter > 2 {
				return nil, tracerr.New("synthetic error missingMessageKeys")
			}
			return nil, nil
		}
		AddMissingKeysCounter := 0
		canaryApi.ToExecute["addMissingKeys"] = func(_ any) ([]byte, error) {
			AddMissingKeysCounter++
			return nil, nil
		}

		reencrypted, failed, err := canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		assert.EqualError(t, err, "synthetic error missingMessageKeys")
		assert.Equal(t, 200, reencrypted)             // two 100 batch succeeded
		assert.Equal(t, 0, failed)                    // We failed to get the batch, we didn't fail any reencryption
		assert.Equal(t, 6, MissingMessageKeysCounter) // 2 firsts that worked, 1fail 3 retries
		assert.Equal(t, 2, AddMissingKeysCounter)

		// New device has a key for only 200 first messages.
		for i := 0; i < 22; i++ {
			_, err = newDevice.RetrieveEncryptionSession(sessions[i*10].Id, false, false, false)
			if i < 20 {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, utils.APIError{Status: 410, Code: "NO_TOKEN"})
			}
		}

		MissingMessageKeysCounter = 0
		AddMissingKeysCounter = 0
		canaryApi.ToExecute["missingMessageKeys"] = func(_ any) ([]byte, error) {
			MissingMessageKeysCounter++
			return nil, nil
		}
		reencrypted, failed, err = canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)
		assert.Equal(t, 20, reencrypted)
		assert.Equal(t, 0, failed)
		assert.Equal(t, 1, MissingMessageKeysCounter)
		assert.Equal(t, 1, AddMissingKeysCounter)

		// New device have a key for all messages.
		for i := 0; i < 22; i++ { // No need to test all, just some of each reencryption pages
			_, err = newDevice.RetrieveEncryptionSession(sessions[i*10].Id, false, false, false)
			require.NoError(t, err)
		}
	})

	t.Run("retries addMissingKeys", func(t *testing.T) {
		// We need a device that will reencrypt with a canaryAPI (canaryDevice), and a device to reencrypt for newDevice.
		canaryDevice := makeNewDevice(t, device1, "sdk_reencrypt_retries_add1")
		canaryCurrentDevice := canaryDevice.storage.currentDevice.get()
		_, _, err = device1.MassReencrypt(canaryCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)

		// Device needing mass-reencrypt
		newDevice := makeNewDevice(t, canaryDevice, "sdk_reencrypt_retries_add2")
		newCurrentDevice := newDevice.storage.currentDevice.get()

		canaryApi := newCanaryBeardApiClient(canaryDevice.apiClient)
		canaryDevice.apiClient = canaryApi

		AddMissingKeysCounter := 0
		canaryApi.ToExecute["addMissingKeys"] = func(_ any) ([]byte, error) {
			AddMissingKeysCounter++
			if AddMissingKeysCounter == 2 {
				return nil, tracerr.New("synthetic error addMissingKeys")
			}
			if AddMissingKeysCounter > 3 {
				return nil, tracerr.New("synthetic error addMissingKeys")
			}
			return nil, nil
		}

		reencrypted, failed, err := canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		assert.EqualError(t, err, "synthetic error addMissingKeys")
		assert.Equal(t, 200, reencrypted)
		assert.Equal(t, 160, failed)              // one full batch failed, plus 3 times the last batch of 20
		assert.Equal(t, 6, AddMissingKeysCounter) // 2 firsts that worked, first throw, 3 retries

		// New device have a key for only 200 first messages.
		for i := 0; i < 22; i++ {
			_, err = newDevice.RetrieveEncryptionSession(sessions[i*10].Id, false, false, false)
			if i < 20 {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, utils.APIError{Status: 410, Code: "NO_TOKEN"})
			}
		}

		AddMissingKeysCounter = 0
		canaryApi.ToExecute["addMissingKeys"] = func(_ any) ([]byte, error) {
			AddMissingKeysCounter++
			return nil, nil
		}
		reencrypted, failed, err = canaryDevice.MassReencrypt(newCurrentDevice.DeviceId, massReencryptOptions)
		require.NoError(t, err)
		assert.Equal(t, 20, reencrypted)
		assert.Equal(t, 0, failed)
		assert.Equal(t, 1, AddMissingKeysCounter)

		// New device has a key for all messages.
		for i := 0; i < 22; i++ { // No need to test all, just some of each reencryption pages
			_, err = newDevice.RetrieveEncryptionSession(sessions[i*10].Id, false, false, false)
			require.NoError(t, err)
		}
	})
}
