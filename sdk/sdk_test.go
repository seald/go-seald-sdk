package sdk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBeardApiClient_ReadDatabaseNotCreated(t *testing.T) {
	options, err := getInitializeOptions("ReadDatabaseNotCreated", true, "sdk_db_not_created")
	require.NoError(t, err)

	accountState, err := Initialize(options)
	require.NoError(t, err)

	currentDevice := accountState.storage.currentDevice.get()
	assert.Equal(t, "", currentDevice.UserId)
	assert.Equal(t, "", currentDevice.DeviceId)
	assert.Nil(t, currentDevice.EncryptionPrivateKey)
	assert.Nil(t, currentDevice.SigningPrivateKey)
	assert.Nil(t, currentDevice.OldEncryptionPrivateKeys)
	assert.Nil(t, currentDevice.OldSigningPrivateKeys)
}

func TestBeardApiClient_ReadDatabaseEmptyFile(t *testing.T) {
	options, err := getInitializeOptions("ReadDatabaseEmptyFile", true, "sdk_db_empty")
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)

	err = os.MkdirAll(filepath.Join(wd, "test_output", "ReadDatabaseEmptyFile"), 0700)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(wd, "test_output", "ReadDatabaseEmptyFile", "current_device_storage"), []byte{}, 0600)
	require.NoError(t, err)

	accountState, err := Initialize(options)
	require.NoError(t, err)

	currentDevice := accountState.storage.currentDevice.get()
	assert.Equal(t, "", currentDevice.UserId)
	assert.Equal(t, "", currentDevice.DeviceId)
	assert.Nil(t, currentDevice.EncryptionPrivateKey)
	assert.Nil(t, currentDevice.SigningPrivateKey)
	assert.Nil(t, currentDevice.OldEncryptionPrivateKeys)
	assert.Nil(t, currentDevice.OldSigningPrivateKeys)
}

func TestMaxParallelRequests(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		options, err := getInitializeOptions("MaxParallelDefault", true, "sdk_max_parallel_default")
		require.NoError(t, err)

		options.MaxParallelRequests = 0

		state, err := Initialize(options)
		require.NoError(t, err)

		assert.Equal(t, 10, state.options.MaxParallelRequests)
		assert.Equal(t, 10, options.MaxParallelRequests)

		err = createTestAccountFromSdkInstance(state)
		require.NoError(t, err)

		err = state.Heartbeat()
		require.NoError(t, err)

		err = state.Close()
		require.NoError(t, err)
	})

	t.Run("custom limit", func(t *testing.T) {
		options, err := getInitializeOptions("MaxParallelCustom", true, "sdk_max_parallel_custom")
		require.NoError(t, err)

		options.MaxParallelRequests = 3

		state, err := Initialize(options)
		require.NoError(t, err)

		assert.Equal(t, 3, state.options.MaxParallelRequests)

		err = createTestAccountFromSdkInstance(state)
		require.NoError(t, err)

		err = state.Heartbeat()
		require.NoError(t, err)

		err = state.Close()
		require.NoError(t, err)
	})

	t.Run("no limit", func(t *testing.T) {
		options, err := getInitializeOptions("MaxParallelUnlimitted", true, "sdk_max_parallel_unlimitted")
		require.NoError(t, err)

		options.MaxParallelRequests = -1

		state, err := Initialize(options)
		require.NoError(t, err)

		assert.Equal(t, -1, state.options.MaxParallelRequests)

		err = createTestAccountFromSdkInstance(state)
		require.NoError(t, err)

		err = state.Heartbeat()
		require.NoError(t, err)

		err = state.Close()
		require.NoError(t, err)
	})
}
