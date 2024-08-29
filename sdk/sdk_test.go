package sdk

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
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
