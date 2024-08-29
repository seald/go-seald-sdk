package sdk

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/common_models"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func Test_Storage(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)

	initOptions, err := getInitializeOptions("testDB_persistence", true, "sdk_storage_1")
	require.NoError(t, err)
	initOptions2, err := getInitializeOptions("testDB_persistence", true, "sdk_storage_2")
	require.NoError(t, err)
	dbPath, err := test_utils.GetDBPath("testDB_persistence")
	require.NoError(t, err)
	initOptions.EncryptionSessionCacheTTL = 1 * time.Hour
	sdk, err := Initialize(initOptions)
	require.NoError(t, err)

	claims := test_utils.Claims{
		Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
		JoinTeam: true,
	}

	jwt, err := test_utils.GetJWT(claims)
	require.NoError(t, err)

	preGeneratedKeys, err := getPreGeneratedKeys()
	require.NoError(t, err)

	_, err = sdk.CreateAccount(&CreateAccountOptions{
		DisplayName:      "Dadada",
		DeviceName:       "Dididi",
		SignupJWT:        jwt,
		ExpireAfter:      time.Hour * 24 * 365 * 5,
		PreGeneratedKeys: preGeneratedKeys,
	})
	require.NoError(t, err)
	currentDevice := sdk.storage.currentDevice.get()

	otherAccount, err := createTestAccount("sdk_storage_other")
	require.NoError(t, err)
	currentDevice2 := otherAccount.storage.currentDevice.get()

	nonce, err := utils.GenerateRandomNonce()
	require.NoError(t, err)
	APValue := fmt.Sprintf("AP-%s@%s", nonce[:10], credentials.AppId)
	preValidationToken, err := utils.GeneratePreValidationToken(APValue, credentials.DomainValidationKey, credentials.DomainValidationKeyId)
	require.NoError(t, err)
	connector, err := sdk.AddConnector(APValue, common_models.ConnectorTypeApp, preValidationToken)
	require.NoError(t, err)

	preGeneratedKeysGroup, err := getPreGeneratedKeys()
	require.NoError(t, err)
	groupId, err := sdk.CreateGroup(
		"groupName",
		[]string{currentDevice.UserId, currentDevice2.UserId},
		[]string{currentDevice.UserId},
		preGeneratedKeysGroup,
	)
	require.NoError(t, err)

	_, _, err = sdk.getUpdatedContacts([]string{currentDevice2.UserId, groupId})
	require.NoError(t, err)

	group := sdk.storage.groups.get(groupId)

	allRights := &RecipientRights{
		Read:    true,
		Revoke:  true,
		Forward: true,
	}
	recipientDevice1 := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
	recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}
	es, err := sdk.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, true)
	message := "Where did the IT guy go? He ransomeware."
	sealdMessage, err := es.EncryptMessage(message)
	require.NoError(t, err)

	preGeneratedKeys2, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{preGeneratedKeys})
	require.NoError(t, err)
	err = sdk.RenewKeys(RenewKeysOptions{
		ExpireAfter:      time.Hour * 24 * 365 * 5,
		PreGeneratedKeys: preGeneratedKeys2,
	})
	require.NoError(t, err)

	es2, err := sdk.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, true)
	require.NoError(t, err)

	// Now, database has a user with: 2 privateKeys, 2 encryptionSessions, 1 connector, 2 contacts, 1 group

	// Cannot read from files, as DB is still locked
	sdkFromLockedLocalDB, err := Initialize(initOptions2)
	require.ErrorIs(t, err, ErrorDatabaseLocked)
	require.Nil(t, sdkFromLockedLocalDB)

	// Close SDK to unlock DB
	err = sdk.Close()
	require.NoError(t, err)

	// Let's read it from files.
	sdkFromLocalDB, err := Initialize(initOptions2)
	require.NoError(t, err)
	require.NotNil(t, sdkFromLocalDB)
	currentDeviceLocalDB := sdkFromLocalDB.storage.currentDevice.get()
	assert.Equal(t, currentDevice.UserId, currentDeviceLocalDB.UserId)

	// check that files have correct permissions
	fileInfo, err := os.Lstat(filepath.Join(dbPath, "current_device_storage"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" { // permissions suck on windows
		assert.Equal(t, os.FileMode(0600), fileInfo.Mode())
	}

	err = sdkFromLocalDB.Heartbeat() // heartbeat needs autologin, which uses signing keys
	require.NoError(t, err)

	// es and es2 should be in ES cache
	esFromLocalDB, err := sdkFromLocalDB.storage.encryptionSessionsCache.get(es.Id)
	require.NoError(t, err)
	require.NotNil(t, esFromLocalDB)
	assert.Equal(t, es.Key.Encode(), esFromLocalDB.Symkey.Encode())

	es2FromLocalDB, err := sdkFromLocalDB.storage.encryptionSessionsCache.get(es2.Id)
	require.NoError(t, err)
	require.NotNil(t, es2FromLocalDB)
	assert.Equal(t, es2.Key.Encode(), es2FromLocalDB.Symkey.Encode())

	retrievedEs, err := sdkFromLocalDB.RetrieveEncryptionSession(es.Id, false, false, false) // No cache, so it uses the *old* privateKey from Storage to get the ES.
	require.NoError(t, err)
	clear, err := retrievedEs.DecryptMessage(sealdMessage)
	assert.Equal(t, message, clear)

	retrievedEs2, err := sdkFromLocalDB.RetrieveEncryptionSession(es2.Id, false, false, false) // No cache, so it uses the privateKey from Storage to get the ES.
	require.NoError(t, err)
	require.NotNil(t, retrievedEs2)
	assert.Equal(t, es2.Id, retrievedEs2.Id)

	// The group should be in group cache
	groupFromLocalDB := sdkFromLocalDB.storage.groups.get(groupId)
	require.NotNil(t, groupFromLocalDB)
	assert.Equal(t, group.Members, groupFromLocalDB.Members)

	// otherAccount and group should be in contact cache
	groupContactFromLocalDB := sdkFromLocalDB.storage.contacts.get(groupId)
	require.NotNil(t, groupContactFromLocalDB)
	assert.True(t, groupContactFromLocalDB.IsGroup)
	assert.Equal(t, group.Id, groupContactFromLocalDB.Id)
	otherUserFromLocalDB := sdkFromLocalDB.storage.contacts.get(currentDevice2.UserId)
	require.NotNil(t, otherUserFromLocalDB)
	assert.False(t, otherUserFromLocalDB.IsGroup)
	assert.Equal(t, currentDevice2.DeviceId, otherUserFromLocalDB.Devices[0].Id)

	connectorFromLocalDB, err := sdkFromLocalDB.storage.connectors.getByValue(APValue, common_models.ConnectorTypeApp)
	require.NoError(t, err)
	require.NotNil(t, connectorFromLocalDB)
	assert.Equal(t, connector, connectorFromLocalDB)
}
