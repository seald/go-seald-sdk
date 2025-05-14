package anonymous_sdk

import (
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestAnonymousEncryptionSessionSDK(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)

	options := &AnonymousInitializeOptions{
		ApiURL:       credentials.ApiUrl,
		AppId:        credentials.AppId,
		InstanceName: "anonymous-tests",
		Platform:     "go-tests",
	}
	aSdk := CreateAnonymousSDK(options)

	sdkFullUser, err := createTestAccount()
	require.NoError(t, err)
	fullUserId := (sdkFullUser.GetCurrentAccountInfo()).UserId

	recipients := &Recipients{
		SealdIds: []string{fullUserId},
	}

	createToken, err := test_utils.GetJWT(test_utils.Claims{
		Recipients: []string{fullUserId},
		Owner:      fullUserId,
		Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
	})
	require.NoError(t, err)

	aES, err := aSdk.CreateAnonymousEncryptionSession(createToken, createToken, recipients)
	require.NoError(t, err)
	assert.True(t, utils.IsUUID(aES.SessionId))

	// Retrieve an ES with the TMR token
	tmrES, err := sdkFullUser.RetrieveEncryptionSession(aES.SessionId, false, false, false)
	require.NoError(t, err)

	t.Run("EncryptMessage DecryptMessage", func(t *testing.T) {
		message := "Paris Marathon 13/04/2025"
		encryptMessage, err := aES.EncryptMessage(message)
		require.NoError(t, err)

		clearMessage, err := aES.DecryptMessage(encryptMessage)
		require.NoError(t, err)
		assert.Equal(t, message, clearMessage)

		clearMessageTMR, err := tmrES.DecryptMessage(encryptMessage)
		require.NoError(t, err)
		assert.Equal(t, message, clearMessageTMR)
	})

	t.Run("EncryptFile DecryptFile", func(t *testing.T) {
		clearData := []byte("There was a successful Tinder match in Antarctica in 2014.")
		clearFileName := "myFile.txt"

		encryptedFile, err := aES.EncryptFile(clearData, clearFileName)
		assert.NoError(t, err)

		clearFile, err := aES.DecryptFile(encryptedFile)
		assert.NoError(t, err)
		assert.Equal(t, clearData, clearFile.FileContent)
		assert.Equal(t, clearFileName, clearFile.Filename)
		assert.Equal(t, aES.SessionId, clearFile.SessionId)

		clearFileTMR, err := tmrES.DecryptFile(encryptedFile)
		assert.NoError(t, err)
		assert.Equal(t, clearData, clearFileTMR.FileContent)
		assert.Equal(t, clearFileName, clearFileTMR.Filename)
		assert.Equal(t, aES.SessionId, clearFileTMR.SessionId)
	})
	t.Run("EncryptFileFromPath DecryptFileFromPath", func(t *testing.T) {
		// Clean work dir
		_ = os.RemoveAll("tmp/")
		err := os.Mkdir("tmp", 0o700)
		require.NoError(t, err)

		clearData := []byte("Japan has 23 vending machines per person.")
		testFileDir, err := filepath.Abs("tmp")
		require.NoError(t, err)
		testFileName := "random"
		testFileExt := ".fact"
		testFilePath := filepath.Join(testFileDir, testFileName+testFileExt)
		err = os.WriteFile(testFilePath, clearData, 0o700)
		require.NoError(t, err)

		encryptedFilePath, err := aES.EncryptFileFromPath(testFilePath)
		require.NoError(t, err)
		assert.Equal(t, testFilePath+".seald", encryptedFilePath)
		decryptedFilePath, err := aES.DecryptFileFromPath(encryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(testFileDir, testFileName+" (1)"+testFileExt), decryptedFilePath)

		decryptedContent, err := os.ReadFile(decryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, clearData, decryptedContent)

		// Test that regular SDK can retrieve the ES from file
		esRetrieve, err := sdkFullUser.RetrieveEncryptionSessionFromFile(encryptedFilePath, true, false, false)
		require.NoError(t, err)
		decryptedFilePath2, err := esRetrieve.DecryptFileFromPath(encryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(testFileDir, testFileName+" (2)"+testFileExt), decryptedFilePath2)
	})

	t.Run("Serialize / Deserialize", func(t *testing.T) {
		serializedSession, err := aES.Serialize()
		require.NoError(t, err)

		deserializedSession, err := aSdk.DeserializeAnonymousEncryptionSession(serializedSession)
		require.NoError(t, err)

		assert.Equal(t, aES.SessionId, deserializedSession.SessionId)
		assert.Equal(t, aES.Key.Encode(), deserializedSession.Key.Encode())
	})
}
