package ssks_password

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"testing"
)

func createUserId() (string, error) {
	nonce, err := utils.GenerateRandomNonce()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("user1-%s", nonce[:10]), nil

}

func TestPluginPassword(t *testing.T) {
	testCred, err := test_utils.GetCredentials()
	require.NoError(t, err)

	options := &PluginPasswordInitializeOptions{
		SsksURL:      testCred.SsksUrl,
		AppId:        testCred.AppId,
		InstanceName: "plugin-password-tests",
		Platform:     "go-tests",
	}
	pluginInstance1 := NewPluginPassword(options)

	dummyData := []byte("dummyData")

	rawStorageKey, err := utils.GenerateRandomNonce()
	require.NoError(t, err)
	rawEncryptionKey, err := symmetric_key.Generate()
	require.NoError(t, err)
	encodedRawEncryptionKey := rawEncryptionKey.Encode()

	t.Parallel()
	t.Run("Password save/retrieve/change", func(t *testing.T) {
		userId, err := createUserId()
		userPassword := userId
		require.NoError(t, err)

		// save identity with a certain password
		ssksId1, err := pluginInstance1.SaveIdentityFromPassword(userId, userPassword, dummyData)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(ssksId1))

		// can retrieve the identity
		retrieveIdentityBuff, err := pluginInstance1.RetrieveIdentityFromPassword(userId, userPassword)
		require.NoError(t, err)
		assert.Equal(t, dummyData, retrieveIdentityBuff)

		// change to different password
		newPassword := "it's not the same password"
		ssksId2, err := pluginInstance1.ChangeIdentityPassword(userId, userPassword, newPassword)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(ssksId2))
		assert.NotEqual(t, ssksId1, ssksId2)

		// can retrieve the identity with the new password
		retrieveIdentityBuff, err = pluginInstance1.RetrieveIdentityFromPassword(userId, newPassword)
		require.NoError(t, err)
		assert.Equal(t, dummyData, retrieveIdentityBuff)

		// cannot retrieve with the old password
		_, err = pluginInstance1.RetrieveIdentityFromPassword(userId, userPassword)
		assert.ErrorIs(t, err, ErrorCannotFindIdentity)
	})

	t.Run("Raw keys save/retrieve", func(t *testing.T) {
		userId, err := createUserId()
		require.NoError(t, err)

		// save identity with raw keys
		ssksId1, err := pluginInstance1.SaveIdentityFromRawKeys(userId, rawStorageKey, encodedRawEncryptionKey, dummyData)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(ssksId1))

		// can retrieve it with these raw keys
		retrieveIdentityBuff, err := pluginInstance1.RetrieveIdentityFromRawKeys(userId, rawStorageKey, encodedRawEncryptionKey)
		require.NoError(t, err)
		assert.Equal(t, dummyData, retrieveIdentityBuff)

		// "delete" identity by saving `nil` with the same keys
		ssksId2, err := pluginInstance1.SaveIdentityFromRawKeys(userId, rawStorageKey, encodedRawEncryptionKey, nil)
		require.NoError(t, err)
		assert.Equal(t, ssksId1, ssksId2)

		// Cannot retrieve it anymore
		_, err = pluginInstance1.RetrieveIdentityFromRawKeys(userId, rawStorageKey, encodedRawEncryptionKey)
		assert.ErrorIs(t, err, ErrorCannotFindIdentity)
	})

	t.Run("SaveIdentityFromPassword", func(t *testing.T) {
		userId, err := createUserId()
		require.NoError(t, err)
		t.Run("no password", func(t *testing.T) {
			_, err = pluginInstance1.SaveIdentityFromPassword(userId, "", dummyData)
			assert.ErrorIs(t, err, ErrorSaveIdentityPasswordNoPassword)
		})
	})

	t.Run("SaveIdentityFromRawKeys", func(t *testing.T) {
		userId, err := createUserId()
		require.NoError(t, err)
		t.Run("no rawStorageKey", func(t *testing.T) {
			_, err = pluginInstance1.SaveIdentityFromRawKeys(userId, "", encodedRawEncryptionKey, dummyData)
			assert.ErrorIs(t, err, ErrorInvalidRawStorageKeyFormat)
		})
		t.Run("no rawEncryptionKey", func(t *testing.T) {
			_, err = pluginInstance1.SaveIdentityFromRawKeys(userId, rawStorageKey, nil, dummyData)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("bad rawEncryptionKey", func(t *testing.T) {
			_, err = pluginInstance1.SaveIdentityFromRawKeys(userId, rawStorageKey, []byte("foobar!"), dummyData)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
	})

	t.Run("RetrieveIdentityFromPassword", func(t *testing.T) {
		userId, err := createUserId()
		require.NoError(t, err)
		t.Run("no password", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentityFromPassword(userId, "")
			assert.ErrorIs(t, err, ErrorRetrieveIdentityPasswordNoPassword)
		})
		t.Run("bad password", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentityFromPassword(userId, "bad password")
			assert.ErrorIs(t, err, ErrorCannotFindIdentity)
		})
	})

	t.Run("RetrieveIdentityFromRawKeys", func(t *testing.T) {
		userId, err := createUserId()
		require.NoError(t, err)
		t.Run("no rawStorageKey", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentityFromRawKeys(userId, "", encodedRawEncryptionKey)
			assert.ErrorIs(t, err, ErrorInvalidRawStorageKeyFormat)
		})
		t.Run("no rawEncryptionKey", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentityFromRawKeys(userId, rawStorageKey, nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("bad rawEncryptionKey", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentityFromRawKeys(userId, rawStorageKey, []byte("foobar!"))
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
	})

	t.Run("ChangeIdentityPassword", func(t *testing.T) {
		userId, err := createUserId()
		userPassword := userId
		require.NoError(t, err)
		newPassword := "this is a new password"
		t.Run("no current password", func(t *testing.T) {
			_, err = pluginInstance1.ChangeIdentityPassword(userId, "", newPassword)
			assert.ErrorIs(t, err, ErrorChangeIdentityNoPassword)
		})
		t.Run("no new password", func(t *testing.T) {
			_, err = pluginInstance1.ChangeIdentityPassword(userId, userPassword, "")
			assert.ErrorIs(t, err, ErrorChangeIdentityNoNewPassword)
		})
		t.Run("bad current password", func(t *testing.T) {
			_, err = pluginInstance1.ChangeIdentityPassword(userId, "bad password", newPassword)
			assert.ErrorIs(t, err, ErrorCannotFindIdentity)
		})
		t.Run("change for the same password", func(t *testing.T) {
			_, err = pluginInstance1.ChangeIdentityPassword(userId, newPassword, newPassword)
			assert.ErrorIs(t, err, ErrorChangeIdentitySamePassword)
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/ssks_password")

			// Can retrieve identity from password
			userId, err := os.ReadFile(filepath.Join(testArtifactsDir, "user_id"))
			require.NoError(t, err)
			password, err := os.ReadFile(filepath.Join(testArtifactsDir, "password"))
			require.NoError(t, err)
			options := &PluginPasswordInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-password-tests-from-js",
				Platform:     "go-tests",
			}
			ssksPassword := NewPluginPassword(options)
			retrievedIdentityFromPassword, err := ssksPassword.RetrieveIdentityFromPassword(
				string(userId),
				string(password),
			)
			require.NoError(t, err)

			// Can retrieve identity from raw keys
			rawStorageKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "raw_storage_key"))
			require.NoError(t, err)
			rawEncryptionKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "raw_encryption_key"))
			require.NoError(t, err)
			decodedKey, err := base64.StdEncoding.DecodeString(string(rawEncryptionKey))
			retrievedIdentityFromRawKeys, err := ssksPassword.RetrieveIdentityFromRawKeys(
				string(userId),
				string(rawStorageKey),
				decodedKey,
			)
			require.NoError(t, err)

			// Retrieved identities are as expected
			exportedIdentity, err := os.ReadFile(filepath.Join(testArtifactsDir, "exported_identity"))
			require.NoError(t, err)
			assert.Equal(t, exportedIdentity, retrievedIdentityFromPassword)
			assert.Equal(t, exportedIdentity, retrievedIdentityFromRawKeys)
		})
		t.Run("Export for JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/ssks_password")
			// make sure dir exists
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// create identity
			account, err := createTestAccount()
			require.NoError(t, err)

			// export identity
			exportedIdentity, err := account.ExportIdentity()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "exported_identity"), exportedIdentity, 0o700)
			require.NoError(t, err)

			// save identity with password
			userId := test_utils.GetRandomString(10)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "user_id"), []byte(userId), 0o700)
			require.NoError(t, err)
			password := test_utils.GetRandomString(10)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "password"), []byte(password), 0o700)
			require.NoError(t, err)
			options := &PluginPasswordInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-password-tests-for-js",
				Platform:     "go-tests",
			}
			ssksPassword := NewPluginPassword(options)
			_, err = ssksPassword.SaveIdentityFromPassword(
				userId,
				password,
				exportedIdentity,
			)

			// save identity with raw keys
			rawStorageKey := test_utils.GetRandomString(64)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "raw_storage_key"), []byte(rawStorageKey), 0o700)
			require.NoError(t, err)
			rawEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			encodedRawEncryptionKey := base64.StdEncoding.EncodeToString(rawEncryptionKey.Encode())
			err = os.WriteFile(filepath.Join(testArtifactsDir, "raw_encryption_key"), []byte(encodedRawEncryptionKey), 0o700)
			require.NoError(t, err)
			_, err = ssksPassword.SaveIdentityFromRawKeys(
				userId,
				rawStorageKey,
				rawEncryptionKey.Encode(),
				exportedIdentity,
			)
		})
	})
}
