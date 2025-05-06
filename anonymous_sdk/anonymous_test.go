package anonymous_sdk

import (
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/seald/go-seald-sdk/ssks_tmr"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestAnonymousSDK(t *testing.T) {
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

	defaultRecipients := &Recipients{
		SealdIds: []string{fullUserId},
	}

	t.Run("createEncryptionSession", func(t *testing.T) {
		createToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients: []string{fullUserId},
			Owner:      fullUserId,
			Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
		})
		require.NoError(t, err)

		es, err := aSdk.CreateAnonymousEncryptionSession(createToken, createToken, defaultRecipients)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(es.SessionId))
	})

	t.Run("Encrypt, classic retrieve and compatibility", func(t *testing.T) {
		// Creating a TMR recipient
		overEncryptionKey, err := symmetric_key.Generate()
		require.NoError(t, err)
		overEncryptionKeyBytes := overEncryptionKey.Encode()

		nonce, err := utils.GenerateRandomNonce()
		require.NoError(t, err)
		userEmail := fmt.Sprintf("user-tmr-%s@test.com", nonce[0:15])

		tmrR := &TMRRecipient{
			AuthFactor:           &common_models.AuthFactor{Type: "EM", Value: userEmail},
			RawOverEncryptionKey: overEncryptionKeyBytes,
		}
		clearText := []byte("Super secret stuff encrypted in GoLang")
		recipients := &Recipients{
			SealdIds:      []string{fullUserId},
			TMRRecipients: []*TMRRecipient{tmrR},
		}

		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients:    []string{fullUserId},
			TmrRecipients: []test_utils.TMRRecipient{{Value: tmrR.AuthFactor.Value, Type: tmrR.AuthFactor.Type}},
			Owner:         fullUserId,
			Scopes:        []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
		})
		require.NoError(t, err)

		es, err := aSdk.CreateAnonymousEncryptionSession(signedToken, signedToken, recipients)
		require.NoError(t, err)
		encrypted, err := es.EncryptFile(clearText, "test.txt")
		require.NoError(t, err)

		t.Run("Retrieve direct", func(t *testing.T) {
			tmrES, err := sdkFullUser.RetrieveEncryptionSession(es.SessionId, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, es.SessionId, tmrES.Id)
			assert.Equal(t, sdk.EncryptionSessionRetrievalDirect, tmrES.RetrievalDetails.Flow)
		})

		t.Run("Retrieve by TMR", func(t *testing.T) {
			// Instantiate a ssks-plugin for TMR auth
			options1 := &ssks_tmr.PluginTMRInitializeOptions{
				SsksURL:      credentials.SsksUrl,
				AppId:        credentials.AppId,
				InstanceName: "plugin-tmr-tests-1",
				Platform:     "go-tests",
			}
			pluginInstance1 := ssks_tmr.NewPluginTMR(options1)

			// Retrieve a TMR token
			backend := test_utils.NewSSKS2MRBackendApiClient(credentials.SsksUrl, credentials.AppId, credentials.SsksBackendAppKey)
			challSendRep, err := backend.ChallengeSend(fullUserId, tmrR.AuthFactor, true, true)
			require.NoError(t, err)
			factorToken, err := pluginInstance1.GetFactorToken(challSendRep.SessionId, tmrR.AuthFactor, credentials.SsksTMRChallenge)
			require.NoError(t, err)

			// Retrieve an ES with the TMR token
			tmrES, err := sdkFullUser.RetrieveEncryptionSessionByTmr(factorToken.Token, es.SessionId, overEncryptionKeyBytes, nil, false, false)
			require.NoError(t, err)
			assert.Equal(t, es.SessionId, tmrES.Id)
			assert.Equal(t, sdk.EncryptionSessionRetrievalViaTmrAccess, tmrES.RetrievalDetails.Flow)

		})

		testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/anonymous")
		err = os.MkdirAll(testArtifactsDir, 0700)
		require.NoError(t, err)
		f, err := os.Create(filepath.Join(testArtifactsDir, "encrypted_file.seald"))
		require.NoError(t, err)
		_, err = f.Write(encrypted)
		require.NoError(t, err)

		// export identity
		exportedIdentity, err := sdkFullUser.ExportIdentity()
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(testArtifactsDir, "exported_identity"), exportedIdentity, 0o700)
		require.NoError(t, err)

		f, err = os.Create(filepath.Join(testArtifactsDir, "message_id"))
		require.NoError(t, err)
		_, err = f.WriteString(es.SessionId)
		require.NoError(t, err)
	})
}
