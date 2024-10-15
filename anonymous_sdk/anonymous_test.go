package anonymous_sdk

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/common_models"
	"go-seald-sdk/ssks_tmr"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
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
	sdk := CreateAnonymousSDK(options)

	anonymousSDKUser, err := sdk.ApiClient.TestGetAnonymousSDKUser(credentials.DebugApiSecret)
	require.NoError(t, err)

	sdkFullUser, err := createTestAccount()
	require.NoError(t, err)
	fullUserId := (sdkFullUser.GetCurrentAccountInfo()).UserId

	// Creating a TMR recipient
	overEncryptionKey, err := symmetric_key.Generate()
	require.NoError(t, err)
	overEncryptionKeyBytes := overEncryptionKey.Encode()

	nonce, err := utils.GenerateRandomNonce()
	require.NoError(t, err)
	userEmail := fmt.Sprintf("user-tmr-%s@test.com", nonce[0:15])

	tmrR := TMRRecipient{
		Type:                 "EM",
		Value:                userEmail,
		RawOverEncryptionKey: overEncryptionKeyBytes,
	}
	clearText := []byte("Super secret stuff encrypted in GoLang")
	recipients := Recipients{
		SealdIds:      []string{anonymousSDKUser.BearduserId},
		TMRRecipients: []TMRRecipient{tmrR},
	}

	signedToken, err := test_utils.GetJWT(test_utils.Claims{
		Recipients:    []string{anonymousSDKUser.BearduserId},
		TmrRecipients: []test_utils.TMRRecipient{{Value: tmrR.Value, Type: tmrR.Type}},
		Owner:         anonymousSDKUser.BearduserId,
		Scopes:        []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
	})
	require.NoError(t, err)
	messageId, encrypted, err := sdk.encrypt(signedToken, signedToken, recipients, clearText, "test.txt")
	require.NoError(t, err)

	// Instantiate a ssks-backend for TMR auth
	options1 := &ssks_tmr.PluginTMRInitializeOptions{
		SsksURL:      credentials.SsksUrl,
		AppId:        credentials.AppId,
		InstanceName: "plugin-tmr-tests-1",
		Platform:     "go-tests",
	}
	pluginInstance1 := ssks_tmr.NewPluginTMR(options1)

	// Retrieve a TMR token
	authFactor := &common_models.AuthFactor{Value: tmrR.Value, Type: "EM"}
	backend := test_utils.NewSSKS2MRBackendApiClient(credentials.SsksUrl, credentials.AppId, credentials.SsksBackendAppKey)
	challSendRep, err := backend.ChallengeSend(fullUserId, authFactor, true, true)
	require.NoError(t, err)
	factorToken, err := pluginInstance1.GetFactorToken(challSendRep.SessionId, authFactor, credentials.SsksTMRChallenge)
	require.NoError(t, err)

	// Retrieve an ES with the TMR token
	tmrES, err := sdkFullUser.RetrieveEncryptionSessionByTmr(factorToken.Token, messageId, overEncryptionKeyBytes, nil, false, false)
	require.NoError(t, err)
	assert.Equal(t, messageId, tmrES.Id)

	testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/anonymous")
	err = os.MkdirAll(testArtifactsDir, 0700)
	require.NoError(t, err)
	f, err := os.Create(filepath.Join(testArtifactsDir, "encrypted_file.seald"))
	require.NoError(t, err)
	_, err = f.Write(encrypted)
	require.NoError(t, err)

	f, err = os.Create(filepath.Join(testArtifactsDir, "message_id"))
	require.NoError(t, err)
	_, err = f.WriteString(messageId)
	require.NoError(t, err)
}
