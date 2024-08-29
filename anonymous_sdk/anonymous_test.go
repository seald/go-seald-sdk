package anonymous_sdk

import (
	"github.com/stretchr/testify/require"
	"go-seald-sdk/test_utils"
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

	signedToken, err := test_utils.GetJWT(test_utils.Claims{
		Recipients: []string{anonymousSDKUser.BearduserId},
		Owner:      anonymousSDKUser.BearduserId,
		Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
	})
	require.NoError(t, err)

	clearText := []byte("Super secret stuff encrypted in GoLang")
	messageId, encrypted, err := sdk.encrypt(signedToken, signedToken, []string{anonymousSDKUser.BearduserId}, clearText, "test.txt")
	require.NoError(t, err)

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
