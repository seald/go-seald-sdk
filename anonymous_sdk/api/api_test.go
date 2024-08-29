package api

import (
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/api_helper"
	"go-seald-sdk/test_utils"
	"os"
	"testing"
	"time"
)

func TestAnonymousApiClient(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).With().Timestamp().Str("instance", "testAnonymousAPI").Logger()
	apiClient := ApiClient{ApiClient: *api_helper.NewApiClient(credentials.ApiUrl, nil, logger)}

	anonymousSDKUser, err := apiClient.TestGetAnonymousSDKUser(credentials.DebugApiSecret)
	require.NoError(t, err)

	t.Run("KeyFind", func(t *testing.T) {
		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients: []string{anonymousSDKUser.BearduserId},
			Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys},
		})
		require.NoError(t, err)

		res, err := apiClient.KeyFind(signedToken, []string{anonymousSDKUser.BearduserId}, 1)
		require.NoError(t, err)

		resAll, err := apiClient.KeyFindAll(signedToken, []string{anonymousSDKUser.BearduserId})
		require.NoError(t, err)

		assert.Equal(t, res.Results, resAll)
		assert.Equal(t, anonymousSDKUser.DeviceId, resAll[0].Id)
	})

	t.Run("SigchainFind", func(t *testing.T) {
		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients: []string{anonymousSDKUser.BearduserId},
			Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindSigchain},
		})
		require.NoError(t, err)

		res, err := apiClient.SigchainFind(signedToken, anonymousSDKUser.BearduserId, 1)
		require.NoError(t, err)

		resAll, err := apiClient.SigchainFindAll(signedToken, anonymousSDKUser.BearduserId)
		require.NoError(t, err)

		assert.Equal(t, res.Results, resAll)
	})

	t.Run("MessageCreate", func(t *testing.T) {
		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients: []string{anonymousSDKUser.BearduserId},
			Owner:      anonymousSDKUser.BearduserId,
			Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
		})
		require.NoError(t, err)

		devices, err := apiClient.KeyFindAll(signedToken, []string{anonymousSDKUser.BearduserId})
		require.NoError(t, err)
		assert.Equal(t, 1, len(devices))

		_, err = apiClient.MessageCreate(signedToken, []EncryptedMessageKey{{CreatedForKey: devices[0].Id, Token: "TOTO", CreatedForKeyHash: "TATA"}}, "test-metadata")
		require.NoError(t, err)
	})
}
