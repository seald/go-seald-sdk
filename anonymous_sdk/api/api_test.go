package api

import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestAnonymousApiClient(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
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

		req := MessageCreateRequest{
			EncryptedMessageKeys: []*EncryptedMessageKey{{CreatedForKey: devices[0].Id, Token: "TOTO", CreatedForKeyHash: "TATA"}},
			Metadata:             "test-metadata",
		}
		_, err = apiClient.MessageCreate(signedToken, &req)
		require.NoError(t, err)
	})

	t.Run("MessageCreate with TMR access", func(t *testing.T) {
		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Recipients:    []string{anonymousSDKUser.BearduserId},
			TmrRecipients: []test_utils.TMRRecipient{{Value: "email@domain.tld", Type: "EM"}},
			Owner:         anonymousSDKUser.BearduserId,
			Scopes:        []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
		})
		require.NoError(t, err)

		devices, err := apiClient.KeyFindAll(signedToken, []string{anonymousSDKUser.BearduserId})
		require.NoError(t, err)
		assert.Equal(t, 1, len(devices))

		req := MessageCreateRequest{
			TMRMessageKeys:       []*TMRMessageKey{{AuthFactorType: "EM", AuthFactorValue: "email@domain.tld", Token: "token"}},
			EncryptedMessageKeys: []*EncryptedMessageKey{{CreatedForKey: devices[0].Id, Token: "TOTO", CreatedForKeyHash: "TATA"}},
			Metadata:             "test-metadata",
		}
		_, err = apiClient.MessageCreate(signedToken, &req)
		require.NoError(t, err)
	})
}
