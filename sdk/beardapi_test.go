package sdk

import (
	"encoding/base64"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/api_helper"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/test_utils"
	"os"
	"testing"
	"time"
)

func TestBeardApiClient_CreateAccount(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	require.NoError(t, err)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).With().Timestamp().Str("instance", "BeardAPITest").Logger()
	apiClient := beardApiClient{*api_helper.NewApiClient(credentials.ApiUrl, nil, logger)}

	preGeneratedKeys, err := getPreGeneratedKeys()
	require.NoError(t, err)

	claims := test_utils.Claims{
		Scopes:   []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam},
		JoinTeam: true,
	}

	jwt, err := test_utils.GetJWT(claims)
	require.NoError(t, err)

	createAccountRequest := &createAccountRequest{
		EncryptionPublicKey: preGeneratedKeys.EncryptionKey.Public().ToB64(),
		SigningPublicKey:    preGeneratedKeys.SigningKey.Public().ToB64(),
		DisplayName:         "Dadada",
		DeviceName:          "Dididi",
		SignupJWT:           jwt,
	}

	user, err := apiClient.createAccount(createAccountRequest)
	require.NoError(t, err)

	challengeResponse, err := apiClient.getChallenge()

	signedChallenge, err := preGeneratedKeys.SigningKey.Sign([]byte(challengeResponse.NextChallenge))
	require.NoError(t, err)

	loginRequest := &loginRequest{
		UserId:          user.User.Id,
		DeviceId:        user.DeviceId,
		KeyId:           user.DeviceId,
		SignedChallenge: base64.StdEncoding.EncodeToString(signedChallenge),
	}
	_, err = apiClient.login(loginRequest)
	require.NoError(t, err)

	block, err := sigchain.CreateSigchainTransaction(&sigchain.CreateSigchainTransactionOptions{
		OperationType:          sigchain.SIGCHAIN_OPERATION_CREATE,
		OperationEncryptionKey: preGeneratedKeys.EncryptionKey.Public(),
		OperationSigningKey:    preGeneratedKeys.SigningKey.Public(),
		OperationDeviceId:      user.DeviceId,
		ExpireAfter:            time.Hour * 24 * 365,
		SigningKey:             preGeneratedKeys.SigningKey,
		Position:               0,
		PreviousHash:           "",
		SignerDeviceId:         user.DeviceId,
	})
	require.NoError(t, err)

	_, err = apiClient.addSigChainTransaction(&addSigChainTransactionRequest{TransactionData: block, IntegrityCheck: true})
	require.NoError(t, err)

	chain := sigchain.Sigchain{
		Blocks: []*sigchain.Block{block},
	}
	_, err = sigchain.CheckSigchainTransactions(chain, false)
	require.NoError(t, err)

	status, err := apiClient.teamStatus(nil)
	require.NoError(t, err)
	assert.Equal(t, "ok", status.Status)
	assert.Equal(t, "BUSINESS", status.Level)
	assert.True(t, status.Active)
	assert.Equal(t, []int{3}, status.Options)
}
