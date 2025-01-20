package sdk

import (
	"encoding/base64"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("createEncryptionSession", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_direct1")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		t.Run("can create", func(t *testing.T) {
			var tokens []encryptedMessageKey
			tokens = append(tokens, encryptedMessageKey{Token: "foobar", CreatedForKey: currentDevice1.DeviceId, CreatedForKeyHash: currentDevice1.EncryptionPrivateKey.Public().GetHash()})

			recipientsMap := make(map[string]*RecipientRights)
			recipientsMap[currentDevice1.UserId] = &RecipientRights{}

			_, err = account1.apiClient.createMessage(&createMessageRequest{
				Tokens:   tokens,
				NotForMe: false,
				Rights:   recipientsMap,
			})
			require.NoError(t, err)
		})

		t.Run("EMK error", func(t *testing.T) {
			fakeId := "5a221722-36c4-11ee-be56-0242ac120002"
			var tokens []encryptedMessageKey
			recipientsMap := make(map[string]*RecipientRights)
			tokens = append(tokens, encryptedMessageKey{Token: "foobar", CreatedForKey: fakeId, CreatedForKeyHash: currentDevice1.EncryptionPrivateKey.Public().GetHash()})
			recipientsMap[currentDevice1.UserId] = &RecipientRights{}

			resp, err := account1.apiClient.createMessage(&createMessageRequest{
				Tokens:   tokens,
				NotForMe: false,
				Rights:   recipientsMap,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, len(resp.FailedCreatedForKey))
			assert.Equal(t, fakeId, resp.FailedCreatedForKey[0])
		})

		t.Run("serializer errors", func(t *testing.T) {
			var tokens []encryptedMessageKey
			recipientsMap := make(map[string]*RecipientRights)
			for i := 0; i < 101; i++ {
				tokens = append(tokens, encryptedMessageKey{Token: "foobar", CreatedForKey: currentDevice1.DeviceId, CreatedForKeyHash: currentDevice1.EncryptionPrivateKey.Public().GetHash()})
				recipientsMap[currentDevice1.UserId] = &RecipientRights{}
			}
			resp, err := account1.apiClient.createMessage(&createMessageRequest{
				Tokens:   tokens,
				NotForMe: false,
				Rights:   recipientsMap,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, len(resp.AddKeySerializerErrors.Tokens))
			assert.Equal(t, "Cannot accept more than 100 keys", resp.AddKeySerializerErrors.Tokens[0])
		})

	})
}
