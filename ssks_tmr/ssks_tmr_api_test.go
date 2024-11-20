package ssks_tmr

import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestSSKSTMRApiClient(t *testing.T) {
	testCred, err := test_utils.GetCredentials()
	require.NoError(t, err)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).With().Timestamp().Str("instance", "testSSKSTMRAPI").Logger()
	ssksTMRApiClient := apiClient{ApiClient: *api_helper.NewApiClient(testCred.SsksUrl, []api_helper.Header{{Name: "X-SEALD-APPID", Value: testCred.AppId}}, logger)}

	nonce, err := utils.GenerateRandomNonce()
	require.NoError(t, err)
	userId := fmt.Sprintf("user1-%s", nonce[0:10])
	authFactorEM := common_models.AuthFactor{Type: "EM", Value: fmt.Sprintf("%s@test.com", userId)}

	backend := test_utils.NewSSKS2MRBackendApiClient(testCred.SsksUrl, testCred.AppId, testCred.SsksBackendAppKey)
	t.Run("challengeValidate", func(t *testing.T) {
		t.Run("empty session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.challengeValidate(testCred.SsksTMRChallenge, authFactorEM, "")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("bad session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.challengeValidate(testCred.SsksTMRChallenge, authFactorEM, "bad-session-id")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("good challengeValidate", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, &authFactorEM, true, false)
			require.NoError(t, err)
			_, err = ssksTMRApiClient.challengeValidate(testCred.SsksTMRChallenge, authFactorEM, challSendRep.SessionId)
			assert.NoError(t, err)
		})
	})
	t.Run("push", func(t *testing.T) {
		t.Run("empty session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.push("data", "")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("bad session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.push("coucou", "bad-session-id")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("good push", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, &authFactorEM, true, false)
			require.NoError(t, err)
			_, err = ssksTMRApiClient.push("coucou", challSendRep.SessionId)
			assert.NoError(t, err)
		})
	})
	t.Run("search", func(t *testing.T) {
		t.Run("empty session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.search("")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("bad session id", func(t *testing.T) {
			_, err = ssksTMRApiClient.search("bad-session-id")
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("good search", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, &authFactorEM, true, true)
			require.NoError(t, err)
			challRes, err := ssksTMRApiClient.challengeValidate(testCred.SsksTMRChallenge, authFactorEM, challSendRep.SessionId)
			require.NoError(t, err)
			dummyString := "dummy data"
			pushRes, err := ssksTMRApiClient.push(dummyString, challRes.NewSessionId)
			require.NoError(t, err)
			require.NotNil(t, pushRes)
			assert.NotEqual(t, "", pushRes.Id)

			retrieveString, err := ssksTMRApiClient.search(challRes.NewSessionId)
			assert.NoError(t, err)
			assert.Equal(t, dummyString, retrieveString.EncryptedDataB64)
		})
	})

	t.Run("getFactorToken", func(t *testing.T) {
		challSendRep, err := backend.ChallengeSend(userId, &authFactorEM, true, true)
		require.NoError(t, err)
		challRes, err := ssksTMRApiClient.challengeValidate(testCred.SsksTMRChallenge, authFactorEM, challSendRep.SessionId)
		require.NoError(t, err)
		retrievedJWT, err := ssksTMRApiClient.getFactorToken(&authFactorEM, challRes.NewSessionId)
		assert.NoError(t, err)
		isMatch, err := regexp.MatchString("^[\\w-]+\\.[\\w-]+\\.[\\w-]+$", retrievedJWT)
		assert.NoError(t, err)
		assert.True(t, isMatch)
	})
}
