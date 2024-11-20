package ssks_tmr

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func getAuthFactor() (*common_models.AuthFactor, error) {
	nonce, err := utils.GenerateRandomNonce()
	if err != nil {
		return nil, err
	}
	userEmail := fmt.Sprintf("%s@test.com", nonce[0:15])

	return &common_models.AuthFactor{Type: "EM", Value: userEmail}, nil
}

func TestTMRPlugin(t *testing.T) {
	testCred, err := test_utils.GetCredentials()
	require.NoError(t, err)

	options1 := &PluginTMRInitializeOptions{
		SsksURL:      testCred.SsksUrl,
		AppId:        testCred.AppId,
		InstanceName: "plugin-tmr-tests-1",
		Platform:     "go-tests",
	}
	pluginInstance1 := NewPluginTMR(options1)
	account1, err := createTestAccount()
	require.NoError(t, err)

	nonce, err := utils.GenerateRandomNonce()
	require.NoError(t, err)
	userId := fmt.Sprintf("user1-%s", nonce[0:15])

	account1ExportedIdentityB64, err := account1.ExportIdentity()
	require.NoError(t, err)

	backend := test_utils.NewSSKS2MRBackendApiClient(testCred.SsksUrl, testCred.AppId, testCred.SsksBackendAppKey)

	twoManRuleKey, err := symmetric_key.Generate()
	require.NoError(t, err)
	rawTMRSymKey := twoManRuleKey.Encode()

	t.Parallel()
	t.Run("can save/retrieve key", func(t *testing.T) {
		authFactor, err := getAuthFactor()
		require.NoError(t, err)
		challSendRespSave, err := backend.ChallengeSend(userId, authFactor, true, false)
		require.NoError(t, err)
		assert.False(t, challSendRespSave.MustAuthenticate)
		saveIdentityRes1, err := pluginInstance1.SaveIdentity(challSendRespSave.SessionId, authFactor, "", rawTMRSymKey, account1ExportedIdentityB64)
		require.NoError(t, err)
		assert.Equal(t, "", saveIdentityRes1.AuthenticatedSessionId)
		assert.True(t, utils.IsUUID(saveIdentityRes1.SsksId))

		challSendRespRetrieve, err := backend.ChallengeSend(userId, authFactor, true, false)
		require.NoError(t, err)
		assert.True(t, challSendRespRetrieve.MustAuthenticate)
		retrievedNotAuth, err := pluginInstance1.RetrieveIdentity(challSendRespRetrieve.SessionId, authFactor, testCred.SsksTMRChallenge, rawTMRSymKey)
		require.NoError(t, err)
		assert.True(t, retrievedNotAuth.ShouldRenewKey)
		assert.True(t, utils.IsUUID(retrievedNotAuth.AuthenticatedSessionId))

		err = account1.RenewKeys(sdk.RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME})
		require.NoError(t, err)
		account1secondKey, err := account1.ExportIdentity()
		saveIdentityRes2, err := pluginInstance1.SaveIdentity(retrievedNotAuth.AuthenticatedSessionId, authFactor, "", rawTMRSymKey, account1secondKey)
		require.NoError(t, err)
		assert.Equal(t, "", saveIdentityRes2.AuthenticatedSessionId)
		assert.True(t, utils.IsUUID(saveIdentityRes2.SsksId))
		assert.Equal(t, saveIdentityRes1.SsksId, saveIdentityRes2.SsksId)
		challSendRespRetrieve2, err := backend.ChallengeSend(userId, authFactor, true, false)
		require.NoError(t, err)
		assert.True(t, challSendRespRetrieve2.MustAuthenticate)
		retrievedAuth, err := pluginInstance1.RetrieveIdentity(challSendRespRetrieve2.SessionId, authFactor, testCred.SsksTMRChallenge, rawTMRSymKey)
		require.NoError(t, err)
		assert.False(t, retrievedAuth.ShouldRenewKey)

		// Assert that a new instance can retrieve
		options1b := &PluginTMRInitializeOptions{
			SsksURL:      testCred.SsksUrl,
			AppId:        testCred.AppId,
			InstanceName: "plugin-tmr-tests-1b",
			Platform:     "go-tests",
		}
		pluginInstance1b := NewPluginTMR(options1b)
		challSendRespRetrieve3, err := backend.ChallengeSend(userId, authFactor, true, false)
		require.NoError(t, err)
		assert.True(t, challSendRespRetrieve3.MustAuthenticate)
		rr, err := pluginInstance1b.RetrieveIdentity(challSendRespRetrieve3.SessionId, authFactor, testCred.SsksTMRChallenge, rawTMRSymKey)
		require.NoError(t, err)
		assert.False(t, rr.ShouldRenewKey)
	})

	t.Run("SsksTMRSaveIdentity", func(t *testing.T) {
		authFactor, err := getAuthFactor()
		require.NoError(t, err)

		// No parallel as we can have only one SessionId per user
		t.Run("bad session id", func(t *testing.T) {
			_, err = pluginInstance1.SaveIdentity("bad-session-id", authFactor, "", rawTMRSymKey, []byte("data"))
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("nil authFactor", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, true, false)
			require.NoError(t, err)
			_, err = pluginInstance1.SaveIdentity(challSendRep.SessionId, nil, testCred.SsksTMRChallenge, rawTMRSymKey, []byte("data"))
			assert.ErrorIs(t, err, ErrorSaveIdentityNoAuthFactor)
		})
		t.Run("nil twoManRuleKey", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			_, err = pluginInstance1.SaveIdentity(challSendRep.SessionId, authFactor, "", nil, []byte("data"))
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("bad challenge", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			_, err = pluginInstance1.SaveIdentity(challSendRep.SessionId, authFactor, "bad-one", rawTMRSymKey, []byte("data"))
			assert.ErrorIs(t, err, utils.APIError{Status: 403, Code: "UNKNOWN"})
		})
		t.Run("nil identity", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			_, err = pluginInstance1.SaveIdentity(challSendRep.SessionId, authFactor, "", rawTMRSymKey, nil)
			assert.ErrorIs(t, err, ErrorSaveIdentityNoIdentity)
		})
		t.Run("save with challenge", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			_, err = pluginInstance1.SaveIdentity(challSendRep.SessionId, authFactor, testCred.SsksTMRChallenge, rawTMRSymKey, []byte("data"))
			assert.NoError(t, err)
		})
	})

	t.Run("SsksTMRRetrieveIdentity", func(t *testing.T) {
		authFactor, err := getAuthFactor()
		require.NoError(t, err)

		// No parallel as we can have only one SessionId per user
		t.Run("bad session id", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentity("bad-session-id", authFactor, "dummy-chall", rawTMRSymKey)
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN"})
		})
		t.Run("no challenge", func(t *testing.T) {
			_, err = pluginInstance1.RetrieveIdentity("bad-session-id", authFactor, "", rawTMRSymKey)
			assert.ErrorIs(t, err, utils.APIError{Status: 400, Code: "UNKNOWN"})
		})
		t.Run("nil authFactor", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, true, false)
			require.NoError(t, err)
			_, err = pluginInstance1.RetrieveIdentity(challSendRep.SessionId, nil, "", rawTMRSymKey)
			assert.ErrorIs(t, err, ErrorRetrieveIdentityNoAuthFactor)
		})
		t.Run("nil twoManRuleKey", func(t *testing.T) {
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			_, err = pluginInstance1.RetrieveIdentity(challSendRep.SessionId, authFactor, "", nil)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecodeInvalidLength)
		})
		t.Run("Retrieve unknown identity", func(t *testing.T) {
			unknownAuthFactor, err := getAuthFactor()
			require.NoError(t, err)
			challSendRep, err := backend.ChallengeSend(userId, unknownAuthFactor, true, false)
			require.NoError(t, err)

			_, err = pluginInstance1.RetrieveIdentity(challSendRep.SessionId, unknownAuthFactor, testCred.SsksTMRChallenge, rawTMRSymKey)
			assert.ErrorIs(t, err, utils.APIError{Status: 404, Code: "UNKNOWN", Raw: "{\\\"model\\\":\\\"TMRKey\\\"}"})
		})
		t.Run("search return non b64", func(t *testing.T) {
			optionsCanary := &PluginTMRInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-tmr-tests-canary",
				Platform:     "go-tests",
			}
			pluginInstanceCanary := NewPluginTMR(optionsCanary)
			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			canaryApi := newCanarySsksTMRApiClient(pluginInstanceCanary.ssksTMRApiClient)
			pluginInstanceCanary.ssksTMRApiClient = canaryApi

			f := func() ([]byte, error) {
				return json.Marshal(map[string]interface{}{
					"data_b64":      "foobar!", // anything that is not a b64 string
					"authenticated": true,
				})
			}

			canaryApi.ToExecute["search"] = f
			_, err = pluginInstanceCanary.RetrieveIdentity(challSendRep.SessionId, authFactor, testCred.SsksTMRChallenge, rawTMRSymKey)
			assert.ErrorIs(t, err, ErrorRetrieveIdentityCannotUnb64Data)
		})
		t.Run("cannot decrypt returned data", func(t *testing.T) {
			optionsCanary := &PluginTMRInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-tmr-tests-canary",
				Platform:     "go-tests",
			}
			pluginInstanceCanary := NewPluginTMR(optionsCanary)
			t.Parallel()
			badSymKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			rawBadSymKey := badSymKey.Encode()

			challSendRep, err := backend.ChallengeSend(userId, authFactor, false, false)
			require.NoError(t, err)
			canaryApi := newCanarySsksTMRApiClient(pluginInstanceCanary.ssksTMRApiClient)
			pluginInstanceCanary.ssksTMRApiClient = canaryApi

			f := func() ([]byte, error) {
				return json.Marshal(map[string]interface{}{
					"data_b64":      "foobarfoobarfoobarfoobar",
					"authenticated": true,
				})
			}

			canaryApi.ToExecute["search"] = f
			_, err = pluginInstanceCanary.RetrieveIdentity(challSendRep.SessionId, authFactor, testCred.SsksTMRChallenge, rawBadSymKey)
			assert.ErrorIs(t, err, ErrorRetrieveIdentityCannotDecryptData)
		})
	})

	t.Run("SsksTMRGetFactorToken", func(t *testing.T) {
		optionsCanary := &PluginTMRInitializeOptions{
			SsksURL:      testCred.SsksUrl,
			AppId:        testCred.AppId,
			InstanceName: "plugin-tmr-tests-canary",
			Platform:     "go-tests",
		}
		pluginInstanceCanary := NewPluginTMR(optionsCanary)

		authFactor, err := getAuthFactor()
		require.NoError(t, err)

		challSendRep, err := backend.ChallengeSend(userId, authFactor, true, false)
		require.NoError(t, err)
		canaryApi := newCanarySsksTMRApiClient(pluginInstanceCanary.ssksTMRApiClient)
		pluginInstanceCanary.ssksTMRApiClient = canaryApi

		getTokenResp, err := pluginInstanceCanary.GetFactorToken(challSendRep.SessionId, authFactor, testCred.SsksTMRChallenge)
		assert.NoError(t, err)
		assert.Equal(t, 1, canaryApi.Counter["challengeValidate"])
		assert.Equal(t, 1, canaryApi.Counter["getFactorToken"])
		isMatch, err := regexp.MatchString("^[\\w-]+\\.[\\w-]+\\.[\\w-]+$", getTokenResp.Token)
		assert.True(t, isMatch)

		// Try a retrieve with an already authenticated session
		_, err = pluginInstanceCanary.GetFactorToken(getTokenResp.AuthenticatedSessionId, authFactor, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, canaryApi.Counter["challengeValidate"]) // No call to challengeValidate
		assert.Equal(t, 2, canaryApi.Counter["getFactorToken"])
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			t.Parallel()
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/ssks_tmr")

			// Send challenge
			email, err := os.ReadFile(filepath.Join(testArtifactsDir, "email"))
			require.NoError(t, err)
			authFactor := common_models.AuthFactor{Type: "EM", Value: string(email)}
			challSendRep, err := backend.ChallengeSend(
				"test-user",
				&authFactor,
				false,
				false,
			)
			require.NoError(t, err)
			require.Equal(t, true, challSendRep.MustAuthenticate)

			// Can retrieve identity
			rawTMRKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "raw_tmr_key"))
			require.NoError(t, err)
			options := &PluginTMRInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-tmr-tests-from-js",
				Platform:     "go-tests",
			}
			ssksTMR := NewPluginTMR(options)
			retrievedIdentity, err := ssksTMR.RetrieveIdentity(
				challSendRep.SessionId,
				&authFactor,
				testCred.SsksTMRChallenge,
				rawTMRKey,
			)
			require.NoError(t, err)

			// Retrieved identity is as expected
			exportedIdentity, err := os.ReadFile(filepath.Join(testArtifactsDir, "exported_identity"))
			require.NoError(t, err)
			assert.Equal(t, exportedIdentity, retrievedIdentity.Identity)
		})
		t.Run("Export for JS", func(t *testing.T) {
			t.Parallel()
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/ssks_tmr")
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

			// send challenge
			email := "go-js-compat-" + test_utils.GetRandomString(10) + "@test.com"
			err = os.WriteFile(filepath.Join(testArtifactsDir, "email"), []byte(email), 0o700)
			require.NoError(t, err)
			authFactor := common_models.AuthFactor{Type: "EM", Value: email}
			challSendRep, err := backend.ChallengeSend(
				"test-user",
				&authFactor,
				true,
				true, // force auth, so that the identity is stored in an authenticated way, to avoid the JS sdk renewing the key
			)
			require.NoError(t, err)
			require.Equal(t, true, challSendRep.MustAuthenticate)

			// save identity
			rawTMRKey := make([]byte, 64)
			_, err = rand.Read(rawTMRKey)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "raw_tmr_key"), rawTMRKey, 0o700)
			require.NoError(t, err)
			options := &PluginTMRInitializeOptions{
				SsksURL:      testCred.SsksUrl,
				AppId:        testCred.AppId,
				InstanceName: "plugin-tmr-tests-for-js",
				Platform:     "go-tests",
			}
			ssksTMR := NewPluginTMR(options)
			_, err = ssksTMR.SaveIdentity(
				challSendRep.SessionId,
				&authFactor,
				testCred.SsksTMRChallenge,
				rawTMRKey,
				exportedIdentity,
			)
		})
	})
}
