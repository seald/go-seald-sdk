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

		aes, err := aSdk.CreateAnonymousEncryptionSession(createToken, createToken, defaultRecipients)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(aes.SessionId))
	})

	t.Run("Encrypt, classic retrieve", func(t *testing.T) {
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
		aes, err := aSdk.CreateAnonymousEncryptionSession(signedToken, signedToken, recipients)
		require.NoError(t, err)

		t.Run("Retrieve direct", func(t *testing.T) {
			tmrES, err := sdkFullUser.RetrieveEncryptionSession(aes.SessionId, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, aes.SessionId, tmrES.Id)
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
			tmrES, err := sdkFullUser.RetrieveEncryptionSessionByTmr(factorToken.Token, aes.SessionId, overEncryptionKeyBytes, nil, false, false)
			require.NoError(t, err)
			assert.Equal(t, aes.SessionId, tmrES.Id)
			assert.Equal(t, sdk.EncryptionSessionRetrievalViaTmrAccess, tmrES.RetrievalDetails.Flow)

		})
	})

	t.Run("retrieve AES by SymEncKey", func(t *testing.T) {
		allRights := &sdk.RecipientRights{
			Read:    true,
			Forward: true,
			Revoke:  true,
		}

		// Create encryption session
		currentDevice := sdkFullUser.GetCurrentAccountInfo()
		sdkFullUserRecipient := &sdk.RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
		session, err := sdkFullUser.CreateEncryptionSession(
			[]*sdk.RecipientWithRights{sdkFullUserRecipient},
			sdk.CreateEncryptionSessionOptions{UseCache: false},
		)
		require.NoError(t, err)

		initialMessage := "A message"
		encryptedMessage, err := session.EncryptMessage(initialMessage)
		require.NoError(t, err)

		// Generate a JWT
		signedToken, err := test_utils.GetJWT(test_utils.Claims{
			Owner:  fullUserId,
			Scopes: []test_utils.JWTPermissionScopes{test_utils.PermissionAll},
		})
		require.NoError(t, err)

		t.Run("SymEncKey Password", func(t *testing.T) {
			password := "superPassword"
			esSymEncKeyPassword, err := session.AddSymEncKeyFromPassword(password, allRights)
			require.NoError(t, err)

			aes, err := aSdk.RetrieveEncryptionSessionFromPassword(signedToken, session.Id, esSymEncKeyPassword.SymEncKeyId, password)
			require.NoError(t, err)

			decryptedMessage, err := aes.DecryptMessage(encryptedMessage)
			require.NoError(t, err)
			assert.Equal(t, initialMessage, decryptedMessage)
		})
		t.Run("SymEncKey RawKeys", func(t *testing.T) {
			rawSecret, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			rawEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			encodedRawEncryptionKey := rawEncryptionKey.Encode()

			esSymEncKeyRawKey, err := session.AddSymEncKeyFromRawKeys(rawSecret, encodedRawEncryptionKey, allRights)
			require.NoError(t, err)

			aes, err := aSdk.RetrieveEncryptionSessionFromRawKey(signedToken, session.Id, esSymEncKeyRawKey.SymEncKeyId, rawSecret, encodedRawEncryptionKey)
			require.NoError(t, err)

			decryptedMessage, err := aes.DecryptMessage(encryptedMessage)
			require.NoError(t, err)
			assert.Equal(t, initialMessage, decryptedMessage)
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/anonymous")

			// import identity from JS
			identity, err := os.ReadFile(filepath.Join(testArtifactsDir, "identity"))
			require.NoError(t, err)
			initOptions, err := getInMemoryInitializeOptions()
			require.NoError(t, err)
			account, err := sdk.Initialize(initOptions)
			require.NoError(t, err)
			err = account.ImportIdentity(identity)
			require.NoError(t, err)

			// can retrieve session
			sessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "session_id"))
			require.NoError(t, err)
			session, err := account.RetrieveEncryptionSession(string(sessionId), false, false, false)
			require.NoError(t, err)

			// can deserialize session
			serializedSession, err := os.ReadFile(filepath.Join(testArtifactsDir, "serialized_session"))
			require.NoError(t, err)
			deserializedSession, err := aSdk.DeserializeAnonymousEncryptionSession(string(serializedSession))
			require.NoError(t, err)
			assert.Equal(t, session.Id, deserializedSession.SessionId)
			assert.Equal(t, session.Key.Encode(), deserializedSession.Key.Encode())

			// session can decrypt message
			encryptedMessage, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_message"))
			require.NoError(t, err)
			decryptedMessage, err := deserializedSession.DecryptMessage(string(encryptedMessage))
			require.NoError(t, err)
			assert.Equal(t, "message content", decryptedMessage)

			// session can decrypt file
			encryptedFile, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_file"))
			require.NoError(t, err)
			decryptedFile, err := deserializedSession.DecryptFile(encryptedFile)
			require.NoError(t, err)
			assert.Equal(t, "file content", string(decryptedFile.FileContent))
			assert.Equal(t, "test.txt", decryptedFile.Filename)

			// Try to retrieve by SymEncKeys
			signedToken, err := test_utils.GetJWT(test_utils.Claims{
				Recipients: []string{fullUserId},
				Owner:      fullUserId,
				Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindSymEncKey},
			})

			fullSessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "full_session_id"))
			require.NoError(t, err)
			encryptedMessageFullSession, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_message_full_session"))
			require.NoError(t, err)
			symEncKeyPasswordId, err := os.ReadFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyPasswordId"))
			require.NoError(t, err)
			symEncKeyPassword, err := os.ReadFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyPassword"))
			require.NoError(t, err)

			// Retrieve by SymEncKeys password
			retrievedSessionSKP, err := aSdk.RetrieveEncryptionSessionFromPassword(signedToken, string(fullSessionId), string(symEncKeyPasswordId), string(symEncKeyPassword))
			require.NoError(t, err)

			decryptedMessageSKP, err := retrievedSessionSKP.DecryptMessage(string(encryptedMessageFullSession))
			require.NoError(t, err)
			assert.Equal(t, "message content", decryptedMessageSKP)

			// Retrieve by SymEncKeys raw key
			symEncKeyRawKeyId, err := os.ReadFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyRawKeyId"))
			require.NoError(t, err)
			rawSymKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "symEncKey_rawSymKey"))
			require.NoError(t, err)
			symEncKeySecret, err := os.ReadFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeySecret"))
			require.NoError(t, err)

			retrievedSessionSKRawKey, err := aSdk.RetrieveEncryptionSessionFromRawKey(signedToken, string(fullSessionId), string(symEncKeyRawKeyId), string(symEncKeySecret), rawSymKey)
			require.NoError(t, err)

			decryptedMessageSKRawKey, err := retrievedSessionSKRawKey.DecryptMessage(string(encryptedMessageFullSession))
			require.NoError(t, err)
			assert.Equal(t, "message content", decryptedMessageSKRawKey)
		})

		t.Run("Export for JS", func(t *testing.T) {
			// ensure artifacts dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/anonymous")
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// create identity
			account, err := createTestAccount()
			require.NoError(t, err)
			currentDevice := account.GetCurrentAccountInfo()

			// create anonymous session, and serialize it, with a message and a file
			createToken, err := test_utils.GetJWT(test_utils.Claims{
				Recipients: []string{currentDevice.UserId},
				Owner:      currentDevice.UserId,
				Scopes:     []test_utils.JWTPermissionScopes{test_utils.PermissionAnonymousFindKeys, test_utils.PermissionAnonymousCreateMessage},
			})
			require.NoError(t, err)
			session, err := aSdk.CreateAnonymousEncryptionSession(createToken, createToken, &Recipients{SealdIds: []string{currentDevice.UserId}})
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "session_id"), []byte(session.SessionId), 0o700)
			require.NoError(t, err)
			serializedSession, err := session.Serialize()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "serialized_session"), []byte(serializedSession), 0o700)
			require.NoError(t, err)
			encryptedMessage, err := session.EncryptMessage("message content")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_message"), []byte(encryptedMessage), 0o700)
			require.NoError(t, err)
			encryptedFile, err := session.EncryptFile([]byte("file content"), "test.txt")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_file"), encryptedFile, 0o700)
			require.NoError(t, err)

			// Create an EncryptionSession and an encrypted message to retrieve & decrypt by anonymous SymEncKeys
			allRights := &sdk.RecipientRights{
				Read:    true,
				Revoke:  true,
				Forward: true,
			}
			recipientcurrentDevice := &sdk.RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
			fullSession, err := account.CreateEncryptionSession([]*sdk.RecipientWithRights{recipientcurrentDevice}, sdk.CreateEncryptionSessionOptions{UseCache: false})
			require.NoError(t, err)

			message := "Best message ever"
			encryptMessageFullSession, err := fullSession.EncryptMessage(message)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "full_session_id"), []byte(fullSession.Id), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_message_full_session"), []byte(encryptMessageFullSession), 0o700)
			require.NoError(t, err)

			// SymEncKey password
			symEncKeyPassword, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			symEncKeyPasswordAdded, err := fullSession.AddSymEncKeyFromPassword(symEncKeyPassword, allRights)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyPasswordId"), []byte(symEncKeyPasswordAdded.SymEncKeyId), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyPassword"), []byte(symEncKeyPassword), 0o700)
			require.NoError(t, err)

			// create a symEncKey raw keys
			rawSecret, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			rawEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			encodedRawEncryptionKey := rawEncryptionKey.Encode()
			symEncKeyRawKeyAdded, err := fullSession.AddSymEncKeyFromRawKeys(rawSecret, encodedRawEncryptionKey, allRights)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeyRawKeyId"), []byte(symEncKeyRawKeyAdded.SymEncKeyId), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "symEncKey_rawSymKey"), encodedRawEncryptionKey, 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "symEncKey_symEncKeySecret"), []byte(rawSecret), 0o700)
			require.NoError(t, err)

			// export identity
			exportedIdentity, err := account.ExportIdentity()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "identity"), exportedIdentity, 0o700)
			require.NoError(t, err)
		})
	})
}
