package sdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/common_models"
	"go-seald-sdk/encrypt_decrypt_file"
	"go-seald-sdk/sdk/sigchain"
	"go-seald-sdk/ssks_tmr"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/test_utils"
	"go-seald-sdk/utils"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testPrivateDevice struct {
	EncryptionKeys []asymkey.PrivateKey
}

func (device testPrivateDevice) getEncryptionKeys() []*asymkey.PrivateKey {
	var keys []*asymkey.PrivateKey
	for _, k := range device.EncryptionKeys {
		k_ := k // I have to re-instantiate the variable, otherwise all iterations of the loop re-use the same pointer
		keys = append(keys, &k_)
	}
	return keys
}

func Test_EncryptionSession(t *testing.T) {
	allRights := &RecipientRights{
		Read:    true,
		Revoke:  true,
		Forward: true,
	}

	t.Parallel()
	t.Run("decryptMessageKey", func(t *testing.T) {
		key1, err := asymkey.Generate(2048)
		require.NoError(t, err)
		key2, err := asymkey.Generate(2048)
		require.NoError(t, err)
		key3, err := asymkey.Generate(2048)
		require.NoError(t, err)
		keyOther, err := asymkey.Generate(2048)
		require.NoError(t, err)
		testPrivateDevice := testPrivateDevice{EncryptionKeys: []asymkey.PrivateKey{*key1, *key2, *key3}}
		rawKey, err := utils.GenerateRandomBytes(64)
		require.NoError(t, err)

		t.Parallel()
		t.Run("decryptMessageKey working with CreatedForKeyHash", func(t *testing.T) {
			encMK1, err := key1.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token1 := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK1),
				CreatedForKeyHash: key1.Public().GetHash(),
			}
			symkey1, err := decryptMessageKey(token1, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey1.Encode(), rawKey)

			encMK2, err := key2.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token2 := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK2),
				CreatedForKeyHash: key2.Public().GetHash(),
			}
			symkey2, err := decryptMessageKey(token2, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey2.Encode(), rawKey)

			encMK3, err := key3.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token3 := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK3),
				CreatedForKeyHash: key3.Public().GetHash(),
			}
			symkey3, err := decryptMessageKey(token3, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey3.Encode(), rawKey)
		})
		t.Run("decryptMessageKey working without CreatedForKeyHash", func(t *testing.T) {
			encMK1, err := key1.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token1 := tokenRetrieved{
				Token: base64.StdEncoding.EncodeToString(encMK1),
			}
			symkey1, err := decryptMessageKey(token1, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey1.Encode(), rawKey)

			encMK2, err := key2.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token2 := tokenRetrieved{
				Token: base64.StdEncoding.EncodeToString(encMK2),
			}
			symkey2, err := decryptMessageKey(token2, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey2.Encode(), rawKey)

			encMK3, err := key3.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token3 := tokenRetrieved{
				Token: base64.StdEncoding.EncodeToString(encMK3),
			}
			symkey3, err := decryptMessageKey(token3, testPrivateDevice)
			require.NoError(t, err)
			require.Equal(t, symkey3.Encode(), rawKey)
		})
		t.Run("decryptMessageKey with bad CreatedForKeyHash", func(t *testing.T) {
			encMK, err := key1.Public().Encrypt(rawKey) // it's actually encrypted for key1, so it could decrypt it if it tried
			require.NoError(t, err)
			token := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK),
				CreatedForKeyHash: keyOther.Public().GetHash(),
			}
			symkey, err := decryptMessageKey(token, testPrivateDevice)
			require.Error(t, err)
			require.Nil(t, symkey)
			require.ErrorIs(t, err, ErrorSessionCannotDecryptEncMK)
		})
		t.Run("decryptMessageKey without CreatedForKeyHash but for another key", func(t *testing.T) {
			encMK, err := keyOther.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token := tokenRetrieved{
				Token: base64.StdEncoding.EncodeToString(encMK),
			}
			symkey, err := decryptMessageKey(token, testPrivateDevice)
			require.Error(t, err)
			require.Nil(t, symkey)
			require.ErrorIs(t, err, ErrorSessionCannotDecryptEncMK)
		})
		t.Run("decryptMessageKey with CreatedForKeyHash but for another key", func(t *testing.T) {
			encMK, err := keyOther.Public().Encrypt(rawKey)
			require.NoError(t, err)
			token := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK),
				CreatedForKeyHash: key1.Public().GetHash(),
			}
			symkey, err := decryptMessageKey(token, testPrivateDevice)
			assert.Error(t, err)
			assert.Nil(t, symkey)
			assert.ErrorContains(t, err, "crypto/rsa: decryption error")
		})
		t.Run("decryptMessageKey with token containing invalid B64", func(t *testing.T) {
			token := tokenRetrieved{
				Token: "&aaa",
			}
			symkey, err := decryptMessageKey(token, testPrivateDevice)
			assert.Error(t, err)
			assert.Nil(t, symkey)
			assert.ErrorContains(t, err, "illegal base64 data at input byte 0")
		})
		t.Run("decryptMessageKey with token correctly encrypted but containing an invalid message key", func(t *testing.T) {
			encMK, err := key1.Public().Encrypt([]byte("bad message key"))
			require.NoError(t, err)
			token := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK),
				CreatedForKeyHash: key1.Public().GetHash(),
			}
			symkey, err := decryptMessageKey(token, testPrivateDevice)
			assert.Error(t, err)
			assert.Nil(t, symkey)
			assert.ErrorContains(t, err, "can't decode SymKey, invalid length")
		})
	})

	t.Run("decryptMessageKeyWithGroup", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_decrypt_with_group")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		preGeneratedKeys, err := getPreGeneratedKeys()
		require.NoError(t, err)
		groupId, err := account1.CreateGroup(
			"Da group",
			[]string{currentDevice1.UserId},
			[]string{currentDevice1.UserId},
			preGeneratedKeys,
		)
		require.NoError(t, err)
		rawKey, err := utils.GenerateRandomBytes(64)
		require.NoError(t, err)
		group := account1.storage.groups.get(groupId)

		// No parallel, as it uses state
		t.Run("decryptMessageKeyWithGroup decrypts a message key for the group", func(t *testing.T) {
			encMK1, err := group.CurrentKey.EncryptionPrivateKey.Public().Encrypt(rawKey)
			require.NoError(t, err)

			token := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK1),
				CreatedForKeyHash: group.CurrentKey.EncryptionPrivateKey.Public().GetHash(),
				KeyId:             group.DeviceId,
			}

			symKey1, err := account1.decryptMessageKeyWithGroup(groupId, token, true)
			require.NoError(t, err)
			assert.Equal(t, symKey1.Encode(), rawKey)
		})
		t.Run("decryptMessageKeyWithGroup with bad token", func(t *testing.T) {
			token := tokenRetrieved{
				Token:             "&aaa",
				CreatedForKeyHash: group.CurrentKey.EncryptionPrivateKey.Public().GetHash(),
				KeyId:             group.DeviceId,
			}

			symKey1, err := account1.decryptMessageKeyWithGroup(groupId, token, true)
			require.Error(t, err)
			assert.Nil(t, symKey1)
			assert.ErrorContains(t, err, "illegal base64 data at input byte 0")
		})
		t.Run("decryptMessageKeyWithGroup with wrong CreatedForKeyHash", func(t *testing.T) {
			encMK1, err := group.CurrentKey.EncryptionPrivateKey.Public().Encrypt(rawKey)
			require.NoError(t, err)

			token := tokenRetrieved{
				Token:             base64.StdEncoding.EncodeToString(encMK1),
				CreatedForKeyHash: "wrong hash",
				KeyId:             group.DeviceId,
			}

			symKey1, err := account1.decryptMessageKeyWithGroup(groupId, token, true)
			require.Error(t, err)
			assert.Nil(t, symKey1)
			assert.ErrorIs(t, err, ErrorSessionCannotDecryptEncMKWithGroup)
		})
	})

	t.Run("createEncryptionSession — bad sealdId", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_direct1")
		require.NoError(t, err)
		_, err = account1.CreateEncryptionSession([]*RecipientWithRights{{Id: "5a221722-36c4-11ee-be56-0242ac120002", Rights: allRights}}, false)
		assert.ErrorIs(t, err, ErrorUnknownUserId)
	})

	t.Run("createEncryptionSession — no recipient rights", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_rights_nil")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		_, err = account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}}, false)
		require.NoError(t, err)
	})

	t.Run("EncryptionSession — RetrieveEncryptionSession direct", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_direct1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_retrieve_direct2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}

		t.Parallel()
		t.Run("Default right", func(t *testing.T) {
			account3, err := createTestAccount("sdk_session_retrieve_direct2")
			require.NoError(t, err)
			currentDevice3 := account3.storage.currentDevice.get()

			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			// account2 can read, forward, but not revoke. We can't list the ACL, so we just try each right.
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
			// account2 can forward
			_, err = session2.AddRecipients([]*RecipientWithRights{{Id: currentDevice3.UserId}})
			require.NoError(t, err)
			// account2 cannot revoke
			_, err = session2.RevokeOthers()
			assert.ErrorIs(t, err, utils.APIError{Status: 403, Code: "NO_ACL"})

			// account1 can forward and can revoke with default right
			_, err = session.AddRecipients([]*RecipientWithRights{{Id: currentDevice3.UserId}})
			require.NoError(t, err)
			resp, err := session.RevokeOthers()
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice2.UserId: "ok", currentDevice3.UserId: "ok"}, resp.RevokeAll.UserIds)
		})
		t.Run("RetrieveEncryptionSession when user has created the session", func(t *testing.T) {
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)

			session2, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
		})
		t.Run("RetrieveEncryptionSession when user is a recipient", func(t *testing.T) {
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice2}, false)
			require.NoError(t, err)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
		})
		t.Run("RetrieveEncryptionSession with multiple recipients", func(t *testing.T) {
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)

			session3, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session3.Id)
			assert.Equal(t, *session.Key, *session3.Key)
		})
		t.Run("RetrieveEncryptionSession fails when user is not a recipient", func(t *testing.T) {
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("RetrieveEncryptionSession fails for session creator when they are not a recipient", func(t *testing.T) {
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice2}, false)
			require.NoError(t, err)

			session2, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("RetrieveEncryptionSession fails when token is invalid", func(t *testing.T) {
			recipientsRightsMap := make(map[string]*RecipientRights)
			recipientsRightsMap[currentDevice1.UserId] = allRights
			response, err := autoLogin(account1, account1.apiClient.createMessage)(&createMessageRequest{
				Tokens: []encryptedMessageKey{{
					CreatedForKey:     currentDevice1.DeviceId,
					CreatedForKeyHash: currentDevice1.EncryptionPrivateKey.Public().GetHash(),
					Token:             "&aaa", // invalid b64
				}},
				NotForMe: false,
				Rights:   recipientsRightsMap,
			})
			require.NoError(t, err)

			session2, err := account1.RetrieveEncryptionSession(response.Message, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2)
			assert.ErrorContains(t, err, "illegal base64 data at input byte 0")
		})
	})
	t.Run("EncryptionSession — RetrieveEncryptionSession from sealdMessage", func(t *testing.T) {
		account, err := createTestAccount("sdk_session_retrieve_message")
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		recipientcurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}

		session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientcurrentDevice}, false)
		require.NoError(t, err)

		message := "Best message ever"
		encryptMessage, err := session.EncryptMessage(message)
		require.NoError(t, err)

		es, err := account.RetrieveEncryptionSessionFromMessage(encryptMessage, false, false, false)
		require.NoError(t, err)
		assert.Equal(t, session.Id, es.Id)

		clearMessage, err := es.DecryptMessage(encryptMessage)
		require.NoError(t, err)
		assert.Equal(t, message, clearMessage)
	})

	t.Run("EncryptionSession — RetrieveEncryptionSession for a group", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_group1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_retrieve_group2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		t.Parallel()
		t.Run("Retrieve encryption session through a group user has created", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			groupRecipient := &RecipientWithRights{Id: groupId, Rights: allRights}
			session, err := account2.CreateEncryptionSession([]*RecipientWithRights{groupRecipient}, false)
			require.NoError(t, err)

			sessionFail, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, sessionFail)

			session2, err := account1.RetrieveEncryptionSession(session.Id, false, false, true)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, session2.RetrievalDetails.Flow)
			assert.Equal(t, groupId, session2.RetrievalDetails.GroupId)
		})

		t.Run("Retrieve encryption session through a group user has been added to", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			groupRecipient := &RecipientWithRights{Id: groupId, Rights: allRights}
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{groupRecipient}, false)
			require.NoError(t, err)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, session2.RetrievalDetails.Flow)
			assert.Equal(t, groupId, session2.RetrievalDetails.GroupId)
		})

		t.Run("Retrieve encryption session through a group user has been added to but knew before renewal", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Da group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			_, err = account2.getUpdatedContactUnlocked(groupId)
			require.NoError(t, err)

			preGeneratedKeys2, err := getPreGeneratedKeys()
			require.NoError(t, err)
			err = account1.RenewGroupKey(groupId, preGeneratedKeys2)
			require.NoError(t, err)

			groupRecipient := &RecipientWithRights{Id: groupId, Rights: allRights}
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{groupRecipient}, false)
			require.NoError(t, err)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, true)
			require.NoError(t, err)

			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, session2.RetrievalDetails.Flow)
			assert.Equal(t, groupId, session2.RetrievalDetails.GroupId)
		})
	})

	t.Run("EncryptionSession — RetrieveEncryptionSession for a proxy", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_proxy1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_retrieve_proxy2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		t.Parallel()
		t.Run("Retrieve encryption session through a proxy", func(t *testing.T) {
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, false)
			require.NoError(t, err)

			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, false)
			require.NoError(t, err)

			sessionFail1, err := account2.RetrieveEncryptionSession(session.Id, false, true, false) // cannot retrieve before proxy is created
			require.Error(t, err)
			assert.Nil(t, sessionFail1)

			err = session.AddProxySession(proxySession.Id, allRights) // add proxy to session
			require.NoError(t, err)

			sessionFail2, err := account2.RetrieveEncryptionSession(session.Id, false, true, false) // cannot retrieve because account2 is not recipient of the proxy
			require.Error(t, err)
			assert.Nil(t, sessionFail2)

			_, err = proxySession.AddRecipients([]*RecipientWithRights{{Id: currentDevice2.UserId, Rights: allRights}}) // add account2 to proxy
			require.NoError(t, err)

			sessionFail3, err := account2.RetrieveEncryptionSession(session.Id, false, false, false) // cannot retrieve with lookupProxyKey set to false
			require.Error(t, err)
			assert.Nil(t, sessionFail3)

			session2, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, *session.Key, *session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, session2.RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, session2.RetrievalDetails.ProxySessionId)
		})

		t.Run("AddProxySession does not error when proxy already exists", func(t *testing.T) {
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, false)
			require.NoError(t, err)

			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, false)
			require.NoError(t, err)

			err = session.AddProxySession(proxySession.Id, allRights) // add proxy to session
			require.NoError(t, err)

			err = session.AddProxySession(proxySession.Id, allRights) // add proxy to session again
			require.NoError(t, err)
		})
	})

	t.Run("EncryptionSession — Session with multiple possible retrieval flows", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_multiple_flows1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_multiple_flows2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		t.Parallel()
		t.Run("direct and group", func(t *testing.T) {
			// create group
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"F211",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// create session for both group and user2
			es1, err := account1.CreateEncryptionSession([]*RecipientWithRights{
				{Id: groupId, Rights: &RecipientRights{Read: true, Forward: true, Revoke: true}},                 // group has all rights
				{Id: currentDevice2.UserId, Rights: &RecipientRights{Read: true, Forward: false, Revoke: false}}, // User2 only has Read
			}, true)
			require.NoError(t, err)

			// user2 can retrieve session directly
			es2, err := account2.RetrieveEncryptionSession(es1.Id, false, true, true)    // set lookups to true, just in case
			assert.Equal(t, EncryptionSessionRetrievalDirect, es2.RetrievalDetails.Flow) // session was retrieved directly

			// user2 should be allowed to add recipient / revoke, via the group
			_, err = es2.AddRecipients([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}})
			require.NoError(t, err)
			_, err = es2.RevokeAll()
			require.NoError(t, err)
		})

		t.Run("direct & proxy", func(t *testing.T) {
			// create proxy session
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{
				{Id: currentDevice1.UserId, Rights: allRights},
				{Id: currentDevice2.UserId, Rights: allRights},
			}, true)
			require.NoError(t, err)

			// create session for user2 & proxy
			es1, err := account1.CreateEncryptionSession([]*RecipientWithRights{
				{Id: currentDevice2.UserId, Rights: &RecipientRights{Read: true, Forward: false, Revoke: false}}, // User2 only has Read
			}, true)
			require.NoError(t, err)
			err = es1.AddProxySession(proxySession.Id, allRights)
			require.NoError(t, err)

			// user2 can retrieve session directly
			es2, err := account2.RetrieveEncryptionSession(es1.Id, false, true, true)    // set lookups to true, just in case
			assert.Equal(t, EncryptionSessionRetrievalDirect, es2.RetrievalDetails.Flow) // session was retrieved directly

			// user2 should be allowed to add recipient / revoke, via the proxy
			_, err = es2.AddRecipients([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}})
			require.NoError(t, err)
			_, err = es2.RevokeAll()
			require.NoError(t, err)
		})
	})

	t.Run("EncryptionSession — RetrieveMultipleEncryptionSessions", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_retrieve_multiple1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_retrieve_multiple2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		t.Parallel()
		t.Run("Retrieve multiple encryption sessions", func(t *testing.T) {
			session1, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			session2, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			session3, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			retrievedSessions, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id, session3.Id},
				true,
				true,
				true,
			)
			require.NoError(t, err)

			assert.Equal(t, 3, len(retrievedSessions))
			assert.Equal(t, retrievedSessions[0].Id, session1.Id)
			assert.Equal(t, retrievedSessions[0].RetrievalDetails, EncryptionSessionRetrievalDetails{
				Flow:      EncryptionSessionRetrievalDirect,
				FromCache: false,
			})
			assert.Equal(t, retrievedSessions[1].Id, session2.Id)
			assert.Equal(t, retrievedSessions[1].RetrievalDetails, EncryptionSessionRetrievalDetails{
				Flow:      EncryptionSessionRetrievalDirect,
				FromCache: false,
			})
			assert.Equal(t, retrievedSessions[2].Id, session3.Id)
			assert.Equal(t, retrievedSessions[2].RetrievalDetails, EncryptionSessionRetrievalDetails{
				Flow:      EncryptionSessionRetrievalDirect,
				FromCache: false,
			})

			// Attempt to retrieve multiple sessions including one with a bad ID
			retrievedSessionsFail, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id, currentDevice1.UserId}, // just using a user's ID as an invalid session ID
				false, false, false,
			)
			require.Error(t, err)
			assert.Nil(t, retrievedSessionsFail)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})

		t.Run("Retrieve multiple encryption sessions via proxy", func(t *testing.T) {
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			session1, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}}, false)
			require.NoError(t, err)

			session2, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}}, false)
			require.NoError(t, err)

			// Add proxy to sessions
			err = session1.AddProxySession(proxySession.Id, nil)
			require.NoError(t, err)

			err = session2.AddProxySession(proxySession.Id, nil)
			require.NoError(t, err)

			// Attempt to retrieve multiple sessions via proxy with lookupProxy flag set to true
			retrievedSessions, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				false, true, false,
			)
			require.NoError(t, err)

			assert.Equal(t, 2, len(retrievedSessions))
			require.NotNil(t, retrievedSessions[0])
			assert.Equal(t, session1.Id, retrievedSessions[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrievedSessions[0].RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, retrievedSessions[0].RetrievalDetails.ProxySessionId)
			require.NotNil(t, retrievedSessions[1])
			assert.Equal(t, session2.Id, retrievedSessions[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrievedSessions[1].RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, retrievedSessions[1].RetrievalDetails.ProxySessionId)

			// Attempt to retrieve multiple sessions via proxy with lookupProxy flag set to false
			retrievedSessionsFail, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				false, false, false,
			)
			require.Error(t, err)
			assert.Nil(t, retrievedSessionsFail)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})

		t.Run("Retrieve multiple encryption sessions via group", func(t *testing.T) {
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Test Group",
				[]string{currentDevice1.UserId, currentDevice2.UserId}, // Include both devices as initial members
				[]string{currentDevice1.UserId, currentDevice2.UserId}, // Admins, typically the same as members in this case
				preGeneratedKeys,
			)
			require.NoError(t, err)

			session1, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: groupId}}, false)
			require.NoError(t, err)

			session2, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: groupId}}, false)
			require.NoError(t, err)

			// Retrieve multiple sessions via group membership with lookupGroup flag set to true
			retrievedSessions, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				false, false, true,
			)
			require.NoError(t, err)

			assert.Equal(t, 2, len(retrievedSessions))
			require.NotNil(t, retrievedSessions[0])
			assert.Equal(t, session1.Id, retrievedSessions[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrievedSessions[0].RetrievalDetails.Flow)
			assert.Equal(t, groupId, retrievedSessions[0].RetrievalDetails.GroupId)
			require.NotNil(t, retrievedSessions[1])
			assert.Equal(t, session2.Id, retrievedSessions[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrievedSessions[1].RetrievalDetails.Flow)
			assert.Equal(t, groupId, retrievedSessions[1].RetrievalDetails.GroupId)

			// Attempt to retrieve multiple sessions via group membership with lookupGroup flag set to false
			retrievedSessionsFail, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				false, false, false,
			)
			require.Error(t, err)
			assert.Nil(t, retrievedSessionsFail)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})

		t.Run("Retrieve multiple encryption sessions from cache", func(t *testing.T) {
			session1, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			session2, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			// First retrieval - expect not to be from cache
			retrievedSessions1, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				true, false, false,
			)
			require.NoError(t, err)
			assert.Equal(t, 2, len(retrievedSessions1))
			require.NotNil(t, retrievedSessions1[0])
			assert.Equal(t, session1.Id, retrievedSessions1[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions1[0].RetrievalDetails.Flow)
			assert.False(t, retrievedSessions1[0].RetrievalDetails.FromCache)
			require.NotNil(t, retrievedSessions1[1])
			assert.Equal(t, session2.Id, retrievedSessions1[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions1[1].RetrievalDetails.Flow)
			assert.False(t, retrievedSessions1[1].RetrievalDetails.FromCache)

			// Second retrieval - this time expecting from cache
			retrievedSessions2, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				true, true, false,
			)
			require.NoError(t, err)
			assert.Equal(t, 2, len(retrievedSessions2))
			require.NotNil(t, retrievedSessions2[0])
			assert.Equal(t, session1.Id, retrievedSessions2[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions2[0].RetrievalDetails.Flow)
			assert.True(t, retrievedSessions2[0].RetrievalDetails.FromCache)
			require.NotNil(t, retrievedSessions2[1])
			assert.Equal(t, session2.Id, retrievedSessions2[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions2[1].RetrievalDetails.Flow)
			assert.True(t, retrievedSessions2[0].RetrievalDetails.FromCache)

			// Third retrieval - cache disabled
			retrievedSessions3, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{session1.Id, session2.Id},
				false, false, false,
			)
			require.NoError(t, err)
			assert.Equal(t, 2, len(retrievedSessions3))
			require.NotNil(t, retrievedSessions3[0])
			assert.Equal(t, session1.Id, retrievedSessions3[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions3[0].RetrievalDetails.Flow)
			assert.False(t, retrievedSessions3[0].RetrievalDetails.FromCache)
			require.NotNil(t, retrievedSessions3[1])
			assert.Equal(t, session2.Id, retrievedSessions3[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions3[1].RetrievalDetails.Flow)
			assert.False(t, retrievedSessions3[0].RetrievalDetails.FromCache)

			// 3 parallel retrievals : one hits API, others cache
			account2.storage.encryptionSessionsCache.delete(session1.Id) // remove from cache
			account2.storage.encryptionSessionsCache.delete(session2.Id)
			var wg sync.WaitGroup
			wg.Add(3)
			var resultFromCache [][]bool
			for i := 0; i < 3; i++ {
				go func() { // launching 3 goroutines in parallel
					defer wg.Done() // Signal the WaitGroup that this goroutine is done
					retrievedSessions, errGoroutine := account2.RetrieveMultipleEncryptionSessions(
						[]string{session1.Id, session2.Id},
						true, false, false,
					)
					if errGoroutine != nil {
						err = errGoroutine
					} else {
						resultFromCache = append(
							resultFromCache,
							[]bool{
								retrievedSessions[0].RetrievalDetails.FromCache,
								retrievedSessions[1].RetrievalDetails.FromCache,
							})
					}
				}()
			}
			wg.Wait()
			require.NoError(t, err)
			assert.Equal(t, 3, len(resultFromCache))
			assert.Equal(t, 1, countOccurrencesCustom(resultFromCache, []bool{false, false}, compareSlices[bool]))
			assert.Equal(t, 2, countOccurrencesCustom(resultFromCache, []bool{true, true}, compareSlices[bool]))
		})

		t.Run("Retrieve multiple encryption sessions with mixed methods", func(t *testing.T) {
			// Setup proxy session
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			// Setup group
			preGeneratedKeys, err := getPreGeneratedKeys()
			require.NoError(t, err)
			groupId, err := account1.CreateGroup(
				"Mixed Methods Group",
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				[]string{currentDevice1.UserId, currentDevice2.UserId},
				preGeneratedKeys,
			)
			require.NoError(t, err)

			// Create sessions
			directSession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			cacheSession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}, {Id: currentDevice2.UserId}}, false)
			require.NoError(t, err)

			groupSession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: groupId}}, false)
			require.NoError(t, err)

			proxiedSession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId}}, false)
			require.NoError(t, err)
			err = proxiedSession.AddProxySession(proxySession.Id, nil)
			require.NoError(t, err)

			// First retrieval to populate cache
			_, err = account2.RetrieveEncryptionSession(
				cacheSession.Id,
				true, false, false,
			)
			require.NoError(t, err)

			// Actual test retrieval
			retrievedSessions, err := account2.RetrieveMultipleEncryptionSessions(
				[]string{directSession.Id, cacheSession.Id, groupSession.Id, proxiedSession.Id},
				true, true, true, // Enable all methods: direct, cache, and via group/proxy
			)
			require.NoError(t, err)

			assert.Equal(t, 4, len(retrievedSessions))
			// Direct session validation
			assert.Equal(t, directSession.Id, retrievedSessions[0].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions[0].RetrievalDetails.Flow)
			assert.False(t, retrievedSessions[0].RetrievalDetails.FromCache)
			// Cache session validation
			assert.Equal(t, cacheSession.Id, retrievedSessions[1].Id)
			assert.Equal(t, EncryptionSessionRetrievalDirect, retrievedSessions[1].RetrievalDetails.Flow)
			assert.True(t, retrievedSessions[1].RetrievalDetails.FromCache)
			// Group session validation
			assert.Equal(t, groupSession.Id, retrievedSessions[2].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrievedSessions[2].RetrievalDetails.Flow)
			assert.Equal(t, groupId, retrievedSessions[2].RetrievalDetails.GroupId)
			// Proxy session validation
			assert.Equal(t, proxiedSession.Id, retrievedSessions[3].Id)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrievedSessions[3].RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, retrievedSessions[3].RetrievalDetails.ProxySessionId)
		})
	})

	t.Run("EncryptionSession - AddRecipients", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_add_recipients1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_add_recipients2")
		require.NoError(t, err)
		account3, err := createTestAccount("sdk_session_add_recipients3")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()
		currentDevice3 := account3.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}
		recipientDevice3 := &RecipientWithRights{Id: currentDevice3.UserId, Rights: allRights}

		t.Parallel()
		t.Run("AddRecipients allows user to retrieve session", func(t *testing.T) {
			// Create a session without account2 nor account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)

			// account2 and account3 cannot retrieve the session
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
			session3, err := account3.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session3)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)

			// Calling AddRecipients to allow account2 and account3
			resp, err := session.AddRecipients([]*RecipientWithRights{recipientDevice2, recipientDevice3})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]AddKeysResponse{currentDevice2.DeviceId: {StatusCode: 200}, currentDevice3.DeviceId: {StatusCode: 200}}, resp.Status)

			// account2 and account3 now can retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2b.Id)
			assert.Equal(t, session.Key, session2b.Key)
			session3b, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session3b.Id)
			assert.Equal(t, session.Key, session3b.Key)
		})
		t.Run("AddRecipients does not error when user is already allowed", func(t *testing.T) {
			// Create a session with account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)

			// Calling AddRecipients to double-allow account2
			resp, err := session.AddRecipients([]*RecipientWithRights{recipientDevice2})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]AddKeysResponse{currentDevice2.DeviceId: {StatusCode: 200}}, resp.Status)
		})
	})

	t.Run("EncryptionSession - RevokeRecipients", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_revoke_recipients1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_revoke_recipients2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}

		t.Parallel()
		t.Run("RevokeRecipients prevents user from retrieving session", func(t *testing.T) {
			// Create a session with account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)

			// account2 can retrieve the session
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)

			// Calling revokeRecipients to remove account2
			resp, err := session.RevokeRecipients([]string{currentDevice2.UserId}, nil)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice2.UserId: "ok"}, resp.UserIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("RevokeRecipients with proxySessions", func(t *testing.T) {
			// Create a proxySession and a session
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)
			err = session.AddProxySession(proxySession.Id, &RecipientRights{Read: true, Forward: true, Revoke: false})
			require.NoError(t, err)

			// account2 can retrieve the session via proxy
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, session2.RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, session2.RetrievalDetails.ProxySessionId)

			// Calling RevokeRecipients to remove proxySession
			resp, err := session.RevokeRecipients(nil, []string{proxySession.Id})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{proxySession.Id: "ok"}, resp.ProxyMkIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("RevokeRecipients does not error when user is not recipient", func(t *testing.T) {
			// Create a session without account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)

			// Calling revokeRecipients to double-revoke account2 (no error, but response will be "ko")
			resp, err := session.RevokeRecipients([]string{currentDevice2.UserId}, nil)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice2.UserId: "ko"}, resp.UserIds)
		})
		t.Run("RevokeRecipients with invalid userIds as input", func(t *testing.T) {
			// Create a session
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)

			// Calling revokeRecipients with bad inputs
			resp, err := session.RevokeRecipients([]string{currentDevice2.DeviceId}, nil) // Not a userId, to have a valid uuid but invalid userId
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice2.DeviceId: "ko"}, resp.UserIds)
			resp2, err := session.RevokeRecipients([]string{"bad-uuid"}, nil)
			assert.Error(t, err)
			assert.Nil(t, resp2)
			assert.ErrorIs(t, err, utils.APIError{Status: 400, Code: "UNKNOWN"})
		})
	})

	t.Run("EncryptionSession - RevokeOthers", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_revoke_others1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_revoke_others2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}

		t.Parallel()
		t.Run("RevokeOthers prevents user from retrieving session", func(t *testing.T) {
			// Create a session with account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)

			// account2 can retrieve the session
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)

			// Calling RevokeOthers to remove account2
			resp, err := session.RevokeOthers()
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice2.UserId: "ok"}, resp.RevokeAll.UserIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)

			// account1 still can
			session1b, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session1b.Id)
			assert.Equal(t, session.Key, session1b.Key)
		})
		t.Run("RevokeOthers with proxySessions", func(t *testing.T) {
			// Create a proxySession and a session
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)
			err = session.AddProxySession(proxySession.Id, &RecipientRights{Read: true, Forward: true, Revoke: false})
			require.NoError(t, err)

			// account2 can retrieve the session via proxy
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, session2.RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, session2.RetrievalDetails.ProxySessionId)

			// Calling RevokeOthers to remove proxySession
			resp, err := session.RevokeOthers()
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{proxySession.Id: "ok"}, resp.RevokeAll.ProxyMkIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
	})

	t.Run("EncryptionSession - RevokeAll", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_revoke_all1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_revoke_all2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}

		t.Parallel()
		t.Run("RevokeAll prevents users from retrieving session", func(t *testing.T) {
			// Create a session with account2
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)

			// account2 can retrieve the session
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)

			// Calling RevokeAll to remove account1 and account2
			resp, err := session.RevokeAll()
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice1.UserId: "ok", currentDevice2.UserId: "ok"}, resp.RevokeAll.UserIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)

			// account1 now cannot either
			session1b, err := account1.RetrieveEncryptionSession(session.Id, false, false, false)
			require.Error(t, err)
			assert.Nil(t, session1b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
		t.Run("RevokeAll with proxySessions", func(t *testing.T) {
			// Create a proxySession and a session
			proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2}, false)
			require.NoError(t, err)
			session, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1}, false)
			require.NoError(t, err)
			err = session.AddProxySession(proxySession.Id, &RecipientRights{Read: true, Forward: true, Revoke: false})
			require.NoError(t, err)

			// account2 can retrieve the session via proxy
			session2, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.NoError(t, err)
			assert.Equal(t, session.Id, session2.Id)
			assert.Equal(t, session.Key, session2.Key)
			assert.Equal(t, EncryptionSessionRetrievalViaProxy, session2.RetrievalDetails.Flow)
			assert.Equal(t, proxySession.Id, session2.RetrievalDetails.ProxySessionId)

			// Calling RevokeAll to remove proxySession
			resp, err := session.RevokeAll()
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, map[string]string{currentDevice1.UserId: "ok"}, resp.RevokeAll.UserIds)
			assert.Equal(t, map[string]string{proxySession.Id: "ok"}, resp.RevokeAll.ProxyMkIds)

			// account2 now cannot retrieve the session
			session2b, err := account2.RetrieveEncryptionSession(session.Id, false, true, false)
			require.Error(t, err)
			assert.Nil(t, session2b)
			assert.ErrorIs(t, err, ErrorNoTokenForYou)
		})
	})

	t.Run("EncryptionSession — Encrypt/Decrypt message", func(t *testing.T) {
		account, err := createTestAccount("sdk_session_encrypt_decrypt_msg")
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
		session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
		require.NoError(t, err)
		clearData := "Some cats are actually allergic to humans"

		encryptedMessage, err := session.EncryptMessage(clearData)
		assert.NoError(t, err)
		clearMessage, err := session.DecryptMessage(encryptedMessage)
		assert.NoError(t, err)
		assert.Equal(t, clearData, clearMessage)
	})

	t.Run("EncryptionSession — Encrypt/Decrypt file", func(t *testing.T) {
		account, err := createTestAccount("sdk_session_encrypt_decrypt_file")
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
		session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
		require.NoError(t, err)
		clearData := []byte("There was a successful Tinder match in Antarctica in 2014.")
		clearFileName := "myFile.txt"

		encryptedFile, err := session.EncryptFile(clearData, clearFileName)
		assert.NoError(t, err)
		clearFile, err := session.DecryptFile(encryptedFile)
		assert.NoError(t, err)
		assert.Equal(t, clearData, clearFile.FileContent)
		assert.Equal(t, clearFileName, clearFile.Filename)
		assert.Equal(t, session.Id, clearFile.SessionId)

		// Quick errors test
		_, err = session.EncryptFile(nil, clearFileName)
		assert.ErrorIs(t, err, encrypt_decrypt_file.ErrorTarFileNoFile)
		_, err = session.DecryptFile(nil)
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("working with path", func(t *testing.T) {
		// Clean work dir
		_ = os.RemoveAll("tmp/")
		err := os.Mkdir("tmp", 0o700)
		require.NoError(t, err)

		clearData := []byte("The giant squid has the largest eyes in the world.")
		testFileDir, err := filepath.Abs("tmp")
		require.NoError(t, err)
		testFileName := "random"
		testFileExt := ".fact"
		testFilePath := filepath.Join(testFileDir, testFileName+testFileExt)
		err = os.WriteFile(testFilePath, clearData, 0o700)
		require.NoError(t, err)

		account, err := createTestAccount("sdk_session_encrypt_decrypt_path")
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}
		session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
		require.NoError(t, err)

		encryptedFilePath, err := session.EncryptFileFromPath(testFilePath)
		require.NoError(t, err)
		assert.Equal(t, testFilePath+".seald", encryptedFilePath)
		decryptedFilePath, err := session.DecryptFileFromPath(encryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(testFileDir, testFileName+" (1)"+testFileExt), decryptedFilePath)

		decryptedContent, err := os.ReadFile(decryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, clearData, decryptedContent)

		esRetrieve, err := account.RetrieveEncryptionSessionFromFile(encryptedFilePath, true, false, false)
		require.NoError(t, err)
		decryptedFilePath2, err := esRetrieve.DecryptFileFromPath(encryptedFilePath)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(testFileDir, testFileName+" (2)"+testFileExt), decryptedFilePath2)

		decryptedContent2, err := os.ReadFile(decryptedFilePath2)
		require.NoError(t, err)
		assert.Equal(t, clearData, decryptedContent2)
	})

	t.Run("EncryptionSession cache", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_cache1")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		recipientDevice1 := &RecipientWithRights{Id: currentDevice1.UserId, Rights: allRights}
		canaryStorageAcc1 := newCanaryFileStorage(account1.options.Database)
		account1.options.Database = canaryStorageAcc1

		account2, err := createTestAccount("sdk_session_cache2")
		require.NoError(t, err)
		currentDevice2 := account2.storage.currentDevice.get()
		recipientDevice2 := &RecipientWithRights{Id: currentDevice2.UserId, Rights: allRights}
		canaryStorageAcc2 := newCanaryFileStorage(account2.options.Database)
		canaryApiAcc2 := newCanaryBeardApiClient(account2.apiClient)
		account2.options.Database = canaryStorageAcc2
		account2.apiClient = canaryApiAcc2

		account3, err := createTestAccount("sdk_session_cache3")
		require.NoError(t, err)
		currentDevice3 := account3.storage.currentDevice.get()
		recipientDevice3 := &RecipientWithRights{Id: currentDevice3.UserId, Rights: allRights}

		assert.Equal(t, 0, account1.storage.encryptionSessionsCache.len())
		esAcc1, err := account1.CreateEncryptionSession([]*RecipientWithRights{recipientDevice1, recipientDevice2, recipientDevice3}, true)
		require.NoError(t, err)
		assert.Equal(t, 1, account1.storage.encryptionSessionsCache.len())
		assert.Equal(t, EncryptionSessionRetrievalCreated, esAcc1.RetrievalDetails.Flow)
		retrieveES, err := account1.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		require.NotNil(t, retrieveES.Symkey)
		assert.Equal(t, EncryptionSessionRetrievalCreated, retrieveES.RetrievalDetails.Flow)
		assert.Equal(t, esAcc1.Key.Encode(), retrieveES.Symkey.Encode())
		assert.Equal(t, 1, canaryStorageAcc1.Counter["WriteEncryptionSession"])

		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		_, err = account2.RetrieveEncryptionSession(esAcc1.Id, true, false, false)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		retrieveES, err = account2.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		require.NotNil(t, retrieveES.Symkey)
		assert.Equal(t, EncryptionSessionRetrievalDirect, retrieveES.RetrievalDetails.Flow)
		assert.Equal(t, esAcc1.Key.Encode(), retrieveES.Symkey.Encode())
		assert.Equal(t, 1, canaryStorageAcc2.Counter["WriteEncryptionSession"])
		assert.Equal(t, 1, canaryApiAcc2.Counter["retrieveMessage"])

		// Retrieve from cache
		esAcc2, err := account2.RetrieveEncryptionSession(esAcc1.Id, true, false, false)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		retrieveES, err = account2.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		require.NotNil(t, retrieveES.Symkey)
		assert.Equal(t, EncryptionSessionRetrievalDirect, retrieveES.RetrievalDetails.Flow)
		assert.Equal(t, esAcc1.Key.Encode(), retrieveES.Symkey.Encode())
		assert.Equal(t, 1, canaryStorageAcc2.Counter["WriteEncryptionSession"])
		assert.Equal(t, 1, canaryApiAcc2.Counter["retrieveMessage"]) // No new API call to retrieveMessage

		// Multiple retrieves lock each-other: only one API call happens and others hit cache
		account2.storage.encryptionSessionsCache.delete(esAcc1.Id) // remove from cache
		canaryApiAcc2.Counter["retrieveMessage"] = 0               // reset counters
		canaryStorageAcc2.Counter["WriteEncryptionSession"] = 0
		var wg sync.WaitGroup
		wg.Add(3)
		var resultFromCache []bool
		for i := 0; i < 3; i++ {
			go func() { // launching 3 goroutines in parallel
				defer wg.Done() // Signal the WaitGroup that this goroutine is done
				es, errGoroutine := account2.RetrieveEncryptionSession(esAcc1.Id, true, false, false)
				if errGoroutine != nil {
					err = errGoroutine
				} else {
					resultFromCache = append(resultFromCache, es.RetrievalDetails.FromCache)
				}
			}()
		}
		wg.Wait()
		require.NoError(t, err)
		assert.Equal(t, 1, canaryApiAcc2.Counter["retrieveMessage"])
		assert.Equal(t, 1, canaryStorageAcc2.Counter["WriteEncryptionSession"])
		assert.Equal(t, 3, len(resultFromCache))
		assert.Equal(t, 1, countOccurrences(resultFromCache, false))
		assert.Equal(t, 2, countOccurrences(resultFromCache, true))

		// Revoking other does not affect cache
		_, err = esAcc2.RevokeRecipients([]string{currentDevice3.UserId}, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		retrieveES, err = account2.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		require.NotNil(t, retrieveES.Symkey)
		assert.Equal(t, EncryptionSessionRetrievalDirect, retrieveES.RetrievalDetails.Flow)
		assert.Equal(t, esAcc1.Key.Encode(), retrieveES.Symkey.Encode())

		// Revoking yourself deletes session from your cache
		_, err = esAcc2.RevokeRecipients([]string{currentDevice2.UserId}, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		retrieveES, err = account2.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		assert.Nil(t, retrieveES)

		// RevokeOthers does not affect cache
		_, err = esAcc1.RevokeOthers()
		require.NoError(t, err)
		assert.Equal(t, 1, account1.storage.encryptionSessionsCache.len())
		retrieveES, err = account1.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		require.NotNil(t, retrieveES.Symkey)
		assert.Equal(t, EncryptionSessionRetrievalCreated, retrieveES.RetrievalDetails.Flow)
		assert.Equal(t, esAcc1.Key.Encode(), retrieveES.Symkey.Encode())

		// Revoking all cleans your cache
		_, err = esAcc1.RevokeAll()
		require.NoError(t, err)
		assert.Equal(t, 0, account1.storage.encryptionSessionsCache.len())
		retrieveES, err = account1.storage.encryptionSessionsCache.get(esAcc1.Id)
		require.NoError(t, err)
		assert.Nil(t, retrieveES)
	})

	t.Run("EncryptionSession clean cache, TTL", func(t *testing.T) {
		// Create account
		initOptions, err := getInMemoryInitializeOptions("sdk_session_clean_cache")
		initOptions.EncryptionSessionCacheTTL = 1000 * time.Millisecond
		initOptions.EncryptionSessionCacheCleanupInterval = -1
		account, err := createTestAccountFromOptions(initOptions)
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		assert.Equal(t, 0, account.storage.encryptionSessionsCache.len())
		recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}

		// Create sessions and check they are in cache
		_, err = account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, true)
		require.NoError(t, err)
		_, err = account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, true)
		require.NoError(t, err)
		assert.Equal(t, 2, account.storage.encryptionSessionsCache.len())

		// After a wait longer than TTL, create another session, and check cache has not been auto-cleaned
		time.Sleep(1300 * time.Millisecond)
		es3, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, true)
		require.NoError(t, err)
		assert.Equal(t, 3, account.storage.encryptionSessionsCache.len()) // cache has not been cleaned of old sessions yet

		// Manual clean removes the obsolete sessions
		account.storage.encryptionSessionsCache.clean()
		assert.Equal(t, 1, account.storage.encryptionSessionsCache.len())

		// wait again : no automatic clean, but trying to retrieve session from cache does clean it
		time.Sleep(1300 * time.Millisecond)
		assert.Equal(t, 1, account.storage.encryptionSessionsCache.len())
		retrieveES, err := account.storage.encryptionSessionsCache.get(es3.Id)
		require.NoError(t, err)
		assert.Nil(t, retrieveES)
		assert.Equal(t, 0, account.storage.encryptionSessionsCache.len())
	})

	t.Run("EncryptionSession cache clean interval", func(t *testing.T) {
		// Create account
		initOptions, err := getInMemoryInitializeOptions("sdk_session_cache_interval")
		initOptions.EncryptionSessionCacheTTL = 2 * time.Second
		initOptions.EncryptionSessionCacheCleanupInterval = 2 * time.Second
		account, err := createTestAccountFromOptions(initOptions)
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()
		assert.Equal(t, 0, account.storage.encryptionSessionsCache.len())
		recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}

		// Create sessions and check they are in cache
		_, err = account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, true)
		require.NoError(t, err)
		_, err = account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, true)
		require.NoError(t, err)
		assert.Equal(t, 2, account.storage.encryptionSessionsCache.len())

		// After a wait longer than cleanup interval and TTL, cache has been cleaned
		time.Sleep(5 * time.Second) // needs to be bigger than TTL (to be sure it's expired) + 2*interval (to be sure interval has indeed run AFTER TTL expired)
		assert.Equal(t, 0, account.storage.encryptionSessionsCache.len())
		err = account.Close()
		require.NoError(t, err)
	})

	t.Run("EncryptionSessionCacheCleanupInterval defaults to sensible values", func(t *testing.T) {
		// When EncryptionSessionCacheTTL is shorter than 10s, EncryptionSessionCacheCleanupInterval defaults to 10s
		initOptionsTestDefaultShort, err := getInMemoryInitializeOptions("sdk_session_cache_interval_default2")
		initOptionsTestDefaultShort.EncryptionSessionCacheTTL = 500 * time.Millisecond
		accountDefaultShort, err := Initialize(initOptionsTestDefaultShort)
		require.NoError(t, err)
		// assert.Equal(t, 10*time.Second, accountDefaultShort.Storage.encryptionSessionsCache.cacheCleanupInterval) // cannot test this, as it is private in storage module
		assert.Equal(t, 10*time.Second, accountDefaultShort.options.EncryptionSessionCacheCleanupInterval)

		// When EncryptionSessionCacheTTL is longer than 10s, EncryptionSessionCacheCleanupInterval defaults to EncryptionSessionCacheTTL
		initOptionsTestDefaultLong, err := getInMemoryInitializeOptions("sdk_session_cache_interval_default2")
		initOptionsTestDefaultLong.EncryptionSessionCacheTTL = 20 * time.Second
		accountDefaultLong, err := Initialize(initOptionsTestDefaultLong)
		require.NoError(t, err)
		// assert.Equal(t, 20*time.Second, accountDefaultLong.Storage.encryptionSessionsCache.cacheCleanupInterval) // cannot test this, as it is private in storage module
		assert.Equal(t, 20*time.Second, accountDefaultLong.options.EncryptionSessionCacheCleanupInterval)
	})

	t.Run("EncryptionSession cache with group", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_cache_group1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_cache_group2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		// create group
		preGeneratedKeys, err := getPreGeneratedKeys()
		require.NoError(t, err)
		groupId, err := account1.CreateGroup(
			"Halocene",
			[]string{currentDevice1.UserId, currentDevice2.UserId},
			[]string{currentDevice1.UserId},
			preGeneratedKeys,
		)
		require.NoError(t, err)

		// create sessions for group
		groupRecipient := &RecipientWithRights{Id: groupId, Rights: allRights}
		es1, err := account1.CreateEncryptionSession([]*RecipientWithRights{groupRecipient}, true)
		require.NoError(t, err)
		es2, err := account1.CreateEncryptionSession([]*RecipientWithRights{groupRecipient}, true)
		require.NoError(t, err)

		// canary api to count api calls
		canaryApi := newCanaryBeardApiClient(account2.apiClient)
		account2.apiClient = canaryApi

		// first retrieve of es1 hits API and adds to cache
		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		retrieveES11, err := account2.RetrieveEncryptionSession(es1.Id, true, false, true)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 2, canaryApi.Counter["retrieveMessage"]) // one retrieveMessage for es1, one for the group key
		require.NotNil(t, retrieveES11.Key)
		assert.Equal(t, es1.Key, retrieveES11.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrieveES11.RetrievalDetails.Flow)
		assert.Equal(t, groupId, retrieveES11.RetrievalDetails.GroupId)
		assert.False(t, retrieveES11.RetrievalDetails.FromCache)

		// second retrieve of es1 does not hit API
		retrieveES12, err := account2.RetrieveEncryptionSession(es1.Id, true, false, true)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 2, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES12.Key)
		assert.Equal(t, es1.Key, retrieveES12.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrieveES12.RetrievalDetails.Flow)
		assert.Equal(t, groupId, retrieveES12.RetrievalDetails.GroupId)
		assert.True(t, retrieveES12.RetrievalDetails.FromCache)

		// first retrieve of es2 hits API and adds to cache
		retrieveES21, err := account2.RetrieveEncryptionSession(es2.Id, true, false, true)
		require.NoError(t, err)
		assert.Equal(t, 2, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 3, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES21.Key)
		assert.Equal(t, es2.Key, retrieveES21.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrieveES21.RetrievalDetails.Flow)
		assert.Equal(t, groupId, retrieveES21.RetrievalDetails.GroupId)
		assert.False(t, retrieveES21.RetrievalDetails.FromCache)

		// second retrieve of es2 does not hit API
		retrieveES22, err := account2.RetrieveEncryptionSession(es2.Id, true, false, true)
		require.NoError(t, err)
		assert.Equal(t, 2, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 3, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES22.Key)
		assert.Equal(t, es2.Key, retrieveES22.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaGroup, retrieveES22.RetrievalDetails.Flow)
		assert.Equal(t, groupId, retrieveES22.RetrievalDetails.GroupId)
		assert.True(t, retrieveES22.RetrievalDetails.FromCache)

		// es1 removed from cache when group revoked from session
		es1CacheBefore, err := account2.storage.encryptionSessionsCache.get(es1.Id)
		assert.NotNil(t, es1CacheBefore)
		_, err = retrieveES12.RevokeRecipients([]string{groupId}, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		es1CacheAfter, err := account2.storage.encryptionSessionsCache.get(es1.Id)
		assert.Nil(t, es1CacheAfter)

		// es2 removed from cache when RevokeOthers is called
		es2CacheBefore, err := account2.storage.encryptionSessionsCache.get(es2.Id)
		assert.NotNil(t, es2CacheBefore)
		_, err = retrieveES22.RevokeOthers()
		require.NoError(t, err)
		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		es2CacheAfter, err := account2.storage.encryptionSessionsCache.get(es2.Id)
		assert.Nil(t, es2CacheAfter)
	})

	t.Run("EncryptionSession cache with proxy", func(t *testing.T) {
		account1, err := createTestAccount("sdk_session_cache_proxy1")
		require.NoError(t, err)
		account2, err := createTestAccount("sdk_session_cache_proxy2")
		require.NoError(t, err)
		currentDevice1 := account1.storage.currentDevice.get()
		currentDevice2 := account2.storage.currentDevice.get()

		// create proxy session
		proxySession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}, {Id: currentDevice2.UserId, Rights: allRights}}, true)
		require.NoError(t, err)

		// create proxied sessions
		es1, err := account1.CreateEncryptionSession([]*RecipientWithRights{}, true)
		require.NoError(t, err)
		err = es1.AddProxySession(proxySession.Id, allRights)
		require.NoError(t, err)

		es2, err := account1.CreateEncryptionSession([]*RecipientWithRights{}, true)
		require.NoError(t, err)
		err = es2.AddProxySession(proxySession.Id, allRights)
		require.NoError(t, err)

		// canary api to count api calls
		canaryApi := newCanaryBeardApiClient(account2.apiClient)
		account2.apiClient = canaryApi

		// first retrieve of es1 hits API and adds to cache
		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 0, canaryApi.Counter["retrieveMessage"])
		retrieveES11, err := account2.RetrieveEncryptionSession(es1.Id, true, true, false)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 1, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES11.Key)
		assert.Equal(t, es1.Key, retrieveES11.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrieveES11.RetrievalDetails.Flow)
		assert.Equal(t, proxySession.Id, retrieveES11.RetrievalDetails.ProxySessionId)
		assert.False(t, retrieveES11.RetrievalDetails.FromCache)

		// second retrieve of es1 does not hit API
		retrieveES12, err := account2.RetrieveEncryptionSession(es1.Id, true, true, false)
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 1, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES12.Key)
		assert.Equal(t, es1.Key, retrieveES12.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrieveES12.RetrievalDetails.Flow)
		assert.Equal(t, proxySession.Id, retrieveES12.RetrievalDetails.ProxySessionId)
		assert.True(t, retrieveES12.RetrievalDetails.FromCache)

		// first retrieve of es2 hits API and adds to cache
		retrieveES21, err := account2.RetrieveEncryptionSession(es2.Id, true, true, false)
		require.NoError(t, err)
		assert.Equal(t, 2, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 2, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES21.Key)
		assert.Equal(t, es2.Key, retrieveES21.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrieveES21.RetrievalDetails.Flow)
		assert.Equal(t, proxySession.Id, retrieveES21.RetrievalDetails.ProxySessionId)
		assert.False(t, retrieveES21.RetrievalDetails.FromCache)

		// second retrieve of es2 does not hit API
		retrieveES22, err := account2.RetrieveEncryptionSession(es2.Id, true, true, false)
		require.NoError(t, err)
		assert.Equal(t, 2, account2.storage.encryptionSessionsCache.len())
		assert.Equal(t, 2, canaryApi.Counter["retrieveMessage"])
		require.NotNil(t, retrieveES22.Key)
		assert.Equal(t, es2.Key, retrieveES22.Key)
		assert.Equal(t, EncryptionSessionRetrievalViaProxy, retrieveES22.RetrievalDetails.Flow)
		assert.Equal(t, proxySession.Id, retrieveES22.RetrievalDetails.ProxySessionId)
		assert.True(t, retrieveES22.RetrievalDetails.FromCache)

		// es1 removed from cache when proxy revoked
		es1CacheBefore, err := account2.storage.encryptionSessionsCache.get(es1.Id)
		assert.NotNil(t, es1CacheBefore)
		_, err = retrieveES12.RevokeRecipients(nil, []string{proxySession.Id})
		require.NoError(t, err)
		assert.Equal(t, 1, account2.storage.encryptionSessionsCache.len())
		es1CacheAfter, err := account2.storage.encryptionSessionsCache.get(es1.Id)
		assert.Nil(t, es1CacheAfter)

		// es2 removed from cache when RevokeOthers is called
		es2CacheBefore, err := account2.storage.encryptionSessionsCache.get(es2.Id)
		assert.NotNil(t, es2CacheBefore)
		_, err = retrieveES22.RevokeOthers()
		require.NoError(t, err)
		assert.Equal(t, 0, account2.storage.encryptionSessionsCache.len())
		es2CacheAfter, err := account2.storage.encryptionSessionsCache.get(es2.Id)
		assert.Nil(t, es2CacheAfter)
	})

	t.Run("TMR access", func(t *testing.T) {
		t.Run("TMR access create/retrieve/convert", func(t *testing.T) {
			credentials, err := test_utils.GetCredentials()
			require.NoError(t, err)

			overEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			overEncryptionKeyBytes := overEncryptionKey.Encode()

			nonce, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			userEmail := fmt.Sprintf("user-tmr-%s@test.com", nonce[0:15])
			badEmail := fmt.Sprintf("bad-user-tmr-%s@test.com", nonce[0:15])
			authFactor := &common_models.AuthFactor{Value: userEmail, Type: "EM"}

			// Initiate account1
			account1, err := createTestAccount("sdk_session_tmr_access_1")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()
			// Initiate userTmr
			accountTMR, err := createTestAccount("sdk_session_tmr_access_tmr")
			require.NoError(t, err)
			userTmrId := accountTMR.storage.currentDevice.get().UserId

			// create a session
			ogSession, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, true)
			require.NoError(t, err)

			recipients := []*TmrRecipientWithRights{{
				AuthFactor:        authFactor,
				OverEncryptionKey: overEncryptionKeyBytes,
				Rights:            allRights,
			}, {
				AuthFactor:        &common_models.AuthFactor{Value: badEmail, Type: "SMS"},
				OverEncryptionKey: overEncryptionKeyBytes,
				Rights:            allRights,
			}}

			// Add a Tmr access
			response, err := ogSession.AddMultipleTmrAccesses(recipients)
			require.NoError(t, err)
			assert.Equal(t, 200, response.Status[userEmail].Status)
			assert.True(t, response.Status[userEmail].TmrKey.AclRead)
			assert.True(t, response.Status[userEmail].TmrKey.AclForward)
			assert.True(t, response.Status[userEmail].TmrKey.AclRevoke)
			assert.Nil(t, response.Status[userEmail].Error)
			assert.Equal(t, 400, response.Status[badEmail].Status)

			list, err := account1.apiClient.listTmrAccesses(&listTmrAccessesRequest{MessageId: ogSession.Id, Page: 1})
			require.NoError(t, err)
			assert.Equal(t, 1, list.NbPage)
			assert.Equal(t, 1, len(list.TmrMKs))

			// Instantiate a ssks-backend for TMR auth
			options1 := &ssks_tmr.PluginTMRInitializeOptions{
				SsksURL:      credentials.SsksUrl,
				AppId:        credentials.AppId,
				InstanceName: "plugin-tmr-tests-1",
				Platform:     "go-tests",
			}
			pluginInstance1 := ssks_tmr.NewPluginTMR(options1)

			// Retrieve a TMR token
			backend := test_utils.NewSSKS2MRBackendApiClient(credentials.SsksUrl, credentials.AppId, credentials.SsksBackendAppKey)
			challSendRep, err := backend.ChallengeSend(userTmrId, authFactor, true, true)
			require.NoError(t, err)
			factorToken, err := pluginInstance1.GetFactorToken(challSendRep.SessionId, authFactor, credentials.SsksTMRChallenge)
			require.NoError(t, err)

			// Retrieve an ES with the TMR token
			tmrES, err := accountTMR.RetrieveEncryptionSessionByTmr(factorToken.Token, ogSession.Id, overEncryptionKeyBytes, nil, false, false)
			require.NoError(t, err)
			assert.Equal(t, ogSession.Key, tmrES.Key)

			retrieveFilters := &TmrAccessesRetrievalFilters{CreatedById: currentDevice1.UserId, TmrAccessId: list.TmrMKs[0].Id}
			tmrESWithFilter, err := accountTMR.RetrieveEncryptionSessionByTmr(factorToken.Token, ogSession.Id, overEncryptionKeyBytes, retrieveFilters, false, false)
			require.NoError(t, err)
			assert.Equal(t, ogSession.Key, tmrESWithFilter.Key)

			// Use the TMR token convert all TMR accesses to 'classic' message access
			converted, err := accountTMR.ConvertTmrAccesses(factorToken.Token, overEncryptionKeyBytes, nil, true)
			require.NoError(t, err)
			assert.Equal(t, 1, len(converted.Succeeded))
			assert.Equal(t, 1, len(converted.Converted))
			assert.Equal(t, 0, len(converted.Errored))
			assert.Equal(t, "ok", converted.Status)

			// Do a 'classic' ES retrieval to check that it has been converted
			esClassicR, err := accountTMR.RetrieveEncryptionSession(ogSession.Id, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, ogSession.Key, esClassicR.Key)
		})

		t.Run("TMR access conversion", func(t *testing.T) {
			credentials, err := test_utils.GetCredentials()
			require.NoError(t, err)

			overEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			overEncryptionKeyBytes := overEncryptionKey.Encode()

			nonce, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			userEmail := fmt.Sprintf("user-tmr-%s@test.com", nonce[0:15])
			authFactor := &common_models.AuthFactor{Value: userEmail, Type: "EM"}

			tmrRecipient := &TmrRecipientWithRights{
				AuthFactor:        authFactor,
				OverEncryptionKey: overEncryptionKeyBytes,
				Rights:            allRights,
			}

			// Initiate account1
			account1, err := createTestAccount("sdk_session_tmr_access_1")
			require.NoError(t, err)
			currentDevice1 := account1.storage.currentDevice.get()
			// Initiate account2
			account2, err := createTestAccount("sdk_session_tmr_access_2")
			require.NoError(t, err)
			currentDevice2 := account2.storage.currentDevice.get()
			// Initiate userTmr
			accountTMR, err := createTestAccount("sdk_session_tmr_access_tmr")
			require.NoError(t, err)
			userTmrId := accountTMR.storage.currentDevice.get().UserId

			var esAcc1 []*EncryptionSession
			var esAcc2 []*EncryptionSession
			// create a session
			for i := 0; i < 12; i++ {
				sessionAcc1, err := account1.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice1.UserId, Rights: allRights}}, true)
				require.NoError(t, err)
				esAcc1 = append(esAcc1, sessionAcc1)
				sessionAcc2, err := account2.CreateEncryptionSession([]*RecipientWithRights{{Id: currentDevice2.UserId, Rights: allRights}}, true)
				require.NoError(t, err)
				esAcc2 = append(esAcc2, sessionAcc2)

				// Add a Tmr access
				tmrAccessId, err := sessionAcc1.AddTmrAccess(tmrRecipient)
				require.NoError(t, err)
				assert.True(t, utils.IsUUID(tmrAccessId))
				tmrAccessId2, err := sessionAcc2.AddTmrAccess(tmrRecipient)
				require.NoError(t, err)
				assert.True(t, utils.IsUUID(tmrAccessId2))
			}

			// Instantiate a ssks-backend for TMR auth
			options1 := &ssks_tmr.PluginTMRInitializeOptions{
				SsksURL:      credentials.SsksUrl,
				AppId:        credentials.AppId,
				InstanceName: "plugin-tmr-tests-1",
				Platform:     "go-tests",
			}
			pluginInstance1 := ssks_tmr.NewPluginTMR(options1)

			// Retrieve a TMR token
			backend := test_utils.NewSSKS2MRBackendApiClient(credentials.SsksUrl, credentials.AppId, credentials.SsksBackendAppKey)
			challSendRep, err := backend.ChallengeSend(userTmrId, authFactor, true, true)
			require.NoError(t, err)
			factorToken, err := pluginInstance1.GetFactorToken(challSendRep.SessionId, authFactor, credentials.SsksTMRChallenge)
			require.NoError(t, err)

			// Try to convert with bad over encryption key
			badOverEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			_, err = accountTMR.ConvertTmrAccesses(factorToken.Token, badOverEncryptionKey.Encode(), nil, true)
			assert.ErrorIs(t, err, ErrorConvertTmrAccessCannotDecrypt)

			// canary api to count api calls
			canaryApi := newCanaryBeardApiClient(accountTMR.apiClient)
			accountTMR.apiClient = canaryApi
			canaryApi.ToExecute["retrieveTmrAccesses"] = func(request any) ([]byte, error) {
				var req = request.(*retrieveTmrAccessesRequest)
				resp, err := canaryApi.Client.retrieveTmrAccesses(req)
				require.NoError(t, err)
				resp.PaginationLimit = 5
				return json.Marshal(resp)
			}

			// Use the TMR token convert all TMR accesses created by the user1
			convertedUser1, err := accountTMR.ConvertTmrAccesses(factorToken.Token, overEncryptionKeyBytes, &TmrAccessesConvertFilters{CreatedById: currentDevice1.UserId}, true)
			require.NoError(t, err)
			assert.Equal(t, 12, len(convertedUser1.Succeeded))
			assert.Equal(t, 12, len(convertedUser1.Converted))
			assert.Equal(t, 0, len(convertedUser1.Errored))
			assert.Equal(t, "ok", convertedUser1.Status)
			// First call to `retrieveTmrAccesses` give us 10 accesses, we convert 5, and 'forget' 5.
			// Second call return 7 accesses, we convert 5, and 'forget' 2.
			// Third call return 2 accesses, we convert 2, and exit.
			assert.Equal(t, 3, canaryApi.Counter["retrieveTmrAccesses"])
			assert.Equal(t, 3, canaryApi.Counter["convertTmrAccesses"])

			// Use the TMR token convert all TMR accesses, but with pagination
			convertedUser2, err := accountTMR.ConvertTmrAccesses(factorToken.Token, overEncryptionKeyBytes, nil, true)
			require.NoError(t, err)
			assert.Equal(t, 12, len(convertedUser2.Succeeded))
			assert.Equal(t, 12, len(convertedUser2.Converted))
			assert.Equal(t, 0, len(convertedUser2.Errored))
			assert.Equal(t, "ok", convertedUser2.Status)
			assert.Equal(t, 6, canaryApi.Counter["retrieveTmrAccesses"])
			assert.Equal(t, 6, canaryApi.Counter["convertTmrAccesses"])
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/encryption_session")

			// import identity from JS
			identity, err := os.ReadFile(filepath.Join(testArtifactsDir, "identity"))
			require.NoError(t, err)
			initOptions, err := getInMemoryInitializeOptions("sdk_session_import_js")
			require.NoError(t, err)
			account, err := Initialize(initOptions)
			require.NoError(t, err)
			err = account.ImportIdentity(identity)
			require.NoError(t, err)

			// can retrieve first session (with old key)
			sessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "session_id"))
			require.NoError(t, err)
			session, err := account.RetrieveEncryptionSession(string(sessionId), false, false, false)
			require.NoError(t, err)

			// session can decrypt message
			encryptedMessage, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_message"))
			require.NoError(t, err)
			decryptedMessage, err := session.DecryptMessage(string(encryptedMessage))
			require.NoError(t, err)
			assert.Equal(t, "message content", decryptedMessage)

			// session can decrypt file
			encryptedFile, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_file"))
			require.NoError(t, err)
			decryptedFile, err := session.DecryptFile(encryptedFile)
			require.NoError(t, err)
			assert.Equal(t, "file content", string(decryptedFile.FileContent))
			assert.Equal(t, "test.txt", decryptedFile.Filename)

			// can retrieve second session (with current key)
			sessionId2, err := os.ReadFile(filepath.Join(testArtifactsDir, "session_id2"))
			require.NoError(t, err)
			session2, err := account.RetrieveEncryptionSession(string(sessionId2), false, false, false)
			require.NoError(t, err)

			// session2 can decrypt message
			encryptedMessage2, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_message2"))
			require.NoError(t, err)
			decryptedMessage2, err := session2.DecryptMessage(string(encryptedMessage2))
			require.NoError(t, err)
			assert.Equal(t, "message content2", decryptedMessage2)

			// session2 can decrypt file
			encryptedFile2, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_file2"))
			require.NoError(t, err)
			decryptedFile2, err := session2.DecryptFile(encryptedFile2)
			require.NoError(t, err)
			assert.Equal(t, "file content2", string(decryptedFile2.FileContent))
			assert.Equal(t, "test2.txt", decryptedFile2.Filename)

			// can open proxied session via proxy
			proxySessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "proxysession_id"))
			require.NoError(t, err)
			proxiedSessionId, err := os.ReadFile(filepath.Join(testArtifactsDir, "proxiedsession_id"))
			require.NoError(t, err)
			proxiedSession, err := account.RetrieveEncryptionSession(string(proxiedSessionId), false, true, false)
			require.NoError(t, err)
			assert.Equal(t, proxiedSession.RetrievalDetails.Flow, EncryptionSessionRetrievalViaProxy)
			assert.Equal(t, proxiedSession.RetrievalDetails.ProxySessionId, string(proxySessionId))

			// can retrieve session via TMR access
			userTmrId, err := os.ReadFile(filepath.Join(testArtifactsDir, "tmrAccess_userId"))
			require.NoError(t, err)
			tmrAccessEm, err := os.ReadFile(filepath.Join(testArtifactsDir, "tmrAccess_em"))
			require.NoError(t, err)
			tmrAccessKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "tmrAccess_rawOverEncryptionKey"))
			require.NoError(t, err)

			// Instantiate a ssks-backend for TMR auth
			credentials, err := test_utils.GetCredentials()
			options1 := &ssks_tmr.PluginTMRInitializeOptions{
				SsksURL:      credentials.SsksUrl,
				AppId:        credentials.AppId,
				InstanceName: "plugin-tmr-tests-1",
				Platform:     "go-tests",
			}
			pluginInstance1 := ssks_tmr.NewPluginTMR(options1)

			// Retrieve a TMR token
			backend := test_utils.NewSSKS2MRBackendApiClient(credentials.SsksUrl, credentials.AppId, credentials.SsksBackendAppKey)
			authFactor := &common_models.AuthFactor{Value: string(tmrAccessEm), Type: "EM"}
			challSendRep, err := backend.ChallengeSend(string(userTmrId), authFactor, true, true)
			require.NoError(t, err)
			factorToken, err := pluginInstance1.GetFactorToken(challSendRep.SessionId, authFactor, credentials.SsksTMRChallenge)
			require.NoError(t, err)

			// Retrieve an ES with the TMR token
			require.NoError(t, err)
			tmrES, err := account.RetrieveEncryptionSessionByTmr(factorToken.Token, string(sessionId), tmrAccessKey, &TmrAccessesRetrievalFilters{}, false, false)
			require.NoError(t, err)
			assert.Equal(t, session.Key, tmrES.Key)
		})

		t.Run("Export for JS", func(t *testing.T) {
			// ensure artifacts dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/encryption_session")
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// create identity
			account, err := createTestAccount("sdk_session_export_js")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()
			recipientCurrentDevice := &RecipientWithRights{Id: currentDevice.UserId, Rights: allRights}

			// create a session, with a message and a file
			session, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "session_id"), []byte(session.Id), 0o700)
			require.NoError(t, err)
			encryptedMessage, err := session.EncryptMessage("message content")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_message"), []byte(encryptedMessage), 0o700)
			require.NoError(t, err)
			encryptedFile, err := session.EncryptFile([]byte("file content"), "test.txt")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_file"), encryptedFile, 0o700)
			require.NoError(t, err)

			// renew key to check if it works for oldKeys
			preGeneratedKeys, err := getPreGeneratedKeysDifferent([]*PreGeneratedKeys{stateToPreGenerated(account)})
			require.NoError(t, err)
			err = account.RenewKeys(RenewKeysOptions{ExpireAfter: sigchain.DEVICE_DEFAULT_LIFE_TIME, PreGeneratedKeys: preGeneratedKeys})
			require.NoError(t, err)

			// create another session (with new key), with a message and a file
			session2, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "session_id2"), []byte(session2.Id), 0o700)
			require.NoError(t, err)
			encryptedMessage2, err := session2.EncryptMessage("message content2")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_message2"), []byte(encryptedMessage2), 0o700)
			require.NoError(t, err)
			encryptedFile2, err := session2.EncryptFile([]byte("file content2"), "test2.txt")
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_file2"), encryptedFile2, 0o700)
			require.NoError(t, err)

			// create proxy session and session openable via proxy
			proxySession, err := account.CreateEncryptionSession([]*RecipientWithRights{recipientCurrentDevice}, false)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "proxysession_id"), []byte(proxySession.Id), 0o700)
			require.NoError(t, err)
			proxiedSession, err := account.CreateEncryptionSession([]*RecipientWithRights{}, false)
			require.NoError(t, err)
			err = proxiedSession.AddProxySession(proxySession.Id, allRights)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "proxiedsession_id"), []byte(proxiedSession.Id), 0o700)
			require.NoError(t, err)

			// add TMR access to the first session
			overEncryptionKey, err := symmetric_key.Generate()
			require.NoError(t, err)
			overEncryptionKeyBytes := overEncryptionKey.Encode()

			nonce, err := utils.GenerateRandomNonce()
			require.NoError(t, err)
			userEmail := fmt.Sprintf("go-js-compat-tmr-access-%s@test.com", nonce[0:15])
			authFactor := &common_models.AuthFactor{Value: userEmail, Type: "EM"}
			tmrRecipient := &TmrRecipientWithRights{
				AuthFactor:        authFactor,
				OverEncryptionKey: overEncryptionKeyBytes,
				Rights:            allRights,
			}
			_, err = session.AddTmrAccess(tmrRecipient)
			require.NoError(t, err)
			userInfo := account.GetCurrentAccountInfo()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "tmrAccess_userId"), []byte(userInfo.UserId), 0o700)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "tmrAccess_em"), []byte(userEmail), 0o700)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "tmrAccess_rawOverEncryptionKey"), overEncryptionKey.Encode(), 0o700)
			require.NoError(t, err)

			// export identity
			exportedIdentity, err := account.ExportIdentity()
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "identity"), exportedIdentity, 0o700)
			require.NoError(t, err)
		})
	})
}
