package mobile_sdk

import (
	"testing"

	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobileEncryptionSession(t *testing.T) {
	// create identities
	sdk1, sdk1UserInfo, err := getTestAccount(test_utils.GetTestName(t), true)
	require.NoError(t, err)
	sdk2, sdk2UserInfo, err := getTestAccount(test_utils.GetTestName(t), true)
	require.NoError(t, err)
	sdk3, sdk3UserInfo, err := getTestAccount(test_utils.GetTestName(t), true)
	require.NoError(t, err)

	allRights := &RecipientRights{
		Read:    true,
		Revoke:  true,
		Forward: true,
	}
	sdk1Recipient := &RecipientWithRights{RecipientId: sdk1UserInfo.UserId, Rights: allRights}
	sdk2Recipient := &RecipientWithRights{RecipientId: sdk2UserInfo.UserId, Rights: allRights}
	recipients1and2 := (&RecipientsWithRightsArray{}).Add(sdk1Recipient).Add(sdk2Recipient)

	t.Run("Creator default right", func(t *testing.T) {
		defautlRightsRecipient := (&RecipientsWithRightsArray{}).Add(&RecipientWithRights{RecipientId: sdk1UserInfo.UserId}).Add(sdk2Recipient)
		mES, err := sdk1.CreateEncryptionSession(defautlRightsRecipient, "test-mobile-1", false)
		require.NoError(t, err)

		// sdk1UserInfo
		revoked, err := mES.RevokeOthers()
		require.NoError(t, err)
		assert.True(t, revoked.Recipients.Get(0).Success)
		assert.Equal(t, sdk2UserInfo.UserId, revoked.Recipients.Get(0).Id)
	})

	t.Run("AddRecipient", func(t *testing.T) {
		mES, err := sdk1.CreateEncryptionSession(&RecipientsWithRightsArray{}, "test-mobile-2", true)
		require.NoError(t, err)

		respAllGood, err := mES.AddRecipients(recipients1and2)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(respAllGood.status))
		assert.True(t, respAllGood.status[0].Success)
		assert.True(t, respAllGood.status[1].Success)
		assert.Equal(t, "", respAllGood.status[0].ErrorCode)
		assert.Equal(t, "", respAllGood.status[1].ErrorCode)

		mes2, err := sdk2.RetrieveEncryptionSession(mES.Id, true, false, false)
		assert.NoError(t, err)
		respWithFailure, err := mes2.AddRecipients(recipients1and2)
		require.NoError(t, err)
		assert.Equal(t, 2, len(respWithFailure.status))
		for _, elem := range respWithFailure.status {
			assert.True(t, elem.Success)
			assert.Equal(t, "", elem.ErrorCode)
		}
	})

	t.Run("RevokeRecipients", func(t *testing.T) {
		mES, err := sdk1.CreateEncryptionSession(recipients1and2, "test-mobile-3", true)
		require.NoError(t, err)

		respAllGood, err := mES.RevokeRecipients(&RecipientsToRevoke{
			SealdIds: &StringArray{items: []string{sdk1UserInfo.UserId, sdk2UserInfo.UserId, sdk3UserInfo.UserId}},
		})
		require.NoError(t, err)
		assert.Equal(t, 3, len(respAllGood.Recipients.status))
		assert.Equal(t, 0, len(respAllGood.ProxySessions.status))
		for _, elem := range respAllGood.Recipients.status {
			switch elem.Id {
			case sdk1UserInfo.UserId:
				assert.True(t, elem.Success)
			case sdk2UserInfo.UserId:
				assert.True(t, elem.Success)
			case sdk3UserInfo.UserId:
				assert.False(t, elem.Success)
			default:
				t.Errorf("Unexpected user ID")
			}
		}

		mESOther, err := sdk1.CreateEncryptionSession(recipients1and2, "test-mobile-4", true)
		require.NoError(t, err)
		revokeOthers, err := mESOther.RevokeOthers()
		require.NoError(t, err)
		assert.Equal(t, 1, len(revokeOthers.Recipients.status))
		assert.Equal(t, 0, len(revokeOthers.ProxySessions.status))
		assert.Equal(t, revokeOthers.Recipients.status[0].Id, sdk2UserInfo.UserId)
		assert.True(t, revokeOthers.Recipients.status[0].Success)

		mESAll, err := sdk1.CreateEncryptionSession(recipients1and2, "test-mobile-5", true)
		require.NoError(t, err)
		mESProxy, err := sdk1.CreateEncryptionSession(recipients1and2, "test-mobile-6", true)
		require.NoError(t, err)
		err = mESAll.AddProxySession(mESProxy.Id, &RecipientRights{Read: true, Revoke: true, Forward: true})
		require.NoError(t, err)
		revokeAll, err := mESAll.RevokeAll()
		require.NoError(t, err)
		assert.Equal(t, 2, len(revokeAll.Recipients.status))
		for _, elem := range revokeAll.Recipients.status {
			switch elem.Id {
			case sdk1UserInfo.UserId:
				assert.True(t, elem.Success)
			case sdk2UserInfo.UserId:
				assert.True(t, elem.Success)
			default:
				t.Errorf("Unexpected user ID")
			}
		}
		assert.Equal(t, 1, len(revokeAll.ProxySessions.status))
		revokeAllProxies0 := revokeAll.ProxySessions.Get(0)
		assert.Equal(t, mESProxy.Id, revokeAllProxies0.Id)
		assert.Equal(t, true, revokeAllProxies0.Success)
	})

	t.Run("tmr accesses", func(t *testing.T) {
		mES, err := sdk1.CreateEncryptionSession(recipients1and2, "test-mobile-7", true)
		require.NoError(t, err)

		overEncryptionKey, err := symmetric_key.Generate()
		require.NoError(t, err)
		overEncryptionKeyBytes := overEncryptionKey.Encode()

		tmrRecipient := &TmrRecipientWithRights{
			Rights:            allRights,
			AuthFactor:        &AuthFactor{Type: "EM", Value: "email@seald.io"},
			OverEncryptionKey: overEncryptionKeyBytes,
		}
		addedTMRAccessId, err := mES.AddTmrAccess(tmrRecipient)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(addedTMRAccessId))

		tmrRecipientsArray := &TmrRecipientWithRightsArray{}
		tmrRecipientsArray.Add(&TmrRecipientWithRights{
			Rights:            allRights,
			AuthFactor:        &AuthFactor{Type: "EM", Value: "email-2@seald.io"},
			OverEncryptionKey: overEncryptionKeyBytes,
		})
		tmrRecipientsArray.Add(&TmrRecipientWithRights{
			Rights:            allRights,
			AuthFactor:        &AuthFactor{Type: "EM", Value: "email-3@seald.io"},
			OverEncryptionKey: overEncryptionKeyBytes,
		})

		addedMultipleTMR, err := mES.AddMultipleTmrAccesses(tmrRecipientsArray)
		require.NoError(t, err)
		res0 := addedMultipleTMR.Get(0)
		res1 := addedMultipleTMR.Get(1)
		assert.ElementsMatch(t, []string{"email-2@seald.io", "email-3@seald.io"}, []string{res0.Id, res1.Id})
		assert.True(t, res0.Success)
		assert.True(t, res1.Success)
		assert.True(t, utils.IsUUID(res0.Result))
		assert.True(t, utils.IsUUID(res1.Result))
	})

	t.Run("SymEncKeys", func(t *testing.T) {
		mES, err := sdk1.CreateEncryptionSession((&RecipientsWithRightsArray{}).Add(sdk1Recipient), "test-mobile-symEncKey", true)
		require.NoError(t, err)

		// encrypt some data
		messageToEncrypt := "This is some data to encrypt"
		encryptedMessage, err := mES.EncryptMessage(messageToEncrypt)
		require.NoError(t, err)
		assert.NotEqual(t, messageToEncrypt, encryptedMessage)

		// add sym enc key with password
		password := "strong-password-1234"
		symEncKeyIdFromPassword, err := mES.AddSymEncKeyFromPassword(password, allRights)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(symEncKeyIdFromPassword))

		// add sym enc key with raw key
		secret := "symEncKey-secret"
		rawKey, err := utils.GenerateRandomBytes(64)
		symEncKeyIdFromRawKeys, err := mES.AddSymEncKeyFromRawKeys(secret, rawKey, allRights)
		require.NoError(t, err)
		assert.True(t, utils.IsUUID(symEncKeyIdFromRawKeys))

		// sdk2 retrieves encryption session with sym enc key password and decrypt
		mESRetrievedWithPassword, err := sdk2.RetrieveEncryptionSessionWithSymEncKeyPassword(mES.Id, symEncKeyIdFromPassword, password, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESRetrievedWithPassword.Id)
		decryptedMessageRetrievedWithPassword, err := mESRetrievedWithPassword.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageRetrievedWithPassword)

		// sdk2 still can't retrieve without sym enc key
		_, err = sdk2.RetrieveEncryptionSession(mES.Id, false, false, false)
		assert.ErrorIs(t, err, utils.SerializableError{Id: "GOSDK_NO_TOKEN_FOR_YOU", Code: "NO_TOKEN_FOR_YOU"})

		// sdk3 retrieve encryption session with sym enc key raw keys and decrypt
		mESRetrievedWithRawKeys, err := sdk3.RetrieveEncryptionSessionWithSymEncKeyRawKeys(mES.Id, symEncKeyIdFromRawKeys, secret, rawKey, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESRetrievedWithRawKeys.Id)
		decryptedMessageRetrievedWithRawKeys, err := mESRetrievedWithRawKeys.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageRetrievedWithRawKeys)

		// sdk3 still can't retrieve without sym enc key
		_, err = sdk3.RetrieveEncryptionSession(mES.Id, false, false, false)
		assert.ErrorIs(t, err, utils.SerializableError{Id: "GOSDK_NO_TOKEN_FOR_YOU", Code: "NO_TOKEN_FOR_YOU"})

		// sdk2 self-adds to encryption session with sym enc key password and decrypt
		mESAddedWithPassword, err := sdk2.SelfAddToEncryptionSessionWithSymEncKeyPassword(mES.Id, symEncKeyIdFromPassword, password, allRights, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESAddedWithPassword.Id)
		decryptedMessageAddedWithPassword, err := mESAddedWithPassword.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageAddedWithPassword)

		// sdk2 now can retrieve without sym enc key
		mESAddedWithPassword2, err := sdk2.RetrieveEncryptionSession(mES.Id, false, false, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESAddedWithPassword2.Id)
		decryptedMessageAddedWithPassword2, err := mESAddedWithPassword2.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageAddedWithPassword2)

		// sdk3 retrieve encryption session with sym enc key raw keys and decrypt
		mESAddedWithRawKeys, err := sdk3.SelfAddToEncryptionSessionWithSymEncKeyRawKeys(mES.Id, symEncKeyIdFromRawKeys, secret, rawKey, allRights, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESAddedWithRawKeys.Id)
		decryptedMessageAddedWithRawKeys, err := mESAddedWithRawKeys.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageAddedWithRawKeys)

		// sdk3 now can retrieve without sym enc key
		mESAddedWithRawKeys2, err := sdk3.RetrieveEncryptionSession(mES.Id, false, false, false)
		require.NoError(t, err)
		assert.Equal(t, mES.Id, mESAddedWithRawKeys2.Id)
		decryptedMessageWithRawKeys2, err := mESAddedWithRawKeys2.DecryptMessage(encryptedMessage)
		require.NoError(t, err)
		assert.Equal(t, messageToEncrypt, decryptedMessageWithRawKeys2)
	})
}
