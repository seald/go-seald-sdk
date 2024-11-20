package exported_identity

import (
	"encoding/base64"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
)

const KeyId = "74debca2-1a54-49d9-88f2-6b60b4417d38"
const UserId = "7fd6d054-a975-4c57-b4b9-e07d9f30d80a"
const B64BackupKeyWithOldKeys = "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"
const B64BackupKeyWithoutOldKeys = "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"
const B64EncryptionKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAPKDFheCcoz5Dmc35evvEy9aHbVpFxGBn+Ze3cS4m11FrEq18FAEfHfm3/+gjUPe1/Pi6Sv7/9/OtKUUEK37nk60hNTabEhSX1Ck5fLP90imMkAvQPh+iTKwF3nh6ypZc9jt/r4/sbK7ZtAhwL4d1VfE5NB38OBq3Dyz5dOHatSlAgMBAAECgYEA7wTWNEukvV8HnCIS4ewbm5MVLuSqEN4SjEq6BxbwQgjWnDgf563UQ5Tw95D1SoyLidv+dxSDh8HCd+WD3wbdacf6SvVYkXzEwYcG8d8p0sYFPo1YODQtQV2lO89nrUyan9UWzC/T5BfmAAiV6gvJgJbKvz1cDoIvdEJGueJXHWECQQD8yMnIB04ldQtotDluakQVmbK/1t6zV6ZL7UdLHrFXXRQ4ctijo+cIhY2GY5PFQue4Wi7vFfirrhEjAaG3SWPpAkEA9ZjYe2dCwO094lU9TmbIypIXDsVVTwa1Cf5x956idHs4S5sGDfE8k+QD0oFV836Pc+0fTgjwcv6Rx60DYwyhXQJBAPFbDT5Nq1GcVY5dNdC06djt7Xu5vtzhvUgVf9K7tXvCxYG4NhzYa8j5K027WeYooXKluNZS1iGli3svHacRDbECQQDgILxu4a1poxf2lRN9mQ9kzi18rVlM5TISDMK013AqHMkjNjYwQxalYFCcqqtlqvn/MUaAUGgeiXNAZgPRQJWBAkARp2VlyPMXM48u+CwfAxrXbj0adEqPeBgXICN+CCPPyH+4sa60tY4wGlaZveSPilSiSEvsVJnpigmRthojHQMt"
const B64SigningKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALEZlMQh11pWnUkYxt3LmxHf0ZrEbFO/z/93DiMZiJOFZlSoqEQtB417HArG72TedykRNcbokeyaonZ3ddgeqaHvBbDI7LHJxI25mnSQVt5NG4jX4bh55PaJlpEB0yN9OhOtX6DALH9BB4niO7kSXeFbltpKixGTfrA4pDL54SPjAgMBAAECgYBsXJ6uM5a1a/HpXAOyinZjxXNXI4C07dSzF4HK8EClIyat/lSXAoZwhzdtULQCIC0BL8qb3ooLH8Lwgb/VcU2RBp71Y7NuNpNKE+Ln3SHST+OJAsNFYhOMf54Y715+rqkOd8TiPnKU/W/OukujYxu/7NCZ1VZANlviTvGmV41soQJBAMaPbfyhMkcIC9g/DupYLLOrEb7nzIriNJm+nDebZ4kAva7oU1VRvDF1QgyQC2OLtCVyP0ptCiQrZ98dHXlzSw8CQQDkVOKWGhlT5Lj+Gr247pV/qVqit2ytqGTp+q6OXVX7Eb9m6b4c3KEzI2BCY3OSEqLT006Vek6MltJNtGcH7OntAkEAk6kcURALVLmOHW2fiPSzoZVpZ//3o5zfIyqV/+Bo2YCcjxMkzcEv49Pgn3kLjybYfDR/DrkSHp3M7CY5whTUTwJBAIEf1/vWypf88vkQmlYo5naJiW4XmOgkIN2JHIn6EpOnl7xVV2PvCWJoERm6MDNdQqPUDc7Omfk7mbbD3LhIrIkCQC5ma8PykWYDAjdHXbDxL1cOJh22WIeSHpintQAcUm29i0JxfOo9Rq7/YjF78mCYft/LeWJ6jl3Zu9B9g4JvnAo="
const B64OldEncryptionKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKakKVh2S+xhk/91X4Z0fpelGlX0PyBKops1hHgnfKGPax7RLv1MJMOzRlwT600wDap1zSR7kE7aK043fX8oeQVa08EsVCRTkcLHtGjD8xY+tGBDo3XBmr1JQi3NOciBjF9cJI8nliR0UFNsh453Y3KDtw4YBJQLWonpNcb3rrOPAgMBAAECgYAm1v5YAwKBLuEa2pWQNhjHaZDw1cPc1+h8eoXMp49x7IaQITttiFDNWDye+3mNfRTCVUCiLzacWldbnK1gdON3zr5PK9vCnG8DGRBvn/AwdmcZI05OhotjihVPl6rWblyA+rVVPqwE48qhBP5yocPOaoMowdm6kpBDAa28k+JjqQJBANJxJ/Yo8Nel9zai1bb22Oy63X5S6NHJiPKbkfJ3o40A7EDZH3dUZ3hohTXncBFLGoWNHuX9ugK9G4hsSp1yxssCQQDKt4lfAzjYBTXWOc1eAOALTr144mCClK9PpdwtcS2Q9h4Zbdxj1FcSvWhJ+YlWSJuYTqZTSTqHiWkvBBKF7SnNAkEAnxtqyVSe84zJ4ocu6kysKiAGgxIQcTzczAEPUbFe+Kbv+P+wKLqqGIF95gl707di8AKIj/9L+fIctQKbT3uODQJAHFSQHzYtEIuR3ZGQcO3AYfQsKKPChx1ObtwoLDWf/51V0Yn3/f+j95t+4q+8ENHu5NdBCWy3gE+k4ow4Jn1hlQJALnZ3zhIpTMxLUWbXlnidd3NKnNPRItFSgCHiu9segVCOcRbbCQ1IUmju3aMlDcUOyJIVYg0T5j6NWcZT2RbWAA=="
const B64OldSigningKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOQRaIDfepnun2Dk9rxWdee2MxYQG6oFhIkLkiSlmelfKAKgzmyaks01nJY6h/XCAmOvlwKkoocrIXxcdNCRY4n1d+l9JEDhQDoN97fOe6V9+uoRYztDAcIBfZXUbbBfy1oyEtDg4peFlv21i+jmJn2RdLyJZUZwyJhxdkCru4t1AgMBAAECgYEAzPbgJkGxmzmavqfHHsfNOqrCCqf7VLeUvt1JP+ocAmHkQUhne68HE6mEynZbzf/HyfL6EgQHlNasR2mIChE/k//5JphET+G6ASpfWw5HRtN4rVLxkf74BeFkV1aqDxdh7ccUrOhOYKczJa1p9c31U7PUfnuTITGbeloDRHpsPQECQQDnz0k/iLECBVdONaCa6eI9ZcKWFgkegQ3mWo/XqB4+NB6sHiArqSc7n/0etFUTZTGLaAGVF8DGjR+Dtm9ptmTVAkEA+94p41gn51Ldp0AW4aLvbURMFuk0eE/T7Mau58E1P74IcpGHge4cErIW0JUhr0Gz4eu4vL9hL5sjkwxZMQxcIQJBAMrxjw8wfMdoJaczDAiT+p4GGPWNFS6/jYu+fXAwn0mWF8RYG5Id5VsuFkxrVJBGZ7nEtJ3yzbMGmjCV57SFGoECQH08g6GKtRS9zH8cTARX6ytuuVLvFGr6boseY9vS4zJVwIePO0zs48KcEOIYNU6aoeIlPo+DrcRpJLA6hKLx3WECQQDS9pePZuh9enKgfLPXUGyXwlyipQ0mWCvrTaDITKbuyrK4NGR+5EHFHwv2ypvUyHn9Ym2D3Wppe7edqIyaIP0I"

func TestBackupKey(t *testing.T) {
	EncryptionKey, err := asymkey.PrivateKeyFromB64(B64EncryptionKey)
	assert.NoError(t, err)
	SigningKey, err := asymkey.PrivateKeyFromB64(B64SigningKey)
	assert.NoError(t, err)
	OldEncryptionKey, err := asymkey.PrivateKeyFromB64(B64OldEncryptionKey)
	assert.NoError(t, err)
	OldSigningKey, err := asymkey.PrivateKeyFromB64(B64OldSigningKey)
	assert.NoError(t, err)

	t.Run("Unmarshal known backup key with old keys", func(t *testing.T) {
		bkp, err := base64.StdEncoding.DecodeString(B64BackupKeyWithOldKeys)
		assert.NoError(t, err)
		var bkpRead ExportedIdentity
		err = bson.Unmarshal(bkp, &bkpRead)
		assert.NoError(t, err)

		assert.Equal(t, UserId, bkpRead.UserId)
		assert.Equal(t, KeyId, bkpRead.KeyId)
		assert.Equal(t, EncryptionKey, bkpRead.EncryptionKey)
		assert.Equal(t, SigningKey, bkpRead.SigningKey)
		assert.Equal(t, 1, len(bkpRead.SerializedOldEncryptionKeys))
		assert.Equal(t, OldEncryptionKey, bkpRead.SerializedOldEncryptionKeys[0])
		assert.Equal(t, 1, len(bkpRead.SerializedOldEncryptionKeys))
		assert.Equal(t, OldSigningKey, bkpRead.SerializedOldSigningKeys[0])
	})

	t.Run("Unmarshal known backup key without old keys", func(t *testing.T) {
		bkp, err := base64.StdEncoding.DecodeString(B64BackupKeyWithoutOldKeys)
		assert.NoError(t, err)
		var bkpRead ExportedIdentity
		err = bson.Unmarshal(bkp, &bkpRead)
		assert.NoError(t, err)

		assert.Equal(t, UserId, bkpRead.UserId)
		assert.Equal(t, KeyId, bkpRead.KeyId)
		assert.Equal(t, EncryptionKey, bkpRead.EncryptionKey)
		assert.Equal(t, SigningKey, bkpRead.SigningKey)
		assert.Equal(t, 0, len(bkpRead.SerializedOldEncryptionKeys))
		assert.Equal(t, 0, len(bkpRead.SerializedOldEncryptionKeys))
	})

	t.Run("Unmarshal truncated backup key", func(t *testing.T) {
		bkp, err := base64.StdEncoding.DecodeString(B64BackupKeyWithoutOldKeys)
		assert.NoError(t, err)
		var bkpRead ExportedIdentity
		// Because of https://jira.mongodb.org/browse/GODRIVER-2167, we need to be careful in the SDK
		assert.Panics(t, func() { _ = bson.Unmarshal(bkp[len(bkp)/2:], &bkpRead) })
	})

	t.Run("Unmarshal non backupKey type", func(t *testing.T) {
		b, err := bson.Marshal(struct {
			UserId int `bson:"userId"`
		}{UserId: 1})
		assert.NoError(t, err)
		var bkpRead ExportedIdentity
		err = bson.Unmarshal(b, &bkpRead)
		assert.EqualError(t, err, "error decoding key userId: cannot decode 32-bit integer into a string type")
	})

	t.Run("Unmarshal backup key with invalid UserId", func(t *testing.T) {
		b64KeyID, err := utils.B64UUID(KeyId)
		assert.NoError(t, err)

		bkp := B64UUIDExportedIdentity{
			UserId:        "dadada",
			KeyId:         b64KeyID,
			EncryptionKey: EncryptionKey,
			SigningKey:    SigningKey,
		}
		b, err := bson.Marshal(bkp)
		assert.NoError(t, err)

		var bkpRead ExportedIdentity
		err = bson.Unmarshal(b, &bkpRead)
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})

	t.Run("Unmarshal backup key with invalid KeyId", func(t *testing.T) {
		b64UserId, err := utils.B64UUID(UserId)
		assert.NoError(t, err)

		bkp := B64UUIDExportedIdentity{
			UserId:        b64UserId,
			KeyId:         "dadada",
			EncryptionKey: EncryptionKey,
			SigningKey:    SigningKey,
		}
		b, err := bson.Marshal(bkp)
		assert.NoError(t, err)

		var bkpRead ExportedIdentity
		err = bson.Unmarshal(b, &bkpRead)
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})

	t.Run("Marshal known backup key without old keys", func(t *testing.T) {
		bkpRef, err := base64.StdEncoding.DecodeString(B64BackupKeyWithoutOldKeys)
		assert.NoError(t, err)
		bkp := ExportedIdentity{
			UserId:        UserId,
			KeyId:         KeyId,
			EncryptionKey: EncryptionKey,
			SigningKey:    SigningKey,
		}
		b, err := bson.Marshal(bkp)
		assert.NoError(t, err)
		assert.Equal(t, bkpRef, b)
	})

	t.Run("Marshal known backup key with old keys", func(t *testing.T) {
		bkpRef, err := base64.StdEncoding.DecodeString(B64BackupKeyWithOldKeys)
		assert.NoError(t, err)
		bkp := ExportedIdentity{
			UserId:                      UserId,
			KeyId:                       KeyId,
			EncryptionKey:               EncryptionKey,
			SigningKey:                  SigningKey,
			SerializedOldEncryptionKeys: []*asymkey.PrivateKey{OldEncryptionKey},
			SerializedOldSigningKeys:    []*asymkey.PrivateKey{OldSigningKey},
		}
		b, err := bson.Marshal(bkp)
		assert.NoError(t, err)
		assert.Equal(t, bkpRef, b)
	})

	t.Run("Marshal backup key with invalid KeyId", func(t *testing.T) {
		bkp := ExportedIdentity{
			UserId:        UserId,
			KeyId:         "dadada",
			EncryptionKey: EncryptionKey,
			SigningKey:    SigningKey,
		}
		_, err := bson.Marshal(bkp)
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})

	t.Run("Marshal backup key with invalid UserId", func(t *testing.T) {
		bkp := ExportedIdentity{
			UserId:        "dadada",
			KeyId:         KeyId,
			EncryptionKey: EncryptionKey,
			SigningKey:    SigningKey,
		}
		_, err := bson.Marshal(bkp)
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})
}
