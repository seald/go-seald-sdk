package exported_identity

import (
	"github.com/ztrue/tracerr"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/utils"
	"go.mongodb.org/mongo-driver/bson"
)

type ExportedIdentity struct {
	UserId                      string                `bson:"userId"`
	KeyId                       string                `bson:"keyId"`
	EncryptionKey               *asymkey.PrivateKey   `bson:"encryptionKey"`
	SigningKey                  *asymkey.PrivateKey   `bson:"signingKey"`
	NewEncryptionKey            *asymkey.PrivateKey   `bson:"newEncryptionKey,omitempty"` // Used when prepareRenew
	NewSigningKey               *asymkey.PrivateKey   `bson:"newSigningKey,omitempty"`    // Used when prepareRenew
	SerializedOldEncryptionKeys []*asymkey.PrivateKey `bson:"serializedOldEncryptionKeys,omitempty"`
	SerializedOldSigningKeys    []*asymkey.PrivateKey `bson:"serializedOldSigningKeys,omitempty"`
}

type B64UUIDExportedIdentity ExportedIdentity

func (bkp ExportedIdentity) MarshalBSON() ([]byte, error) {
	b64UserId, e := utils.B64UUID(bkp.UserId)
	if e != nil {
		return nil, tracerr.Wrap(e)
	}

	b64KeyId, e := utils.B64UUID(bkp.KeyId)
	if e != nil {
		return nil, tracerr.Wrap(e)
	}

	return bson.Marshal(B64UUIDExportedIdentity{
		UserId:                      b64UserId,
		KeyId:                       b64KeyId,
		EncryptionKey:               bkp.EncryptionKey,
		SigningKey:                  bkp.SigningKey,
		NewEncryptionKey:            bkp.NewEncryptionKey,
		NewSigningKey:               bkp.NewSigningKey,
		SerializedOldEncryptionKeys: bkp.SerializedOldEncryptionKeys,
		SerializedOldSigningKeys:    bkp.SerializedOldSigningKeys,
	})
}

func (bkp *ExportedIdentity) UnmarshalBSON(b []byte) error {
	var data B64UUIDExportedIdentity
	err := bson.Unmarshal(b, &data)
	if err != nil {
		return tracerr.Wrap(err)
	}

	userId, e := utils.UnB64UUID(data.UserId)
	if e != nil {
		return tracerr.Wrap(e)
	}

	keyId, e := utils.UnB64UUID(data.KeyId)
	if e != nil {
		return tracerr.Wrap(e)
	}
	*bkp = ExportedIdentity(data)
	bkp.UserId = userId
	bkp.KeyId = keyId

	return nil
}
