package anonymous_sdk

import (
	"encoding/base64"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/messages"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/ztrue/tracerr"
	"go.mongodb.org/mongo-driver/bson"
)

// The AnonymousEncryptionSession struct represents an anonymous encryption session, with which you can then encrypt / decrypt multiple messages.
type AnonymousEncryptionSession struct {
	aSDK *AnonymousSDK `bson:"-"`
	// SessionId is the ID of this EncryptionSession.
	SessionId string `bson:"id"`
	// Key represents the SymKey of this EncryptionSession. For advanced use only.
	Key *symmetric_key.SymKey `bson:"key"`
}

// EncryptMessage encrypts a clear-text string into an encrypted message, for the recipients of this session.
func (aES *AnonymousEncryptionSession) EncryptMessage(clearMessage string) (string, error) {
	sealdMessage, err := messages.EncryptMessage(clearMessage, aES.SessionId, aES.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return sealdMessage, nil
}

// DecryptMessage decrypts an encrypted message string into the corresponding clear-text string.
func (aES *AnonymousEncryptionSession) DecryptMessage(encryptedMessage string) (string, error) {
	clearMessage, err := messages.DecryptMessage(encryptedMessage, aES.SessionId, aES.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return clearMessage, nil
}

// EncryptFile encrypts a clear-text file into an encrypted file, for the recipients of this session.
func (aES *AnonymousEncryptionSession) EncryptFile(clearFile []byte, filename string) ([]byte, error) {
	sealdFile, err := encrypt_decrypt_file.EncryptBytes(clearFile, filename, aES.SessionId, aES.Key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return sealdFile, nil
}

// DecryptFile decrypts an encrypted file into the corresponding clear-text file.
func (aES *AnonymousEncryptionSession) DecryptFile(encryptedFile []byte) (*common_models.ClearFile, error) {
	clearFile, err := encrypt_decrypt_file.DecryptBytes(encryptedFile, aES.SessionId, aES.Key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return clearFile, nil
}

// EncryptFileFromPath encrypts a clear-text file into an encrypted file, for the recipients of this session.
// Returns the path of the encrypted file.
// The encrypted file will be created alongside the clear one, in the same directory, with the same name,
// and a `.seald` extension added.
// If a file already exist with that name, a numeric suffix will be added (up to 99).
func (aES *AnonymousEncryptionSession) EncryptFileFromPath(clearFilePath string) (string, error) {
	aES.aSDK.logger.Debug().Str("clearFilePath", clearFilePath).Msg("EncryptFileFromPath encrypting...")
	sealdFile, err := encrypt_decrypt_file.EncryptFileFromPath(clearFilePath, aES.SessionId, aES.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	aES.aSDK.logger.Debug().Str("sealdFile", sealdFile).Msg("EncryptFileFromPath encrypted")
	return sealdFile, nil
}

// DecryptFileFromPath decrypts an encrypted file into the corresponding clear-text file.
// Returns the path of the decrypted file.
// The clear file will be created alongside the encrypted one, in the same directory.
// The output file will be named with the name it had at encryption.
// If a file already exist with that name, a numeric suffix will be added (up to 99).
func (aES *AnonymousEncryptionSession) DecryptFileFromPath(encryptedFilePath string) (string, error) {
	aES.aSDK.logger.Debug().Str("encryptedFilePath", encryptedFilePath).Msg("DecryptFileFromPath decrypting...")
	clearFilePath, err := encrypt_decrypt_file.DecryptFileFromPath(encryptedFilePath, aES.SessionId, aES.Key)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	aES.aSDK.logger.Debug().Str("clearFilePath", clearFilePath).Msg("DecryptFileFromPath decrypted")
	return clearFilePath, nil
}

// Serialize serialized the AnonymousEncryptionSession to a string.
// This is for advanced use.
// May be used to keep sessions in a cache.
// WARNING: a user could use this cache to work around being revoked. Use with caution.
// WARNING: if the cache is accessible to another user, they could use it to decrypt messages they are not supposed
// to have access to. Make sure only the current user in question can access this cache, for example by encrypting it.
func (aES *AnonymousEncryptionSession) Serialize() (string, error) {
	res, err := bson.Marshal(aES)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

// DeserializeAnonymousEncryptionSession deserializes a serialized session.
// For advanced use.
func (aSDK *AnonymousSDK) DeserializeAnonymousEncryptionSession(str string) (*AnonymousEncryptionSession, error) {
	bsoned, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var session AnonymousEncryptionSession
	err = bson.Unmarshal(bsoned, &session)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	session.aSDK = aSDK
	return &session, nil
}
