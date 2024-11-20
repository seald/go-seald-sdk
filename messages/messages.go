package messages

import (
	"encoding/base64"
	"encoding/json"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

var (
	// ErrorEncryptMessageNoSymKey is returned when no symkey is given at encryption
	ErrorEncryptMessageNoSymKey = utils.NewSealdError("ENCRYPT_MESSAGE_NO_SYMKEY", "encrypt message no symKey")
	// ErrorEncryptMessageInvalidSessionId is returned when the given sessionId is not an UUIDv4
	ErrorEncryptMessageInvalidSessionId = utils.NewSealdError("ENCRYPT_MESSAGE_INVALID_SESSION_ID", "invalid sessionId")
	// ErrorDecryptMessageNoSymKey is returned when no symkey is given at decryption
	ErrorDecryptMessageNoSymKey = utils.NewSealdError("DECRYPT_MESSAGE_NO_SYMKEY", "decrypt message no symKey")
	// ErrorDecryptMessageCannotUnmarshal is returned when the given encrypted string is not a parsable Seald message
	ErrorDecryptMessageCannotUnmarshal = utils.NewSealdError("DECRYPT_MESSAGE_CANNOT_UNMARSHAL", "unable to parse given encrypted message")
	// ErrorDecryptMessageInvalidSessionId is returned when the parsed sessionId does not match the expected sessionId
	ErrorDecryptMessageInvalidSessionId = utils.NewSealdError("DECRYPT_MESSAGE_INVALID_SESSION_ID", "this session cannot decrypt this message")
)

type SealdMessage struct {
	Data      string `json:"data"`
	SessionId string `json:"sessionId"`
}

func EncryptMessage(clearString string, sessionId string, key *symmetric_key.SymKey) (string, error) {
	if key == nil {
		return "", tracerr.Wrap(ErrorEncryptMessageNoSymKey)
	}
	if !utils.IsUUID(sessionId) {
		return "", tracerr.Wrap(ErrorEncryptMessageInvalidSessionId)
	}
	encryptedData, err := key.Encrypt([]byte(clearString))
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	encryptedJson := SealdMessage{
		Data:      base64.StdEncoding.EncodeToString(encryptedData),
		SessionId: sessionId,
	}
	message, err := json.Marshal(encryptedJson)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return string(message), nil
}

func DecryptMessage(encryptedString string, sessionId string, key *symmetric_key.SymKey) (string, error) {
	if key == nil {
		return "", tracerr.Wrap(ErrorDecryptMessageNoSymKey)
	}
	var encryptedJson SealdMessage
	err := json.Unmarshal([]byte(encryptedString), &encryptedJson)
	if err != nil {
		return "", tracerr.Wrap(ErrorDecryptMessageCannotUnmarshal)
	}

	if encryptedJson.SessionId != sessionId {
		return "", tracerr.Wrap(ErrorDecryptMessageInvalidSessionId)
	}

	encryptedData, err := utils.Base64DecodeString(encryptedJson.Data)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	clearString, err := key.Decrypt(encryptedData)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return string(clearString), nil
}
