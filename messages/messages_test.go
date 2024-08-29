package messages

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/symmetric_key"
	"testing"
)

func TestEncryptDecryptMessages(t *testing.T) {
	clearText := "Cats sleep 16 to 18 hours per day."
	sessionId := "04cc5834-f6b8-4abc-9f38-289085dbbd64"
	symKey, err := symmetric_key.Generate()
	if err != nil {
		tracerr.Print(err)
		t.Fail()
		return
	}

	t.Parallel()
	t.Run("Can Encrypt-Decrypt message", func(t *testing.T) {
		encryptedMessage, err := EncryptMessage(clearText, sessionId, symKey)
		if err != nil {
			tracerr.Print(err)
			t.Fail()
			return
		}

		clearMessage, err := DecryptMessage(encryptedMessage, sessionId, symKey)
		if err != nil {
			tracerr.Print(err)
			t.Fail()
			return
		}
		assert.Equal(t, clearText, clearMessage)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Parallel()
		t.Run("nil symKey", func(t *testing.T) {
			_, err := EncryptMessage(clearText, sessionId, nil)
			assert.ErrorIs(t, err, ErrorEncryptMessageNoSymKey)
		})
		t.Run("no sessionId", func(t *testing.T) {
			_, err := EncryptMessage(clearText, "", symKey)
			assert.ErrorIs(t, err, ErrorEncryptMessageInvalidSessionId)
		})
		t.Run("bad sessionId", func(t *testing.T) {
			_, err := EncryptMessage(clearText, "", symKey)
			assert.ErrorIs(t, err, ErrorEncryptMessageInvalidSessionId)
		})
	})

	t.Run("Decrypt", func(t *testing.T) {
		t.Parallel()
		t.Run("nil symKey", func(t *testing.T) {
			_, err := DecryptMessage("we don't care about this string", sessionId, nil)
			assert.ErrorIs(t, err, ErrorDecryptMessageNoSymKey)
		})
		t.Run("Unmarshal bad string", func(t *testing.T) {
			_, err := DecryptMessage("we don't care about this string. Oh wait, we do!", sessionId, symKey)
			assert.ErrorIs(t, err, ErrorDecryptMessageCannotUnmarshal)
		})
		t.Run("bad session id", func(t *testing.T) {
			encryptedMessage, err := EncryptMessage(clearText, sessionId, symKey)
			if err != nil {
				tracerr.Print(err)
				t.Fail()
				return
			}

			_, err = DecryptMessage(encryptedMessage, "04cc5834-0000-0000-9f38-289085dbbd64", symKey)
			assert.ErrorIs(t, err, ErrorDecryptMessageInvalidSessionId)
		})
		t.Run("bad message cannot decrypt", func(t *testing.T) {
			encryptedJson := SealdMessage{
				Data:      "75OtMUvzLEqvQTuz7zm6XsN5RIS5+JiZ0UEoM/ly6VpE6FwXCvaKEstRjJSFH3YO3Fe8h+g45+qtu1YOyFhyrw==",
				SessionId: sessionId,
			}
			encryptedMessage, err := json.Marshal(encryptedJson)
			if err != nil {
				tracerr.Print(err)
				t.Fail()
				return
			}

			_, err = DecryptMessage(string(encryptedMessage), sessionId, symKey)
			assert.ErrorIs(t, err, symmetric_key.ErrorDecryptMacMismatch)
		})
		t.Run("bad message cannot unb64", func(t *testing.T) {
			encryptedJson := SealdMessage{
				Data:      "foobar!",
				SessionId: sessionId,
			}
			encryptedMessage, err := json.Marshal(encryptedJson)
			if err != nil {
				tracerr.Print(err)
				t.Fail()
				return
			}

			_, err = DecryptMessage(string(encryptedMessage), sessionId, symKey)
			assert.EqualError(t, err, "illegal base64 data at input byte 6")
		})
	})
}
