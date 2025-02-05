package sdk

import (
	"encoding/json"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/messages"
	"github.com/ztrue/tracerr"
)

func generateKey(keySize int, keyChan chan *asymkey.PrivateKey, errChan chan error) {
	key, err := asymkey.Generate(keySize)
	if err != nil {
		errChan <- err
	} else {
		keyChan <- key
	}
	close(keyChan)
	close(errChan)
}

func generateKeyPair(keySize int) (*asymkey.PrivateKey, *asymkey.PrivateKey, error) {
	encryptionKeyChan := make(chan *asymkey.PrivateKey)
	encryptionKeyErrChan := make(chan error)

	signingKeyChan := make(chan *asymkey.PrivateKey)
	signingKeyErrChan := make(chan error)

	go generateKey(keySize, encryptionKeyChan, encryptionKeyErrChan)
	go generateKey(keySize, signingKeyChan, signingKeyErrChan)

	encryptionKey, encryptionErr := <-encryptionKeyChan, <-encryptionKeyErrChan
	signingKey, signingErr := <-signingKeyChan, <-signingKeyErrChan

	if encryptionErr != nil {
		return nil, nil, tracerr.Wrap(encryptionErr)
	}
	if signingErr != nil {
		return nil, nil, tracerr.Wrap(signingErr)
	}

	return encryptionKey, signingKey, nil
}

// ParseSessionIdFromFile takes the path to an encrypted file, and returns the session id.
func ParseSessionIdFromFile(encryptedFilePath string) (string, error) {
	mid, err := encrypt_decrypt_file.ParseFileHeaderFromPath(encryptedFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return mid, nil
}

// ParseSessionIdFromBytes takes an encrypted file as bytes, and returns the session id.
func ParseSessionIdFromBytes(fileBytes []byte) (string, error) {
	mid, _, err := encrypt_decrypt_file.ParseFileHeaderBytes(fileBytes)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return mid, nil
}

// ParseSessionIdFromMessage takes an encrypted message, and returns the session id.
func ParseSessionIdFromMessage(message string) (string, error) {
	var sealdMessage messages.SealdMessage
	err := json.Unmarshal([]byte(message), &sealdMessage)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return sealdMessage.SessionId, nil
}
