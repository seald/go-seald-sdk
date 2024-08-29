package sdk

import (
	"bytes"
	"encoding/json"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/asymkey"
	"go-seald-sdk/encrypt_decrypt_file"
	"go-seald-sdk/messages"
	"os"
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
	file, err := os.Open(encryptedFilePath)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	mid, err := encrypt_decrypt_file.ParseFileHeader(file)
	if err != nil {
		_ = file.Close() // ignore err as we will already return one
		return "", tracerr.Wrap(err)
	}
	err = file.Close()
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return mid, nil
}

// ParseSessionIdFromBytes takes an encrypted file as bytes, and returns the session id.
func ParseSessionIdFromBytes(fileBytes []byte) (string, error) {
	fileReader := bytes.NewReader(fileBytes)
	mid, err := encrypt_decrypt_file.ParseFileHeader(fileReader)
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
