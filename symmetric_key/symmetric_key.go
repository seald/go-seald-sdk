package symmetric_key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
)

var (
	// ErrorDecodeInvalidLength is returned when decoding a key of invalid lenth
	ErrorDecodeInvalidLength = utils.NewSealdError("SYMKEY_DECODE_INVALID_LENGTH", "can't decode SymKey, invalid length")
	// ErrorPadInvalidBlockLen is returned when padding to an invalid length
	ErrorPadInvalidBlockLen = utils.NewSealdError("SYMKEY_PAD_INVALID_BLOCK_LEN", "invalid padding block length")
	// ErrorUnpadInvalidBlockLen is returned when the padding of a block has an invalid length
	ErrorUnpadInvalidBlockLen = utils.NewSealdError("SYMKEY_UNPAD_INVALID_BLOCK_LEN", "invalid unpadding block length")
	// ErrorUnpadInvalidDataLen is returned when the unpadded data has an invalid length
	ErrorUnpadInvalidDataLen = utils.NewSealdError("SYMKEY_UNPAD_INVALID_DATA_LEN", "invalid data length")
	// ErrorUnpadInvalidPadLen is returned when the padding lenth is invalid
	ErrorUnpadInvalidPadLen = utils.NewSealdError("SYMKEY_UNPAD_INVALID_PAD_LEN", "invalid padding length")
	// ErrorUnpadInvalidPad is returned when the padding is invalid
	ErrorUnpadInvalidPad = utils.NewSealdError("SYMKEY_UNPAD_INVALID_PAD", "invalid padding")
	// ErrorEncryptInvalidKeySize is returned when the encryption key has an invalid size
	ErrorEncryptInvalidKeySize = utils.NewSealdError("SYMKEY_ENCRYPT_INVALID_KEY_SIZE", "encrypt invalid key size")
	// ErrorDecryptInvalidKeySize is returned when the decryption key has an invalid size
	ErrorDecryptInvalidKeySize = utils.NewSealdError("SYMKEY_DECRYPT_INVALID_KEY_SIZE", "decrypt invalid key size")
	// ErrorDecryptCipherTooShort is returned when the ciphertext is too short
	ErrorDecryptCipherTooShort = utils.NewSealdError("SYMKEY_DECRYPT_CIPHER_TOO_SHORT", "ciphertext is too short")
	// ErrorDecryptMacMismatch is returned when the decrypted mac does not match
	ErrorDecryptMacMismatch = utils.NewSealdError("SYMKEY_DECRYPT_MAC_MISMATCH", "macs do not match")
)

type SymKey struct {
	encryptionKey []byte
	hmacKey       []byte
}

func Generate() (*SymKey, error) {
	randomData, err := utils.GenerateRandomBytes(64)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	symKey := SymKey{
		encryptionKey: randomData[:32],
		hmacKey:       randomData[32:],
	}
	return &symKey, nil
}

func (symKey *SymKey) Encode() []byte {
	encodedSymKey := make([]byte, 64)
	copy(encodedSymKey, symKey.hmacKey)
	copy(encodedSymKey[32:], symKey.encryptionKey)
	return encodedSymKey
}

func Decode(key []byte) (SymKey, error) {
	if len(key) != 64 {
		return SymKey{}, tracerr.Wrap(ErrorDecodeInvalidLength)
	}
	symKey := SymKey{
		encryptionKey: key[32:],
		hmacKey:       key[:32],
	}
	return symKey, nil
}

func aesEncrypt(iv []byte, encryptionKey []byte, plaintext []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)

	plainTextBytes := make([]byte, len(plaintext))
	copy(plainTextBytes, plaintext)
	plainTextBytes, err = pkcs7Pad(plainTextBytes, encrypter.BlockSize())

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	cipherText := make([]byte, len(plainTextBytes))
	encrypter.CryptBlocks(cipherText, plainTextBytes)

	return cipherText, nil
}

func aesDecrypt(iv []byte, encryptionKey []byte, cipherText []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plainTextBytes := make([]byte, len(cipherText))

	decrypter.CryptBlocks(plainTextBytes, cipherText)

	plainTextBytes, err = pkcs7Unpad(plainTextBytes, decrypter.BlockSize())

	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return plainTextBytes, nil
}

func calculateHMAC(key []byte, message []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)

	macRes := mac.Sum(nil)

	return macRes, nil
}

// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, tracerr.Wrap(ErrorPadInvalidBlockLen.AddDetails(fmt.Sprintf("%d", blocklen)))
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, tracerr.Wrap(ErrorUnpadInvalidBlockLen.AddDetails(fmt.Sprintf("%d", blocklen)))
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, tracerr.Wrap(ErrorUnpadInvalidDataLen.AddDetails(fmt.Sprintf("%d", len(data))))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, tracerr.Wrap(ErrorUnpadInvalidPadLen)
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, tracerr.Wrap(ErrorUnpadInvalidPad)
		}
	}

	return data[:len(data)-padlen], nil
}

func (symKey *SymKey) Encrypt(plaintext []byte) ([]byte, error) {
	if len(symKey.hmacKey) != 32 || len(symKey.encryptionKey) != 32 {
		return nil, tracerr.Wrap(ErrorEncryptInvalidKeySize)
	}
	iv, err := utils.GenerateRandomBytes(16)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	cipherText, err := aesEncrypt(iv, symKey.encryptionKey, plaintext)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	toMac := make([]byte, 16+len(cipherText))
	copy(toMac[:], iv)
	copy(toMac[16:], cipherText)

	mac, err := calculateHMAC(symKey.hmacKey, toMac)

	res := append([]byte{}, iv...)
	res = append(res, cipherText...)
	res = append(res, mac...)

	return res, nil
}

func (symKey *SymKey) Decrypt(encryptedMessage []byte) ([]byte, error) {
	if len(symKey.hmacKey) != 32 || len(symKey.encryptionKey) != 32 {
		return nil, tracerr.Wrap(ErrorDecryptInvalidKeySize)
	}
	cipherTextLength := len(encryptedMessage) - 16 - 32
	if cipherTextLength < 0 {
		return nil, tracerr.Wrap(ErrorDecryptCipherTooShort)
	}

	iv := encryptedMessage[:16]
	cipherText := encryptedMessage[16 : len(encryptedMessage)-32]
	mac := encryptedMessage[len(encryptedMessage)-32:]

	toMac := make([]byte, 16+len(cipherText))
	copy(toMac[:], iv)
	copy(toMac[16:], cipherText)

	calculatedMac, err := calculateHMAC(symKey.hmacKey, toMac)

	if !hmac.Equal(mac, calculatedMac) {
		return nil, tracerr.Wrap(ErrorDecryptMacMismatch)
	}

	plainText, err := aesDecrypt(iv, symKey.encryptionKey, cipherText)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return plainText, nil
}
