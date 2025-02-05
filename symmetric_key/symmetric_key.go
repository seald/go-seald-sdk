package symmetric_key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"hash"
	"io"
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
	// ErrorInvalidKeySize is returned when the key has an invalid size
	ErrorInvalidKeySize = utils.NewSealdError("SYMKEY_INVALID_KEY_SIZE", "invalid key size")
	// ErrorDecryptCipherInvalid is returned when the ciphertext has invalid length (not full blocks)
	ErrorDecryptCipherInvalid = utils.NewSealdError("SYMKEY_DECRYPT_CIPHER_INVALID", "ciphertext is invalid")
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

	if len(cipherText)%decrypter.BlockSize() != 0 { // should never hit this, as the mac error should hit first
		return nil, tracerr.Wrap(ErrorDecryptCipherInvalid)
	}
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
		return nil, tracerr.Wrap(ErrorInvalidKeySize)
	}
	iv, err := utils.GenerateRandomBytes(16)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	cipherText, err := aesEncrypt(iv, symKey.encryptionKey, plaintext)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	res := append(iv, cipherText...)
	mac, err := calculateHMAC(symKey.hmacKey, res)

	res = append(res, mac...)

	return res, nil
}

type encryptReader struct {
	src       io.Reader
	symKey    *SymKey
	encrypter *cipher.BlockMode
	mac       *hash.Hash

	stateErr      error
	firstReadDone bool
	nReadDone     int
	nBytesRead    int
	finished      bool
	outputBuff    []byte
}

func (symKey *SymKey) EncryptReader(plaintextReader io.Reader) (io.Reader, error) {
	if len(symKey.hmacKey) != 32 || len(symKey.encryptionKey) != 32 {
		return nil, tracerr.Wrap(ErrorInvalidKeySize)
	}
	return &encryptReader{src: plaintextReader, symKey: symKey}, nil
}

func (r *encryptReader) Read(p []byte) (int, error) {
	r.nReadDone += 1
	if r.stateErr != nil {
		return 0, r.stateErr
	}

	if !r.firstReadDone {
		r.firstReadDone = true

		iv, err := utils.GenerateRandomBytes(16)
		if err != nil {
			r.stateErr = tracerr.Wrap(err)
			return 0, r.stateErr
		}

		aesCipher, err := aes.NewCipher(r.symKey.encryptionKey)
		if err != nil {
			r.stateErr = tracerr.Wrap(err)
			return 0, r.stateErr
		}
		encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
		r.encrypter = &encrypter

		mac := hmac.New(sha256.New, r.symKey.hmacKey)
		r.mac = &mac
		(*r.mac).Write(iv)

		if len(p) >= 16 {
			copy(p, iv)
			r.nBytesRead += 16
			return 16, nil
		} else {
			copy(p, iv[0:len(p)])
			r.outputBuff = append(r.outputBuff, iv[len(p):]...)
			r.nBytesRead += len(p)
			return len(p), nil
		}
	}

	writeOffset := 0
	if len(r.outputBuff) > 0 { // if we have some data in the output buffer, write it first
		if len(p) <= len(r.outputBuff) { // if the output buffer has more data than the current read asks for, output what is asked and return
			copy(p, r.outputBuff)
			r.outputBuff = r.outputBuff[len(p):]
			r.nBytesRead += len(p)
			return len(p), nil
		} else { // otherwise, start by writing the buffer to output, remember the offset, then continue
			copy(p, r.outputBuff)
			writeOffset = len(r.outputBuff)
			r.outputBuff = nil
			if r.finished { // if the stream is finished, no need to continue
				r.nBytesRead += writeOffset
				return writeOffset, nil
			}
		}
	}

	if r.finished {
		return 0, io.EOF
	}

	// determine how much we must read from source
	blockSize := (*r.encrypter).BlockSize()
	requiredBytes := len(p) - writeOffset
	requiredBlocks := requiredBytes / blockSize
	if requiredBytes%blockSize != 0 {
		requiredBlocks = requiredBlocks + 1
	}
	bytesToRead := requiredBlocks * blockSize

	inputBuff := make([]byte, bytesToRead)

	read, err := io.ReadFull(r.src, inputBuff)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) { // if input is finished, let's do the end  computations
			r.finished = true
			inputBuff = inputBuff[:read]
			// pad the remaining plaintext
			plainTextRemaining, err := pkcs7Pad(inputBuff, blockSize)
			if err != nil {
				r.stateErr = tracerr.Wrap(err)
				return 0, r.stateErr
			}
			// encrypt it
			cipherTextRemaining := make([]byte, len(plainTextRemaining))
			(*r.encrypter).CryptBlocks(cipherTextRemaining, plainTextRemaining)
			r.outputBuff = append(r.outputBuff, cipherTextRemaining...)
			// compute HMAC and append it
			(*r.mac).Write(cipherTextRemaining)
			r.outputBuff = append(r.outputBuff, (*r.mac).Sum(nil)...)
			// output what we can
			if len(r.outputBuff) <= requiredBytes { // if we have enough room to write the whole output, do it
				copy(p[writeOffset:], r.outputBuff)
				totalWritten := writeOffset + len(r.outputBuff)
				r.nBytesRead += totalWritten
				r.outputBuff = nil
				return totalWritten, nil
			} else { // otherwise, write what we can, and keep the rest for later
				copy(p[writeOffset:], r.outputBuff[:requiredBytes])
				r.outputBuff = r.outputBuff[requiredBytes:]
				r.nBytesRead += len(p)
				return len(p), nil
			}
		} else {
			r.stateErr = tracerr.Wrap(err)
			return 0, r.stateErr
		}
	}

	// we managed to read all we needed. Let's encrypt it
	cipherTextChunk := make([]byte, bytesToRead)
	(*r.encrypter).CryptBlocks(cipherTextChunk, inputBuff)
	(*r.mac).Write(cipherTextChunk)

	// copy what fits in the output, and keep the rest for next read
	copied := copy(p[writeOffset:], cipherTextChunk)
	r.outputBuff = cipherTextChunk[copied:]
	r.nBytesRead += len(p)
	return len(p), nil
}

func (symKey *SymKey) Decrypt(encryptedMessage []byte) ([]byte, error) {
	if len(symKey.hmacKey) != 32 || len(symKey.encryptionKey) != 32 {
		return nil, tracerr.Wrap(ErrorInvalidKeySize)
	}
	cipherTextLength := len(encryptedMessage) - 16 - 32
	if cipherTextLength < 0 {
		return nil, tracerr.Wrap(io.ErrUnexpectedEOF)
	}

	iv := encryptedMessage[:16]
	cipherText := encryptedMessage[16 : len(encryptedMessage)-32]
	toMac := encryptedMessage[:len(encryptedMessage)-32]
	mac := encryptedMessage[len(encryptedMessage)-32:]

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

type decryptReader struct {
	src       io.Reader
	symKey    *SymKey
	decrypter *cipher.BlockMode
	mac       *hash.Hash

	stateErr                  error
	firstReadDone             bool
	nReadDone                 int
	nBytesRead                int
	finished                  bool
	potentialLastBlockAndHmac []byte
	outputBuff                []byte
}

func (symKey *SymKey) DecryptReader(plaintextReader io.Reader) (io.Reader, error) {
	if len(symKey.hmacKey) != 32 || len(symKey.encryptionKey) != 32 {
		return nil, tracerr.Wrap(ErrorInvalidKeySize)
	}
	return &decryptReader{src: plaintextReader, symKey: symKey}, nil
}

func (r *decryptReader) Read(p []byte) (int, error) {
	r.nReadDone += 1
	if r.stateErr != nil {
		return 0, r.stateErr
	}

	if !r.firstReadDone {
		r.firstReadDone = true

		// Read IV (16 bytes)
		// Also, read 48 bytes for potential last bloc and hmac, so that the first "main" read is like all others
		// Combining the 2 in 1 read, to optimize
		ivAndPotentialLastBlockAndHmac := make([]byte, 64)
		_, err := io.ReadFull(r.src, ivAndPotentialLastBlockAndHmac)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				r.stateErr = tracerr.Wrap(io.ErrUnexpectedEOF)
				return 0, r.stateErr
			} else {
				r.stateErr = tracerr.Wrap(err)
				return 0, r.stateErr
			}
		}

		iv := ivAndPotentialLastBlockAndHmac[:16]
		r.potentialLastBlockAndHmac = ivAndPotentialLastBlockAndHmac[16:]

		// Initialize crypto objects
		aesCipher, err := aes.NewCipher(r.symKey.encryptionKey)
		if err != nil {
			r.stateErr = tracerr.Wrap(err)
			return 0, r.stateErr
		}
		decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
		r.decrypter = &decrypter

		mac := hmac.New(sha256.New, r.symKey.hmacKey)
		r.mac = &mac
		(*r.mac).Write(iv)
	}

	writeOffset := 0
	if len(r.outputBuff) > 0 { // if we have some data in the output buffer, write it first
		if len(p) <= len(r.outputBuff) { // if the output buffer has more data than the current read asks for, output what is asked and return
			copy(p, r.outputBuff)
			r.outputBuff = r.outputBuff[len(p):]
			r.nBytesRead += len(p)
			return len(p), nil
		} else { // otherwise, start by writing the buffer to output, remember the offset, then continue
			copy(p, r.outputBuff)
			writeOffset = len(r.outputBuff)
			r.outputBuff = nil
			if r.finished { // if the stream is finished, no need to continue
				r.nBytesRead += writeOffset
				return writeOffset, nil
			}
		}
	}

	if r.finished {
		return 0, io.EOF
	}

	// determine how much we must read from source
	blockSize := (*r.decrypter).BlockSize()
	requiredBytes := len(p) - writeOffset
	requiredBlocks := requiredBytes / blockSize
	if requiredBytes%blockSize != 0 {
		requiredBlocks = requiredBlocks + 1
	}
	bytesToRead := requiredBlocks * blockSize

	inputBuff := make([]byte, bytesToRead+48) // add 48 to put potentialLastBlockAndHmac at the start
	copy(inputBuff, r.potentialLastBlockAndHmac)

	read, err := io.ReadFull(r.src, inputBuff[48:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) { // if input is finished, let's do the end  computations
			r.finished = true
			inputBuff = inputBuff[:read+48]
			macBuff := inputBuff[read+16:]
			cipherTextRemaining := inputBuff[:read+16]

			// Now that we have all the remaining cipherText, compute HMAC and verify it
			(*r.mac).Write(cipherTextRemaining)
			macRes := (*r.mac).Sum(nil)
			if !hmac.Equal(macBuff, macRes) {
				r.stateErr = tracerr.Wrap(ErrorDecryptMacMismatch)
				return 0, r.stateErr
			}

			// Decrypt & unpad remaining ciphertext
			decipheredChunk := make([]byte, read+16)
			(*r.decrypter).CryptBlocks(decipheredChunk, cipherTextRemaining)
			plainTextRemaining, err := pkcs7Unpad(decipheredChunk, blockSize)
			if err != nil {
				r.stateErr = tracerr.Wrap(err)
				return 0, r.stateErr
			}
			r.outputBuff = append(r.outputBuff, plainTextRemaining...)
			// output what we can
			if len(r.outputBuff) <= requiredBytes { // if we have enough room to write the whole output, do it
				copy(p[writeOffset:], r.outputBuff)
				totalWritten := writeOffset + len(r.outputBuff)
				r.nBytesRead += totalWritten
				r.outputBuff = nil
				return totalWritten, nil
			} else { // otherwise, write what we can, and keep the rest for later
				copy(p[writeOffset:], r.outputBuff[:requiredBytes])
				r.outputBuff = r.outputBuff[requiredBytes:]
				r.nBytesRead += len(p)
				return len(p), nil
			}
		} else {
			r.stateErr = tracerr.Wrap(err)
			return 0, r.stateErr
		}
	}

	// we managed to read all we needed. Let's keep the last 48 bytes as potential last block & HMAC, and decrypt the rest
	r.potentialLastBlockAndHmac = inputBuff[bytesToRead:]
	cipherText := inputBuff[:bytesToRead]
	(*r.mac).Write(cipherText)
	decipheredChunk := make([]byte, bytesToRead)
	(*r.decrypter).CryptBlocks(decipheredChunk, cipherText)

	// copy what fits in the output, and keep the rest for next read
	copied := copy(p[writeOffset:], decipheredChunk)
	r.outputBuff = decipheredChunk[copied:]
	r.nBytesRead += len(p)
	return len(p), nil
}
