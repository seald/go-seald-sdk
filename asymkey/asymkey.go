package asymkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"golang.org/x/text/encoding/charmap"
	"hash/crc32"
)

var (
	// ErrorPrivateKeyDecodeUnknownKeyType is returned when a decoded private key is of an invalid type
	ErrorPrivateKeyDecodeUnknownKeyType = utils.NewSealdError("ASYMKEY_PRIVATE_KEY_DECODE_UNKNOWN_KEY_TYPE", "PrivateKeyDecode: unknown key type")
	// ErrorGenerateInvalidSize is returned when an invalid key size is given at key generation
	ErrorGenerateInvalidSize = utils.NewSealdError("ASYMKEY_GENERATE_INVALID_SIZE", "Cannot generate a Private Key of given bit length. Acceptable values are 1024, 2049 and 4096")
	// ErrorUnmarshalBSONValueTooShort is returned when trying to unmarshal a bson that is too short
	ErrorUnmarshalBSONValueTooShort = utils.NewSealdError("ASYMKEY_UNMARSHALL_BSON_VALUE_TOO_SHORT", "Cannot unmarshal, not enough bytes")
	// ErrorUnmarshalBSONValueInvalidType is returned when trying to unmarshal a bson that is not a string
	ErrorUnmarshalBSONValueInvalidType = utils.NewSealdError("ASYMKEY_UNMARSHALL_BSON_VALUE_INVALID_TYPE", "Cannot unmarshal, type is not String")
	// ErrorDecryptCryptoRSA is returned when an error happen during decryption
	ErrorDecryptCryptoRSA = utils.NewSealdError("ASYMKEY_DECRYPT_CRYPTO_ERROR", "Cannot decrypt")
	// ErrorPublicKeyDecodeUnknownKeyType is returned when a decoded public key is of an invalid type
	ErrorPublicKeyDecodeUnknownKeyType = utils.NewSealdError("ASYMKEY_PUBLIC_KEY_DECODE_UNKNOWN_KEY_TYPE", "PublicKeyDecode: unknown key type")
)

func calculateCRC32(message []byte) []byte {
	checksum := crc32.ChecksumIEEE(message)

	checksumBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(checksumBytes, checksum)

	return checksumBytes
}

type PrivateKey struct {
	key rsa.PrivateKey
}

type PublicKey struct {
	key rsa.PublicKey
}

func PrivateKeyDecode(key []byte) (*PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &PrivateKey{*k}, nil
	default:
		return nil, tracerr.Wrap(ErrorPrivateKeyDecodeUnknownKeyType.AddDetails(fmt.Sprintf("%T", privateKey)))
	}
}

func PrivateKeyDecodePKCS1DER(key []byte) (*PrivateKey, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &PrivateKey{*privateKey}, nil
}

func PrivateKeyFromB64(b64 string) (*PrivateKey, error) {
	pkcs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return PrivateKeyDecode(pkcs)
}

func Generate(bits int) (*PrivateKey, error) {
	if bits != 1024 && bits != 2048 && bits != 4096 {
		return nil, tracerr.Wrap(ErrorGenerateInvalidSize.AddDetails(fmt.Sprintf("%d is invalid", bits)))
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil { // cannot cover
		return nil, tracerr.Wrap(err)
	}
	return &PrivateKey{*privateKey}, nil
}

func (k *PrivateKey) Encode() []byte {
	b, err := x509.MarshalPKCS8PrivateKey(&k.key)
	if err != nil {
		// An error cannot happen for an RSA key, even if it isn't a valid RSA key
		// The only code paths that may lead to an error exist for other types of Private keys, which isn't possible
		// due to the typing.
		panic(err)
	}
	return b
}

func (k *PrivateKey) EncodePKCS1DER() []byte {
	return x509.MarshalPKCS1PrivateKey(&k.key)
}

func (k *PrivateKey) ToB64() string {
	b := k.Encode()
	return base64.StdEncoding.EncodeToString(b)
}

func (k *PrivateKey) MarshalJSON() ([]byte, error) {
	str := k.ToB64()
	return json.Marshal(str)
}

func (k *PrivateKey) UnmarshalJSON(b []byte) error {
	var data string
	err := json.Unmarshal(b, &data)
	if err != nil {
		return tracerr.Wrap(err)
	}
	privateKey, err := PrivateKeyFromB64(data)
	if err != nil {
		return tracerr.Wrap(err)
	}
	k.key = privateKey.key
	return nil
}

func (k *PrivateKey) MarshalBSONValue() (bsontype.Type, []byte, error) {
	b := k.Encode()
	bu, e := charmap.ISO8859_1.NewDecoder().Bytes(b)

	if e != nil { // cannot cover
		return bsontype.String, nil, tracerr.Wrap(e)
	}

	t, bm, e := bson.MarshalValue(string(bu))
	return t, bm, e
}

func (k *PrivateKey) UnmarshalBSONValue(t bsontype.Type, bu []byte) error {
	if t != bsontype.String {
		return tracerr.Wrap(ErrorUnmarshalBSONValueInvalidType)
	}
	str, _, ok := bsoncore.ReadString(bu)
	if !ok {
		return tracerr.Wrap(ErrorUnmarshalBSONValueTooShort)
	}
	b, err := charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))

	if err != nil { // cannot cover
		return tracerr.Wrap(err)
	}
	privateKey, err := PrivateKeyDecode(b)
	if err != nil {
		return tracerr.Wrap(err)
	}
	k.key = privateKey.key
	return nil
}

func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{k.key.PublicKey}
}

func (k *PrivateKey) Decrypt(encryptedMessage []byte) ([]byte, error) {
	decryptedMessage, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &k.key, encryptedMessage, nil)
	if err != nil {
		return nil, tracerr.Wrap(ErrorDecryptCryptoRSA.AddDetails(err.Error()))
	}
	checksumBytes := make([]byte, 4)
	if len(decryptedMessage) < 4 {
		return nil, tracerr.Wrap(ErrorDecryptCryptoRSA.AddDetails("cleartext is too short, cannot find crc32"))
	}
	message := make([]byte, len(decryptedMessage)-4)
	copy(checksumBytes, decryptedMessage[:4])
	copy(message, decryptedMessage[4:])

	checksumBytes2 := calculateCRC32(message)

	if subtle.ConstantTimeCompare(checksumBytes2, checksumBytes) != 1 {
		return nil, tracerr.Wrap(ErrorDecryptCryptoRSA.AddDetails("crc32 do not match"))
	}

	return message, nil
}

func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(message)
	signature, err := rsa.SignPSS(rand.Reader, &k.key, crypto.SHA256, hash.Sum(nil), nil)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return signature, nil
}

func PublicKeyDecode(key []byte) (*PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		return &PublicKey{*k}, nil
	default:
		return nil, tracerr.Wrap(ErrorPublicKeyDecodeUnknownKeyType.AddDetails(fmt.Sprintf("%T", publicKey)))
	}
}

func PublicKeyFromB64(b64 string) (*PublicKey, error) {
	pkcs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return PublicKeyDecode(pkcs)
}

func (k *PublicKey) Encode() []byte {
	b, err := x509.MarshalPKIXPublicKey(&k.key)
	if err != nil {
		// An error cannot happen for an RSA key, even if it isn't a valid RSA key
		// The only code paths that may lead to an error exist for other types of Private keys, which isn't possible
		// due to the typing.
		panic(err)
	}
	return b
}

func (k *PublicKey) ToB64() string {
	rawKey := k.Encode()
	return base64.StdEncoding.EncodeToString(rawKey)
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	b64 := k.ToB64()
	return json.Marshal(b64)
}

func (k *PublicKey) UnmarshalJSON(b []byte) error {
	var data string
	err := json.Unmarshal(b, &data)
	if err != nil {
		return tracerr.Wrap(err)
	}
	key, err := PublicKeyFromB64(data)
	if err != nil {
		return tracerr.Wrap(err)
	}
	k.key = key.key
	return nil
}

func (k *PublicKey) GetHash() string {
	rawKey := k.Encode()
	h := sha256.Sum256(rawKey)
	return base64.StdEncoding.EncodeToString(h[:])
}

func (k *PublicKey) Encrypt(message []byte) ([]byte, error) {
	checksumBytes := calculateCRC32(message)

	toEncrypt := append(checksumBytes, message...)

	encryptedMessage, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &k.key, toEncrypt, nil)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return encryptedMessage, nil
}

func (k *PublicKey) Verify(message, signature []byte) error {
	hash := sha256.New()
	hash.Write(message)
	return rsa.VerifyPSS(&k.key, crypto.SHA256, hash.Sum(nil), signature, nil)
}

func (k *PrivateKey) BitLen() int {
	return k.key.N.BitLen()
}

func (k *PublicKey) BitLen() int {
	return k.key.N.BitLen()
}
