package asymkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"os"
	"path/filepath"
	"testing"
)

// Known good RSA key (it's the one for the test sdk user)
const B64PrivateKey = "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"
const B64PrivateKeyLatin1String = "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"
const B64PrivateKeyPKCS1DER = "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"
const B64PublicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3opK11jeseUHYgJyTAgcMWZSrvD0EB4It3lcJ2mHljXjAy/IxzUbNsJujdOb5BCUXRhjHWXVm8OrS/I70o6k2RZb82wAHZjXqBzLQas78LI6fO8VIf7wLrYGC4X+chx/Kg2O+eJyjHJmNQD/6qayTLNJVQolyGoTTVB3L+wfEfFWDY+iBi2tjvpEyWjtrPHWcEea0hosFzthLd2lmAtomoxuJXJ7m+RRGBagOt8BnEgY34zHeBNLW0yH2melPo/5MPZ7lt2flC67C1JlttwWRlSRxpggDgoZv3FXXd6sLuHoiCFLbkejp8BLdpAHdGjVhDDKbAsUzLMcBLLIu74+kz/wCyNQR75opVQo8W0g0NxLG0pH4IOmOkFBvsNdwkhXcR8T4NILZEA5AvP+kScK89/0OjtvficPIEwjxuoZ7EVAV4P52OxqrRW+OPwzchFSQ/9s9OdRpo+41AKBskTkYYpNyMrOcpBxpJFXrlCE5SVfoZ7Job9ks9/6L/FDOsEBBApL1+XwpJTo5RwjTF2gh2bFc9oLx6zQ9riXxJ9ZPXj0Fv29gfsJQome7slzHW0xS50e7DZe4YAEw0Aqj9QV0ctZmaL7Lp6hwmTmh0fu1O5ZTU4UKX4aYrf+32F5BBCg3FwE3cksWHFaMGwAs7Psl9vEtT0dZUO0E2Ki4hpYJtECAwEAAQ=="
const PublicKeyHash = "jAxDFue28yKEiwzzdcVD88NEMLhMlH88QZfP0ZUz3V8="
const Message = "BEARTH_AUTH-5796203a-660e-41f0-9f33-45a944c3df45"
const MessageCRC32 = "2f6f4134"
const B64Signature = "E/iCSem7PiwH41Yb6V/wrCFpDKV29ucS1A//lShxgu1ocWuybZcdGGQRZJPI4ODQcMjkTriaJHbDg2KE8FWtullTL4dRpcZehJusaMwJ581qjVHYh5oOVW4hFKPG2Ijfa3RA90rCXzAHj98VCJRY16Awnh0bT4QpDMAJAHPiD5gr77vjdUpxSkbJcx1aeFUnqQsAV1GmKnzutf7f2EdsaJyCoN7z/KuIZf1Fax/UV6l4Ds2BnMUPH+PZbwuFnVZbypLVkjBIurA3XrIyZ44XOSXHh5D/R2g4kU86zIfo8ysMP/LZ8FshF5GJbfC0+ju2YAR4Ayge/r731Q3QIK1VtW4H1q/tH+zM479xTeiNTIPPhdMjAQ0jfaB9vreVCC0FEZsk0jpZJ0ZOwMoVjplMqi0P6oYb1ry6zPoyezrEmTO+ri06bUxXSsBROgrJVwMjiBiI/6X3QvDQUwkP53P13ueBOVj2BxSf3DNanp1P3ZmGjpgcdacboG2EFgdH8y/PEDRZ9O302yOfzqNpsxezdVn+HtDr2HXQTWl2UQTfbX0r3sj6pFTZ+gdzg/0pUOZKDft/Ou9/xUE3GteQEU6jsZjxPErqBldnnbvzIS0/6HaXUfV79n9FeEDLKPvsDRiWOowNk07115t+dmmAHTioW+D81iML7jVLLuNr2dE4fkI="
const EncryptedMessage = "aRV+yBK7o0952bie5r8M5qmv1llIlst/pc/M6r6huMdIZUd8DSMEZnat2xzuLqBeGuLod3cz3275gglGkrp8oJTaG2IZ8PYG4tsycumElHtMJFN8ZaouwA49qZuLaChg/2TcJN2ZYka/sNsfDtVQ2QYliXPqXcTNuvFfLwtMJPhxllBLydw8PlXkIOFqSj7TkJRM9DZOCdQNmr6DWsCaFRMmFibb8BPJUDFp+jZny9c0GWkDRxPJbLXeibRzvfBt3Ml0yWCKDtEXoSPPky3d5IFftKWepJacJnDcAYGPPo0Zr3hwrrw97Yn5/7FXelofMBIyaARKHAP09WxyFsYtri4386zP1LeRI5970vhVAQjoGc5U8/kdgaeUoD1VJH83BEKPLa+i04tEY/1uzZbHLx/vFcwlS9JrNfS/LqQXLwUbpME1dby3YRtJNev77QZZ7ra/ZtVJJdR5Ehk7iJH6hefrrunIy+v7aNK2WfouoyS9St9Uvtj4OtQfbng2Hp/arhO6al83Rsq+cTO5FBFprspHdbimFU8WCYzCfVZH3qIgkbXivJBflDyEqFnu2dqUIxlVRtdLofKgXr4xm1Ee9aTyaxCKV7ctzYAmOMmhMT0rpiA/+Ad5DffJMUaRfMrogxJu/W3tCG+k252WA018hLwSSxqr9kWrDCfcDG/l9DA="
const HexNullHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestAsymkey(t *testing.T) {
	publicKey, err := PublicKeyFromB64(B64PublicKey)
	assert.NoError(t, err)
	privateKey, err := PrivateKeyFromB64(B64PrivateKey)
	assert.NoError(t, err)
	var key4096 *PrivateKey

	t.Parallel()
	t.Run("PrivateKey", func(t *testing.T) {
		t.Run("Generate", func(t *testing.T) {
			t.Parallel()
			t.Run("Error at generate", func(t *testing.T) {
				_, err := Generate(-1)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorGenerateInvalidSize)
				}
			})
			t.Run("Generate 1024 bits", func(t *testing.T) {
				key, err := Generate(1024)
				assert.NoError(t, err)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, key.key.Size(), 128)
				assert.Equal(t, key.key.E, 65537)
				assert.Equal(t, key.BitLen(), 1024)
				assert.Equal(t, key.Public().BitLen(), 1024)
			})
			t.Run("Generate 2048 bits", func(t *testing.T) {
				key, err := Generate(2048)
				assert.NoError(t, err)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, key.key.Size(), 256)
				assert.Equal(t, key.key.E, 65537)
				assert.Equal(t, key.BitLen(), 2048)
				assert.Equal(t, key.Public().BitLen(), 2048)
			})
			t.Run("Generate 4096 bits", func(t *testing.T) {
				key, err := Generate(4096)
				assert.NoError(t, err)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, key.key.Size(), 512)
				assert.Equal(t, key.key.E, 65537)
				assert.Equal(t, key.BitLen(), 4096)
				assert.Equal(t, key.Public().BitLen(), 4096)
				key4096 = key // store it in external variable, so it can be later exported for JS
			})
		})

		t.Run("Encode / Decode", func(t *testing.T) {
			t.Parallel()

			t.Run("Encode private key", func(t *testing.T) {
				rawKey := privateKey.Encode()
				rawKeyReference, err := base64.StdEncoding.DecodeString(B64PrivateKey)
				assert.NoError(t, err)
				assert.Equal(t, rawKey, rawKeyReference)
			})

			t.Run("Decode private key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKey)
				require.NoError(t, err)
				key, err := PrivateKeyDecode(rawKey)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, 512, key.key.Size())
				assert.Equal(t, 65537, key.key.E)
			})

			t.Run("Decode invalid private key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKey)
				require.NoError(t, err)
				rawKey[0] = 0
				_, err = PrivateKeyDecode(rawKey)
				assert.EqualError(t, err, "asn1: structure error: tags don't match (16 vs {class:0 tag:0 length:2370 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs8 @4")
			})

			t.Run("Decode empty private key", func(t *testing.T) {
				_, err = PrivateKeyDecode([]byte{})
				assert.EqualError(t, err, "asn1: syntax error: sequence truncated")
			})

			t.Run("Decode ED25519 key instead of RSA", func(t *testing.T) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				b, err := x509.MarshalPKCS8PrivateKey(privKey)

				_, err = PrivateKeyDecode(b)
				assert.ErrorIs(t, err, ErrorPrivateKeyDecodeUnknownKeyType)
			})

			t.Run("Decode invalid base64", func(t *testing.T) {
				_, err := PrivateKeyFromB64("$" + B64PrivateKey)
				assert.EqualError(t, err, "illegal base64 data at input byte 0")
			})

			t.Run("EncodePKCS1DER private key", func(t *testing.T) {
				rawKey := privateKey.EncodePKCS1DER()
				rawKeyReference, err := base64.StdEncoding.DecodeString(B64PrivateKeyPKCS1DER)
				assert.NoError(t, err)
				assert.Equal(t, rawKey, rawKeyReference)
			})

			t.Run("DecodePKCS1DER private key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKeyPKCS1DER)
				require.NoError(t, err)
				key, err := PrivateKeyDecodePKCS1DER(rawKey)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, 512, key.key.Size())
				assert.Equal(t, 65537, key.key.E)
				assert.Equal(t, B64PrivateKey, key.ToB64())
			})

			t.Run("Decode PKCS1DER private key with normal decode", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKeyPKCS1DER)
				require.NoError(t, err)
				_, err = PrivateKeyDecode(rawKey)
				assert.EqualError(t, err, "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
			})

			t.Run("Decode normal private key with DecodePKCS1DER", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKey)
				require.NoError(t, err)
				_, err = PrivateKeyDecodePKCS1DER(rawKey)
				assert.EqualError(t, err, "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
			})

			t.Run("DecodePKCS1DER invalid private key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PrivateKeyPKCS1DER)
				require.NoError(t, err)
				rawKey[0] = 0
				_, err = PrivateKeyDecodePKCS1DER(rawKey)
				assert.EqualError(t, err, "asn1: structure error: tags don't match (16 vs {class:0 tag:0 length:2344 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs1PrivateKey @4")
			})

			t.Run("DecodePKCS1DER empty private key", func(t *testing.T) {
				_, err = PrivateKeyDecodePKCS1DER([]byte{})
				assert.EqualError(t, err, "asn1: syntax error: sequence truncated")
			})
		})

		t.Run("JSON", func(t *testing.T) {
			t.Parallel()
			t.Run("Marshal", func(t *testing.T) {
				m, err := json.Marshal(privateKey)
				assert.NoError(t, err)

				assert.Equal(t, "\""+B64PrivateKey+"\"", string(m))
			})

			t.Run("Unmarshal", func(t *testing.T) {
				var pKey PrivateKey
				err := json.Unmarshal([]byte("\""+B64PrivateKey+"\""), &pKey)

				assert.NoError(t, err)

				privateKeyExpected, err := PrivateKeyFromB64(B64PrivateKey)
				assert.NoError(t, err)

				assert.Equal(t, *privateKeyExpected, pKey)
			})

			t.Run("Unmarshal non string", func(t *testing.T) {
				var pKey PrivateKey
				err := json.Unmarshal([]byte("1"), &pKey)

				if assert.Error(t, err) {
					assert.EqualError(t, err, "json: cannot unmarshal number into Go value of type string")
				}
			})

			t.Run("Unmarshal non base64", func(t *testing.T) {
				var pKey PrivateKey
				err := json.Unmarshal([]byte("\"€\""), &pKey)

				if assert.Error(t, err) {
					assert.EqualError(t, err, "illegal base64 data at input byte 0")
				}
			})
		})

		t.Run("BSON", func(t *testing.T) {
			t.Parallel()
			t.Run("MarshalBSONValue", func(t *testing.T) {
				referenceBytes, err := base64.StdEncoding.DecodeString(B64PrivateKeyLatin1String)
				assert.NoError(t, err)
				referenceStr := string(referenceBytes)
				bsonType, b, err := privateKey.MarshalBSONValue()
				assert.NoError(t, err)
				assert.Equal(t, bsonType, bsontype.String)
				str, rem, couldFinish := bsoncore.ReadString(b)
				assert.True(t, couldFinish)
				assert.Equal(t, 0, len(rem))
				assert.Equal(t, referenceStr, str)
			})

			t.Run("UnmarshalBSONValue", func(t *testing.T) {
				referenceBytes, err := base64.StdEncoding.DecodeString(B64PrivateKeyLatin1String)
				assert.NoError(t, err)
				referenceStr := string(referenceBytes)
				referenceMarshalledString := bsoncore.AppendString([]byte{}, referenceStr)
				var key PrivateKey
				err = key.UnmarshalBSONValue(bsontype.String, referenceMarshalledString)
				assert.NoError(t, err)
				assert.NoError(t, key.key.Validate())
				assert.Equal(t, key.key.Size(), 512)
				assert.Equal(t, key.key.E, 65537)
			})

			t.Run("Invalid type for UnmarshalBSONValue", func(t *testing.T) {
				referenceBytes, err := base64.StdEncoding.DecodeString(B64PrivateKeyLatin1String)
				assert.NoError(t, err)
				referenceMarshalledBinary := bsoncore.AppendBinary([]byte{}, bsontype.BinaryGeneric, referenceBytes)
				var key PrivateKey
				err = key.UnmarshalBSONValue(bsontype.Binary, referenceMarshalledBinary)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorUnmarshalBSONValueInvalidType)
				}
			})

			t.Run("Truncated input for UnmarshalBSONValue", func(t *testing.T) {
				referenceBytes, err := base64.StdEncoding.DecodeString(B64PrivateKeyLatin1String)
				assert.NoError(t, err)
				referenceStr := string(referenceBytes)
				referenceMarshalledString := bsoncore.AppendString([]byte{}, referenceStr)
				var key PrivateKey
				err = key.UnmarshalBSONValue(bsontype.String, referenceMarshalledString[len(referenceMarshalledString)/2:])
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorUnmarshalBSONValueTooShort)
				}
			})

			t.Run("Invalid private key for UnmarshalBSONValue", func(t *testing.T) {
				referenceBytes, err := base64.StdEncoding.DecodeString(B64PrivateKeyLatin1String)
				assert.NoError(t, err)
				referenceBytes = append([]byte{0x00}, referenceBytes...)
				referenceStr := string(referenceBytes)
				referenceMarshalledString := bsoncore.AppendString([]byte{}, referenceStr)
				var key PrivateKey
				err = key.UnmarshalBSONValue(bsontype.String, referenceMarshalledString)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "asn1: structure error: tags don't match (16 vs {class:0 tag:0 length:48 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs8 @2")
				}
			})
		})

		t.Run("Public", func(t *testing.T) {
			t.Parallel()
			t.Run("Export public key", func(t *testing.T) {
				publicKey := privateKey.Public()
				assert.Equal(t, publicKey.key.E, privateKey.key.E)
				assert.Equal(t, publicKey.key.N, privateKey.key.N)
				assert.Equal(t, B64PublicKey, publicKey.ToB64())
			})
		})

		t.Run("Decryption", func(t *testing.T) {
			t.Parallel()
			cipherText, err := base64.StdEncoding.DecodeString(EncryptedMessage)
			assert.NoError(t, err)
			t.Run("Valid decryption", func(t *testing.T) {
				clearText, err := privateKey.Decrypt(cipherText)
				assert.NoError(t, err)
				assert.Equal(t, []byte(Message), clearText)
			})

			t.Run("Invalid CipherText", func(t *testing.T) {
				cipherText2 := make([]byte, len(cipherText))
				copy(cipherText2, cipherText)
				cipherText2[0] = 0
				_, err := privateKey.Decrypt(cipherText2)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "ASYMKEY_DECRYPT_CRYPTO_ERROR - Cannot decrypt : crypto/rsa: decryption error")
				}
			})
			t.Run("Invalid CRC32", func(t *testing.T) {
				clearMessage := []byte(Message)
				invalidClearText := make([]byte, len(clearMessage)+4)
				copy(invalidClearText[4:], clearMessage)
				cipherText2, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.Public().key, invalidClearText, nil)
				assert.NoError(t, err)
				_, err = privateKey.Decrypt(cipherText2)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorDecryptCryptoRSA)
				}
			})

			t.Run("Cleartext shorter than CRC32", func(t *testing.T) {
				invalidClearText := []byte{'L', 'O', 'L'}
				cipherText2, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.Public().key, invalidClearText, nil)
				assert.NoError(t, err)
				_, err = privateKey.Decrypt(cipherText2)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorDecryptCryptoRSA)
				}
			})

			t.Run("Empty message", func(t *testing.T) {
				invalidClearText := []byte{0, 0, 0, 0}
				cipherText2, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.Public().key, invalidClearText, nil)
				assert.NoError(t, err)
				message, err := privateKey.Decrypt(cipherText2)
				assert.NoError(t, err)
				assert.Equal(t, len(message), 0)
			})

			t.Run("Empty message with invalid CRC32", func(t *testing.T) {
				invalidClearText := []byte{0, 0, 0, 1}
				cipherText2, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.Public().key, invalidClearText, nil)
				assert.NoError(t, err)
				_, err = privateKey.Decrypt(cipherText2)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorDecryptCryptoRSA)
				}
			})
		})

		t.Run("Signature", func(t *testing.T) {
			t.Parallel()
			t.Run("Valid signature", func(t *testing.T) {
				signature, err := privateKey.Sign([]byte(Message))
				assert.NoError(t, err)
				hash := sha256.New()
				hash.Write([]byte(Message))
				err = rsa.VerifyPSS(&privateKey.Public().key, crypto.SHA256, hash.Sum(nil), signature, nil)
				assert.NoError(t, err)

				err = privateKey.Public().Verify([]byte(Message), signature)
				assert.NoError(t, err)
			})

			t.Run("Empty textToSign", func(t *testing.T) {
				signature, err := privateKey.Sign([]byte{})
				assert.NoError(t, err)
				nullHash, err := hex.DecodeString(HexNullHash)
				assert.NoError(t, err)
				err = rsa.VerifyPSS(&privateKey.Public().key, crypto.SHA256, nullHash, signature, nil)
				assert.NoError(t, err)

				err = privateKey.Public().Verify([]byte{}, signature)
				assert.NoError(t, err)
			})

			t.Run("TextToSign larger than key", func(t *testing.T) {
				largeTextToSign := make([]byte, privateKey.key.Size()*2)
				_, err := rand.Read(largeTextToSign)
				assert.NoError(t, err)
				signature, err := privateKey.Sign(largeTextToSign)
				hash := sha256.New()
				hash.Write(largeTextToSign)
				err = rsa.VerifyPSS(&privateKey.Public().key, crypto.SHA256, hash.Sum(nil), signature, nil)
				assert.NoError(t, err)

				err = privateKey.Public().Verify(largeTextToSign, signature)
				assert.NoError(t, err)
			})

			t.Run("Invalid private key", func(t *testing.T) {
				privateKey, err := PrivateKeyFromB64(B64PrivateKey)
				assert.NoError(t, err)
				privateKey.key.E = 0 // should break
				_, err = privateKey.Sign([]byte(Message))
				if assert.Error(t, err) {
					assert.ErrorContains(t, err, "rsa") // "rsa: internal error" vs "crypto/rsa: decryption error"
				}
			})
		})
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Run("Encode / Decode", func(t *testing.T) {
			t.Parallel()

			t.Run("Encode public key", func(t *testing.T) {
				rawKey := publicKey.Encode()
				rawKeyReference, err := base64.StdEncoding.DecodeString(B64PublicKey)
				assert.NoError(t, err)
				assert.Equal(t, rawKeyReference, rawKey)
			})

			t.Run("Decode public key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PublicKey)
				assert.NoError(t, err)
				key, err := PublicKeyDecode(rawKey)
				assert.Equal(t, 0, key.key.N.Cmp(privateKey.key.N))
				assert.Equal(t, key.key.Size(), 512)
				assert.Equal(t, key.key.E, 65537)
			})

			t.Run("Decode invalid public key", func(t *testing.T) {
				rawKey, err := base64.StdEncoding.DecodeString(B64PublicKey)
				assert.NoError(t, err)
				rawKey[0] = 0
				_, err = PublicKeyDecode(rawKey)
				t.Log(err)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "asn1: structure error: tags don't match (16 vs {class:0 tag:0 length:546 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} publicKeyInfo @4")
				}
			})

			t.Run("Decode empty public key", func(t *testing.T) {
				_, err := PublicKeyDecode([]byte{})
				t.Log(err)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "asn1: syntax error: sequence truncated")
				}
			})

			t.Run("Decode ED25519 key instead of RSA", func(t *testing.T) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				b, err := x509.MarshalPKIXPublicKey(privKey.Public())

				_, err = PublicKeyDecode(b)
				if assert.Error(t, err) {
					assert.ErrorIs(t, err, ErrorPublicKeyDecodeUnknownKeyType)
				}
			})

			t.Run("Decode invalid base64", func(t *testing.T) {
				_, err := PublicKeyFromB64("$" + B64PublicKey)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "illegal base64 data at input byte 0")
				}
			})
		})

		t.Run("JSON", func(t *testing.T) {
			t.Parallel()
			t.Run("Marshal", func(t *testing.T) {
				m, err := json.Marshal(publicKey)
				assert.NoError(t, err)

				assert.Equal(t, "\""+B64PublicKey+"\"", string(m))
			})

			t.Run("Unmarshal", func(t *testing.T) {
				var pKey PublicKey
				err := json.Unmarshal([]byte("\""+B64PublicKey+"\""), &pKey)

				assert.NoError(t, err)

				publicKeyExpected, err := PublicKeyFromB64(B64PublicKey)
				assert.NoError(t, err)

				assert.Equal(t, *publicKeyExpected, pKey)
			})

			t.Run("Unmarshal non string", func(t *testing.T) {
				var pKey PublicKey
				err := json.Unmarshal([]byte("1"), &pKey)

				if assert.Error(t, err) {
					assert.EqualError(t, err, "json: cannot unmarshal number into Go value of type string")
				}
			})

			t.Run("Unmarshal non base64", func(t *testing.T) {
				var pKey PublicKey
				err := json.Unmarshal([]byte("\"€\""), &pKey)

				if assert.Error(t, err) {
					assert.EqualError(t, err, "illegal base64 data at input byte 0")
				}
			})
		})

		t.Run("Hash", func(t *testing.T) {
			t.Parallel()
			t.Run("Get public key hash", func(t *testing.T) {
				hash := publicKey.GetHash()
				assert.Equal(t, PublicKeyHash, hash)
			})
		})

		t.Run("Encryption", func(t *testing.T) {
			t.Parallel()
			clearText := []byte(Message)

			t.Run("Valid encryption", func(t *testing.T) {
				cipherText, err := publicKey.Encrypt(clearText)
				assert.NoError(t, err)

				decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &privateKey.key, cipherText, nil)
				assert.NoError(t, err)
				if assert.Greater(t, len(decrypted), 4) {
					crc32 := decrypted[0:4]
					clear := decrypted[4:]
					assert.Equal(t, clearText, clear)
					assert.Equal(t, hex.EncodeToString(crc32), MessageCRC32)
				}

				res, err := privateKey.Decrypt(cipherText)
				assert.NoError(t, err)
				assert.Equal(t, clearText, res)
			})

			t.Run("Empty clearText", func(t *testing.T) {
				cipherText, err := publicKey.Encrypt([]byte{})
				assert.NoError(t, err)

				decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &privateKey.key, cipherText, nil)
				assert.NoError(t, err)

				assert.Equal(t, []byte{0, 0, 0, 0}, decrypted)

				res, err := privateKey.Decrypt(cipherText)
				assert.NoError(t, err)
				assert.Equal(t, []byte{}, res)
			})

			t.Run("Message larger than key", func(t *testing.T) {
				largeClearText := make([]byte, privateKey.key.Size()*2)
				_, err := rand.Read(largeClearText)
				assert.NoError(t, err)

				_, err = publicKey.Encrypt(largeClearText)
				if assert.Error(t, err) {
					assert.ErrorContains(t, err, "crypto/rsa: message too long for RSA") // different versions of Go have different error messages for this "RSA public key size" / "RSA key size"
				}
			})
		})

		t.Run("Signature verification", func(t *testing.T) {
			referenceSignature, err := base64.StdEncoding.DecodeString(B64Signature)
			assert.NoError(t, err)
			t.Parallel()
			t.Run("Valid signature", func(t *testing.T) {
				err := publicKey.Verify([]byte(Message), referenceSignature)
				assert.NoError(t, err)
			})

			t.Run("Signature mismatch", func(t *testing.T) {
				err := publicKey.Verify([]byte{0x00}, referenceSignature)
				if assert.Error(t, err) {
					assert.EqualError(t, err, "crypto/rsa: verification error")
				}
			})

			t.Run("Truncated signature", func(t *testing.T) {
				err := publicKey.Verify([]byte(Message), referenceSignature[len(referenceSignature)/2:])
				if assert.Error(t, err) {
					assert.EqualError(t, err, "crypto/rsa: verification error")
				}
			})

			t.Run("Empty signature", func(t *testing.T) {
				err := publicKey.Verify([]byte(Message), []byte{})
				if assert.Error(t, err) {
					assert.EqualError(t, err, "crypto/rsa: verification error")
				}
			})
		})
	})

	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/asymkey")

			// Can import private key from JS
			rawPrivateKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "private_key"))
			require.NoError(t, err)
			privateKeyFromJS, err := PrivateKeyFromB64(string(rawPrivateKey))
			require.NoError(t, err)

			// Can import public key from JS
			rawPublicKey, err := os.ReadFile(filepath.Join(testArtifactsDir, "public_key"))
			require.NoError(t, err)
			publicKeyFromJS, err := PublicKeyFromB64(string(rawPublicKey))
			require.NoError(t, err)

			// public key is as expected
			assert.Equal(t, publicKeyFromJS, privateKeyFromJS.Public())

			// B64 exports are identical
			assert.Equal(t, string(rawPrivateKey), privateKeyFromJS.ToB64())
			assert.Equal(t, string(rawPublicKey), publicKeyFromJS.ToB64())

			// Key hash is as expected
			keyHash, err := os.ReadFile(filepath.Join(testArtifactsDir, "key_hash"))
			require.NoError(t, err)
			assert.Equal(t, string(keyHash), publicKeyFromJS.GetHash())

			// Imported private key can decrypt data
			clearData, err := os.ReadFile(filepath.Join(testArtifactsDir, "clear_data"))
			require.NoError(t, err)
			encryptedData, err := os.ReadFile(filepath.Join(testArtifactsDir, "encrypted_data"))
			require.NoError(t, err)
			decryptedData, err := privateKeyFromJS.Decrypt(encryptedData)
			require.NoError(t, err)
			assert.Equal(t, clearData, decryptedData)

			// Imported public key can verify signature
			signature, err := os.ReadFile(filepath.Join(testArtifactsDir, "signature"))
			require.NoError(t, err)
			err = publicKeyFromJS.Verify(clearData, signature)
			assert.NoError(t, err)
		})
		t.Run("Export for JS", func(t *testing.T) {
			// make sure dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/asymkey")
			err = os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// write private key
			privateKeyB64 := key4096.ToB64()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "private_key"), []byte(privateKeyB64), 0o700)
			require.NoError(t, err)

			// write public key
			publicKeyB64 := key4096.Public().ToB64()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "public_key"), []byte(publicKeyB64), 0o700)
			require.NoError(t, err)

			// write key hash
			keyHash := key4096.Public().GetHash()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "key_hash"), []byte(keyHash), 0o700)
			require.NoError(t, err)

			// generate & write random clear data
			clearData, err := utils.GenerateRandomBytes(100)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "clear_data"), clearData, 0o700)
			require.NoError(t, err)

			// write encrypted data
			encryptedData, err := key4096.Public().Encrypt(clearData)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "encrypted_data"), encryptedData, 0o700)
			require.NoError(t, err)

			// write signature
			signature, err := key4096.Sign(clearData)
			err = os.WriteFile(filepath.Join(testArtifactsDir, "signature"), signature, 0o700)
			require.NoError(t, err)
		})
	})
}
