package ssks_password

import (
	"encoding/hex"
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/utils"
	"golang.org/x/crypto/scrypt"
	"regexp"
)

var (
	// ErrorInvalidRawStorageKeyFormat is returned when the rawStorageKey have an invalid format
	ErrorInvalidRawStorageKeyFormat = utils.NewSealdError("SSKSPASSWORD_INVALID_RAW_STORAGE_KEY_FORMAT", "invalid rawStorageKey format")
)

func deriveSecret(appId string, userId string, password string) (string, error) {
	salt := utils.NormalizeString(fmt.Sprintf("seald-ssks-secret|%s|%s", appId, userId))
	N := 16384
	r := 8
	p := 1
	bytes, err := scrypt.Key(utils.NormalizeString(password), salt, N, r, p, 64)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return hex.EncodeToString(bytes), nil
}

func deriveKey(appId string, userId string, password string, salt []byte) ([]byte, error) {
	fullSalt := append([]byte{}, salt...)
	fullSalt = append(fullSalt, utils.NormalizeString(fmt.Sprintf("seald-ssks-encryption|%s|%s", appId, userId))...)
	N := 16384
	r := 8
	p := 1
	bytes, err := scrypt.Key(utils.NormalizeString(password), fullSalt, N, r, p, 64)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return bytes, nil
}
func checkRawStorageKeyFormat(rawStorageKey string) error {
	re := regexp.MustCompile(`[A-Za-z0-9+/=-_@.]{1,256}`)
	if !re.MatchString(rawStorageKey) {
		return tracerr.Wrap(ErrorInvalidRawStorageKeyFormat)
	}
	return nil
}
