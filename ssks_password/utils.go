package ssks_password

import (
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"regexp"
)

var (
	// ErrorInvalidRawStorageKeyFormat is returned when the rawStorageKey have an invalid format
	ErrorInvalidRawStorageKeyFormat = utils.NewSealdError("SSKSPASSWORD_INVALID_RAW_STORAGE_KEY_FORMAT", "invalid rawStorageKey format")
)

func checkRawStorageKeyFormat(rawStorageKey string) error {
	re := regexp.MustCompile(`[A-Za-z0-9+/=-_@.]{1,256}`)
	if !re.MatchString(rawStorageKey) {
		return tracerr.Wrap(ErrorInvalidRawStorageKeyFormat)
	}
	return nil
}
