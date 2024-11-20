package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/ztrue/tracerr"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/exp/constraints"
	"golang.org/x/text/unicode/norm"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	// ErrorInvalidJWT is returned when the given JWT is invalid
	ErrorInvalidJWT = NewSealdError("INVALID_JWT", "invalid JWT")
	// ErrorInvalidAuthChallenge is returned when the given authentication challenge is invalid
	ErrorInvalidAuthChallenge = NewSealdError("INVALID_AUTH_CHALLENGE", "invalid auth challenge")
	// ErrorInvalidUUID is returned when a UUID is invalid
	ErrorInvalidUUID = NewSealdError("INVALID_UUID", "invalid UUID")
	// ErrorInvalidUUIDSlice is returned when the given slice of UUID include an invalid UUID
	ErrorInvalidUUIDSlice = NewSealdError("INVALID_UUID_SLICE", "invalid UUID in slice")
	// ErrorNotUnique is returned when items in a slice are not unique.
	ErrorNotUnique = NewSealdError("NOT_UNIQUE", "not unique")
	// ErrorInvalidAuthFactorType is returned when an authentication factor has an invalid type
	ErrorInvalidAuthFactorType     = NewSealdError("INVALID_AUTH_FACTOR_TYPE", "authentication factor type must be 'EM' or 'SMS'")
	ErrorInvalidAuthFactorValueEM  = NewSealdError("INVALID_AUTH_FACTOR_VALUE_EM", "Invalid authentication factor value. It must be a valid email address.")
	ErrorInvalidAuthFactorValueSMS = NewSealdError("INVALID_AUTH_FACTOR_VALUE_SMS", "Invalid authentication factor value. Cannot parse phone number.")
)

var (
	UUIDRegexp               = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	b64UUIDRegexp            = regexp.MustCompile(`^[A-Za-z0-9%+]{22}$`)
	validJWTRegexp           = regexp.MustCompile("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*$") // it's in URL base64 _-
	validAuthChallengeRegexp = regexp.MustCompile("^BEARD-AUTH-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
	emailRegexp              = regexp.MustCompile("^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]{2,}$")
	phoneRegexp              = regexp.MustCompile("^\\+[0-9]+$")
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return b, nil
}

func B64toS64(str string) string {
	return strings.Replace(strings.Replace(str, "/", "%", -1), "=", "", -1)
}

func S64toB64(str string) string {
	return strings.Replace(str, "%", "/", -1) + strings.Repeat("=", (4-(len(str)%4))%4)
}

func IsUUID(uuid string) bool {
	return UUIDRegexp.MatchString(uuid)
}

func CheckUUID(uuid string) error {
	if IsUUID(uuid) {
		return nil
	}
	return tracerr.Wrap(ErrorInvalidUUID.AddDetails(uuid))
}

func CheckUUIDSlice(uuids []string) error {
	for _, uuid := range uuids {
		if !IsUUID(uuid) {
			return tracerr.Wrap(ErrorInvalidUUIDSlice.AddDetails(uuid))
		}
	}
	return nil
}
func IsEmail(email string) bool {
	lowerCaseEmail := strings.ToLower(email)
	return emailRegexp.MatchString(lowerCaseEmail)
}

func CheckAuthFactor(af *common_models.AuthFactor) error {
	if af.Type == "EM" {
		if IsEmail(af.Value) {
			return nil
		}
		return tracerr.Wrap(ErrorInvalidAuthFactorValueEM.AddDetails(af.Value))
	}
	if af.Type == "SMS" {
		if phoneRegexp.MatchString(af.Value) {
			return nil

		}
		return tracerr.Wrap(ErrorInvalidAuthFactorValueSMS.AddDetails(af.Value))
	}
	return tracerr.Wrap(ErrorInvalidAuthFactorType.AddDetails(af.Type))
}

func IsB64UUID(uuid string) bool {
	return b64UUIDRegexp.MatchString(uuid)
}

func B64UUID(uuid string) (string, error) {
	uuid = strings.ToLower(uuid)
	if !IsUUID(uuid) {
		return "", tracerr.Wrap(ErrorInvalidUUID)
	}
	uuid = strings.Replace(uuid, "-", "", -1)
	bytes, err := hex.DecodeString(uuid)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	b64ID := base64.StdEncoding.EncodeToString(bytes)
	return B64toS64(b64ID), nil
}

func UnB64UUID(id string) (string, error) {
	if !IsB64UUID(id) {
		return "", tracerr.Wrap(ErrorInvalidUUID)
	}
	id = S64toB64(id)
	bytes, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	hexID := hex.EncodeToString(bytes)
	uuid := hexID[0:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:]
	if !IsUUID(uuid) {
		return "", tracerr.Wrap(ErrorInvalidUUID)
	}
	return uuid, nil
}

func GenerateRandomNonce() (string, error) {
	rawNonce := make([]byte, 32)
	_, err := rand.Read(rawNonce)
	if err != nil { // Note that err == nil only if we read the requested number of bytes
		return "", tracerr.Wrap(err)
	}
	return hex.EncodeToString(rawNonce), nil // 32 bytes encoded in hex is 64 chars
}

func GenerateUserLicenseToken(nonce string, userId string, appId string, validationKey string, validationKeyId string) (string, error) {
	N := 16384
	r := 8
	p := 1
	tokenBytes, err := scrypt.Key(
		[]byte(userId+"@"+appId+"-"+validationKey),
		[]byte(nonce),
		N, r, p, 64,
	)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	token := hex.EncodeToString(tokenBytes)
	userLicenseToken := validationKeyId + ":" + nonce + ":" + token
	return userLicenseToken, nil
}

// Set implements three methods: Add, Remove & Has.
// It needs to be defined with a comparable generic type such as int or string.
// The len operator can be used on Set.
// Internally a Set represents the presence of an element with a map of struct{}{} for efficiency, as explained here:
// https://itnext.io/set-in-go-map-bool-and-map-struct-performance-comparison-5315b4b107b.
type Set[T comparable] map[T]struct{}

// Add adds the given element to the Set.
func (s Set[T]) Add(element T) {
	s[element] = struct{}{}
}

// Remove removes given element from Set. If element is not in Set, Remove is a no-op.
func (s Set[T]) Remove(element T) {
	delete(s, element)
}

// Has checks if element is in Set, and returns true or false.
func (s Set[T]) Has(element T) bool {
	_, ok := s[element]
	return ok
}

func SliceSameMembers[T comparable](s1 []T, s2 []T) bool {
	// if length is different, fail fast
	if len(s1) != len(s2) {
		return false
	}
	// make a copy of the slice, so we can modify it later without changing our input
	s2_ := make([]T, len(s2))
	copy(s2_, s2)

	for _, e1 := range s1 {
		found := -1
		for i2, e2 := range s2_ {
			if e2 == e1 {
				found = i2
				break
			}
		}
		if found == -1 {
			// if we have no match, return false
			return false
		} else {
			// if we have a match, remove the item from s2_ (without keeping items order, because we don't care)
			// so that it cannot match another item from s1
			s2_[found] = s2_[len(s2_)-1]
			s2_ = s2_[:len(s2_)-1]
		}
	}
	return true
}

func SliceMap[T interface{}, U interface{}](s []T, f func(T) U) []U {
	output := make([]U, len(s))
	for i, e := range s {
		output[i] = f(e)
	}
	return output
}

func SliceIncludes[T comparable](s []T, u T) bool {
	for _, e := range s {
		if e == u {
			return true
		}
	}
	return false
}

func ChunkSlice[T any](slice []T, chunkSize int) [][]T {
	var chunks [][]T
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func UniqueSlice[T comparable](slice []T) []T {
	uniqueMap := make(map[T]any)
	for _, el := range slice {
		uniqueMap[el] = nil
	}

	var uniqueSlice []T
	for key := range uniqueMap {
		uniqueSlice = append(uniqueSlice, key)
	}

	return uniqueSlice
}

func CheckSliceUnique[T comparable](slice []T) error {
	for xi, x := range slice {
		for _, y := range slice[xi+1:] {
			if x == y {
				return ErrorNotUnique.AddDetails(fmt.Sprint(x))
			}
		}
	}
	return nil
}

func NormalizeString(s string) []byte {
	return norm.NFKC.Bytes([]byte(s))
}

type PreValidationToken struct {
	DomainValidationKeyId string `json:"domain_validation_key_id"`
	Nonce                 string `json:"nonce"`
	Token                 string `json:"token"`
}

func GeneratePreValidationToken(connectorValue string, domainValidationKey string, domainValidationKeyId string) (*PreValidationToken, error) {
	nonce, err := GenerateRandomNonce()
	N := 16384
	r := 8
	p := 1

	bytes, err := scrypt.Key(
		NormalizeString(fmt.Sprintf("%s-%s", connectorValue, domainValidationKey)),
		NormalizeString(nonce), N, r, p, 64)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &PreValidationToken{
		DomainValidationKeyId: domainValidationKeyId,
		Nonce:                 nonce,
		Token:                 hex.EncodeToString(bytes),
	}, nil
}

func CheckValidJWT(jwt string) error {
	if validJWTRegexp.MatchString(jwt) {
		return nil
	}
	return tracerr.Wrap(ErrorInvalidJWT.AddDetails(jwt))
}

func CheckValidAuthChallenge(challenge string) error {
	if validAuthChallengeRegexp.MatchString(challenge) {
		return nil
	}
	return tracerr.Wrap(ErrorInvalidAuthChallenge.AddDetails(challenge))
}

func Min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

type MutexGroup struct {
	internalMap     map[string]*sync.Mutex
	internalMapLock sync.RWMutex
	globalLock      sync.Mutex
}

func (group *MutexGroup) getLock(key string, createIfNecessary bool) *sync.Mutex {
	group.internalMapLock.RLock()
	lock := group.internalMap[key]
	group.internalMapLock.RUnlock()
	if lock == nil {
		if !createIfNecessary {
			panic("Trying to unlock a lock which does not exist")
			return nil
		}
		group.internalMapLock.Lock()
		// maybe another goroutine created it before we acquired the global write lock?
		lock = group.internalMap[key]
		if lock == nil {
			lock = &sync.Mutex{}
			if group.internalMap == nil {
				group.internalMap = make(map[string]*sync.Mutex)
			}
			group.internalMap[key] = lock
		}
		group.internalMapLock.Unlock()
	}
	return lock
}

func (group *MutexGroup) getKeys() []string {
	keys := make([]string, 0, len(group.internalMap))
	for key, _ := range group.internalMap {
		keys = append(keys, key)
	}
	return keys
}

func (group *MutexGroup) Lock(key string) {
	group.getLock(key, true).Lock()
}

func (group *MutexGroup) Unlock(key string) {
	group.getLock(key, false).Unlock()
}

func (group *MutexGroup) LockMultiple(keys []string) {
	var keys_ sort.StringSlice // making a copy before sorting, to avoid modifying the underlying array in place
	copy(keys_, keys)
	keys_.Sort() // Sorting here to avoid deadlocks
	for _, key := range keys {
		group.Lock(key)
	}
}

func (group *MutexGroup) UnlockMultiple(keys []string) {
	// Sorting here is not necessary
	for _, key := range keys {
		group.Unlock(key)
	}
}

func (group *MutexGroup) LockAll() {
	group.internalMapLock.RLock()
	group.LockMultiple(group.getKeys())
	group.globalLock.Lock()
}

func (group *MutexGroup) UnlockAll() {
	group.UnlockMultiple(group.getKeys())
	group.internalMapLock.RUnlock()
	group.globalLock.Unlock()
}

// Base64DecodeString decodes a Base64-encoded string, handling both
// padded and non-padded input, as well as new-lines.
func Base64DecodeString(s string) ([]byte, error) {
	if strings.Contains(s, "=") {
		return base64.StdEncoding.DecodeString(s)
	} else {
		return base64.RawStdEncoding.DecodeString(s)
	}
}

// Ternary is a helper function to inline ternary operations
func Ternary[T any](condition bool, valTrue T, valFalse T) T {
	if condition {
		return valTrue
	}
	return valFalse
}
