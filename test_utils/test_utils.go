package test_utils

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/utils"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const DatabaseEncryptionKeyB64 = "V4olGDOE5bAWNa9HDCvOACvZ59hUSUdKmpuZNyl1eJQnWKs5/l+PGnKUv4mKjivL3BtU014uRAIF2sOl83o6vQ"

var (
	ErrorSyntheticTestError = utils.NewSealdError("SYNTHETIC_TEST_ERROR", "Synthetic test error")
)

func SyntheticErrorCallback(_ any) ([]byte, error) {
	return nil, tracerr.Wrap(ErrorSyntheticTestError)
}

func GetDBPath(dbName string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	dbPath := filepath.Join(wd, "test_output", dbName)
	return dbPath, nil
}

type Credentials struct {
	ApiUrl                string `json:"api_url"`
	AppId                 string `json:"app_id"`
	DomainValidationKeyId string `json:"domain_validation_key_id"`
	DomainValidationKey   string `json:"domain_validation_key"`
	JWTSharedSecretId     string `json:"jwt_shared_secret_id"`
	JWTSharedSecret       string `json:"jwt_shared_secret"`
	DebugApiSecret        string `json:"debug_api_secret"`
	SsksUrl               string `json:"ssks_url"`
	SsksBackendAppKey     string `json:"ssks_backend_app_key"`
	SsksTMRChallenge      string `json:"ssks_tmr_challenge"`
}

func GetCredentials() (*Credentials, error) {
	credentialsFile := filepath.Join(GetCurrentPath(), "../test_credentials.json")

	content, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	var credentials Credentials
	err = json.Unmarshal(content, &credentials)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &credentials, nil
}

type JWTPermissionScopes int

const (
	PermissionAll                    JWTPermissionScopes = iota - 1
	PermissionAnonymousCreateMessage JWTPermissionScopes = 0
	PermissionAnonymousFindKeys      JWTPermissionScopes = 1
	PermissionAnonymousFindSigchain  JWTPermissionScopes = 2
	PermissionJoinTeam               JWTPermissionScopes = 3
	PermissionAddConnector           JWTPermissionScopes = 4
)

type ConnectorAdd struct {
	Value string                      `json:"value,omitempty"`
	Type  common_models.ConnectorType `json:"type,omitempty"`
}

type TMRRecipient struct {
	Value string `json:"auth_factor_value"`
	Type  string `json:"auth_factor_type"`
}

type Claims struct {
	Recipients    []string
	TmrRecipients []TMRRecipient
	Owner         string
	JoinTeam      bool
	ConnectorAdd  ConnectorAdd
	Scopes        []JWTPermissionScopes
}

func GetJWT(claims Claims) (string, error) {
	credentials, err := GetCredentials()
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	customClaims := jwt.MapClaims{
		"join_team": claims.JoinTeam,
		"iss":       credentials.JWTSharedSecretId,
		"iat":       time.Now().Unix(),
	}

	if claims.Recipients != nil {
		customClaims["recipients"] = claims.Recipients
	}
	if claims.TmrRecipients != nil {
		customClaims["tmr_recipients"] = claims.TmrRecipients
	}
	if claims.Owner != "" {
		customClaims["owner"] = claims.Owner
	}
	if claims.Scopes != nil {
		customClaims["scopes"] = claims.Scopes
	}
	if claims.ConnectorAdd.Value != "" {
		customClaims["connector_add"] = claims.ConnectorAdd
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)
	signedToken, err := token.SignedString([]byte(credentials.JWTSharedSecret))
	return signedToken, tracerr.Wrap(err)
}

func GetCurrentPath() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}

var testDirsNames sync.Map

func GetTestName(t testing.TB) string {
	loadedValue, _ := testDirsNames.LoadOrStore(t.Name(), 0)
	value := loadedValue.(int)
	name := fmt.Sprintf("%s_%d", t.Name(), value)
	testDirsNames.Store(t.Name(), value+1)
	return name
}

func GetRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic("Error generating random in GetRandomString:" + err.Error())
	}
	str := hex.EncodeToString(b)
	return str[0:length]
}
