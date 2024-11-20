package ssks_password

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"io"
	"os"
	"time"
)

var (
	// ErrorCannotFindIdentity is returned when we couldn't find an identity with this id/password combination
	ErrorCannotFindIdentity = utils.NewSealdError("SSKSPASSWORD_CANNOT_FIND_IDENTITY", "ssks password cannot find identity with this id/password combination")
	// ErrorSaveIdentityPasswordNoPassword is returned when no user password was provided
	ErrorSaveIdentityPasswordNoPassword = utils.NewSealdError("SSKSPASSWORD_SAVE_IDENTITY_NO_PASSWORD", "user password was not provided at save")
	// ErrorRetrieveIdentityPasswordNoPassword is returned when no user password was provided
	ErrorRetrieveIdentityPasswordNoPassword = utils.NewSealdError("SSKSPASSWORD_RETRIEVE_IDENTITY_NO_PASSWORD", "user password was not provided at retrieve")
	// ErrorChangeIdentityNoPassword is returned when the user current password was not provided
	ErrorChangeIdentityNoPassword = utils.NewSealdError("SSKSPASSWORD_CHANGE_IDENTITY_NO_PASSWORD", "user current password was not provided")
	// ErrorChangeIdentityNoNewPassword is returned when the user new password was not provided
	ErrorChangeIdentityNoNewPassword = utils.NewSealdError("SSKSPASSWORD_CHANGE_IDENTITY_NO_NEW_PASSWORD", "user new password was not provided")
	// ErrorChangeIdentitySamePassword is returned when the new password is the same as the old one
	ErrorChangeIdentitySamePassword = utils.NewSealdError("SSKSPASSWORD_CHANGE_IDENTITY_SAME_PASSWORD", "new password cannot be the same as the current password")
	//ErrorInvalidB64 is returned when an internal process encounters invalid B64 unexpectedly
	ErrorInvalidB64 = utils.NewSealdError("SSKSPASSWORD_INVALID_B64", "invalid base64")
)

type PluginPassword struct {
	appId                 string
	ssksPasswordApiClient apiClientInterface
	Logger                zerolog.Logger
}

// PluginPasswordInitializeOptions is the main options object for initializing the PluginPassword instance.
type PluginPasswordInitializeOptions struct {
	// SsksURL is the SSKS server for this instance to use. This value is given on your Seald dashboard.
	SsksURL string
	// AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard.
	AppId string
	// LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. Use one of the zerolog level constants.
	LogLevel zerolog.Level
	// LogNoColor should be set to true if you want to disable colors in the log output.
	LogNoColor bool
	// InstanceName is an arbitrary name to give to this PluginPassword instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
	InstanceName string
	// Platform is a name that references the platform on which the PluginPassword is running ("go" / "ios" / "android" / "c" / "c-flutter" / ...)
	Platform string
	// LogWriter is the io.Writer to which to write the logs. Defaults to os.Stdout.
	LogWriter io.Writer
}

func NewPluginPassword(options *PluginPasswordInitializeOptions) *PluginPassword {
	if options.LogWriter == nil {
		options.LogWriter = os.Stdout
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	instanceLogger := zerolog.New(zerolog.ConsoleWriter{Out: options.LogWriter, TimeFormat: time.StampMilli, NoColor: options.LogNoColor}).With().Timestamp().Logger()
	instanceLogger = instanceLogger.Level(options.LogLevel)
	if options.InstanceName != "" {
		instanceLogger = instanceLogger.With().Str("instance", options.InstanceName).Logger()
	}

	instanceLogger.Debug().Msg("Initialize new PluginPassword instance...")
	instanceLogger.Trace().Interface("opts", options).Msg("PluginPassword Init options")

	apiLogger := instanceLogger.With().Str("component", "pluginPasswordApiClient").Logger()
	version_ := fmt.Sprintf("sdk-go-ssks-password/%s/%s", options.Platform, utils.Version)

	client := PluginPassword{
		ssksPasswordApiClient: &apiClient{
			ApiClient: *api_helper.NewApiClient(
				options.SsksURL,
				[]api_helper.Header{
					{Name: "X-SEALD-APPID", Value: options.AppId},
					{Name: "X-SEALD-VERSION", Value: version_},
				},
				apiLogger,
			),
		},
		appId:  options.AppId,
		Logger: instanceLogger,
	}
	return &client
}

// SaveIdentityFromPassword will save the given identity for the given userId, encrypted with the given password.
// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
func (pluginPassword *PluginPassword) SaveIdentityFromPassword(userId string, password string, identity []byte) (string, error) {
	if password == "" {
		return "", tracerr.Wrap(ErrorSaveIdentityPasswordNoPassword)
	}

	salt, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	secret, err := deriveSecret(pluginPassword.appId, userId, password)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	keyBuffer, err := deriveKey(pluginPassword.appId, userId, password, salt)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	symKey, err := symmetric_key.Decode(keyBuffer)
	encryptedIdentity, err := symKey.Encrypt(identity)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	saltAndData := append([]byte{}, salt...)
	saltAndData = append(saltAndData, encryptedIdentity...)
	encryptedB64Identity := base64.StdEncoding.EncodeToString(saltAndData)

	pushResult, err := pluginPassword.ssksPasswordApiClient.push(pluginPassword.appId, userId, encryptedB64Identity, secret)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return pushResult.Id, nil
}

// SaveIdentityFromRawKeys will save the given identity for the given userId, encrypted with the given raw keys.
// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
func (pluginPassword *PluginPassword) SaveIdentityFromRawKeys(userId string, rawStorageKey string, rawEncryptionKey []byte, identity []byte) (string, error) {
	err := checkRawStorageKeyFormat(rawStorageKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	symKey, err := symmetric_key.Decode(rawEncryptionKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptedIdentity, err := symKey.Encrypt(identity)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	encryptedB64Identity := base64.StdEncoding.EncodeToString(encryptedIdentity)

	pushResult, err := pluginPassword.ssksPasswordApiClient.push(pluginPassword.appId, userId, encryptedB64Identity, rawStorageKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return pushResult.Id, nil
}

// RetrieveIdentityFromPassword will retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
func (pluginPassword *PluginPassword) RetrieveIdentityFromPassword(userId string, password string) ([]byte, error) {
	if password == "" {
		return nil, tracerr.Wrap(ErrorRetrieveIdentityPasswordNoPassword)
	}

	secret, err := deriveSecret(pluginPassword.appId, userId, password)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	searchResult, err := pluginPassword.ssksPasswordApiClient.search(pluginPassword.appId, userId, secret)
	if err != nil {
		var apiError utils.APIError
		if errors.As(err, &apiError) && apiError.Status == 404 && apiError.Raw == "{\"model\":\"StrictUser\"}" {
			return nil, tracerr.Wrap(ErrorCannotFindIdentity)
		}
		return nil, tracerr.Wrap(err)
	}

	encryptedData, err := base64.StdEncoding.DecodeString(searchResult.EncryptedDataB64)
	if err != nil {
		return nil, tracerr.Wrap(ErrorInvalidB64.AddDetails(err.Error()))
	}
	salt := encryptedData[0:32]
	rawKey, err := deriveKey(pluginPassword.appId, userId, password, salt)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	symKey, err := symmetric_key.Decode(rawKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// this key should be the correct one, as the password was already correct when derived as secret
	clearData, err := symKey.Decrypt(encryptedData[32:])
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if len(clearData) == 0 {
		return nil, tracerr.Wrap(ErrorCannotFindIdentity)
	}
	return clearData, nil
}

// RetrieveIdentityFromRawKeys will retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
func (pluginPassword *PluginPassword) RetrieveIdentityFromRawKeys(userId string, rawStorageKey string, rawEncryptionKey []byte) ([]byte, error) {
	err := checkRawStorageKeyFormat(rawStorageKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	// Parse key before API call as it might fail.
	symKey, err := symmetric_key.Decode(rawEncryptionKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	searchResult, err := pluginPassword.ssksPasswordApiClient.search(pluginPassword.appId, userId, rawStorageKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedData, err := base64.StdEncoding.DecodeString(searchResult.EncryptedDataB64)
	if err != nil {
		return nil, tracerr.Wrap(ErrorInvalidB64.AddDetails(err.Error()))
	}

	clearData, err := symKey.Decrypt(encryptedData)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if len(clearData) == 0 {
		return nil, tracerr.Wrap(ErrorCannotFindIdentity)
	}
	return clearData, nil
}

// ChangeIdentityPassword will change the password used to encrypt the identity for the userId.
// Returns the new SSKS ID of the stored identity.
func (pluginPassword *PluginPassword) ChangeIdentityPassword(userId string, currentPassword string, newPassword string) (string, error) {
	if currentPassword == "" {
		return "", tracerr.Wrap(ErrorChangeIdentityNoPassword)
	}
	if newPassword == "" {
		return "", tracerr.Wrap(ErrorChangeIdentityNoNewPassword)
	}
	if currentPassword == newPassword {
		return "", tracerr.Wrap(ErrorChangeIdentitySamePassword)
	}
	userKey, err := pluginPassword.RetrieveIdentityFromPassword(userId, currentPassword)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	newId, err := pluginPassword.SaveIdentityFromPassword(userId, newPassword, userKey)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	// Reset ssks old key/value
	_, err = pluginPassword.SaveIdentityFromPassword(userId, currentPassword, nil)
	if err != nil {
		return "", tracerr.Wrap(err)
	}
	return newId, nil
}
