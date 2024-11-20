package ssks_tmr

import (
	"encoding/base64"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"io"
	"os"
	"time"
)

var (
	// ErrorSaveIdentityNoAuthFactor is returned when no authentication factor is given to save
	ErrorSaveIdentityNoAuthFactor = utils.NewSealdError("SSKSTMR_SAVE_IDENTITY_NO_AUTH_FACTOR", "save authentication factor cannot be nil")
	// ErrorSaveIdentityNoIdentity is returned when no identity was provided to save
	ErrorSaveIdentityNoIdentity = utils.NewSealdError("SSKSTMR_SAVE_IDENTITY_NO_IDENTITY", "tmr identity was not provided")
	// ErrorRetrieveIdentityNoAuthFactor is returned when no authentication factor is given to retrieve
	ErrorRetrieveIdentityNoAuthFactor = utils.NewSealdError("SSKSTMR_RETRIEVE_IDENTITY_NO_AUTH_FACTOR", "retrieve authentication factor cannot be nil")
	// ErrorRetrieveIdentityCannotUnb64Data is returned when the retrieved value is not b64
	ErrorRetrieveIdentityCannotUnb64Data = utils.NewSealdError("SSKSTMR_RETRIEVE_IDENTITY_CANNOT_UNB64_DATA", "cannot unb64 returned value")
	// ErrorRetrieveIdentityCannotDecryptData is returned when the retrieve data cannot be decrypted
	ErrorRetrieveIdentityCannotDecryptData = utils.NewSealdError("SSKSTMR_RETRIEVE_IDENTITY_CANNOT_DECRYPT_DATA", "cannot decrypt returned value")
)

type PluginTMR struct {
	appId            string
	ssksTMRApiClient apiClientInterface
	Logger           zerolog.Logger
}

// PluginTMRInitializeOptions is the main options object for initializing the PluginTMR instance.
type PluginTMRInitializeOptions struct {
	// SsksURL is the SSKS server for this instance to use. This value is given on your Seald dashboard.
	SsksURL string
	// AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard.
	AppId string
	// LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. Use one of the zerolog level constants.
	LogLevel zerolog.Level
	// LogNoColor should be set to true if you want to disable colors in the log output.
	LogNoColor bool
	// InstanceName is an arbitrary name to give to this PluginTMR instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
	InstanceName string
	// Platform is a name that references the platform on which the PluginTMR is running ("go" / "ios" / "android" / "c" / "c-flutter" / ...)
	Platform string
	// LogWriter is the io.Writer to which to write the logs. Defaults to os.Stdout.
	LogWriter io.Writer
}

func NewPluginTMR(options *PluginTMRInitializeOptions) *PluginTMR {
	if options.LogWriter == nil {
		options.LogWriter = os.Stdout
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	instanceLogger := zerolog.New(zerolog.ConsoleWriter{Out: options.LogWriter, TimeFormat: time.StampMilli, NoColor: options.LogNoColor}).With().Timestamp().Logger()
	instanceLogger = instanceLogger.Level(options.LogLevel)
	if options.InstanceName != "" {
		instanceLogger = instanceLogger.With().Str("instance", options.InstanceName).Logger()
	}

	instanceLogger.Debug().Msg("Initialize new PluginTMR instance...")
	instanceLogger.Trace().Interface("opts", options).Msg("PluginTMR Init options")

	apiLogger := instanceLogger.With().Str("component", "pluginTmrApiClient").Logger()
	version_ := fmt.Sprintf("sdk-go-ssks-tmr/%s/%s", options.Platform, utils.Version)
	instanceLogger.Debug().Str("version", version_).Msg("Version")
	client := PluginTMR{
		ssksTMRApiClient: &apiClient{
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
	instanceLogger.Debug().Msg("New PluginTMR instance created.")
	return &client
}

// SaveIdentityResponse is returned by SaveIdentity when an identity has been successfully saved.
// Contains the SsksId of the stored identity, which can be used by your backend to manage it.
// If a challenge was passed, also contains an AuthenticatedSessionId, that you can use to perform further SSKS TMR operations without challenge.
type SaveIdentityResponse struct {
	SsksId                 string
	AuthenticatedSessionId string
}

// SaveIdentity will save the given identity for the given authFactor.
func (pluginTMR *PluginTMR) SaveIdentity(sessionId string, authFactor *common_models.AuthFactor, challenge string, rawTMRSymKey []byte, identity []byte) (*SaveIdentityResponse, error) {
	if authFactor == nil {
		return nil, tracerr.Wrap(ErrorSaveIdentityNoAuthFactor)
	}
	tmrSymKey, err := symmetric_key.Decode(rawTMRSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if identity == nil {
		return nil, tracerr.Wrap(ErrorSaveIdentityNoIdentity)
	}
	pushSessionId := sessionId
	authenticatedSessionId := ""
	if challenge != "" {
		challengeValidated, err := pluginTMR.ssksTMRApiClient.challengeValidate(challenge, *authFactor, sessionId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		pushSessionId = challengeValidated.NewSessionId
		authenticatedSessionId = pushSessionId
	}

	encryptedRawData, err := tmrSymKey.Encrypt(identity)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	encryptedB64Data := base64.StdEncoding.EncodeToString(encryptedRawData)

	pushResult, err := pluginTMR.ssksTMRApiClient.push(encryptedB64Data, pushSessionId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &SaveIdentityResponse{SsksId: pushResult.Id, AuthenticatedSessionId: authenticatedSessionId}, nil
}

// RetrieveIdentityResponse is returned by RetrieveIdentity when an identity has been successfully retrieved.
// If the boolean ShouldRenewKey is set to true, the account MUST renew its private key using `sdk.RenewKeys`
// Also contains an AuthenticatedSessionId, that you can use to perform further SSKS TMR operations without challenge.
type RetrieveIdentityResponse struct {
	Identity               []byte
	ShouldRenewKey         bool
	AuthenticatedSessionId string
}

// RetrieveIdentity will retrieve the identity stored on the SSKS server for the given authFactor
func (pluginTMR *PluginTMR) RetrieveIdentity(sessionId string, authFactor *common_models.AuthFactor, challenge string, rawTMRSymKey []byte) (*RetrieveIdentityResponse, error) {
	tmrSymKey, err := symmetric_key.Decode(rawTMRSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if authFactor == nil {
		return nil, tracerr.Wrap(ErrorRetrieveIdentityNoAuthFactor)
	}
	challengeValidated, err := pluginTMR.ssksTMRApiClient.challengeValidate(challenge, *authFactor, sessionId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	authenticatedSessionId := challengeValidated.NewSessionId

	searchResult, err := pluginTMR.ssksTMRApiClient.search(authenticatedSessionId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encryptedData, err := base64.StdEncoding.DecodeString(searchResult.EncryptedDataB64)
	if err != nil {
		return nil, tracerr.Wrap(ErrorRetrieveIdentityCannotUnb64Data.AddDetails(err.Error()))
	}

	clearData, err := tmrSymKey.Decrypt(encryptedData)
	if err != nil {
		return nil, tracerr.Wrap(ErrorRetrieveIdentityCannotDecryptData.AddDetails(err.Error()))
	}

	return &RetrieveIdentityResponse{Identity: clearData, ShouldRenewKey: !searchResult.Authenticated, AuthenticatedSessionId: authenticatedSessionId}, nil
}

// GetFactorTokenResponse is returned by GetFactorToken when a JWT has successfully been retrieved.
// Contains retrieved Token.
// Also contains an AuthenticatedSessionId, that you can use to perform further SSKS TMR operations without challenge.
type GetFactorTokenResponse struct {
	Token                  string
	AuthenticatedSessionId string
}

// GetFactorToken will retrieve a JWT to get TMR accesses created for the authentication factor.
func (pluginTMR *PluginTMR) GetFactorToken(sessionId string, authFactor *common_models.AuthFactor, challenge string) (*GetFactorTokenResponse, error) {
	if authFactor == nil {
		return nil, tracerr.Wrap(ErrorRetrieveIdentityNoAuthFactor)
	}

	authenticatedSessionId := sessionId
	if challenge != "" {
		challengeValidated, err := pluginTMR.ssksTMRApiClient.challengeValidate(challenge, *authFactor, sessionId)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		authenticatedSessionId = challengeValidated.NewSessionId
	}

	token, err := pluginTMR.ssksTMRApiClient.getFactorToken(authFactor, authenticatedSessionId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return &GetFactorTokenResponse{Token: token, AuthenticatedSessionId: authenticatedSessionId}, nil
}
