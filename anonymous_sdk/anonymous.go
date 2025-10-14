package anonymous_sdk

import (
	"encoding/base64"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"io"
	"os"
	"time"
)

var (
	// ErrorInvalidB64 is returned when an internal process encounters invalid B64 unexpectedly
	ErrorInvalidB64 = utils.NewSealdError("ANONYMOUS_RETRIEVE_INVALID_B64", "invalid base64")
)

type AnonymousSDK struct {
	ApiURL    string
	AppId     string
	ApiClient *ApiClient
	logger    zerolog.Logger
}

// AnonymousInitializeOptions is the main options object for initializing the Anonymous SDK instance.
type AnonymousInitializeOptions struct {
	// ApiURL is the Seald server for this instance to use. This value is given on your Seald dashboard.
	ApiURL string
	// AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard.
	AppId string
	// LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. Use one of the zerolog level constants.
	LogLevel zerolog.Level
	// LogNoColor should be set to true if you want to disable colors in the log output.
	LogNoColor bool
	// InstanceName is an arbitrary name to give to this Anonymous instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
	InstanceName string
	// Platform is a name that references the platform on which the Anonymous SDK is running ("go" / "ios" / "android" / "c" / "c-flutter" / ...)
	Platform string
	// LogWriter is the io.Writer to which to write the logs. Defaults to os.Stdout.
	LogWriter io.Writer
	// MaxParallelRequests is the maximum number of concurrent network requests allowed per Anonymous SDK instance.
	// Set to 0 for the default (10). Set to a negative value to disable the limit entirely.
	MaxParallelRequests int
}

// CreateAnonymousSDK is the function to use to create an instance of the Anonymous SDK.
// It receives an AnonymousInitializeOptions object, and returns a State representing the instantiated Anonymous SDK.
func CreateAnonymousSDK(options *AnonymousInitializeOptions) *AnonymousSDK {
	if options.LogWriter == nil {
		options.LogWriter = os.Stdout
	}
	if options.MaxParallelRequests == 0 {
		options.MaxParallelRequests = 10
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	instanceLogger := zerolog.New(zerolog.ConsoleWriter{Out: options.LogWriter, TimeFormat: time.StampMilli, NoColor: options.LogNoColor}).With().Timestamp().Logger()
	instanceLogger = instanceLogger.Level(options.LogLevel)
	if options.InstanceName != "" {
		instanceLogger = instanceLogger.With().Str("instance", options.InstanceName).Logger()
	}

	instanceLogger.Debug().Msg("Initialize new anonymous instance...")
	instanceLogger.Trace().Interface("opts", options).Msg("Anonymous Init options")

	apiLogger := instanceLogger.With().Str("component", "anonymousApiClient").Logger()
	version_ := fmt.Sprintf("sdk-go-anonymous/%s/%s", options.Platform, utils.Version)
	return &AnonymousSDK{
		AppId:  options.AppId,
		ApiURL: options.ApiURL,
		ApiClient: &ApiClient{
			ApiClient: *api_helper.NewApiClient(
				options.ApiURL,
				[]api_helper.Header{
					{Name: "X-SEALD-APP-ID", Value: options.AppId},
					{Name: "X-SEALD-VERSION", Value: version_},
				},
				apiLogger,
				options.MaxParallelRequests,
			),
		},
		logger: instanceLogger,
	}
}

type TMRRecipient struct {
	AuthFactor           *common_models.AuthFactor
	RawOverEncryptionKey []byte
}

type Recipients struct {
	SealdIds      []string
	TMRRecipients []*TMRRecipient
}

func (aSDK *AnonymousSDK) createMessageFromIdsAndToken(encryptionToken string, getKeysToken string, recipients *Recipients, metadata string, messageSymKey *symmetric_key.SymKey) (string, error) {
	devices, err := aSDK.ApiClient.KeyFindAll(getKeysToken, recipients.SealdIds)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	var encryptedMessageKeys []*EncryptedMessageKey
	for i := 0; i < len(devices); i++ {
		deviceKey, err := asymkey.PublicKeyFromB64(devices[i].EncryptionPubKey)
		if err != nil {
			return "", tracerr.Wrap(err)
		}
		token, err := deviceKey.Encrypt(messageSymKey.Encode())
		if err != nil {
			return "", tracerr.Wrap(err)
		}
		encryptedMessageKeys = append(encryptedMessageKeys, &EncryptedMessageKey{
			CreatedForKey:     devices[i].Id,
			CreatedForKeyHash: deviceKey.GetHash(),
			Token:             base64.StdEncoding.EncodeToString(token),
		})
	}

	// Handling TMR Accesses
	var encryptedTMRAccess []*TMRMessageKey
	for i := 0; i < len(recipients.TMRRecipients); i++ {
		tmrSymKey, err := symmetric_key.Decode(recipients.TMRRecipients[i].RawOverEncryptionKey)
		if err != nil {
			return "", tracerr.Wrap(err)
		}
		token, err := tmrSymKey.Encrypt(messageSymKey.Encode())
		if err != nil {
			return "", tracerr.Wrap(err)
		}

		encryptedTMRAccess = append(encryptedTMRAccess, &TMRMessageKey{
			AuthFactorValue: recipients.TMRRecipients[i].AuthFactor.Value,
			AuthFactorType:  recipients.TMRRecipients[i].AuthFactor.Type,
			Token:           base64.StdEncoding.EncodeToString(token),
		})
	}

	request := &MessageCreateRequest{
		EncryptedMessageKeys: encryptedMessageKeys,
		TMRMessageKeys:       encryptedTMRAccess,
		Metadata:             metadata,
	}

	messageCreated, err := aSDK.ApiClient.MessageCreate(encryptionToken, request)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	return messageCreated.Id, nil
}

// CreateAnonymousEncryptionSession creates an encryption session, and returns the associated EncryptionSession instance,
// with which you can then encrypt / decrypt multiple messages.
func (aSDK *AnonymousSDK) CreateAnonymousEncryptionSession(encryptionToken string, getKeysToken string, recipients *Recipients) (*AnonymousEncryptionSession, error) {
	// TODO: handle metadata? Also missing for classic ES.
	sessionSymKey, err := symmetric_key.Generate()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	messageId, err := aSDK.createMessageFromIdsAndToken(encryptionToken, getKeysToken, recipients, "", sessionSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	aSDK.logger.Trace().Str("messageId", messageId).Msg("Response from CreateEncryptionSession")

	res := AnonymousEncryptionSession{SessionId: messageId, Key: sessionSymKey, aSDK: aSDK}
	return &res, nil
}

// RetrieveEncryptionSessionFromPassword retrieves an Encryption Session with a SymEncKey, and returns the associated
// AnonymousEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (aSDK *AnonymousSDK) RetrieveEncryptionSessionFromPassword(retrieveJWT string, sessionId string, symEncKeyId string, symEncKeyPassword string) (*AnonymousEncryptionSession, error) {
	rawSecretBytes, err := utils.DeriveSecret("seald-SymEncKey-Secret", aSDK.AppId, sessionId, symEncKeyPassword)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	rawSecret := base64.StdEncoding.EncodeToString(rawSecretBytes)

	encSymEncKeyB64, err := aSDK.ApiClient.RetrieveSession(retrieveJWT, &RetrieveSessionRequest{Id: symEncKeyId, Secret: rawSecret})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encSymEncKey, err := base64.StdEncoding.DecodeString(encSymEncKeyB64.SymEncKeyData)
	if err != nil {
		return nil, tracerr.Wrap(ErrorInvalidB64.AddDetails(err.Error()))
	}

	rawSymKey, err := utils.DeriveKey("seald-SymEncKey-SymKey", aSDK.AppId, sessionId, symEncKeyPassword, []byte{})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	encryptionSymKey, err := symmetric_key.Decode(rawSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	rawSessionSymKey, err := encryptionSymKey.Decrypt(encSymEncKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	sessionSymKey, err := symmetric_key.Decode(rawSessionSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	res := AnonymousEncryptionSession{SessionId: sessionId, Key: &sessionSymKey, aSDK: aSDK}
	return &res, nil
}

// RetrieveEncryptionSessionFromRawKey retrieves an Encryption Session with a SymEncKey, and returns the associated
// AnonymousEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
func (aSDK *AnonymousSDK) RetrieveEncryptionSessionFromRawKey(retrieveJWT string, sessionId string, symEncKeyId string, symEncKeyRawSecret string, rawSymKey []byte) (*AnonymousEncryptionSession, error) {
	encSymEncKeyB64, err := aSDK.ApiClient.RetrieveSession(retrieveJWT, &RetrieveSessionRequest{Id: symEncKeyId, Secret: symEncKeyRawSecret})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	encSymEncKey, err := base64.StdEncoding.DecodeString(encSymEncKeyB64.SymEncKeyData)
	if err != nil {
		return nil, tracerr.Wrap(ErrorInvalidB64.AddDetails(err.Error()))
	}

	symEncKey, err := symmetric_key.Decode(rawSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	rawSessionSymKey, err := symEncKey.Decrypt(encSymEncKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	sessionSymKey, err := symmetric_key.Decode(rawSessionSymKey)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	res := AnonymousEncryptionSession{SessionId: sessionId, Key: &sessionSymKey, aSDK: aSDK}
	return &res, nil
}
