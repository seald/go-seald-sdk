package anonymous_sdk

import (
	"encoding/base64"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/anonymous_sdk/api"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/encrypt_decrypt_file"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"io"
	"log"
	"os"
	"time"
)

type AnonymousSDK struct {
	ApiURL    string
	ApiClient *api.ApiClient
	Logger    zerolog.Logger
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
}

func CreateAnonymousSDK(options *AnonymousInitializeOptions) AnonymousSDK {
	if options.LogWriter == nil {
		options.LogWriter = os.Stdout
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
	return AnonymousSDK{
		ApiURL: options.ApiURL,
		ApiClient: &api.ApiClient{
			ApiClient: *api_helper.NewApiClient(
				options.ApiURL,
				[]api_helper.Header{
					{Name: "X-SEALD-APP-ID", Value: options.AppId},
					{Name: "X-SEALD-VERSION", Value: version_},
				},
				apiLogger,
			),
		},
	}
}

type TMRRecipient struct {
	Type                 string
	Value                string
	RawOverEncryptionKey []byte
}

type Recipients struct {
	SealdIds      []string
	TMRRecipients []TMRRecipient
}

func (sdk AnonymousSDK) encrypt(encryptionToken string, getKeysToken string, recipients Recipients, clearFile []byte, filename string) (string, []byte, error) {
	log.Printf("Doing anonymous encrypt %s for %d sealdIds and %d TMR accesses", filename, len(recipients.SealdIds), len(recipients.SealdIds))
	symKey, err := symmetric_key.Generate()
	if err != nil {
		return "", nil, tracerr.Wrap(err)
	}

	devices, err := sdk.ApiClient.KeyFindAll(getKeysToken, recipients.SealdIds)
	if err != nil {
		return "", nil, tracerr.Wrap(err)
	}

	var encryptedMessageKeys []*api.EncryptedMessageKey
	for i := 0; i < len(devices); i++ {
		deviceKey, err := asymkey.PublicKeyFromB64(devices[i].EncryptionPubKey)
		if err != nil {
			return "", nil, tracerr.Wrap(err)
		}
		token, err := deviceKey.Encrypt(symKey.Encode())
		if err != nil {
			return "", nil, tracerr.Wrap(err)
		}
		encryptedMessageKeys = append(encryptedMessageKeys, &api.EncryptedMessageKey{
			CreatedForKey:     devices[i].Id,
			CreatedForKeyHash: deviceKey.GetHash(),
			Token:             base64.StdEncoding.EncodeToString(token),
		})
	}

	// Handling TMR Accesses
	var encryptedTMRAccess []*api.TMRMessageKey
	for i := 0; i < len(recipients.TMRRecipients); i++ {
		tmrSymKey, err := symmetric_key.Decode(recipients.TMRRecipients[i].RawOverEncryptionKey)
		if err != nil {
			return "", nil, tracerr.Wrap(err)
		}
		token, err := tmrSymKey.Encrypt(symKey.Encode())
		if err != nil {
			return "", nil, tracerr.Wrap(err)
		}

		encryptedTMRAccess = append(encryptedTMRAccess, &api.TMRMessageKey{
			AuthFactorValue: recipients.TMRRecipients[i].Value,
			AuthFactorType:  recipients.TMRRecipients[i].Type,
			Token:           base64.StdEncoding.EncodeToString(token),
		})
	}

	request := &api.MessageCreateRequest{
		EncryptedMessageKeys: encryptedMessageKeys,
		TMRMessageKeys:       encryptedTMRAccess,
		Metadata:             filename,
	}
	msg, err := sdk.ApiClient.MessageCreate(encryptionToken, request)
	if err != nil {
		return "", nil, tracerr.Wrap(err)
	}

	encrypted, err := encrypt_decrypt_file.EncryptFile(clearFile, filename, msg.Id, symKey)
	if err != nil {
		return "", nil, tracerr.Wrap(err)
	}

	return msg.Id, encrypted, nil
}
