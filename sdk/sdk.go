package sdk

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/api_helper"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"io"
	"os"
	"sync"
	"time"
)

var (
	// ErrorInvalidAppId is returned when the AppId given in InitializeOptions is invalid.
	ErrorInvalidAppId = utils.NewSealdError("INVALID_APP_ID", "the AppId is invalid")
	// ErrorInvalidKeySize is returned when the KeySize given in InitializeOptions is invalid. Valid values are 1024, 2048 and 4096.
	ErrorInvalidKeySize = utils.NewSealdError("INVALID_KEY_SIZE", "the KeySize is invalid")
	// ErrorRequireAccount is returned when trying to use a function that needs an account, but the SDK instance has no account yet
	ErrorRequireAccount = utils.NewSealdError("REQUIRE_ACCOUNT", "this function cannot be called before creating an account")
	// ErrorRequireNoAccount is returned when trying to use a function that needs an SDK without account
	ErrorRequireNoAccount = utils.NewSealdError("REQUIRE_NO_ACCOUNT", "this function cannot be called once an account has been created")
	// ErrorSdkClosed is returned when this SDK instance has been closed
	ErrorSdkClosed = utils.NewSealdError("SDK_CLOSED", "this SDK instance has already been closed")
	// ErrorPlatformRequired is returned Platform is not defined
	ErrorPlatformRequired = utils.NewSealdError("SDK_PLATFORM_REQUIRED", "Platform argument is required")
	// ErrorDatabaseRequired is returned Database is not defined
	ErrorDatabaseRequired = utils.NewSealdError("SDK_DATABASE_REQUIRED", "Database argument is required")
)

// InitializeOptions is the main options object for initializing the SDK instance.
type InitializeOptions struct {
	// ApiURL is the Seald server for this instance to use. This value is given on your Seald dashboard.
	ApiURL string
	// Database is the storage backend instance to use to store the data for this Seald instance.
	Database Database
	// KeySize is the Asymmetric key size for newly generated keys. Defaults to 4096. Warning: for security, it is extremely not recommended to lower this value. For advanced use only.
	KeySize int
	// AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard.
	AppId string
	// EncryptionSessionCacheTTL is the duration of cache lifetime in nanoseconds. -1 to cache forever. Default to 0 (no cache).
	EncryptionSessionCacheTTL time.Duration
	// EncryptionSessionCacheCleanupInterval is the interval in nanoseconds between auto cleans of the cache. Defaults to EncryptionSessionCacheTTL with a minimum of 10s. Set to 0 to force default. Set to -1 to disable automatic cleanup.
	EncryptionSessionCacheCleanupInterval time.Duration
	// LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. Use one of the zerolog level constants.
	LogLevel zerolog.Level
	// LogNoColor should be set to true if you want to disable colors in the log output.
	LogNoColor bool
	// InstanceName is an arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
	InstanceName string
	// Platform is a name that references the platform on which the SDK is running ("go" / "ios" / "android" / "c" / "c-flutter" / ...)
	Platform string
	// LogWriter is the io.Writer to which to write the logs. Defaults to os.Stdout.
	LogWriter io.Writer
}

type storage struct {
	currentDevice           currentDeviceStorage
	contacts                contactsStorage
	connectors              connectorsStorage
	encryptionSessionsCache encryptionSessionCache
	groups                  groupsStorage
}

type stateLocks struct {
	currentDeviceLock sync.RWMutex     // Lock when doing something that can change the current device (creating account / importing identity)
	loginLock         sync.Mutex       // Used to avoid having multiple logins in parallel, which could invalidate each-other's challenges
	contactsLockGroup utils.MutexGroup // When doing something which could update a contact's data, lock it to avoid conflicts
	cacheLockGroup    utils.MutexGroup // Used to avoid having multiple session retrievals in parallel, when the subsequent ones could use the cache
}

// State is the object representing an instance of the Seald SDK.
// You must never create a State yourself. Instead, always use Initialize.
type State struct {
	apiClient beardApiClientInterface
	storage   storage
	locks     stateLocks
	options   *InitializeOptions
	logger    zerolog.Logger
	closed    bool
}

func validateOptions(options InitializeOptions) error {
	// TODO: validate URL
	if !utils.IsUUID(options.AppId) {
		return tracerr.Wrap(ErrorInvalidAppId)
	}
	if options.KeySize != 4096 && options.KeySize != 2048 && options.KeySize != 1024 {
		return tracerr.Wrap(ErrorInvalidKeySize)
	}
	if options.Platform == "" {
		return tracerr.Wrap(ErrorPlatformRequired)
	}
	if options.Database == nil {
		return tracerr.Wrap(ErrorDatabaseRequired)
	}
	return nil
}

// Initialize is the function to use to create an instance of the SDK.
// It receives an InitializeOptions object, and returns a State representing the instantiated SDK.
func Initialize(options *InitializeOptions) (*State, error) {
	if options.KeySize == 0 {
		options.KeySize = 4096
	}
	err := validateOptions(*options)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if options.LogWriter == nil {
		options.LogWriter = os.Stdout
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	instanceLogger := zerolog.New(zerolog.ConsoleWriter{Out: options.LogWriter, TimeFormat: time.StampMilli, NoColor: options.LogNoColor}).With().Timestamp().Logger()
	instanceLogger = instanceLogger.Level(options.LogLevel)
	if options.InstanceName != "" {
		instanceLogger = instanceLogger.With().Str("instance", options.InstanceName).Logger()
	}

	instanceLogger.Debug().Msg("Initialize new instance...")
	instanceLogger.Trace().Interface("opts", options).Msg("Init options") // Storage symkey is not printed ;)

	if options.KeySize == 0 {
		options.KeySize = 4096
	}
	// if `EncryptionSessionCacheCleanupInterval` is left to default, set it to `encryptionSessionCacheTTL` with a minimum of 10 seconds
	if options.EncryptionSessionCacheCleanupInterval == 0 {
		options.EncryptionSessionCacheCleanupInterval = utils.Max(options.EncryptionSessionCacheTTL, 10*time.Second)
	}

	err = options.Database.initialize()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	apiLogger := instanceLogger.With().Str("component", "beardApiClient").Logger()
	version_ := fmt.Sprintf("sdk-go/%s/%s", options.Platform, utils.Version)
	state := State{
		apiClient: &beardApiClient{
			ApiClient: *api_helper.NewApiClient(
				options.ApiURL,
				[]api_helper.Header{
					{Name: "X-SEALD-APP-ID", Value: options.AppId},
					{Name: "X-SEALD-VERSION", Value: version_},
				},
				apiLogger,
			),
		},
		options: options,
		logger:  instanceLogger,
	}

	err = options.Database.readCurrentDevice(&state.storage.currentDevice)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = options.Database.readContacts(&state.storage.contacts)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = options.Database.readGroups(&state.storage.groups)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = options.Database.readConnectors(&state.storage.connectors)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = options.Database.readEncryptionSessions(&state.storage.encryptionSessionsCache)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	state.storage.encryptionSessionsCache.setTTL(options.EncryptionSessionCacheTTL)
	state.storage.encryptionSessionsCache.startCleanupInterval(options.EncryptionSessionCacheCleanupInterval)

	state.closed = false

	return &state, nil
}

// Close closes the current SDK instance. This frees any lock on the current database. After calling Close, the instance cannot be used anymore.
func (state *State) Close() error {
	if state.closed == true { // Checking if already closed, to bail out
		state.logger.Debug().Msg("Already closed")
		return nil
	}

	state.locks.currentDeviceLock.Lock()
	defer state.locks.currentDeviceLock.Unlock()

	if state.closed == true { // Checking again, because maybe it got closed while we were acquiring the lock
		state.logger.Debug().Msg("Already closed after lock")
		return nil
	}

	state.logger.Debug().Msg("Closing...")

	state.storage.encryptionSessionsCache.stopCleanupInterval()

	err := state.options.Database.close()
	if err != nil {
		return tracerr.Wrap(err)
	}

	state.closed = true
	state.logger.Info().Msg("Closed")

	return nil
}

func (state *State) login(challenge string) error {
	state.locks.loginLock.Lock()
	defer state.locks.loginLock.Unlock()

	if state.apiClient.isAuthenticated() { // If authenticated, bail
		return nil
	}

	if challenge == "" {
		challengeResponse, err := state.apiClient.getChallenge() // No autoLogin because we are doing a login
		if err != nil {
			return tracerr.Wrap(err)
		}
		challenge = challengeResponse.NextChallenge
	}

	err := utils.CheckValidAuthChallenge(challenge)
	if err != nil {
		return tracerr.Wrap(err)
	}

	currentDevice := state.storage.currentDevice.get()

	signedChallenge, err := currentDevice.SigningPrivateKey.Sign([]byte(challenge))
	if err != nil {
		return tracerr.Wrap(err)
	}

	loginRequest := &loginRequest{
		UserId:            currentDevice.UserId,
		DeviceId:          currentDevice.DeviceId,
		KeyId:             currentDevice.DeviceId,
		SignedChallenge:   base64.StdEncoding.EncodeToString(signedChallenge),
		SigningPubkeyHash: currentDevice.SigningPrivateKey.Public().GetHash(),
	}
	_, err = state.apiClient.login(loginRequest) // No autoLogin because we are doing a login
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

func (state *State) saveContacts() error {
	return state.options.Database.writeContacts(&state.storage.contacts)
}

func (state *State) saveCurrentDevice() error {
	return state.options.Database.writeCurrentDevice(&state.storage.currentDevice)
}

func (state *State) saveGroups() error {
	return state.options.Database.writeGroups(&state.storage.groups)
}

func (state *State) saveConnectors() error {
	return state.options.Database.writeConnectors(&state.storage.connectors)
}

func (state *State) saveEncryptionSessions() error {
	return state.options.Database.writeEncryptionSessions(&state.storage.encryptionSessionsCache)
}

func autoLogin[T func(*U) (*V, error), U any, V any](state *State, f T) func(*U) (*V, error) {
	return func(args *U) (*V, error) {
		// If not authenticated, do a login (login already bails if authenticated, but it's better to avoid a useless lock-unlock when possible)
		if !state.apiClient.isAuthenticated() {
			err := state.login("")
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
		}

		// call the actual function
		res, err := f(args)
		if err == nil { // if no error, return the function's result
			return res, nil
		}

		if errors.Is(err, utils.APIError{Status: 403, Code: "NOT_AUTHENTICATED"}) { // if the error was caused because we lost auth
			// clear the known auth cookies
			state.apiClient.clear()
			if state.storage.currentDevice.get().UserId != "" { // if we have an account
				err = state.login("") // then we just have to do a login and retry the original call
				if err != nil {
					return nil, tracerr.Wrap(err)
				}
				return f(args)
			}
		}
		// if we don't have an account, or the error is not an APIError, or not one of the expected ones, just return the original error
		return nil, tracerr.Wrap(err)
	}
}

func handleLocked[T func(*U) (*V, error), U any, V any](state *State, f T, retries int) func(args *U) (*V, error) {
	return func(args *U) (*V, error) {
		// call the actual function
		res, err := f(args)
		if err == nil { // if no error, return the function's result
			return res, nil
		}

		if errors.Is(err, utils.APIError{Status: 423, Code: ""}) && retries > 0 { // if the error was caused by a lock
			state.logger.Debug().Int("retries", retries).Msg("Request failed because of lock, waiting 1s then retrying.")
			time.Sleep(1 * time.Second)
			return handleLocked[T, U, V](state, f, retries-1)(args)
		}
		return nil, tracerr.Wrap(err)
	}
}

func handleMultipleAcl[T requestWithLookups[T], V any](state *State, f func(T) (*V, error)) func(T) (*V, error) {
	return func(args T) (*V, error) {
		// call the actual function
		res, err := f(args)
		if err == nil { // if no error, return the function's result
			return res, nil
		}

		// if it's an error that could be because of a lack of rights, retry with forced rights
		if errors.Is(err, utils.APIError{Status: 403, Code: "UNAUTHORIZED_MESSAGE"}) || errors.Is(err, utils.APIError{Status: 403, Code: "NO_ACL"}) {
			state.logger.Debug().Msg("Request failed because of ACLs, retrying with forceLookups.")
			return f(args.forceLookups())
		}
		return nil, tracerr.Wrap(err)
	}
}

func (state *State) checkSdkState(mustHaveAccount bool) error {
	if state.closed {
		return tracerr.Wrap(ErrorSdkClosed)
	}
	hasAccount := state.storage.currentDevice.get().UserId != ""
	if !hasAccount && mustHaveAccount {
		return tracerr.Wrap(ErrorRequireAccount)
	}
	if hasAccount && !mustHaveAccount {
		return tracerr.Wrap(ErrorRequireNoAccount)
	}
	// No need to check team - we must join one at account creation
	return nil
}
