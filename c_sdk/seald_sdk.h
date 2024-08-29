#ifndef LIB_SEALD_SDK_H
#define LIB_SEALD_SDK_H

// Helper SealdError

/**
 * SealdError represents an error that happened during an operation.
 * Not all fields are necessarily filled.
 */
typedef struct {
    /** If the error is returned by the Seald server, the HTTP status code.  */
    int Status;
    /** The error code, which is a machine-readable string that represents this error. */
    char* Code;
    /** The error ID, which is a unique string for the precise place this error was thrown from. */
    char* Id;
    /** A human-readable description of the error. */
    char* Description;
    /** Details about the error. */
    char* Details;
    /** The raw underlying error. */
    char* Raw;
    /** The call stack in Seald native code. */
    char* NativeStack;
} SealdError;

/**
 * SealdError_Free frees the memory allocated for the SealdError and all its fields.
 *
 * @param err The SealdError to free.
 */
void SealdError_Free(SealdError* err);

// Helper SealdStringArray

/**
 * SealdStringArray holds an array of strings.
 */
typedef struct SealdStringArray SealdStringArray;

/**
 * SealdStringArray_New instantiates a new SealdStringArray.
 *
 * @return The newly created SealdStringArray.
 */
SealdStringArray* SealdStringArray_New();

/**
 * SealdStringArray_Free frees the memory allocated for the SealdStringArray itself, and all strings contained therein.
 *
 * @param array The SealdStringArray to free.
 */
void SealdStringArray_Free(SealdStringArray* array);

/**
 * SealdStringArray_Add adds a given string to the array.
 * SealdStringArray_Add does *not* take ownership of the given strings. It creates a copy for itself.
 *
 * @param array The SealdStringArray to add a string to.
 * @param s The string to add.
 */
void SealdStringArray_Add(SealdStringArray* array, char* s);

/**
 * SealdStringArray_Get returns the string at position i.
 * The caller is responsible for calling `free` on this returned string when no longer necessary.
 *
 * @param array The SealdStringArray from which to retrieve an element.
 * @param i The position from which we want to retrieve the string.
 * @return The string at position i.
 */
char* SealdStringArray_Get(SealdStringArray* array, int i);

/**
 * SealdStringArray_Size returns the size of the given SealdStringArray.
 *
 * @param array The SealdStringArray for which to retrieve the size.
 * @return The size of the given SealdStringArray.
 */
int SealdStringArray_Size(SealdStringArray* array);


// Helper SealdActionStatus

/**
 * SealdActionStatus represents the status of an operation on single user/device
 */
typedef struct {
    /** The ID of the user/device concerned by the action */
    char* Id;
    /** The status of the action: 1 if succeeded, 0 otherwise.  */
    int Success;
    /** A human readable error if applicable */
    char* ErrorCode;
    /** The result of the action */
    char* Result;
} SealdActionStatus;

/**
 * SealdActionStatus_Free frees the memory allocated for the SealdActionStatus itself, and all fields within.
 *
 * @param d The SealdActionStatus to free.
 */
void SealdActionStatus_Free(SealdActionStatus* d);


// Helper SealdActionStatusArray

/**
 * SealdActionStatusArray holds an array of SealdActionStatus instances.
 */
typedef struct SealdActionStatusArray SealdActionStatusArray;

/**
 * SealdActionStatusArray instantiates a new SealdActionStatusArray.
 *
 * @return The newly created SealdActionStatusArray.
 */
SealdActionStatusArray* SealdActionStatusArray_New();

/**
 * SealdActionStatusArray_Add adds a given SealdActionStatus instance to the array.
 * SealdActionStatusArray_Add *takes ownership* of the given SealdActionStatus.
 * The caller *must not* use it anymore, and must not call `free` on it.
 *
 * @param array The SealdActionStatusArray to add a SealdActionStatus instance to.
 * @param d The SealdActionStatus instance to add.
 */
void SealdActionStatusArray_Add(SealdActionStatusArray* array, SealdActionStatus* d);

/**
 * SealdActionStatusArray_Free frees the memory allocated for the SealdActionStatusArray itself, and all SealdActionStatus instances contained therein.
 *
 * @param array The SealdActionStatusArray to free.
 */
void SealdActionStatusArray_Free(SealdActionStatusArray* array);

/**
 * SealdActionStatusArray_Size returns the size of the given SealdActionStatusArray.
 *
 * @param array The SealdActionStatusArray for which to retrieve the size.
 * @return The size of the given SealdActionStatusArray.
 */
int SealdActionStatusArray_Size(SealdActionStatusArray* array);

/**
 * SealdActionStatusArray_Get returns a reference to the SealdActionStatus instance at position i.
 * The caller *must not* call `free` on it.
 *
 * @param array The SealdActionStatusArray from which to retrieve an element.
 * @param i The position from which we want to retrieve the SealdActionStatus instance.
 * @return The SealdActionStatus instance at position i.
 */
SealdActionStatus* SealdActionStatusArray_Get(SealdActionStatusArray* array, int i);


// Helper SealdRevokeResult

/**
 * SealdRevokeResult represents the result of a revocation operation.
 */
typedef struct {
    /** The Seald recipients the revocation operation acted on */
    SealdActionStatusArray* Recipients;
    /** The proxy sessions the revocation operation acted on */
    SealdActionStatusArray* ProxySessions;
} SealdRevokeResult;

/**
 * SealdRevokeResult_Free frees the memory allocated for the SealdRevokeResult itself, and all fields within.
 *
 * @param d The SealdRevokeResult to free.
 */
void SealdRevokeResult_Free(SealdRevokeResult* d);


// Helper SealdClearFile

/**
 * SealdClearFile represents a decrypted file.
 */
typedef struct {
    /** The filename of the decrypted file */
    char* Filename;
    /** The ID of the EncryptionSession to which this file belongs */
    char* SessionId;
    /** The content of the decrypted file */
    unsigned char* FileContent;
    /** The length of FileContent */
    int FileContentLen;
} SealdClearFile;

/**
 * SealdClearFile_Free is a helper to free a SealdClearFile instance and all fields within.
 *
 * @param cf The SealdClearFile to free.
 */
void SealdClearFile_Free(SealdClearFile* cf);


// Helper SealdTmrAccessesRetrievalFilters

/**
 * SealdTmrAccessesRetrievalFilters holds the tmr accesses filters used when retrieving an EncryptionSession.
 */
typedef struct {
    /** SealdId of the user who created the TMR access. */
    char* CreatedById;
    /** Id of the TMR access to use. */
    char* TmrAccessId;
} SealdTmrAccessesRetrievalFilters;

/**
 * SealdTmrAccessesRetrievalFilters_Free is a helper to free a SealdTmrAccessesRetrievalFilters instance and all fields within.
 *
 * @param filters The SealdTmrAccessesRetrievalFilters to free.
 */
void SealdTmrAccessesRetrievalFilters_Free(SealdTmrAccessesRetrievalFilters* filters);

// Helper SealdTmrAccessesConvertFilters


/**
 * SealdTmrAccessesConvertFilters holds the tmr accesses filters used when converting TMR accesses.
 */
typedef struct {
    /** Id of the session with the TMR access to convert. */
    char* SessionId;
    /** SealdId of the user who created the TMR accesses to convert. */
    char* CreatedById;
    /** Id of the TMR access to convert. */
    char* TmrAccessId;
} SealdTmrAccessesConvertFilters;

/**
 * SealdTmrAccessesConvertFilters_Free is a helper to free a SealdTmrAccessesConvertFilters instance and all fields within.
 *
 * @param filters The SealdTmrAccessesConvertFilters to free.
 */
void SealdTmrAccessesConvertFilters_Free(SealdTmrAccessesConvertFilters* filters);

// Helper SealdConvertTmrAccessesResult


/**
 * SealdConvertTmrAccessesResult is returned when calling SealdSdk_ConvertTmrAccesses,
 * containing the result of conversion
 */
typedef struct {
    /** Status of the conversion `ok` or `ko`. */
    char* Status;
    /** IDs of the accesses that were fully converted. */
    SealdStringArray* Converted;
    /** The number of conversions that succeeded. */
    int Succeeded;
    /** The number of conversions that failed. */
    int Errored;
} SealdConvertTmrAccessesResult;

/**
 * SealdConvertTmrAccessesResult_Free is a helper to free a SealdConvertTmrAccessesResult instance and all fields within.
 *
 * @param result The SealdConvertTmrAccessesResult to free.
 */
void SealdConvertTmrAccessesResult_Free(SealdConvertTmrAccessesResult* result);

// Helper SealdAccountInfo

/**
 * SealdAccountInfo is returned when calling SealdSdk_createAccount or SealdSdk_getCurrentAccountInfo,
 * containing information about the local account.
 */
typedef struct {
    /** The ID of the current user for this SDK instance. */
    char* UserId;
    /** The ID of the current device for this SDK instance. */
    char* DeviceId;
    /** The date at which the current device keys expire, as a Unix timestamp in seconds. For continued operation, renew your device keys before this date. `0` if it is not known locally: use SealdSdk_UpdateCurrentDevice to retrieve it. */
    long long DeviceExpires;
} SealdAccountInfo;

/**
 * SealdAccountInfo_Free is a helper to free a SealdAccountInfo instance and all fields within.
 *
 * @param info The SealdAccountInfo to free.
 */
void SealdAccountInfo_Free(SealdAccountInfo* info);


// Helper SealdInitializeOptions

/**
 * SealdInitializeOptions is the main options object for initializing the SDK instance
 */
typedef struct {
    /** ApiURL is the Seald server for this instance to use. This value is given on your Seald dashboard. */
    char* ApiURL;
    /** AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard. */
    char* AppId;
    /** KeySize is the Asymmetric key size for newly generated keys. Defaults to 4096. Warning: for security, it is extremely not recommended to lower this value. For advanced use only. */
    int KeySize;
    /** DatabasePath is the path where to store the local Seald database. If `NULL` or empty, uses an in-memory only database. */
    char* DatabasePath;
    /** DatabaseEncryptionKey is the encryption key with which to encrypt the local Seald database. Required when passing `DatabasePath`. This **must** be a cryptographically random buffer of 64 bytes. */
    unsigned char* DatabaseEncryptionKey;
    /** DatabaseEncryptionKeyLen The length of DatabaseEncryptionKey. */
    int DatabaseEncryptionKeyLen;
    /** EncryptionSessionCacheTTL is the duration of cache lifetime in Milliseconds. `-1` to cache forever. `0` for no cache. */
    long long EncryptionSessionCacheTTL;
    /** LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. */
    signed char LogLevel;
    /** LogNoColor should be set to `0` if you want to enable colors in the log output, `1` if you don't. */
    int LogNoColor;
    /** InstanceName is an arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. */
    char* InstanceName;
    /** Platform is a name that references the platform on which the SDK is running. */
    char* Platform;
} SealdInitializeOptions;


// Helper SealdCreateSubIdentityResponse

/**
 * SealdCreateSubIdentityResponse represents a newly created sub identity.
 */
typedef struct {
    /** The ID of the newly created device. */
    char* DeviceId;
    /** The identity export of the newly created sub-identity. */
    unsigned char* BackupKey;
    /** The length of BackupKey. */
    int BackupKeyLen;
} SealdCreateSubIdentityResponse;

/**
 * SealdCreateSubIdentityResponse_Free is a helper to free a SealdCreateSubIdentityResponse instance and all fields within.
 *
 * @param resp The SealdCreateSubIdentityResponse to free.
 */
void SealdCreateSubIdentityResponse_Free(SealdCreateSubIdentityResponse* resp);


// Helper SealdConnector

/**
 * SealdConnector represents all details about a connector.
 */
typedef struct {
    char* SealdId;
    char* Type;
    char* Value;
    char* Id;
    char* State;
} SealdConnector;

/**
 * SealdConnector_Free is a helper to free a SealdConnector instance and all fields within.
 *
 * @param c The SealdConnector to free.
 */
void SealdConnector_Free(SealdConnector* c);


// Helper SealdConnectorsArray

/**
 * SealdConnectorsArray holds an array of SealdConnector instances.
 */
typedef struct SealdConnectorsArray SealdConnectorsArray;

/**
 * SealdConnectorsArray_New instantiates a new SealdConnectorsArray.
 *
 * @return The newly created SealdConnectorsArray.
 */
SealdConnectorsArray* SealdConnectorsArray_New();

/**
 * SealdConnectorsArray_Free frees the memory allocated for the SealdConnectorsArray itself, and all SealdConnector instances contained therein.
 *
 * @param array The SealdConnectorsArray to free.
 */
void SealdConnectorsArray_Free(SealdConnectorsArray* array);

/**
 * SealdConnectorsArray_Add adds a given SealdConnector instance to the array.
 * SealdConnectorsArray_Add *takes ownership* of the given SealdConnector.
 * The caller *must not* use it anymore, and must not call `free` on it.
 *
 * @param array The SealdConnectorsArray to add a SealdConnector instance to.
 * @param c The SealdConnector instance to add.
 */
void SealdConnectorsArray_Add(SealdConnectorsArray* array, SealdConnector* c);

/**
 * SealdConnectorsArray_Get returns a reference to the SealdConnector instance at position i.
 * The caller *must not* call `free` on it.
 *
 * @param array The SealdConnectorsArray from which to retrieve an element.
 * @param i The position from which we want to retrieve the SealdConnector instance.
 * @return The SealdConnector instance at position i.
 */
SealdConnector* SealdConnectorsArray_Get(SealdConnectorsArray* array, int i);

/**
 * SealdConnectorsArray_Size returns the size of the given SealdConnectorsArray.
 *
 * @param array The SealdConnectorsArray for which to retrieve the size.
 * @return The size of the given SealdConnectorsArray.
 */
int SealdConnectorsArray_Size(SealdConnectorsArray* array);


// Helper SealdConnectorTypeValueArray

/**
 * SealdConnectorTypeValueArray holds an array of connector type-value pairs.
 */
typedef struct SealdConnectorTypeValueArray SealdConnectorTypeValueArray;

/**
 * SealdConnectorTypeValueArray_New instantiates a new SealdConnectorTypeValueArray.
 *
 * @return The newly created SealdConnectorTypeValueArray.
 */
SealdConnectorTypeValueArray* SealdConnectorTypeValueArray_New();

/**
 * SealdConnectorTypeValueArray_Free frees the memory allocated for the SealdConnectorTypeValueArray itself, and all connector type-value pairs contained therein.
 *
 * @param array The SealdConnectorTypeValueArray to free.
 */
void SealdConnectorTypeValueArray_Free(SealdConnectorTypeValueArray* array);

/**
 * SealdConnectorTypeValueArray_Add adds a given connector type-value pair to the array.
 * SealdConnectorTypeValueArray_Add *does not take ownership* of the given strings. It creates copies for itself.
 *
 * @param array The SealdConnectorTypeValueArray to add a connector type-value pair to.
 * @param connectorType The connector type to add.
 * @param connectorValue The connector value to add.
 */
void SealdConnectorTypeValueArray_Add(SealdConnectorTypeValueArray* array, char* connectorType, char* connectorValue);

/**
 * SealdConnectorTypeValueArray_Get returns the connector type-value pair at position i.
 * The caller is responsible for calling `free` on the returned type and value when no longer necessary.
 *
 * @param array The SealdConnectorTypeValueArray from which to retrieve a connector type-value pair.
 * @param i The position from which we want to retrieve the connector type-value pair.
 * @param connectorType A pointer to which to write the connector type at position i.
 * @param connectorValue A pointer to which to write the connector value at position i.
 */
void SealdConnectorTypeValueArray_Get(SealdConnectorTypeValueArray* array, int i, char** connectorType, char** connectorValue);

/**
 * SealdConnectorTypeValueArray_Size returns the size of the given SealdConnectorTypeValueArray.
 *
 * @param array The SealdConnectorTypeValueArray for which to retrieve the size.
 * @return The size of the given SealdConnectorTypeValueArray.
 */
int SealdConnectorTypeValueArray_Size(SealdConnectorTypeValueArray* array);


// Helper SealdRecipientsWithRightsArray

/**
 * SealdRecipientsWithRightsArray holds an array of recipients with rights.
 */
typedef struct SealdRecipientsWithRightsArray SealdRecipientsWithRightsArray;

/**
 * SealdRecipientsWithRightsArray_New instantiates a new SealdRecipientsWithRightsArray.
 *
 * @return The newly created SealdRecipientsWithRightsArray.
 */
SealdRecipientsWithRightsArray* SealdRecipientsWithRightsArray_New();

/**
 * SealdRecipientsWithRightsArray_Free frees the memory allocated for the SealdRecipientsWithRightsArray itself, and all SealdRecipientsWithRights contained therein.
 *
 * @param array The SealdRecipientsWithRightsArray to free.
 */
void SealdRecipientsWithRightsArray_Free(SealdRecipientsWithRightsArray* array);

/**
 * SealdRecipientsWithRightsArray_Add adds a recipient with its associated rights to the array.
 * SealdRecipientsWithRightsArray_Add *does not take ownership* of the given strings and booleans. It creates copies for itself.
 *
 * @param array The SealdRecipientsWithRightsArray to add the recipients-rights pair to.
 * @param sealdId Internal Seald IDs. Returned for users with SealdSdk_getCurrentAccountInfo, for groups when creating them.
 * @param readRight The right to read the message.
 * @param forwardRight The right to forward the message to another user.
 * @param revokeRight The right to revoke another user from a message, or to remove rights from them.
 */
void SealdRecipientsWithRightsArray_Add(SealdRecipientsWithRightsArray* array, char* sealdId, int readRight, int forwardRight, int revokeRight);

/**
 * SealdRecipientsWithRightsArray_AddWithDefaultRights adds a recipient with default rights.
 * Default rights are: read: true, forward: true, revoke: false
 * Default rights for the current user when creating an encryptionSession are read: true, forward: true, revoke: true
 *
 * @param array The SealdRecipientsWithRightsArray to add the recipients-rights pair to.
 * @param sealdId Internal Seald IDs. Returned for users with SealdSdk_getCurrentAccountInfo, for groups when creating them.
 */
void SealdRecipientsWithRightsArray_AddWithDefaultRights(SealdRecipientsWithRightsArray* array, char* sealdId);

/**
 * SealdRecipientsWithRightsArray_Get returns the user and its associated rights at position i.
 * For rights, returns -1 if rights are not set (using default rights).
 * The caller is responsible for calling `free` on the returned recipientId when no longer necessary.
 *
 * @param array The SealdRecipientsWithRightsArray from which to retrieve the recipients-rights pair.
 * @param i The position from which we want to retrieve the recipients-rights pair.
 * @param recipientId A pointer to which to write the recipient id at position i.
 * @param recipientRightRead A pointer to which to write the read right value at position i.
 * @param recipientRightForward A pointer to which to write the forward right value at position i.
 * @param recipientRightRevoke A pointer to which to write the revoke right value at position i.
 */
void SealdRecipientsWithRightsArray_Get(SealdRecipientsWithRightsArray* array, int i, char** recipientId, int* recipientRightRead, int* recipientRightForward, int* recipientRightRevoke);

/**
 * SealdRecipientsWithRightsArray_Size returns the size of the given SealdRecipientsWithRightsArray.
 *
 * @param array The SealdRecipientsWithRightsArray for which to retrieve the size.
 * @return The size of the given SealdRecipientsWithRightsArray.
 */
int SealdRecipientsWithRightsArray_Size(SealdRecipientsWithRightsArray* array);


// Helper SealdTmrRecipientsWithRightsArray

/**
 * SealdTmrRecipientsWithRightsArray holds an array of TMR recipients with associated rights.
 */
typedef struct SealdTmrRecipientsWithRightsArray SealdTmrRecipientsWithRightsArray;

/**
 * SealdTmrRecipientsWithRightsArray_New instantiates a new SealdTmrRecipientsWithRightsArray.
 *
 * @return The newly created SealdTmrRecipientsWithRightsArray.
 */
SealdTmrRecipientsWithRightsArray* SealdTmrRecipientsWithRightsArray_New();

/**
 * SealdTmrRecipientsWithRightsArray_Free frees the memory allocated for the SealdTmrRecipientsWithRightsArray itself, and all SealdTmrRecipientWithRights contained therein.
 *
 * @param array The SealdTmrRecipientsWithRightsArray to free.
 */
void SealdTmrRecipientsWithRightsArray_Free(SealdTmrRecipientsWithRightsArray* array);

/**
 * SealdTmrRecipientsWithRightsArray_Add adds a tmr recipient with its associated rights to the array.
 * SealdTmrRecipientsWithRightsArray_Add *does not take ownership* of the given strings and booleans. It creates copies for itself.
 *
 * @param array The SealdTmrRecipientsWithRightsArray to add the recipients-rights pair to.
 * @param authFactorType The type of authentication factor. 'EM' or 'SMS'
 * @param authFactorValue The value of authentication factor.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 * @param readRight The right to read the message.
 * @param forwardRight The right to forward the message to another user.
 * @param revokeRight The right to revoke another user from a message, or to remove rights from them.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 */

void SealdTmrRecipientsWithRightsArray_Add(SealdTmrRecipientsWithRightsArray* array, char* authFactorType, char* authFactorValue, unsigned char* overEncryptionKey, int overEncryptionKeyLen, int readRight, int forwardRight, int revokeRight);

/**
 * SealdTmrRecipientsWithRightsArray_AddWithDefaultRights adds a recipient with default rights.
 * SealdTmrRecipientsWithRightsArray_AddWithDefaultRights *does not take ownership* of the given strings and booleans. It creates copies for itself.
 * Default rights are: read: true, forward: true, revoke: false
 *
 * @param array The SealdTmrRecipientsWithRightsArray to add the recipients-rights pair to.
 * @param authFactorType The type of authentication factor. 'EM' or 'SMS'
 * @param authFactorValue The value of authentication factor.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 */
void SealdTmrRecipientsWithRightsArray_AddWithDefaultRights(SealdTmrRecipientsWithRightsArray* array, char* authFactorType, char* authFactorValue, unsigned char* overEncryptionKey, int overEncryptionKeyLen);
/**
 * SealdTmrRecipientsWithRightsArray_Get returns the TMR recipient and its associated rights at position i.
 * The caller is responsible for calling `free` on the returned char** when no longer necessary.
 *
 * @param array The SealdTmrRecipientsWithRightsArray from which to retrieve the recipients-rights pair.
 * @param i The position from which we want to retrieve the recipients-rights pair.
 * @param authFactorType A pointer to which to write the recipient authentication factor type at position i.
 * @param authFactorValue A pointer to which to write the recipient authentication factor value at position i.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 * @param recipientRightRead A pointer to which to write the read right value at position i.
 * @param recipientRightForward A pointer to which to write the forward right value at position i.
 * @param recipientRightRevoke A pointer to which to write the revoke right value at position i.
 */
void SealdTmrRecipientsWithRightsArray_Get(SealdTmrRecipientsWithRightsArray* array, int i, char** authFactorType, char** authFactorValue, unsigned char** overEncryptionKey, int* overEncryptionKeyLen, int* recipientRightRead, int* recipientRightForward, int* recipientRightRevoke);

/**
 * SealdTmrRecipientsWithRightsArray_Size returns the size of the given SealdTmrRecipientsWithRightsArray.
 *
 * @param array The SealdTmrRecipientsWithRightsArray for which to retrieve the size.
 * @return The size of the given SealdTmrRecipientsWithRightsArray.
 */
int SealdTmrRecipientsWithRightsArray_Size(SealdTmrRecipientsWithRightsArray* array);


// Helper SealdPreValidationToken

/**
 * SealdPreValidationToken represents a way for your server to authorize the adding of a connector.
 */
typedef struct {
    char* DomainValidationKeyId;
    char* Nonce;
    char* Token;
} SealdPreValidationToken;

/**
 * SealdPreValidationToken_Free is a helper to free a SealdPreValidationToken instance and all fields within.
 *
 * @param t The SealdPreValidationToken to free.
 */
void SealdPreValidationToken_Free(SealdPreValidationToken* t);


// Helper SealdMassReencryptOptions

/**
 * SealdMassReencryptOptions represents options for SealdSdk_MassReencrypt.
 */
typedef struct {
    /** Number of times to retry. Defaults to 3. */
    int Retries;
    /** Default to 1000. */
    int RetrieveBatchSize;
    /** Time to wait between retries, in Milliseconds. Defaults to 3 seconds. */
    long long WaitBetweenRetries;
    /** Whether to wait for provisioning (new behaviour) or not. `1` to wait, `0` to not wait. Defaults to `1`. */
    int WaitProvisioning; // bool
    /** Time to wait if device is not provisioned on the server yet, in Milliseconds. The actual wait time will be increased on subsequent tries, by `WaitProvisioningTimeStep`, up to `WaitProvisioningTimeMax`. Defaults to 5 seconds. */
    long long WaitProvisioningTime;
    /** Maximum time to wait if device is not provisioned on the server yet, in Milliseconds. Defaults to 10 seconds. */
    long long WaitProvisioningTimeMax;
    /** Amount to increase the time to wait if device is not provisioned on the server yet, in Milliseconds. Defaults to 1 second. */
    long long WaitProvisioningTimeStep;
    /** Maximum number of tries to check if the device is provisioned yet. Defaults to 100. */
    int WaitProvisioningRetries;
    /** Whether to update the local account before trying the reencryption. `1` to update, `0` to not update. Defaults to `0`. */
    int ForceLocalAccountUpdate; // bool
} SealdMassReencryptOptions;

/**
 * Initialize a SealdMassReencryptOptions instance with default values.
 */
SealdMassReencryptOptions SealdMassReencryptOptions_Defaults();


// Helper SealdMassReencryptResponse

/**
 * SealdMassReencryptResponse represents the results of a call to [SealdSdk.massReencrypt].
 */
typedef struct {
    /** The number of session keys that were reencrypted for the given device. */
    int Reencrypted;
    /** The number of session keys that could not be reencrypted for the given device. */
    int Failed;
} SealdMassReencryptResponse;


// Helper SealdDeviceMissingKeys

/**
 * SealdDeviceMissingKeys represents a device of the current account which is missing some keys,
 * and for which you probably want to call SealdSdk_MassReencrypt.
 */
typedef struct {
    /** The ID of the device which is missing some keys. */
    char* DeviceId;
} SealdDeviceMissingKeys;

/**
 * SealdDeviceMissingKeys_Free frees the memory allocated for the SealdDeviceMissingKeys itself, and all fields within.
 *
 * @param d The SealdDeviceMissingKeys to free.
 */
void SealdDeviceMissingKeys_Free(SealdDeviceMissingKeys* d);


// Helper SealdDeviceMissingKeysArray

/**
 * SealdDeviceMissingKeysArray holds an array of SealdDeviceMissingKeys instances.
 */
typedef struct SealdDeviceMissingKeysArray SealdDeviceMissingKeysArray;

/**
 * SealdDeviceMissingKeysArray_New instantiates a new SealdDeviceMissingKeysArray.
 *
 * @return The newly created SealdDeviceMissingKeysArray.
 */
SealdDeviceMissingKeysArray* SealdDeviceMissingKeysArray_New();

/**
 * SealdDeviceMissingKeysArray_Free frees the memory allocated for the SealdDeviceMissingKeysArray itself, and all SealdDeviceMissingKeys instances contained therein.
 *
 * @param array The SealdDeviceMissingKeysArray to free.
 */
void SealdDeviceMissingKeysArray_Free(SealdDeviceMissingKeysArray* array);

/**
 * SealdDeviceMissingKeysArray_Add adds a given SealdDeviceMissingKeys instance to the array.
 * SealdDeviceMissingKeysArray_Add *takes ownership* of the given SealdDeviceMissingKeys.
 * The caller *must not* use it anymore, and must not call `free` on it.
 *
 * @param array The SealdDeviceMissingKeysArray to add a SealdDeviceMissingKeys instance to.
 * @param d The SealdDeviceMissingKeys instance to add.
 */
void SealdDeviceMissingKeysArray_Add(SealdDeviceMissingKeysArray* array, SealdDeviceMissingKeys* d);

/**
 * SealdDeviceMissingKeysArray_Get returns a reference to the SealdDeviceMissingKeys instance at position i.
 * The caller *must not* call `free` on it.
 *
 * @param array The SealdDeviceMissingKeysArray from which to retrieve an element.
 * @param i The position from which we want to retrieve the SealdDeviceMissingKeys instance.
 * @return The SealdDeviceMissingKeys instance at position i.
 */
SealdDeviceMissingKeys* SealdDeviceMissingKeysArray_Get(SealdDeviceMissingKeysArray* array, int i);

/**
 * SealdDeviceMissingKeysArray_Size returns the size of the given SealdDeviceMissingKeysArray.
 *
 * @param array The SealdDeviceMissingKeysArray for which to retrieve the size.
 * @return The size of the given SealdDeviceMissingKeysArray.
 */
int SealdDeviceMissingKeysArray_Size(SealdDeviceMissingKeysArray* array);


// Helper SealdEncryptionSessionRetrievalFlow

/**
 * SealdEncryptionSessionRetrievalFlow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session
 */
typedef enum {
    /** The session was created locally. */
    SealdEncryptionSessionRetrievalCreated, // 0
    /** The session was retrieved as a direct recipient. */
    SealdEncryptionSessionRetrievalDirect, // 1
    /** The session was retrieved as a member of a group. */
    SealdEncryptionSessionRetrievalViaGroup, // 2
    /** The session was retrieved through a proxy session. */
    SealdEncryptionSessionRetrievalViaProxy, // 3
    /** The session was retrieved through a TMR access. */
    SealdEncryptionSessionRetrievalViaTmrAccess // 4
} SealdEncryptionSessionRetrievalFlow;


// Helper SealdEncryptionSessionRetrievalDetails

/**
 * SealdEncryptionSessionRetrievalDetails represents the details of how an Encryption Session was retrieved.
 */
typedef struct {
    /** The way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session. */
    SealdEncryptionSessionRetrievalFlow Flow;
    /** If the session was retrieved as member of a group, the ID of the group in question. */
    char* GroupId;
    /** If the session was retrieved through a proxy session, the ID of this proxy session. */
    char* ProxySessionId;
    /** Indicates if this session was retrieved from the cache. 0 for False. 1 for True. */
    int FromCache; // bool
} SealdEncryptionSessionRetrievalDetails;

/**
 * SealdEncryptionSessionRetrievalDetails_Free frees the memory allocated for the SealdEncryptionSessionRetrievalDetails itself, and all its fields.
 *
 * @param details The SealdEncryptionSessionRetrievalDetails to free.
 */
void SealdEncryptionSessionRetrievalDetails_Free(SealdEncryptionSessionRetrievalDetails* details);


// Helper SealdGetSigchainResponse

/**
 * SealdGetSigchainResponse is returned when calling SealdSdk_GetSigchainHash,
 * containing the hash value and the position of the hash in the sigchain.
 */
typedef struct {
    /** The sigchain hash. */
    char* Hash;
    /** The position of the associated hash in the sigchain */
    int Position;
} SealdGetSigchainResponse;

/**
 * SealdGetSigchainResponse_Free frees the memory allocated for the SealdGetSigchainResponse itself, and all its fields.
 *
 * @param sigchainInfo The SealdGetSigchainResponse to free.
 */
void SealdGetSigchainResponse_Free(SealdGetSigchainResponse* sigchainInfo);


// Helper SealdCheckSigchainResponse

/**
 * SealdCheckSigchainResponse is returned when calling SealdSdk_CheckSigchainHash,
 * containing if the hash was found in the sigchain or not.
 *
 * If the hash was found, it also contain at which position it was found. Empty pointers otherwise.
 */
typedef struct {
    /** Whether or not the hash was found in the user's sigchain. `1` for True, `0` for False. */
    int Found;
    /** The position in the sigchain where the expected hash was found */
    int Position;
    /** The number of transaction in the sigchain */
    int LastPosition;
} SealdCheckSigchainResponse;


// Class Encryption Session

/**
 * SealdEncryptionSession represents an encryption session, with which you can then encrypt / decrypt multiple messages.
 * This should not be created directly, and should be retrieved with SealdSdk_RetrieveEncryptionSession
 * or SealdSdk_RetrieveEncryptionSessionFromMessage.
 */
typedef struct SealdEncryptionSession SealdEncryptionSession;

/**
 * SealdEncryptionSession_Free frees the memory allocated for the SealdEncryptionSession.
 *
 * @param es The Encryption Session to free
 */
void SealdEncryptionSession_Free(SealdEncryptionSession* es);

/**
 * SealdEncryptionSession_Id returns the session ID of this encryption session.
 *
 * @param es The encryption session instance for which to return the session ID.
 * @return The session ID of the given encryption session instance. The caller must call `free` on this when no longer needed.
 */
char* SealdEncryptionSession_Id(SealdEncryptionSession* es);

/**
 * SealdEncryptionSession_RetrievalDetails returns the retrieval details of this encryption session.
 *
 * @param es The encryption session instance for which to return the retrieval details.
 * @return The retrieval details of the given encryption session instance. The caller must call [SealdEncryptionSessionRetrievalDetails_Free] on this when no longer needed.
 */
SealdEncryptionSessionRetrievalDetails* SealdEncryptionSession_RetrievalDetails(SealdEncryptionSession* es);

/**
 * Add a proxy session as a recipient of this session.
 * Any recipient of the proxy session will also be able to retrieve this session.
 * The current user has to be a direct recipient of the proxy session.
 *
 * @param es The SealdEncryptionSession instance.
 * @param proxySessionId The ID of the session to add as proxy.
 * @param readRight The read right to assign to this proxy.
 * @param forwardRight The forward right to assign to this proxy.
 * @param revokeRight The revoke right to assign to this proxy.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_AddProxySession(SealdEncryptionSession* es, char* proxySessionId, int readRight, int forwardRight, int revokeRight, SealdError** error);

/**
 * Revoke some recipients or proxy sessions from this session.
 * If you want to revoke all recipients, see SealdEncryptionSession_RevokeAll instead.
 * If you want to revoke all recipients besides yourself, see SealdEncryptionSession_RevokeOthers.
 *
 * @param es The SealdEncryptionSession instance.
 * @param recipientsIds The Seald IDs of users to revoke from this session.
 * @param proxySessionsIds The IDs of proxy sessions to revoke from this session.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_RevokeRecipients(SealdEncryptionSession* es, SealdStringArray* recipientsIds, SealdStringArray* proxySessionsIds, SealdRevokeResult** result, SealdError** error);

/**
 * Revoke this session entirely.
 *
 * @param es The SealdEncryptionSession instance.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_RevokeAll(SealdEncryptionSession* es, SealdRevokeResult** result, SealdError** error);

/**
 * Revoke all recipients besides yourself from this session.
 *
 * @param es The SealdEncryptionSession instance.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_RevokeOthers(SealdEncryptionSession* es, SealdRevokeResult** result, SealdError** error);

/**
 * Add new recipients to this session.
 * These recipients will be able to read all encrypted messages of this session.
 *
 * To add a user as recipient, the SDK need to add every device associated with the user.
 * The returned SealdActionStatusArray instance includes a SealdActionStatus for every DEVICES that needs to be added.
 * The `id` field in each SealdActionStatus correspond to the deviceIds of those devices
 *
 * @param es The SealdEncryptionSession instance.
 * @param recipients The Seald IDs of users to add to this session.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_AddRecipients(SealdEncryptionSession* es, SealdRecipientsWithRightsArray* recipients, SealdActionStatusArray** result, SealdError** error);

/**
 * Encrypt a clear-text string into an encrypted message, for the recipients of this session.
 *
 * @param es The SealdEncryptionSession instance.
 * @param clearMessage The message to encrypt.
 * @param result A pointer to which to write the resulting encrypted message.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_EncryptMessage(SealdEncryptionSession* es, char* clearMessage, char** result, SealdError** error);

/**
 * Decrypt an encrypted message string into the corresponding clear-text string.
 *
 * @param es The SealdEncryptionSession instance.
 * @param encryptedMessage The encrypted message to decrypt.
 * @param result A pointer to which to write the resulting decrypted message.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_DecryptMessage(SealdEncryptionSession* es, char* encryptedMessage, char** result, SealdError** error);

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param es The SealdEncryptionSession instance.
 * @param clearFile An array of bytes of the clear-text content of the file to encrypt.
 * @param clearFileLen The length of clearFile.
 * @param filename The name of the file to encrypt.
 * @param result A pointer to which to write the resulting encrypted file.
 * @param resultLen A pointer to which to write the length of result.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_EncryptFile(SealdEncryptionSession* es, unsigned char* clearFile, int clearFileLen, char* filename, unsigned char** result, int* resultLen, SealdError** error);

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param es The SealdEncryptionSession instance.
 * @param encryptedFile An array of bytes of the content of the encrypted file to decrypt.
 * @param encryptedFileLen The length of encryptedFile.
 * @param result A pointer to a SealdClearFile* to store the resulting decrypted file.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_DecryptFile(SealdEncryptionSession* es, unsigned char* encryptedFile, int encryptedFileLen, SealdClearFile** result, SealdError** error);

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param es The SealdEncryptionSession instance.
 * @param clearFilePath The path of the file to encrypt.
 * @param result A pointer to a char pointer where the path of the encrypted file will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_EncryptFileFromPath(SealdEncryptionSession* es, char* clearFilePath, char** result, SealdError** error);

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param es The SealdEncryptionSession instance.
 * @param encryptedFilePath The path of the file to encrypted file to decrypt.
 * @param result A pointer to a char pointer where the path of the decrypted file will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdEncryptionSession_DecryptFileFromPath(SealdEncryptionSession* es, char* encryptedFilePath, char** result, SealdError** error);

/**
 * Add a TMR access to this session for the given authentication factor.
 *
 * @param es The SealdEncryptionSession instance.
 * @param authFactorType The type of authentication factor. 'EM' or 'SMS'
 * @param authFactorValue The value of authentication factor.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 * @param readRight The right to read the message.
 * @param forwardRight The right to forward the message to another user.
 * @param revokeRight The right to revoke another user from a message, or to remove rights from them.
 * @param result A pointer to a `*char` which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return
 */
int SealdEncryptionSession_AddTmrAccess(SealdEncryptionSession* es, char* authFactorType, char* authFactorValue, unsigned char* overEncryptionKey, int overEncryptionKeyLen, int readRight, int forwardRight, int revokeRight, char** result, SealdError** error);

/**
 * Add multiple TMR accesses to this session for the given authentication factors.
 *
 * @param es The SealdEncryptionSession instance.
 * @param recipients The TMR recipients with their associated rights.
 * @param result A pointer to a `SealdActionStatusArray` which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return
 */
int SealdEncryptionSession_AddMultipleTmrAccesses(SealdEncryptionSession* es, SealdTmrRecipientsWithRightsArray* recipients, SealdActionStatusArray** result, SealdError** error);

// Helper SealdEncryptionSessionArray

/**
 * SealdEncryptionSessionArray holds an array of encryption sessions.
 */
typedef struct SealdEncryptionSessionArray SealdEncryptionSessionArray;

/**
 * SealdEncryptionSessionArray_New instantiates a new SealdEncryptionSessionArray.
 *
 * @return The newly created SealdEncryptionSessionArray.
 */
SealdEncryptionSessionArray* SealdEncryptionSessionArray_New();

/**
 * SealdEncryptionSessionArray_Free frees the memory allocated for the SealdEncryptionSessionArray itself.
 *
 * @param array The SealdEncryptionSessionArray to free.
 */
void SealdEncryptionSessionArray_Free(SealdEncryptionSessionArray* array);

/**
 * SealdEncryptionSessionArray_Add adds an encryption session to the array.
 *
 * @param array The SealdEncryptionSessionArray to add the encryption session to.
 * @param es The Encryption Session to add.
 */
void SealdEncryptionSessionArray_Add(SealdEncryptionSessionArray* array, SealdEncryptionSession* es);

/**
 * SealdEncryptionSessionArray_Get returns the encryption session at position i.
 * The caller is responsible for calling `SealdEncryptionSession_Free` on the returned SealdEncryptionSession* when no longer necessary.
 *
 * @param array The SealdEncryptionSessionArray from which to retrieve the encryption session.
 * @param i The position from which we want to retrieve the encryption session.
 * @return The SealdConnector instance at position i.
 */
SealdEncryptionSession* SealdEncryptionSessionArray_Get(SealdEncryptionSessionArray* array, int i);

/**
 * SealdEncryptionSessionArray_Size returns the size of the given SealdEncryptionSessionArray.
 *
 * @param array The SealdEncryptionSessionArray for which to retrieve the size.
 * @return The size of the given SealdEncryptionSessionArray.
 */
int SealdEncryptionSessionArray_Size(SealdEncryptionSessionArray* array);
// Class SDK

/**
 * This is the main class for the Seald SDK. It represents an instance of the Seald SDK.
 */
typedef struct SealdSdk SealdSdk;

/**
 * Initialize a Seald SDK Instance.
 *
 * @param options A pointer to a SealdInitializeOptions instance.
 * @param result A pointer to a SealdSdk* to store the created SDK instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_Initialize(SealdInitializeOptions* options, SealdSdk** result, SealdError** error);

/**
 * Close the current SDK instance. This frees any lock on the current database, and frees the memory.
 * After calling close, the instance cannot be used anymore.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_Close(SealdSdk* sealdSdk, SealdError** error);

/* Account */

/**
 * Create a new Seald SDK Account for this Seald SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param displayName A name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param deviceName A name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device.
 * @param signupJwt The JWT to allow this SDK instance to create an account.
 * @param expireAfter The duration during which the created device key will be valid without renewal, in Milliseconds. Optional, defaults to 5 years.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param result A pointer to SealdAccountInfo*, to store a SealdAccountInfo instance containing the Seald ID of the newly created Seald user, the device ID, and the date at which the current device keys will expire.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_CreateAccount(SealdSdk* sealdSdk, char* displayName, char* deviceName, char* signupJwt, long long expireAfter, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, SealdAccountInfo** result, SealdError** error);

/**
 * Return information about the current account, or `NULL` if there is none.
 *
 * @param sealdSdk The SealdSdk instance.
 * @return A SealdAccountInfo instance, containing the Seald ID of the local Seald user, the device ID, and the date at which the current device keys will expire. `NULL` if there is no local user.
 */
SealdAccountInfo* SealdSdk_GetCurrentAccountInfo(SealdSdk* sealdSdk);

/**
 * Updates the locally known information about the current device.
 *
 * You should never have to call this manually, except if you getting `0` in sealdAccountInfo.DeviceExpires,
 * which can happen if migrating from an older version of the SDK,
 * or if the internal call to SealdSdk_UpdateCurrentDevice failed when calling SealdSdk_ImportIdentity.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_UpdateCurrentDevice(SealdSdk* sealdSdk, SealdError** error);

/**
 * Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param result A pointer where to store the prepared renewal.
 * @param resultLen A pointer where to store the result length.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_PrepareRenew(SealdSdk* sealdSdk, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, unsigned char** result, int* resultLen, SealdError** error);

/**
 * Renew the keys of the current device, extending their validity.
 * If the current device has expired, you will need to call SealdSdk_RenewKeys before you are able to do anything else.
 * Warning: if the identity of the current device is stored externally, for example on SSKS,
 * you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param keyExpireAfter The duration during which the renewed device key will be valid without further renewal, in Milliseconds. Optional, defaults to 5 years.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preparedRenewal Optional. The preparedRenewal generated by calling `SealdSdk_RenewKeys`. If preparedRenewal is given, preGeneratedEncryptionKey and preGeneratedSigningKey will be ignored.
 * @param preparedRenewalLen The length of preparedRenewal.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RenewKeys(SealdSdk* sealdSdk, long long keyExpireAfter, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, unsigned char* preparedRenewal, int preparedRenewalLen, SealdError** error);

/**
 * Create a new sub-identity, or new device, for the current user account.
 * After creating this new device, you will probably want to call SealdSdk_MassReencrypt,
 * so that the newly created device will be able to decrypt EncryptionSessions previously created for this account.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
 * @param expireAfter The duration during which the device key for the device to create will be valid without renewal, in Milliseconds. Optional, defaults to 5 years.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param result A pointer to store a CreateSubIdentityResponse* instance, containing `DeviceId` (the ID of the newly created device), `BackupKey` (the identity export of the newly created sub-identity), and `BackupKeyLen` (the length of `BackupKey`).
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_CreateSubIdentity(SealdSdk* sealdSdk, char* deviceName, long long expireAfter, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, SealdCreateSubIdentityResponse** result, SealdError** error);

/**
 * Load an identity export into the current SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param identity The identity export that this SDK instance should import.
 * @param identityLen The length of identity.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ImportIdentity(SealdSdk* sealdSdk, unsigned char* identity, int identityLen, SealdError** error);

/**
 * Export the current device as an identity export.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param result A pointer where to store the identity export of the current identity of this SDK instance.
 * @param resultLen A pointer where to store the result length.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ExportIdentity(SealdSdk* sealdSdk, unsigned char** result, int* resultLen, SealdError** error);

/**
 * Push a given JWT to the Seald server, for example to add a connector to the current account.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param jwt The JWT to push.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_PushJWT(SealdSdk* sealdSdk, char* jwt, SealdError** error);

/**
 * Just call the Seald server, without doing anything.
 * This may be used for example to verify that the current instance has a valid identity.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_Heartbeat(SealdSdk* sealdSdk, SealdError** error);

/* Groups */

/**
 * Create a group, and returns the created group's ID.
 * `admins` must also be members.
 * `admins` must include yourself.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupName A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param members The Seald IDs of the members to add to the group. Must include yourself.
 * @param admins The Seald IDs of the members to also add as group admins. Must include yourself.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param groupId A pointer where to store the ID of the created group.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_CreateGroup(SealdSdk* sealdSdk, char* groupName, SealdStringArray* members, SealdStringArray* admins, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, char** groupId, SealdError** error);

/**
 * Add members to a group.
 * Can only be done by a group administrator.
 * Can also specify which of these newly added group members should also be admins.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupId The group in which to add members.
 * @param membersToAdd The Seald IDs of the members to add to the group.
 * @param adminsToSet The Seald IDs of the newly added members to also set as group admins.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_AddGroupMembers(SealdSdk* sealdSdk, char* groupId, SealdStringArray* membersToAdd, SealdStringArray* adminsToSet, SealdError** error);

/**
 * Remove members from the group.
 * Can only be done by a group administrator.
 * You should call SealdSdk_RenewGroupKey() after this.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupId The group from which to remove members.
 * @param membersToRemove The Seald IDs of the members to remove from the group.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RemoveGroupMembers(SealdSdk* sealdSdk, char* groupId, SealdStringArray* membersToRemove, SealdError** error);

/**
 * Renew the group's private key.
 * Can only be done by a group administrator.
 * Should be called after removing members from the group.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupId The group for which to renew the private key.
 * @param preGeneratedEncryptionKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param preGeneratedSigningKey A B64 encoding of a pre-generated key, or `NULL`. Either both must be passed, or neither.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RenewGroupKey(SealdSdk* sealdSdk, char* groupId, char* preGeneratedEncryptionKey, char* preGeneratedSigningKey, SealdError** error);

/**
 * Add some existing group members to the group admins, and/or removes admin status from some existing group admins.
 * Can only be done by a group administrator.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupId The group for which to set admins.
 * @param addToAdmins The Seald IDs of existing group members to add as group admins.
 * @param removeFromAdmins The Seald IDs of existing group members to remove from group admins.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_SetGroupAdmins(SealdSdk* sealdSdk, char* groupId, SealdStringArray* addToAdmins, SealdStringArray* removeFromAdmins, SealdError** error);

/**
 * ShouldRenewGroup returns a boolean that indicates whether or not this group should be renewed.
 * The result is `1` if the group expires in less than 6 months, `0` otherwise.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param groupId The group for which to check if renewal is necessary.
 * @param result A pointer where to store the result.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ShouldRenewGroup(SealdSdk* sealdSdk, char* groupId, int* result, SealdError** error);

/* EncryptionSession */

/**
 * Create an encryption session, and returns the associated SealdEncryptionSession instance,
 * with which you can then encrypt / decrypt multiple messages.
 * Warning : if you want to be able to retrieve the session later,
 * you must put your own Seald ID in the `recipients` argument.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param recipients The Seald IDs of users who should be able to retrieve this session.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param result A pointer where to store the created SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_CreateEncryptionSession(SealdSdk* sealdSdk, SealdRecipientsWithRightsArray* recipients, int useCache, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve an encryption session with the `messageId`, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param messageId The ID of the message belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy. `1` for True, `0` for False.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group. `1` for True, `0` for False.
 * @param result A pointer where to store the retrieved SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveEncryptionSession(SealdSdk* sealdSdk, char* messageId, int useCache, int lookupProxyKey, int lookupGroupKey, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve an encryption session from a Seald message, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param message Any message belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy. `1` for True, `0` for False.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group. `1` for True, `0` for False.
 * @param result A pointer where to store the retrieved SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveEncryptionSessionFromMessage(SealdSdk* sealdSdk, char* message, int useCache, int lookupProxyKey, int lookupGroupKey, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve an encryption session from a file path, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param filePath The path to an encrypted file belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy. `1` for True, `0` for False.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group. `1` for True, `0` for False.
 * @param result A pointer where to store the retrieved SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveEncryptionSessionFromFile(SealdSdk* sealdSdk, char* filePath, int useCache, int lookupProxyKey, int lookupGroupKey, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve an encryption session from bytes, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param fileBytes The bytes of an encrypted file belonging to the session to retrieve.
 * @param fileBytesLen The length of fileBytes.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy. `1` for True, `0` for False.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group. `1` for True, `0` for False.
 * @param result A pointer where to store the retrieved SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveEncryptionSessionFromBytes(SealdSdk* sealdSdk, unsigned char* fileBytes, int fileBytesLen, int useCache, int lookupProxyKey, int lookupGroupKey, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve an encryption session with a TMR access JWT.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param tmrJWT The TMR JWT.
 * @param sessionId The id of the session to retrieve.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 * @param tmrAccessesRetrievalFilters Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
 * @param tryIfMultiple If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one. `1` to loop, `0` otherwise.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param result A pointer where to store the retrieved SealdEncryptionSession instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveEncryptionSessionByTmr(SealdSdk* sealdSdk, char* tmrJWT, char* sessionId, unsigned char* overEncryptionKey, int overEncryptionKeyLen, SealdTmrAccessesRetrievalFilters* tmrAccessesRetrievalFilters, int tryIfMultiple, int useCache, SealdEncryptionSession** result, SealdError** error);

/**
 * Retrieve multiple encryption sessions with a SealdStringArray of sessionIds, and return a
 * SealdEncryptionSessionArray of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
 * The returned array of EncryptionSession instances is in the same order as the input array.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param sessionIds The IDs of sessions to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally). `1` to use cache, `0` to not use it.
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy. `1` for True, `0` for False.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group. `1` for True, `0` for False.
 * @param result A pointer where to store the retrieved SealdEncryptionSessionArray instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveMultipleEncryptionSessions(SealdSdk* sealdSdk, SealdStringArray* sessionIds, int useCache, int lookupProxyKey, int lookupGroupKey, SealdEncryptionSessionArray** result, SealdError** error);

/* Connectors */

/**
 * Get all the info for the given connectors to look for, updates the local cache of connectors,
 * and returns a SealdStringArray with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
 * If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
 * with the details of the missing connector.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param connectorTypeValues A SealdConnectorTypeValueArray instance.
 * @param result A pointer where to store the SealdStringArray of Seald IDs of the users corresponding to these connectors.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_GetSealdIdsFromConnectors(SealdSdk* sealdSdk, SealdConnectorTypeValueArray* connectorTypeValues, SealdStringArray** result, SealdError** error);

/**
 * List all connectors known locally for a given Seald ID.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param sealdId The Seald ID for which to list connectors.
 * @param result A pointer where to store the SealdConnectorsArray instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_GetConnectorsFromSealdId(SealdSdk* sealdSdk, char* sealdId, SealdConnectorsArray** result, SealdError** error);

/**
 * Add a connector to the current identity.
 * If no preValidationToken is given, the connector will need to be validated before use.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param value The value of the connector to add.
 * @param connectorType The type of the connector.
 * @param preValidationToken Given by your server to authorize the adding of a connector.
 * @param result A pointer where to store the created SealdConnector instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_AddConnector(SealdSdk* sealdSdk, char* value, char* connectorType, SealdPreValidationToken* preValidationToken, SealdConnector** result, SealdError** error);

/**
 * Validate an added connector that was added without a preValidationToken.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param connectorId The ID of the connector to validate.
 * @param challenge The challenge.
 * @param result A pointer to a SealdConnector pointer where the result will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ValidateConnector(SealdSdk* sealdSdk, char* connectorId, char* challenge, SealdConnector** result, SealdError** error);

/**
 * Remove a connector belonging to the current account.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param connectorId The ID of the connector to remove.
 * @param result A pointer to a SealdConnector pointer where the result will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RemoveConnector(SealdSdk* sealdSdk, char* connectorId, SealdConnector** result, SealdError** error);

/**
 * List connectors associated to the current account.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param result A pointer to a SealdConnectorsArray pointer where the result will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ListConnectors(SealdSdk* sealdSdk, SealdConnectorsArray** result, SealdError** error);

/**
 * Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param connectorId The ID of the connector to retrieve.
 * @param result A pointer to a SealdConnector pointer where the result will be stored.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_RetrieveConnector(SealdSdk* sealdSdk, char* connectorId, SealdConnector** result, SealdError** error);

/* Reencrypt */

/**
 * Retrieve, re-encrypt, and add missing keys for a certain device.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param deviceId The ID of the device for which to re-rencrypt.
 * @param options A SealdMassReencryptOptions instance.
 * @param result A pointer to a SealdMassReencryptResponse instance, which will be populated with the number of re-encrypted keys, and the number of keys for which re-encryption failed.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_MassReencrypt(SealdSdk* sealdSdk, char* deviceId, SealdMassReencryptOptions options, SealdMassReencryptResponse* result, SealdError** error);

/**
 * List which of the devices of the current account are missing keys,
 * so you can call SealdSdk_MassReencrypt for them.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param forceLocalAccountUpdate Whether to update the local account. `1` to update, `0` to not update.
 * @param result A pointer to a SealdDeviceMissingKeysArray*, in which to write the result.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_DevicesMissingKeys(SealdSdk* sealdSdk, int forceLocalAccountUpdate, SealdDeviceMissingKeysArray** result, SealdError** error);

/**
 * Get a user's sigchain transaction hash at index `position`.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param userId The Seald ID of the concerned user.
 * @param position Get the hash at the given position. -1 to get the last. Default to -1.
 * @param result A pointer to a SealdGetSigchainResponse*, in which to write the result.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_GetSigchainHash(SealdSdk* sealdSdk, char* userId, int position, SealdGetSigchainResponse** result, SealdError** error);

/**
 * Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param userId The Seald ID of the concerned user.
 * @param expectedHash The expected sigchain hash.
 * @param position Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
 * @param result A pointer to a SealdCheckSigchainResponse*, in which to write the result.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_CheckSigchainHash(SealdSdk* sealdSdk, char* userId, char* expectedHash, int position, SealdCheckSigchainResponse** result, SealdError** error);

/**
 * Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
 * All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
 *
 * @param sealdSdk The SealdSdk instance.
 * @param tmrJWT The TMR JWT.
 * @param overEncryptionKey The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param overEncryptionKeyLen The length of overEncryptionKey.
 * @param conversionFilters Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
 * @param deleteOnConvert Whether or not to delete the TMR access after conversion. `1` to delete, `0` otherwise.
 * @param result A pointer where to a SealdConvertTmrAccessesResult
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSdk_ConvertTmrAccesses(SealdSdk* sealdSdk, char* tmrJWT, unsigned char* overEncryptionKey, int overEncryptionKeyLen, SealdTmrAccessesConvertFilters* conversionFilters, int deleteOnConvert, SealdConvertTmrAccessesResult** result, SealdError** error);

// Helper SealdSsksTMRPluginInitializeOptions

/**
 * SealdSsksTMRPluginInitializeOptions is the main options object for initializing the SDK instance
 */
typedef struct {
    /** SsksURL is the SSKS server for this instance to use. This value is given on your Seald dashboard. */
    char* SsksURL;
    /** AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard. */
    char* AppId;
    /** LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. */
    signed char LogLevel;
    /** LogNoColor should be set to `0` if you want to enable colors in the log output, `1` if you don't. */
    int LogNoColor;
    /** InstanceName is an arbitrary name to give to this SealdSsksTMRPlugin instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. */
    char* InstanceName;
    /** Platform is a name that references the platform on which the SealdSsksTMRPlugin is running. */
    char* Platform;
} SealdSsksTMRPluginInitializeOptions;

// Helper SealdSsksTMRPluginSaveIdentityResponse

/**
 * SealdSsksTMRPluginSaveIdentityResponse is returned by SealdSsksTMRPlugin_SaveIdentity when an identity has been successfully saved
 */
typedef struct {
    /** The SSKS ID of the stored identity, which can be used by your backend to manage it. */
    char* SsksId;
    /** If a challenge was passed, an authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge. */
    char* AuthenticatedSessionId;
} SealdSsksTMRPluginSaveIdentityResponse;

void SealdSsksTMRPluginSaveIdentityResponse_Free(SealdSsksTMRPluginSaveIdentityResponse* resp);

// Helper SealdSsksTMRPluginRetrieveIdentityResponse

/**
 * SealdSsksTMRPluginRetrieveIdentityResponse holds a retrieved identity
 */
typedef struct {
    /** The retrieved identity. It can be used with `SealdSdk_ImportIdentity` */
    unsigned char* Identity;
    /** IdentityLen The Identity length. */
    int IdentityLen;
    /** If the boolean ShouldRenewKey is set to 1, the account MUST renew its private key using `SealdSdk_RenewKeys` */
    int ShouldRenewKey;
    /** An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge. */
    char* AuthenticatedSessionId;
} SealdSsksTMRPluginRetrieveIdentityResponse;

void SealdSsksTMRPluginRetrieveIdentityResponse_Free(SealdSsksTMRPluginRetrieveIdentityResponse* resp);

// Helper SealdSsksTMRPluginGetFactorTokenResponse

/**
 * SealdSsksTMRPluginGetFactorTokenResponse holds a retrieved authentication factor token
 */
typedef struct {
    /** The retrieved token. It can be used with `SealdSdk_RetrieveEncryptionSessionByTmr` and `SealdSdk_ConvertTmrAccesses` */
    char* Token;
    /** An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge. */
    char* AuthenticatedSessionId;
} SealdSsksTMRPluginGetFactorTokenResponse;

void SealdSsksTMRPluginGetFactorTokenResponse_Free(SealdSsksTMRPluginGetFactorTokenResponse* resp);

// SealdSsksTMRPlugin

/**
 * SealdSsksTMRPlugin represents the Seald SSKS TMR plugin
 */
typedef struct SealdSsksTMRPlugin SealdSsksTMRPlugin;

/**
 * Initialize an instance of Seald SSKS TMR plugin.
 *
 * @param options A pointer to a SealdSsksTMRPluginInitializeOptions instance.
 * @param result A pointer to a SealdSsksTMRPlugin* to store the created plugin instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksTMRPlugin_Initialize(SealdSsksTMRPluginInitializeOptions* options, SealdSsksTMRPlugin** result, SealdError** error);

/**
 * Close the current SSKS TMR plugin instance. This  frees the memory.
 * After calling close, the instance cannot be used anymore.
 *
 * @param tmrPlugin The SSKS TMR plugin instance.
 */
void SealdSsksTMRPlugin_Free(SealdSsksTMRPlugin* tmrPlugin);

/**
 * Save the Seald account to SSKS.
 *
 * @param tmrPlugin The SSKS TMR plugin instance.
 * @param sessionId The user's session ID.
 * @param authFactorType The type of authentication factor. Can be "EM" or "SMS".
 * @param authFactorValue The value of authentication factor.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param rawTMRSymKeyLen The length of rawTMRSymKey.
 * @param identity The identity to save.
 * @param identityLen The length of identity.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param result A pointer to a SealdSsksTMRPluginSaveIdentityResponse*.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksTMRPlugin_SaveIdentity(SealdSsksTMRPlugin* tmrPlugin, char* sessionId, char* authFactorType, char* authFactorValue, unsigned char* rawTMRSymKey, int rawTMRSymKeyLen, unsigned char* identity, int identityLen, char* challenge, SealdSsksTMRPluginSaveIdentityResponse** result, SealdError** error);

/**
 * Retrieve the Seald account previously saved with `SealdSsksTMRPlugin_SaveIdentity`.
 *
 * @param tmrPlugin The SSKS TMR plugin instance.
 * @param sessionId The user's session ID.
 * @param authFactorType The type of authentication factor. Can be "EM" or "SMS".
 * @param authFactorValue The value of authentication factor.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param rawTMRSymKeyLen The length of rawTMRSymKey.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param result A pointer to a SealdSsksTMRPluginRetrieveIdentityResponse*.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksTMRPlugin_RetrieveIdentity(SealdSsksTMRPlugin* tmrPlugin, char* sessionId, char* authFactorType, char* authFactorValue, unsigned char* rawTMRSymKey, int rawTMRSymKeyLen, char* challenge, SealdSsksTMRPluginRetrieveIdentityResponse** result, SealdError** error);

/**
 * Retrieve the TMR JWT associated with an authentication factor.
 *
 * @param tmrPlugin The SSKS TMR plugin instance.
 * @param sessionId The user's session ID.
 * @param authFactorType The type of authentication factor. Can be "EM" or "SMS".
 * @param authFactorValue The value of authentication factor.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param result A pointer to a SealdSsksTMRPluginGetFactorTokenResponse*.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksTMRPlugin_GetFactorToken(SealdSsksTMRPlugin* tmrPlugin, char* sessionId, char* authFactorType, char* authFactorValue, char* challenge, SealdSsksTMRPluginGetFactorTokenResponse** result, SealdError** error);

// Helper SealdSsksPasswordPluginInitializeOptions

/**
 * SealdSsksPasswordPluginInitializeOptions is the main options object for initializing the SDK instance.
 */
typedef struct {
    /** SsksURL is the SSKS server for this instance to use. This value is given on your Seald dashboard. */
    char* SsksURL;
    /** AppId is the ID given by the Seald server to your app. This value is given on your Seald dashboard. */
    char* AppId;
    /** LogLevel is the minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. */
    signed char LogLevel;
    /** LogNoColor should be set to `0` if you want to enable colors in the log output, `1` if you don't. */
    int LogNoColor;
    /** InstanceName is an arbitrary name to give to this SealdSsksPasswordPlugin instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. */
    char* InstanceName;
    /** Platform is a name that references the platform on which the SealdSsksPasswordPlugin is running. */
    char* Platform;
} SealdSsksPasswordPluginInitializeOptions;

// SealdSsksPasswordPlugin

/**
 * SealdSsksPasswordPlugin represents the Seald SSKS Password plugin
 */
typedef struct SealdSsksPasswordPlugin SealdSsksPasswordPlugin;

/**
 * Initialize an instance of Seald SSKS Password plugin.
 *
 * @param options A pointer to a SealdSsksPasswordPluginInitializeOptions instance.
 * @param result A pointer to a SealdSsksPasswordPlugin* to store the created plugin instance.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_Initialize(SealdSsksPasswordPluginInitializeOptions* options, SealdSsksPasswordPlugin** result, SealdError** error);

/**
 * Close the current SSKS Password plugin instance. This  frees the memory.
 * After calling close, the instance cannot be used anymore.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 */
void SealdSsksPasswordPlugin_Free(SealdSsksPasswordPlugin* passwordPlugin);

/**
 * Save the given identity for the given userId, encrypted with the given password.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 * @param userId The ID of the user.
 * @param password The password to encrypt the key.
 * @param identity The identity to save.
 * @param identityLen The length of identity.
 * @param result A pointer where to store the SSKS ID of the stored identity, which can be used by your backend to manage it.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_SaveIdentityFromPassword(SealdSsksPasswordPlugin* passwordPlugin, char* userId, char* password, unsigned char* identity, int identityLen, char** result, SealdError** error);

/**
 * Save the given identity for the given userId, encrypted with the given raw keys.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 * @param userId The ID of the user.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param rawEncryptionKeyLen The length of rawEncryptionKey.
 * @param identity The identity to save.
 * @param identityLen The length of identity.
 * @param result A pointer where to store the SSKS ID of the stored identity, which can be used by your backend to manage it.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_SaveIdentityFromRawKeys(SealdSsksPasswordPlugin* passwordPlugin, char* userId, char* rawStorageKey, unsigned char* rawEncryptionKey, int rawEncryptionKeyLen, unsigned char* identity, int identityLen, char** result, SealdError** error);

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 * @param userId The ID of the userId.
 * @param password The password to encrypt the key.
 * @param retrievedIdentity A pointer where to store the retrieved identity.
 * @param retrievedIdentityLen A pointer where to store the length of the retrieved identity.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(SealdSsksPasswordPlugin* passwordPlugin, char* userId, char* password, unsigned char** retrievedIdentity, int* retrievedIdentityLen, SealdError** error);

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 * @param userId The ID of the userId.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
 * @param rawEncryptionKeyLen The length of rawEncryptionKey.
 * @param retrievedIdentity A pointer where to store the retrieved identity.
 * @param retrievedIdentityLen A pointer where to store the length of the retrieved identity.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys(SealdSsksPasswordPlugin* passwordPlugin, char* userId, char* rawStorageKey, unsigned char* rawEncryptionKey, int rawEncryptionKeyLen, unsigned char** retrievedIdentity, int* retrievedIdentityLen, SealdError** error);

/**
 * Change the password use to encrypt the identity for the userId.
 *
 * @param passwordPlugin The SSKS Password plugin instance.
 * @param userId The ID of the userId.
 * @param currentPassword The user's current password.
 * @param newPassword The new password.
 * @param result A pointer where to store the new SSKS ID of the stored identity.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdSsksPasswordPlugin_ChangeIdentityPassword(SealdSsksPasswordPlugin* passwordPlugin, char* userId, char* currentPassword, char* newPassword, char** result, SealdError** error);

// SealdUtils

/**
 * Takes the path to an encrypted file, and returns the session id.
 *
 * @param file Path to the encrypted file.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdUtils_ParseSessionIdFromFile(char* encryptedFilePath, char** result, SealdError** error);

/**
 * Takes an encrypted file as bytes, and returns the session id.
 *
 * @param fileBytes The encrypted file as bytes.
 * @param fileBytesLen The length of fileBytes.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdUtils_ParseSessionIdFromBytes(unsigned char* fileBytes, int fileBytesLen, char** result, SealdError** error);

/**
 * Takes an encrypted message, and returns the session id.
 *
 * @param message The encrypted message.
 * @param result A pointer to which to write the response.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Error code: `-1` if an error happened, `0` for success.
 */
int SealdUtils_ParseSessionIdFromMessage(char* message, char** result, SealdError** error);

/**
 * Internal function. Do not use directly.
 */
int SealdUtils_PKCS1DERtoPKCS8(char* pkcs1DerRsaKey, char** result, SealdError** error);

/**
 * Internal function. Do not use directly.
 */
int SealdUtils_GeneratePrivateKey(int size, char** result, SealdError** error);

#endif // LIB_SEALD_SDK_H
