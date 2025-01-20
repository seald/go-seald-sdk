//
//  Helpers.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#ifndef Helpers_h
#define Helpers_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>

NS_ASSUME_NONNULL_BEGIN

/** Error domain for Seald operations */
extern NSString*const SealdErrorDomain;

/**
 * Seald errors do not use the native NSError's `code` property.
 * Instead, Seald errors will contain its details in the NSError's userInfo, with the following properties:
 * - `status`: If the error is returned by the Seald server, the HTTP status code.
 * - `code`: The error code, which is a machine-readable string that represents this error. Note: This is different from the 'code' property inherited from NSError which is an NSInteger.
 * - `id`: The error ID, which is a unique string for the precise place this error was thrown from.
 * - `description`: A human-readable description of the error.
 * - `details`: Details about the error.
 * - `raw`: The raw underlying error.
 * - `nativeStack`: The call stack in Seald native code.
 */
typedef NS_ENUM (NSInteger, SealdErrorCode) {
    SealdErrorCodeSealdError = -1,
};

/**
 * Represents a set of pre-generated private keys.
 * Returned by SealdSdk.generatePrivateKeys.
 * Can be passed to functions that need private keys.
 */
typedef SealdSdkInternalsMobile_sdkPreGeneratedKeys SealdGeneratedPrivateKeys;

/** \cond */
void _SealdInternal_ConvertError(NSError* originalError, NSError*_Nullable* errorPtr);

SealdSdkInternalsMobile_sdkStringArray* arrayToStringArray(const NSArray<NSString*>* stringArray);

NSArray<NSString*>* stringArrayToArray(SealdSdkInternalsMobile_sdkStringArray* stringArray);
/** \endcond */

/**
 * SealdClearFile represents a decrypted file.
 */
@interface SealdClearFile : NSObject
/** The filename of the decrypted file */
@property (atomic, strong, readonly) NSString* filename;
/** The ID of the EncryptionSession to which this file belongs */
@property (atomic, strong, readonly) NSString* messageId;
/** The content of the decrypted file */
@property (atomic, strong, readonly) NSData* fileContent;
/** \cond */
- (instancetype) initWithFilename:(NSString*)filename
                        messageId:(NSString*)messageId
                      fileContent:(NSData*)fileContent;
/** \endcond */
@end

/**
 * SealdAccountInfo is returned when calling SealdSdk.createAccountWithSignupJwt:deviceName:displayName:expireAfter:error:
 * or SealdSdk.getCurrentAccountInfo, containing information about the local account.
 */
@interface SealdAccountInfo : NSObject
/** The ID of the current user for this SDK instance. */
@property (atomic, strong, readonly) NSString* userId;
/** The ID of the current device for this SDK instance. */
@property (atomic, strong, readonly) NSString* deviceId;
/** The date at which the current device keys expire. For continued operation, renew your device keys before this date. `nil` if it is not known locally: use SealdSdk.updateCurrentDeviceWithError: to retrieve it. */
@property (atomic, strong, readonly) NSDate* deviceExpires;
/** \cond */
- (instancetype) initWithUserId:(NSString*)userId
                       deviceId:(NSString*)deviceId
                  deviceExpires:(NSDate*)deviceExpires;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkAccountInfo*)accountInfo;
/** \endcond */
@end

/**
 * SealdCreateSubIdentityResponse represents a newly created sub identity.
 */
@interface SealdCreateSubIdentityResponse : NSObject
/** The ID of the newly created device. */
@property (atomic, strong, readonly) NSString* deviceId;
/** The identity export of the newly created sub-identity. */
@property (atomic, strong, readonly) NSData* backupKey;
/** \cond */
- (instancetype) initWithDeviceId:(NSString*)deviceId
                        backupKey:(NSData*)backupKey;
/** \endcond */
@end


/**
 * SealdBeardError represents an error returned by the server.
 * It contains a specific `id` and `code` to determine the underlying reason.
 */
@interface SealdBeardError : NSObject
/** The error id. */
@property (atomic, strong, readonly) NSString* errorId;
/** The error code. */
@property (atomic, strong, readonly) NSString* code;
/** \cond */
- (instancetype) initWithId:(NSString*)errorId
                       code:(NSString*)code;
/** \endcond */
@end


/**
 * SealdAddKeysResponse represents the result when trying to add a session key for one recipient's device.
 */
@interface SealdAddKeysResponse : NSObject
/** The "http-like" status code of the request for this specific recipient's device. */
@property (atomic, assign, readonly) NSInteger statusCode;
/** The error that happened while trying to add a key for this recipient's device, if any. */
@property (atomic, strong, readonly) SealdBeardError* error;
/** \cond */
- (instancetype) initWithStatusCode:(NSInteger)statusCode
                              error:(SealdBeardError*)error;
/** \endcond */
@end

/**
 * SealdConnectorTypeValue is a simplified representation of a connector for which we don't know all details.
 */
@interface SealdConnectorTypeValue : NSObject
/** The type of the connector. */
@property (atomic, strong, readonly) NSString* type;
/** The value of the connector. */
@property (atomic, strong, readonly) NSString* value;
/**
 * Initialize a SealdConnectorTypeValue instance.
 *
 * @param type The type of the connector.
 * @param value The value of the connector.
 */
- (instancetype) initWithType:(NSString*)type
                        value:(NSString*)value;
/** \cond */
- (SealdSdkInternalsMobile_sdkConnectorTypeValue*) toMobileSdk;
+ (SealdSdkInternalsMobile_sdkConnectorTypeValueArray*) toMobileSdkArray:(NSArray<SealdConnectorTypeValue*>*)connectorsArray;
/** \endcond */
@end

/**
 * SealdConnector represents all details about a connector.
 */
@interface SealdConnector : NSObject
/** The seald ID of the associated user. */
@property(atomic, strong, readonly) NSString* sealdId;
/** The type of the connector. */
@property(atomic, strong, readonly) NSString* type;
/** The value of the connector. */
@property(atomic, strong, readonly) NSString* value;
/** The ID of the connector. */
@property(atomic, strong, readonly) NSString* connectorId;
/** The state of the connector. */
@property(atomic, strong, readonly) NSString* state;
/** \cond */
- (instancetype) initWithSealdId:(NSString*)sealdId
                            type:(NSString*)type
                           value:(NSString*)value
                     connectorId:(NSString*)connectorId
                           state:(NSString*)state;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkConnector*)c;
+ (NSArray<SealdConnector*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkConnectorsArray*)connectorsArray;
+ (SealdSdkInternalsMobile_sdkConnectorsArray*) toMobileSdkArray:(NSArray<SealdConnector*>*)connectorsArray;
- (SealdSdkInternalsMobile_sdkConnector*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdPreValidationToken represents a way for your server to authorize the adding of a connector.
 */
@interface SealdPreValidationToken : NSObject
@property (atomic, strong, readonly) NSString* domainValidationKeyId;
@property (atomic, strong, readonly) NSString* nonce;
@property (atomic, strong, readonly) NSString* token;
/** \cond */
- (instancetype) initWithDomainValidationKeyId:(NSString*)domainValidationKeyId
                                         nonce:(NSString*)nonce
                                         token:(NSString*)token;
- (SealdSdkInternalsMobile_sdkPreValidationToken*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdMassReencryptOptions represents options for SealdSdk.massReencryptWithDeviceId:options:error: function.
 */
@interface SealdMassReencryptOptions : NSObject
/** Number of times to retry. Defaults to 3. */
@property (atomic, assign) NSInteger retries;
/** Default to 1000. */
@property (atomic, assign) NSInteger retrieveBatchSize;
/** Time to wait between retries. Defaults to 3 seconds. */
@property (atomic, assign) NSTimeInterval waitBetweenRetries;
/** Whether to wait for provisioning (new behaviour) or not. Defaults to `YES`. */
@property (atomic, assign) BOOL waitProvisioning;
/** Time to wait if device is not provisioned on the server yet. The actual wait time will be increased on subsequent tries, by `waitProvisioningTimeStep`, up to `waitProvisioningTimeMax`. Defaults to 5 seconds. */
@property (atomic, assign) NSTimeInterval waitProvisioningTime;
/** Maximum time to wait if device is not provisioned on the server yet. Defaults to 10 seconds. */
@property (atomic, assign) NSTimeInterval waitProvisioningTimeMax;
/** Amount to increase the time to wait if device is not provisioned on the server yet. Defaults to 1 second. */
@property (atomic, assign) NSTimeInterval waitProvisioningTimeStep;
/** Maximum number of tries to check if the device is provisioned yet. Defaults to 100. */
@property (atomic, assign) NSInteger waitProvisioningRetries;
/** Whether to update the local account before trying the reencryption. Defaults to `NO`. */
@property (atomic, assign) BOOL forceLocalAccountUpdate;
/**
 * Initialize a SealdMassReencryptOptions instance with default values.
 */
- (instancetype) init;
/** \cond */
- (SealdSdkInternalsMobile_sdkMassReencryptOptions*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdMassReencryptResponse represents the results of a call to SealdSdk.massReencryptWithDeviceId:options:error:.
 */
@interface SealdMassReencryptResponse : NSObject
/** The number of session keys that were reencrypted for the given device. */
@property (atomic, assign, readonly) NSInteger reencrypted;
/** The number of session keys that could not be reencrypted for the given device. */
@property (atomic, assign, readonly) NSInteger failed;
/** \cond */
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkMassReencryptResponse*)d;
- (instancetype) initWithReencrypted:(NSInteger)reencrypted
                              failed:(NSInteger)failed;
/** \endcond */
@end

/**
 * SealdDeviceMissingKeys represents a device of the current account which is missing some keys,
 * and for which you probably want to call SealdSdk.massReencryptWithDeviceId:options:error:.
 */
@interface SealdDeviceMissingKeys : NSObject
/** The ID of the device which is missing some keys. */
@property (nonatomic, strong, readonly) NSString* deviceId;
/** \cond */
- (instancetype) initWithDeviceId:(NSString*)deviceId;
+ (SealdDeviceMissingKeys*) fromMobileSdk:(SealdSdkInternalsMobile_sdkDeviceMissingKeys*)d;
+ (NSArray<SealdDeviceMissingKeys*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkDevicesMissingKeysArray*)array;
/** \endcond */
@end


/**
 * SealdActionStatus represents the status of an operation on single user/device.
 */
@interface SealdActionStatus : NSObject
/** The status of the action: true if succeeded, false otherwise. */
@property (atomic, assign) bool success;
/** An error message, or an empty string. */
@property (atomic, strong) NSString* errorCode;
/** The result of the action. */
@property (atomic, strong) NSString* result;
/** \cond */
+ (NSDictionary<NSString*,SealdActionStatus*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkActionStatusArray*)array;
/** \endcond */
@end

/**
 * SealdRevokeResult represents the result of a revocation operation.
 */
@interface SealdRevokeResult : NSObject
/** The Seald recipients the revocation operation acted on. */
@property (atomic, strong, readonly) NSDictionary<NSString*,SealdActionStatus*>* recipients;
/** The proxy sessions the revocation operation acted on. */
@property (atomic, strong, readonly) NSDictionary<NSString*,SealdActionStatus*>* proxySessions;
/** \cond */
- (instancetype) initWithRecipients:(NSDictionary<NSString*,SealdActionStatus*>*)recipients
                      proxySessions:(NSDictionary<NSString*,SealdActionStatus*>*)proxySessions;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkRevokeResult*)revokeResult;
/** \endcond */
@end

/**
 * SealdRecipientRights represents the rights a user can have over an encrypted message or an encryption session.
 *
 */
@interface SealdRecipientRights : NSObject
/** The right to read the message */
@property (atomic, assign) BOOL read;
/** The right to forward the message to another user */
@property (atomic, assign) BOOL forward;
/** The right to revoke another user from a message, or to remove rights from them */
@property (atomic, assign) BOOL revoke;
/**
 * Initialize a SealdRecipientRights instance.
 *
 * @param read Set the right to read the message.
 * @param forward Set the right to forward the message to another user.
 * @param revoke Set the right to revoke another user from a message, or to remove rights from them.
 */
- (instancetype) initWithRead:(BOOL)read
                      forward:(BOOL)forward
                       revoke:(BOOL)revoke;
- (instancetype) initWithDefaultRights;
/** \cond */
- (SealdSdkInternalsMobile_sdkRecipientRights*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdRecipientWithRights represents a recipient with associated rights.
 * Default rights are: read: true, forward: true, revoke: false
 * Default rights for the current user when creating an encryptionSession are read: true, forward: true, revoke: true
 */
@interface SealdRecipientWithRights : NSObject
/** Internal Seald IDs. Returned for users with `sdk.getCurrentAccountInfo`, for groups when creating them */
@property (atomic, strong) NSString* recipientId;
/** The rights for the associated recipient ID */
@property (atomic, strong) SealdRecipientRights* rights;
/**
 * Initialize a SealdRecipientWithRights instance.
 *
 * @param recipientId The sealdId of the recipient.
 * @param rights The rights for the associated recipient ID.
 */
- (instancetype) initWithRecipientId:(NSString*)recipientId
                              rights:(SealdRecipientRights*_Nullable)rights;
/**
 * Initialize a SealdRecipientWithRights instance with the default rights.
 *
 * @param recipientId The sealdId of the recipient.
 */
- (instancetype) initWithRecipientId:(NSString*)recipientId;
/** \cond */
- (SealdSdkInternalsMobile_sdkRecipientWithRights*) toMobileSdk;
+ (SealdSdkInternalsMobile_sdkRecipientsWithRightsArray*) toMobileSdkArray:(NSArray<SealdRecipientWithRights*>*)rwrArray;
/** \endcond */
@end

/**
 * SealdEncryptionSessionRetrievalFlow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session
 */
typedef NS_ENUM (NSInteger, SealdEncryptionSessionRetrievalFlow) {
    /** The session was created locally. */
    SealdEncryptionSessionRetrievalCreated = 0,
    /** The session was retrieved as a direct recipient. */
    SealdEncryptionSessionRetrievalDirect = 1,
    /** The session was retrieved as a member of a group. */
    SealdEncryptionSessionRetrievalViaGroup = 2,
    /** The session was retrieved through a proxy session. */
    SealdEncryptionSessionRetrievalViaProxy = 3,
    /** The session was retrieved through a TMR access. */
    SealdEncryptionSessionRetrievalViaTmrAccess = 4
};

/**
 * SealdEncryptionSessionRetrievalDetails represents the details of how an Encryption Session was retrieved.
 */
@interface SealdEncryptionSessionRetrievalDetails : NSObject
/** The way the session was retrieved: as a direct recipient, as a member of a group, or through a proxy session. */
@property (atomic, assign, readonly) SealdEncryptionSessionRetrievalFlow flow;
/** If the session was retrieved as a member of a group, the ID of the group in question. Null if not applicable. */
@property (atomic, strong, readonly) NSString* groupId;
/** If the session was retrieved through a proxy session, the ID of this proxy session. Null if not applicable. */
@property (atomic, strong, readonly) NSString* proxySessionId;
/** Indicates if this session was retrieved from the cache. */
@property (atomic, assign, readonly) BOOL fromCache;
/** \cond */
- (instancetype) initWithFlow:(SealdEncryptionSessionRetrievalFlow)flow
                      groupId:(NSString*)groupId
               proxySessionId:(NSString*)proxySessionId
                    fromCache:(BOOL)fromCache;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkEncryptionSessionRetrievalDetails*)details;
/** \endcond */
@end

/**
 * SealdGetSigchainResponse is returned when calling SealdSdk.getSigchainHashWithUserId:position:error:
 * containing the hash value and the position of the hash in the sigchain.
 */
@interface SealdGetSigchainResponse : NSObject
/** The sigchain hash. */
@property (atomic, strong, readonly) NSString* sigchainHash;
/** The position of the associated hash in the sigchain */
@property (atomic, readonly) NSInteger position;
/** \cond */
- (instancetype) initWithSigchainHash:(NSString*)sigchainHash
                             position:(NSInteger)position;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGetSigchainResponse*)nativeResp;
/** \endcond */
@end

/**
 * SealdCheckSigchainResponse is returned when calling SealdSdk.checkSigchainHashWithUserId:expectedHash:position:error:
 * containing if the hash was found in the sigchain or not.
 *
 * If the hash was found, it also contain at which position it was found. 0 otherwise.
 */
@interface SealdCheckSigchainResponse : NSObject
/** Whether or not the hash was found in the user's sigchain. */
@property (atomic, assign, readonly) BOOL found;
/** The position in the sigchain where the expected hash was found */
@property (atomic, readonly) NSInteger position;
/** The number of transaction in the sigchain */
@property (atomic, readonly) NSInteger lastPosition;
/** \cond */
- (instancetype) initWithFound:(BOOL)hash
                      position:(NSInteger)position
                  lastPosition:(NSInteger)lastPosition;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkCheckSigchainResponse*)nativeResp;
/** \endcond */
@end

/**
 * SealdTmrAuthFactor represents a user's authentication factor
 */
@interface SealdTmrAuthFactor : NSObject
/** The value of the authentication factor */
@property (nonatomic, readonly) NSString* value;
/** The type of authentication factor. Either `@"EM"` or `@"SMS"` */
@property (nonatomic, readonly) NSString* type;
/**
 * Initialize a SealdTmrAuthFactor instance.
 *
 * @param value The value of the authentication factor.
 * @param type The type of authentication factor.
 */
- (instancetype) initWithValue:(NSString*)value
                          type:(NSString*)type;
/** \cond */
- (SealdSdkInternalsMobile_sdkAuthFactor*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdTmrRecipientWithRights represents a TMR recipient with associated rights.
 *
 */
@interface SealdTmrRecipientWithRights : NSObject
/** The authentication method, to which SSKS has sent a challenge at the request of your app's server. */
@property (atomic, strong) SealdTmrAuthFactor* authFactor;
/** The rights for the associated authentication factor */
@property (atomic, strong) SealdRecipientRights* rights;
/** The over encryption key. */
@property (atomic, strong) NSData* overEncryptionKey;
/**
 * Initialize a SealdTmrRecipientWithRights instance.
 *
 * @param authFactor The authentication factor.
 * @param overEncryptionKey The over encryption key.
 * @param rights The rights for the associated authentication factor.
 */
- (instancetype) initWithAuthFactor:(SealdTmrAuthFactor*)authFactor
                  overEncryptionKey:(NSData*)overEncryptionKey
                             rights:(SealdRecipientRights*_Nullable)rights;
/**
 * Initialize a SealdTmrRecipientWithRights instance with the default rights.
 *
 * @param authFactor The authentication factor.
 * @param overEncryptionKey The over encryption key.
 */
- (instancetype) initWithAuthFactor:(SealdTmrAuthFactor*)authFactor
                  overEncryptionKey:(NSData*)overEncryptionKey;
/** \cond */
- (SealdSdkInternalsMobile_sdkTmrRecipientWithRights*) toMobileSdk;
+ (SealdSdkInternalsMobile_sdkTmrRecipientWithRightsArray*) toMobileSdkArray:(NSArray<SealdTmrRecipientWithRights*>*)rwrArray
                                                                       error:(NSError*_Nullable*)error;
/** \endcond */
@end

/**
 * SealdTmrAccessesRetrievalFilters holds the tmr accesses filters used when retrieving an EncryptionSession.
 */
@interface SealdTmrAccessesRetrievalFilters : NSObject
/** SealdId of the user who created the TMR access. */
@property (atomic, assign, readonly) NSString* createdById;
/** Id of the TMR access to use.*/
@property (atomic, assign, readonly) NSString* tmrAccessId;
/**
 * Initialize a SealdTmrAccessesRetrievalFilters instance.
 *
 * @param createdById The SealdId of the user who created the TMR accesses to convert.
 * @param tmrAccessId The Id of the TMR access to convert.
 */
- (instancetype) initWithCreatedById:(NSString*)createdById
                         tmrAccessId:(NSString*)tmrAccessId;
/** \cond */
- (SealdSdkInternalsMobile_sdkTmrAccessesRetrievalFilters*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdTmrAccessesConvertFilters holds the tmr accesses filters used when converting TMR accesses.
 */
@interface SealdTmrAccessesConvertFilters : NSObject
/** Id of the session with the TMR access to convert. */
@property (atomic, assign, readonly) NSString* sessionId;
/** SealdId of the user who created the TMR accesses to convert. */
@property (atomic, assign, readonly) NSString* createdById;
/** Id of the TMR access to convert.*/
@property (atomic, assign, readonly) NSString* tmrAccessId;
/**
 * Initialize a SealdTmrAccessesConvertFilters instance.
 *
 * @param sessionId The sessionId with the TMR access to convert.
 * @param createdById The SealdId of the user who created the TMR accesses to convert.
 * @param tmrAccessId The Id of the TMR access to convert

 */
- (instancetype) initWithSessionId:(NSString*)sessionId
                       createdById:(NSString*)createdById
                       tmrAccessId:(NSString*)tmrAccessId;
/** \cond */
- (SealdSdkInternalsMobile_sdkTmrAccessesConvertFilters*) toMobileSdk;
/** \endcond */
@end

/**
 * SealdConvertTmrAccessesResult is returned when calling SealdSdk.convertTmrAccesses:token:overEncryptionKey:conversionFilters:deleteOnConvert:error:.
 * containing the result of conversion
 */
@interface SealdConvertTmrAccessesResult : NSObject
/** Status of the conversion `ok` or `ko`. */
@property (atomic, assign, readonly) NSString* status;
/** The number of conversions that succeeded. */
@property (atomic, readonly) NSInteger succeeded;
/** The number of conversions that failed. */
@property (atomic, readonly) NSInteger errored;
/** IDs of the accesses that were fully converted. */
@property (atomic, readonly) NSArray<NSString*>* converted;
/** \cond */
- (instancetype) initWithStatus:(NSString*)status
                      succeeded:(NSInteger)succeeded
                        errored:(NSInteger)errored
                      converted:(NSArray<NSString*>*)converted;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkConvertTmrAccessesResponse*)nativeResp;
/** \endcond */
@end



/**
 * SealdGroupTmrTemporaryKey holds the information about a group TMR temporary key.
 */
@interface SealdGroupTmrTemporaryKey : NSObject
/** Id of the TMR key. */
@property (atomic, readonly) NSString* keyId;
/** The id of the group. */
@property (atomic, readonly) NSString* groupId;
/** Does that key give the admin status. */
@property (atomic, readonly) BOOL isAdmin;
/** Id of the user who created this key. */
@property (atomic, readonly) NSString* createdById;
/** The type of authentication factor. */
@property (atomic, readonly) NSString* authFactorType;
/** Date of creation. */
@property (atomic, readonly) NSTimeInterval* created;
/** \cond */
- (instancetype) initWithKeyId:(NSString*)keyId
                       groupId:(NSString*)groupId
                       isAdmin:(BOOL)isAdmin
                   createdById:(NSString*)createdById
                       created:(NSTimeInterval)created
                authFactorType:(NSString*)authFactorType;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGroupTMRTemporaryKey*)nativeResp;
/** \endcond */
@end

/**
 * SealdListedGroupTMRTemporaryKeys holds a list of GroupTmrTemporaryKey.
 */
@interface SealdListedGroupTMRTemporaryKeys : NSObject
/** Number of pages found. */
@property (atomic, readonly) NSInteger nbPage;
/** Temporary keys found. */
@property (atomic, readonly) NSArray<SealdGroupTmrTemporaryKey*>* keys;
/** \cond */
- (instancetype) initWithNbPage:(NSInteger)nbPage
                           keys:(NSArray<SealdGroupTmrTemporaryKey*>*)keys;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkListedGroupTMRTemporaryKeys*)nativeResp;
/** \endcond */
@end

/**
 * SealdSearchGroupTMRTemporaryKeys holds the tmr filters used when searching group TMR temporary keys.
 */
@interface SealdSearchGroupTMRTemporaryKeys : NSObject
/** Return only the TMR temporary keys that give access to this groupId. */
@property (atomic, assign, readonly) NSString* groupId;
/** Page to return. */
@property (atomic, assign, readonly) NSInteger page;
/** Should return all pages after `Page`. */
@property (atomic, assign, readonly) BOOL all;
/** \cond */
- (SealdSdkInternalsMobile_sdkSearchGroupTMRTemporaryKeysOpts*) toMobileSdk;
/** \endcond */
@end
NS_ASSUME_NONNULL_END

#endif /* Helpers_h */
