//
//  SealdSdk.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#ifndef SealdSdk_h
#define SealdSdk_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>
#import "Helpers.h"
#import "SealdEncryptionSession.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * This is the main class for the Seald SDK. It represents an instance of the Seald SDK.
 */
@interface SealdSdk : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileSDK* sdkInstance;
    NSInteger keySize;
    /** \endcond */
}
/**
 * Initialize a Seald SDK Instance.
 *
 * @param apiUrl The Seald server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param databasePath The path where to store the local Seald database. If no path is passed, uses an in-memory only database.
 * @param databaseEncryptionKey The encryption key with which to encrypt the local Seald database. Required when passing `databasePath`. This **must** be a cryptographically random NSData of 64 bytes.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `NO` if you want to enable colors in the log output, `YES` if you don't.
 * @param encryptionSessionCacheTTL The duration of cache lifetime. `-1` to cache forever. Default to `0` (no cache).
 * @param keySize The Asymmetric key size for newly generated keys. Defaults to 4096. Warning: for security, it is extremely not recommended to lower this value.
 * @param error Error pointer.
 */
- (instancetype) initWithApiUrl:(const NSString*)apiUrl
                          appId:(const NSString*)appId
                   databasePath:(const NSString*_Nullable)databasePath
          databaseEncryptionKey:(const NSData*_Nullable)databaseEncryptionKey
                   instanceName:(const NSString*)instanceName
                       logLevel:(const NSInteger)logLevel
                     logNoColor:(const BOOL)logNoColor
      encryptionSessionCacheTTL:(const NSTimeInterval)encryptionSessionCacheTTL
                        keySize:(const NSInteger)keySize
                          error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Close the current SDK instance. This frees any lock on the current database. After calling close, the instance cannot be used anymore.
 *
 * @param error Error pointer.
 */
- (void) closeWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Close the current SDK instance. This frees any lock on the current database. After calling close, the instance cannot be used anymore.
 *
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) closeAsyncWithCompletionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Generate private keys.
 *
 * @param error Error pointer.
 * @return A SealdGeneratedPrivateKeys instance that can be used with methods that need private keys.
 */
- (SealdGeneratedPrivateKeys*) generatePrivateKeysWithError:(NSError*_Nullable*)error;

/**
 * Generate private keys.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdGeneratedPrivateKeys*` representing the generated private keys and a `NSError` that indicates if any error occurred.
 */
- (void) generatePrivateKeysAsyncWithCompletionHandler:(void (^)(SealdGeneratedPrivateKeys* privateKeys, NSError*_Nullable error))completionHandler;

// Account
/**
 * Create a new Seald SDK Account for this Seald SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param signupJwt The JWT to allow this SDK instance to create an account.
 * @param deviceName A name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device.
 * @param displayName A name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
 * @param error Error pointer.
 * @return A SealdAccountInfo instance, containing the Seald ID of the newly created Seald user, the device ID, and the date at which the current device keys will expire.
 */
- (SealdAccountInfo*) createAccountWithSignupJwt:(const NSString*)signupJwt
                                      deviceName:(const NSString*)deviceName
                                     displayName:(const NSString*)displayName
                                     privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                     expireAfter:(const NSTimeInterval)expireAfter
                                           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Create a new Seald SDK Account for this Seald SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param signupJwt The JWT to allow this SDK instance to create an account.
 * @param deviceName A name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device.
 * @param displayName A name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdAccountInfo*` representing the created user and a `NSError` that indicates if any error occurred.
 */
- (void) createAccountAsyncWithSignupJwt:(const NSString*)signupJwt
                              deviceName:(const NSString*)deviceName
                             displayName:(const NSString*)displayName
                             privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                             expireAfter:(const NSTimeInterval)expireAfter
                       completionHandler:(void (^)(SealdAccountInfo* accountInfo, NSError*_Nullable error))completionHandler;

/**
 * Return information about the current account, or `nil` if there is none.
 *
 * @return A SealdAccountInfo instance, containing the Seald ID of the local Seald user, the device ID, and the date at which the current device keys will expire. `nil` if there is no local user.
 */
- (nullable SealdAccountInfo*) getCurrentAccountInfo;

/**
 * Return information about the current account, or `nil` if there is none.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdAccountInfo*` containing the current user infos and a `NSError*` that indicates if any error occurred.
 */
- (void) getCurrentAccountInfoAsyncWithCompletionHandler:(void (^)(SealdAccountInfo*_Nullable))completionHandler __attribute__((swift_async_name("getCurrentAccountInfoAsync()")));

/**
 * Updates the locally known information about the current device.
 *
 * You should never have to call this manually, except if you getting `nil` in sealdAccountInfo.deviceExpires,
 * which can happen if migrating from an older version of the SDK,
 * or if the internal call to updateCurrentDevice failed when calling SealdSdk.importIdentity:error:.
 *
 * @param error Error pointer.
 */
- (void) updateCurrentDeviceWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Updates the locally known information about the current device.
 *
 * You should never have to call this manually, except if you getting `nil` in sealdAccountInfo.deviceExpires,
 * which can happen if migrating from an older version of the SDK,
 * or if the internal call to updateCurrentDevice failed when calling SealdSdk.importIdentity:error:.
 *
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) updateCurrentDeviceAsyncWithCompletionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew.
 *
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param error Error pointer.
 * @return The prepared renewal.
 */
- (NSData*) prepareRenewWithPrivateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));


/**
 * Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew.
 *
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSData*` representing the prepared renewal and a `NSError` that indicates if any error occurred.
 */
- (void) prepareRenewAsyncWithPrivateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                        completionHandler:(void (^)(NSData* preparedRenewal, NSError*_Nullable error))completionHandler;

/**
 * Renew the keys of the current device, extending their validity.
 * If the current device has expired, you will need to call SealdSdk.renewKeysWithExpireAfter:error: before you are able to do anything else.
 * Warning: if the identity of the current device is stored externally, for example on SSKS,
 * you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
 *
 * @param preparedRenewal Optional. The preparedRenewal generated by calling SealdSdk.prepareRenew:error:.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
 * @param error Error pointer.
 */
- (void) renewKeysWithPreparedRenewal:(nullable const NSData*)preparedRenewal
                          privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                          expireAfter:(const NSTimeInterval)expireAfter
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Renew the keys of the current device, extending their validity.
 * If the current device has expired, you will need to call SealdSdk.renewKeysWithExpireAfter:error: before you are able to do anything else.
 * Warning: if the identity of the current device is stored externally, for example on SSKS,
 * you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
 *
 * @param preparedRenewal Optional. The preparedRenewal generated by calling SealdSdk.prepareRenew:error:.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) renewKeysAsyncWithPreparedRenewal:(nullable const NSData*)preparedRenewal
                               privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                               expireAfter:(const NSTimeInterval)expireAfter
                         completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Create a new sub-identity, or new device, for the current user account.
 * After creating this new device, you will probably want to call SealdSdk.massReencryptWithDeviceId:options:error:,
 * so that the newly created device will be able to decrypt EncryptionSessions previously created for this account.
 *
 * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 * @return A CreateSubIdentityResponse instance, containing `deviceId` (the ID of the newly created device) and `backupKey` (the identity export of the newly created sub-identity).
 */
- (SealdCreateSubIdentityResponse*) createSubIdentityWithDeviceName:(const NSString*)deviceName
                                                        privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                                        expireAfter:(const NSTimeInterval)expireAfter
                                                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Create a new sub-identity, or new device, for the current user account.
 * After creating this new device, you will probably want to call SealdSdk.massReencryptWithDeviceId:options:error:,
 * so that the newly created device will be able to decrypt EncryptionSessions previously created for this account.
 *
 * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param expireAfter The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdCreateSubIdentityResponse*` representing the created sub-identity and a `NSError` that indicates if any error occurred.
 */
- (void) createSubIdentityAsyncWithDeviceName:(const NSString*)deviceName
                                  privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                  expireAfter:(const NSTimeInterval)expireAfter
                            completionHandler:(void (^)(SealdCreateSubIdentityResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Load an identity export into the current SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param identity The identity export that this SDK instance should import.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) importIdentity:(const NSData*)identity
                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Load an identity export into the current SDK instance.
 * This function can only be called if the current SDK instance does not have an account yet.
 *
 * @param identity The identity export that this SDK instance should import.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) importIdentityAsyncWithIdentity:(const NSData*)identity
                       completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Export the current device as an identity export.
 *
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 * @return The identity export of the current identity of this SDK instance.
 */
- (NSData*) exportIdentityWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Export the current device as an identity export.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSData*` containing the exported identity, and a `NSError` that indicates if any error occurred.
 */
- (void) exportIdentityAsyncWithCompletionHandler:(void (^)(NSData* identity, NSError*_Nullable error))completionHandler;

/**
 * Push a given JWT to the Seald server, for example to add a connector to the current account.
 *
 * @param jwt The JWT to push
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) pushJWT:(const NSString*)jwt
           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Push a given JWT to the Seald server, for example to add a connector to the current account.
 *
 * @param jwt The JWT to push
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) pushJWTAsyncWithJWT:(const NSString*)jwt
           completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Just call the Seald server, without doing anything.
 * This may be used for example to verify that the current instance has a valid identity.
 *
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) heartbeatWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Just call the Seald server, without doing anything.
 * This may be used for example to verify that the current instance has a valid identity.
 *
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) heartbeatAsyncWithCompletionHandler:(void (^)(NSError*_Nullable error))completionHandler;

// Groups
/**
 * Create a group, and returns the created group's ID.
 * `admins` must also be members.
 * `admins` must include yourself.
 *
 * @param groupName A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param members The Seald IDs of the members to add to the group. Must include yourself.
 * @param admins The Seald IDs of the members to also add as group admins. Must include yourself.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 * @return The ID of the created group.
 */
- (NSString*) createGroupWithGroupName:(const NSString*)groupName
                               members:(const NSArray<NSString*>*)members
                                admins:(const NSArray<NSString*>*)admins
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Create a group, and returns the created group's ID.
 * `admins` must also be members.
 * `admins` must include yourself.
 *
 * @param groupName A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
 * @param members The Seald IDs of the members to add to the group. Must include yourself.
 * @param admins The Seald IDs of the members to also add as group admins. Must include yourself.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSString*` containint the ID of the created group and a `NSError` that indicates if any error occurred.
 */
- (void) createGroupAsyncWithGroupName:(const NSString*)groupName
                               members:(const NSArray<NSString*>*)members
                                admins:(const NSArray<NSString*>*)admins
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                     completionHandler:(void (^)(NSString* groupId, NSError*_Nullable error))completionHandler;

/**
 * Add members to a group.
 * Can only be done by a group administrator.
 * Can also specify which of these newly added group members should also be admins.
 *
 * @param groupId The group in which to add members.
 * @param membersToAdd The Seald IDs of the members to add to the group.
 * @param adminsToSet The Seald IDs of the newly added members to also set as group admins.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) addGroupMembersWithGroupId:(const NSString*)groupId
                       membersToAdd:(const NSArray<NSString*>*)membersToAdd
                        adminsToSet:(const NSArray<NSString*>*)adminsToSet
                        privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add members to a group.
 * Can only be done by a group administrator.
 * Can also specify which of these newly added group members should also be admins.
 *
 * @param groupId The group in which to add members.
 * @param membersToAdd The Seald IDs of the members to add to the group.
 * @param adminsToSet The Seald IDs of the newly added members to also set as group admins.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) addGroupMembersAsyncWithGroupId:(const NSString*)groupId
                            membersToAdd:(const NSArray<NSString*>*)membersToAdd
                             adminsToSet:(const NSArray<NSString*>*)adminsToSet
                             privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                       completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Remove members from the group.
 * Can only be done by a group administrator.
 * You should call SealdSdk.renewGroupKeyWithGroupId:error: after this.
 *
 * @param groupId The group from which to remove members.
 * @param membersToRemove The Seald IDs of the members to remove from the group.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) removeGroupMembersWithGroupId:(const NSString*)groupId
                       membersToRemove:(const NSArray<NSString*>*)membersToRemove
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Remove members from the group.
 * Can only be done by a group administrator.
 * You should call SealdSdk.renewGroupKeyWithGroupId:error: after this.
 *
 * @param groupId The group from which to remove members.
 * @param membersToRemove The Seald IDs of the members to remove from the group.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) removeGroupMembersAsyncWithGroupId:(const NSString*)groupId
                            membersToRemove:(const NSArray<NSString*>*)membersToRemove
                                privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                          completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Renew the group's private key.
 * Can only be done by a group administrator.
 * Should be called after removing members from the group.
 *
 * @param groupId The group for which to renew the private key.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) renewGroupKeyWithGroupId:(const NSString*)groupId
                      privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                            error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Renew the group's private key.
 * Can only be done by a group administrator.
 * Should be called after removing members from the group.
 *
 * @param groupId The group for which to renew the private key.
 * @param privateKeys Optional. Pre-generated private keys, returned by a call to SealdSdk.generatePrivateKeysWithError:.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */
- (void) renewGroupKeyAsyncWithGroupId:(const NSString*)groupId
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                     completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Add some existing group members to the group admins, and/or removes admin status from some existing group admins.
 * Can only be done by a group administrator.
 *
 * @param groupId The group for which to set admins.
 * @param addToAdmins The Seald IDs of existing group members to add as group admins.
 * @param removeFromAdmins The Seald IDs of existing group members to remove from group admins.
 * @param error If an error occurs, upon return contains an `NSError` object that describes the problem.
 */
- (void) setGroupAdminsWithGroupId:(const NSString*)groupId
                       addToAdmins:(const NSArray<NSString*>*)addToAdmins
                  removeFromAdmins:(const NSArray<NSString*>*)removeFromAdmins
                             error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add some existing group members to the group admins, and/or removes admin status from some existing group admins.
 * Can only be done by a group administrator.
 *
 * @param groupId The group for which to set admins.
 * @param addToAdmins The Seald IDs of existing group members to add as group admins.
 * @param removeFromAdmins The Seald IDs of existing group members to remove from group admins.
 * @param completionHandler A callback called after function execution. This callback take a pointer to a `NSError` that indicates if any error occurred.
 */

- (void) setGroupAdminsAsyncWithGroupId:(const NSString*)groupId
                            addToAdmins:(const NSArray<NSString*>*)addToAdmins
                       removeFromAdmins:(const NSArray<NSString*>*)removeFromAdmins
                      completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

// EncryptionSession
/**
 * Create an encryption session, and returns the associated SealdEncryptionSession instance,
 * with which you can then encrypt / decrypt multiple messages.
 * Warning : if you want to be able to retrieve the session later,
 * you must put your own UserId in the `recipients` argument.
 *
 * @param recipients The Seald IDs with the associated rights of users who should be able to retrieve this session.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param error The error that occurred while creating the session, if any.
 * @return The created SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) createEncryptionSessionWithRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                                         useCache:(const BOOL)useCache
                                                            error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Create an encryption session, and returns the associated SealdEncryptionSession instance,
 * with which you can then encrypt / decrypt multiple messages.
 * Warning : if you want to be able to retrieve the session later,
 * you must put your own UserId in the `recipients` argument.
 *
 * @param recipients The Seald IDs with the associated rights of users who should be able to retrieve this session.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` containing the created encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) createEncryptionSessionAsyncWithRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                           useCache:(const BOOL)useCache
                                  completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve an encryption session with the `sessionId`, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sessionId The ID of the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param error The error that occurred while retrieving the session, if any.
 * @return The retrieved SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) retrieveEncryptionSessionWithSessionId:(const NSString*)sessionId
                                                          useCache:(const BOOL)useCache
                                                    lookupProxyKey:(const BOOL)lookupProxyKey
                                                    lookupGroupKey:(const BOOL)lookupGroupKey
                                                             error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve an encryption session with the `sessionId`, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param sessionId The ID of the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` instance of the retrieved encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveEncryptionSessionAsyncWithSessionId:(const NSString*)sessionId
                                            useCache:(const BOOL)useCache
                                      lookupProxyKey:(const BOOL)lookupProxyKey
                                      lookupGroupKey:(const BOOL)lookupGroupKey
                                   completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve an encryption session from a seald message, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param message Any message belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param error The error that occurred while retrieving the session, if any.
 * @return The retrieved SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) retrieveEncryptionSessionFromMessage:(const NSString*_Nonnull)message
                                                        useCache:(const BOOL)useCache
                                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                                  lookupGroupKey:(const BOOL)lookupGroupKey
                                                           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve an encryption session from a seald message, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param message Any message belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` instance of the retrieved encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveEncryptionSessionAsyncFromMessage:(const NSString*_Nonnull)message
                                          useCache:(const BOOL)useCache
                                    lookupProxyKey:(const BOOL)lookupProxyKey
                                    lookupGroupKey:(const BOOL)lookupGroupKey
                                 completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve an encryption session from a file URI, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param fileURI An URI to an encrypted file belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param error The error that occurred while retrieving the session, if any.
 * @return The retrieved SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) retrieveEncryptionSessionFromFile:(const NSString*_Nonnull)fileURI
                                                     useCache:(const BOOL)useCache
                                               lookupProxyKey:(const BOOL)lookupProxyKey
                                               lookupGroupKey:(const BOOL)lookupGroupKey
                                                        error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve an encryption session from a file URI, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param fileURI An URI to an encrypted file belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` instance of the retrieved encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveEncryptionSessionAsyncFromFile:(const NSString*_Nonnull)fileURI
                                       useCache:(const BOOL)useCache
                                 lookupProxyKey:(const BOOL)lookupProxyKey
                                 lookupGroupKey:(const BOOL)lookupGroupKey
                              completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve an encryption session from  an `NSData*`, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param fileBytes `NSData*` of an encrypted file belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param error The error that occurred while retrieving the session, if any.
 * @return The retrieved SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) retrieveEncryptionSessionFromBytes:(const NSData*_Nonnull)fileBytes
                                                      useCache:(const BOOL)useCache
                                                lookupProxyKey:(const BOOL)lookupProxyKey
                                                lookupGroupKey:(const BOOL)lookupGroupKey
                                                         error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve an encryption session from  an `NSData*`, and returns the associated
 * SealdEncryptionSession instance, with which you can then encrypt / decrypt multiple messages.
 *
 * @param fileBytes `NSData*` of an encrypted file belonging to the session to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
 * @param lookupGroupKey Whether or not to try retrieving the session via a group.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` instance of the retrieved encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveEncryptionSessionAsyncFromBytes:(const NSData*_Nonnull)fileBytes
                                        useCache:(const BOOL)useCache
                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                  lookupGroupKey:(const BOOL)lookupGroupKey
                               completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve an encryption session with a TMR access JWT.
 *
 * @param tmrJWT The TMR JWT.
 * @param sessionId The id of the session to retrieve.
 * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param tmrAccessesFilters Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
 * @param tryIfMultiple If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param error The error that occurred while retrieving the session, if any.
 * @return The retrieved SealdEncryptionSession, or null if an error occurred.
 */
- (SealdEncryptionSession*) retrieveEncryptionSessionByTmr:(const NSString*)tmrJWT
                                                 sessionId:(const NSString*)sessionId
                                         overEncryptionKey:(const NSData*)overEncryptionKey
                                        tmrAccessesFilters:(const SealdTmrAccessesRetrievalFilters*_Nullable)tmrAccessesFilters
                                             tryIfMultiple:(const BOOL)tryIfMultiple
                                                  useCache:(const BOOL)useCache
                                                     error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve an encryption session with a TMR access JWT.
 *
 * @param tmrJWT The TMR JWT.
 * @param sessionId The id of the session to retrieve.
 * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param tmrAccessesFilters Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
 * @param tryIfMultiple If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdEncryptionSession*` instance of the retrieved encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveEncryptionSessionAsyncByTmr:(const NSString*)tmrJWT
                                   sessionId:(const NSString*)sessionId
                           overEncryptionKey:(const NSData*)overEncryptionKey
                          tmrAccessesFilters:(const SealdTmrAccessesRetrievalFilters*_Nullable)tmrAccessesFilters
                               tryIfMultiple:(const BOOL)tryIfMultiple
                                    useCache:(const BOOL)useCache
                           completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Retrieve multiple encryption sessions with an NSArray of sessionIds, and return an
 * NSArray of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
 * The returned array of EncryptionSession instances is in the same order as the input array.
 *
 * @param sessionIds The IDs of sessions to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the sessions via proxies.
 * @param lookupGroupKey Whether or not to try retrieving the sessions via groups.
 * @param error The error that occurred while retrieving the sessions, if any.
 * @return The `NSArray` of retrieved SealdEncryptionSession instances, or null if an error occurred.
 */
- (NSArray<SealdEncryptionSession*>*) retrieveMultipleEncryptionSessions:(const NSArray<NSString*>*)sessionIds
                                                                useCache:(const BOOL)useCache
                                                          lookupProxyKey:(const BOOL)lookupProxyKey
                                                          lookupGroupKey:(const BOOL)lookupGroupKey
                                                                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve multiple encryption sessions with an NSArray of sessionIds, and return an
 * NSArray of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
 * The returned array of EncryptionSession instances is in the same order as the input array.
 *
 * @param sessionIds The IDs of sessions to retrieve.
 * @param useCache Whether or not to use the cache (if enabled globally).
 * @param lookupProxyKey Whether or not to try retrieving the sessions via proxies.
 * @param lookupGroupKey Whether or not to try retrieving the sessions via groups.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSArray<SealdEncryptionSession*>*` instance of the retrieved encryption sessions, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveMultipleEncryptionSessionsAsync:(const NSArray<NSString*>*)sessionIds
                                        useCache:(const BOOL)useCache
                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                  lookupGroupKey:(const BOOL)lookupGroupKey
                               completionHandler:(void (^)(NSArray<SealdEncryptionSession*>* encryptionSessions, NSError*_Nullable error))completionHandler;

// Connectors
/**
 * Get all the info for the given connectors to look for, updates the local cache of connectors,
 * and returns a slice with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
 * If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
 * with the details of the missing connector.
 *
 * @param connectorTypeValues An Array of ConnectorTypeValue instances.
 * @param error An error pointer to fill in case of an error.
 * @return An Array of NSString with the Seald IDs of the users corresponding to these connectors.
 */
- (NSArray<NSString*>*) getSealdIdsFromConnectors:(const NSArray<SealdConnectorTypeValue*>*)connectorTypeValues
                                            error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))) __attribute__((swift_async_name("getSealdIdsFromConnectors()")));

/**
 * Get all the info for the given connectors to look for, updates the local cache of connectors,
 * and returns a slice with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
 * If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
 * with the details of the missing connector.
 *
 * @param connectorTypeValues An Array of ConnectorTypeValue instances.
 * @param completionHandler A callback called after function execution. This callback take two arguments, an Array of NSString with the Seald IDs of the users corresponding to these connectors, and a `NSError*` that indicates if any error occurred.
 */
- (void) getSealdIdsAsyncFromConnectors:(const NSArray<SealdConnectorTypeValue*>*)connectorTypeValues
                      completionHandler:(void (^)(NSArray<NSString*>* sealdIds, NSError*_Nullable error))completionHandler __attribute__((swift_async_name("getSealdIdsAsyncFromConnectors(connectorTypeValues:)")));

/**
 * List all connectors know locally for a given sealdId.
 *
 * @param sealdId The Seald ID for which to list connectors
 * @param error An error pointer to fill in case of an error.
 * @return An Array of Connector instances.
 */
- (NSArray<SealdConnector*>*) getConnectorsFromSealdId:(const NSString*)sealdId
                                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))) __attribute__((swift_async_name("getConnectorsFromSealdId(sealdId:)")));

/**
 * List all connectors know locally for a given sealdId.
 *
 * @param sealdId The Seald ID for which to list connectors
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `NSArray` of `SealdConnector*` instances, and a `NSError*` that indicates if any error occurred.
 */
- (void) getConnectorsAsyncFromSealdId:(const NSString*)sealdId
                     completionHandler:(void (^)(NSArray<SealdConnector*>* connectors, NSError*_Nullable error))completionHandler __attribute__((swift_async_name("getConnectorsAsyncFromSealdId(sealdId:)")));

/**
 * Add a connector to the current identity.
 * If no preValidationToken is given, the connector will need to be validated before use.
 *
 * @param value The value of the connector to add.
 * @param connectorType The type of the connector.
 * @param preValidationToken Given by your server to authorize the adding of a connector.
 * @param error An error pointer to fill in case of an error.
 * @return The created Connector.
 */
- (SealdConnector*) addConnectorWithValue:(const NSString*)value
                            connectorType:(const NSString*)connectorType
                       preValidationToken:(const SealdPreValidationToken*)preValidationToken
                                    error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add a connector to the current identity.
 * If no preValidationToken is given, the connector will need to be validated before use.
 *
 * @param value The value of the connector to add.
 * @param connectorType The type of the connector.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdConnector*` instances of the added connector, and a `NSError*` that indicates if any error occurred.
 */
- (void) addConnectorAsyncWithValue:(const NSString*)value
                      connectorType:(const NSString*)connectorType
                 preValidationToken:(const SealdPreValidationToken*)preValidationToken
                  completionHandler:(void (^)(SealdConnector* connector, NSError*_Nullable error))completionHandler;

/**
 * Validate an added connector that was added without a preValidationToken.
 *
 * @param connectorId The ID of the connector to validate.
 * @param challenge The challenge.
 * @param error An error pointer to fill in case of an error.
 * @return The modified Connector.
 */
- (SealdConnector*) validateConnector:(const NSString*)connectorId
                            challenge:(const NSString*)challenge
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Validate an added connector that was added without a preValidationToken.
 *
 * @param connectorId The ID of the connector to validate.
 * @param challenge The challenge.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdConnector*` instances of the validated connector, and a `NSError*` that indicates if any error occurred.
 */
- (void) validateConnectorAsyncWithConnectorId:(const NSString*)connectorId
                                     challenge:(const NSString*)challenge
                             completionHandler:(void (^)(SealdConnector* connector, NSError*_Nullable error))completionHandler;

/**
 * Remove a connector belonging to the current account.
 *
 * @param connectorId The ID of the connector to remove.
 * @param error An error pointer to fill in case of an error.
 * @return The modified Connector.
 */
- (SealdConnector*) removeConnector:(const NSString*)connectorId
                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Remove a connector belonging to the current account.
 *
 * @param connectorId The ID of the connector to remove.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdConnector*` instances of the removed connector, and a `NSError*` that indicates if any error occurred.
 */
- (void) removeConnectorAsyncWithConnectorId:(const NSString*)connectorId
                           completionHandler:(void (^)(SealdConnector* connector, NSError*_Nullable error))completionHandler;

/**
 * List connectors associated to the current account.
 *
 * @param error An error pointer to fill in case of an error.
 * @return The array of connectors associated to the current account.
 */
- (NSArray<SealdConnector*>*) listConnectorsWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * List connectors associated to the current account.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `NSArray` of `SealdConnector*` instances of the listed connectors, and a `NSError*` that indicates if any error occurred.
 */
- (void) listConnectorsAsyncWithCompletionHandler:(void (^)(NSArray<SealdConnector*>* connectors, NSError*_Nullable error))completionHandler;

/**
 * Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
 *
 * @param connectorId The ID of the connector to retrieve.
 * @param error An error pointer to fill in case of an error.
 * @return The Connector.
 */
- (SealdConnector*) retrieveConnector:(const NSString*)connectorId
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
 *
 * @param connectorId The ID of the connector to retrieve.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdConnector*` instance of the retrieved connector, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveConnectorAsyncWithConnectorId:(const NSString*)connectorId
                             completionHandler:(void (^)(SealdConnector* connector, NSError*_Nullable error))completionHandler;

// Reencrypt
/**
 * Retrieve, re-encrypt, and add missing keys for a certain device.
 *
 * @param deviceId The ID of the device for which to re-rencrypt.
 * @param options A SealdMassReencryptOptions instance, or `nil` to use default options.
 * @param error An `NSError` object that will be populated if an error occurs while executing the operation.
 * @return A SealdMassReencryptResponse instance, containing the number of re-encrypted keys, and the number of keys for which re-encryption failed.
 */
- (SealdMassReencryptResponse*) massReencryptWithDeviceId:(const NSString*)deviceId
                                                  options:(const SealdMassReencryptOptions*)options
                                                    error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve, re-encrypt, and add missing keys for a certain device.
 *
 * @param deviceId The ID of the device for which to re-rencrypt.
 * @param options A SealdMassReencryptOptions instance, or `nil` to use default options.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdMassReencryptResponse*` instance containing the number of re-encrypted keys of the retrieved connector, and a `NSError*` that indicates if any error occurred.
 */
- (void) massReencryptAsyncWithDeviceId:(const NSString*)deviceId
                                options:(const SealdMassReencryptOptions*)options
                      completionHandler:(void (^)(SealdMassReencryptResponse* response, NSError*_Nullable error))completionHandler;

/**
 * List which of the devices of the current account are missing keys,
 * so you can call SealdSdk.massReencryptWithDeviceId:options:error: for them.
 *
 * @param forceLocalAccountUpdate Whether to update the local account
 * @param error If an error occurs, upon return contains an NSError object that describes the problem.
 * @return An `NSArray` of SealdDeviceMissingKeys instances, containing the ID of the device.
 */
- (NSArray<SealdDeviceMissingKeys*>*) devicesMissingKeysWithForceLocalAccountUpdate:(const BOOL)forceLocalAccountUpdate
                                                                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * List which of the devices of the current account are missing keys,
 * so you can call SealdSdk.massReencryptWithDeviceId:options:error: for them.
 *
 * @param forceLocalAccountUpdate Whether to update the local account
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `NSArray` of SealdDeviceMissingKeys instances, containing the ID of the device, and a `NSError*` that indicates if any error occurred.
 */
- (void) devicesMissingKeysAsyncWithForceLocalAccountUpdate:(const BOOL)forceLocalAccountUpdate
                                          completionHandler:(void (^)(NSArray<SealdDeviceMissingKeys*>* devices, NSError*_Nullable error))completionHandler;
/**
 * Get a user's sigchain transaction hash at index `position`.
 *
 * @param userId The Seald ID of the concerned user.
 * @param position Get the hash at the given position. -1 to get the last. Default to -1.
 * @param error If an error occurs, upon return contains an NSError object that describes the problem.
 * @return A SealdGetSigchainResponse instance.
 */
- (SealdGetSigchainResponse*) getSigchainHashWithUserId:(const NSString*)userId
                                               position:(const long)position
                                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))) __attribute__((swift_async_name("getSigchainHashWithUserId(userId:position:)")));
/**
 * Get a user's sigchain transaction hash at index `position`.
 *
 * @param userId The Seald ID of the concerned user.
 * @param position Get the hash at the given position. -1 to get the last. Default to -1.
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `SealdGetSigchainResponse` instance containing the hash, and a `NSError*` that indicates if any error occurred.
 */
- (void) getSigchainHashAsyncWithUserId:(const NSString*)userId
                               position:(const long)position
                      completionHandler:(void (^)(SealdGetSigchainResponse* response, NSError*_Nullable error))completionHandler __attribute__((swift_async_name("getSigchainHashAsync(withUserId:position:)")));

/**
 * Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
 *
 * @param userId The Seald ID of the concerned user.
 * @param expectedHash The expected sigchain hash.
 * @param position Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
 * @param error If an error occurs, upon return contains an NSError object that describes the problem.
 * @return A SealdCheckSigchainResponse instance.
 */
- (SealdCheckSigchainResponse*) checkSigchainHashWithUserId:(const NSString*)userId
                                               expectedHash:(const NSString*)expectedHash
                                                   position:(const long)position
                                                      error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
 *
 * @param userId The Seald ID of the concerned user.
 * @param expectedHash The expected sigchain hash.
 * @param position Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `SealdCheckSigchainResponse` instance containing the response, and a `NSError*` that indicates if any error occurred.
 */
- (void) checkSigchainHashAsyncWithUserId:(const NSString*)userId
                             expectedHash:(const NSString*)expectedHash
                                 position:(const long)position
                        completionHandler:(void (^)(SealdCheckSigchainResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
 * All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
 *
 * @param tmrJWT The TMR JWT.
 * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param conversionFilters Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
 * @param deleteOnConvert Whether or not to delete the TMR access after conversion.
 * @param error The error that occurred while retrieving the session, if any.
 * @return A SealdConvertTmrAccessesResult instance.
 */
- (SealdConvertTmrAccessesResult*) convertTmrAccesses:(const NSString*)tmrJWT
                                    overEncryptionKey:(const NSData*)overEncryptionKey
                                    conversionFilters:(const SealdTmrAccessesConvertFilters*_Nullable)conversionFilters
                                      deleteOnConvert:(const BOOL)deleteOnConvert
                                                error:(NSError*_Nullable*)error;

/**
 * Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
 * All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
 *
 * @param tmrJWT The TMR JWT.
 * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param conversionFilters Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
 * @param deleteOnConvert Whether or not to delete the TMR access after conversion.
 * @param completionHandler A callback called after function execution. This callback take two arguments, an `convertTmrAccessesAsync` instance containing the response, and a `NSError*` that indicates if any error occurred.
 */
- (void) convertTmrAccessesAsync:(const NSString*)tmrJWT
               overEncryptionKey:(const NSData*)overEncryptionKey
               conversionFilters:(const SealdTmrAccessesConvertFilters*_Nullable)conversionFilters
                 deleteOnConvert:(const BOOL)deleteOnConvert
               completionHandler:(void (^)(SealdConvertTmrAccessesResult* response, NSError*_Nullable error))completionHandler;
@end

NS_ASSUME_NONNULL_END

#endif /* SealdSdk_h */
