//
//  SealdSsksPasswordPlugin.h
//  SealdSdk
//
//  Created by Clément Congard on 27/04/2023.
//

#ifndef SealdSsksPasswordPlugin_h
#define SealdSsksPasswordPlugin_h

#import <SealdSdkInternals/SealdSdkInternals.h>
#import "Helpers.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * This is the main class for the Seald SSKS password plugin. It represents an instance of the Plugin.
 */
@interface SealdSsksPasswordPlugin : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileSSKSPassword* ssksPasswordPlugin;
    /** \endcond */
}
/**
 * Initialize an instance of Seald SSKS Password plugin.
 *
 * @param ssksURL The URL of the SSKS Identity Key Storage to which it should connect.
 * @param appId The application ID to use.
 * @param instanceName An arbitrary name to give to this SSKS Plugin instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `NO` if you want to enable colors in the log output, `YES` if you don't.
 */
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId
                    instanceName:(const NSString*)instanceName
                        logLevel:(const NSInteger)logLevel
                      logNoColor:(const BOOL)logNoColor;
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId;

/**
 * Save the given identity for the given userId, encrypted with the given password.
 *
 * @param userId The ID of the userId.
 * @param password The password to encrypt the key.
 * @param identity The identity to save.
 * @param error Error pointer.
 * @return A NSString containing the SSKS ID of the stored identity, which can be used by your backend to manage it.
 */
- (NSString*) saveIdentityWithUserId:(const NSString*)userId
                            password:(const NSString*)password
                            identity:(const NSData*)identity
                               error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Save the given identity for the given userId, encrypted with the given password.
 *
 * @param userId The ID of the userId.
 * @param password The password to encrypt the key.
 * @param identity The identity to save.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSString*` containing the SSKS ID of the stored identity, which can be used by your backend to manage it, and a `NSError*` that indicates if any error occurred.
 */
- (void) saveIdentityAsyncWithUserId:(const NSString*)userId
                            password:(const NSString*)password
                            identity:(const NSData*)identity
                   completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler;

/**
 * Save the given identity for the given userId, encrypted with the given raw keys.
 *
 * @param userId The ID of the userId.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param error Error pointer.
 * @return A NSString containing the SSKS ID of the stored identity, which can be used by your backend to manage it.
 */
- (NSString*) saveIdentityWithUserId:(const NSString*)userId
                       rawStorageKey:(const NSString*)rawStorageKey
                    rawEncryptionKey:(const NSData*)rawEncryptionKey
                            identity:(const NSData*)identity
                               error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Save the given identity for the given userId, encrypted with the given raw keys.
 *
 * @param userId The ID of the userId.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSString*` containing the SSKS ID of the stored identity, which can be used by your backend to manage it, and a `NSError*` that indicates if any error occurred.
 */
- (void) saveIdentityAsyncWithUserId:(const NSString*)userId
                       rawStorageKey:(const NSString*)rawStorageKey
                    rawEncryptionKey:(const NSData*)rawEncryptionKey
                            identity:(const NSData*)identity
                   completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler;

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param userId The ID of the userId.
 * @param password The password to encrypt the key.
 * @param error Error pointer.
 * @return A NSData containing the retrieved identity
 */
- (NSData*) retrieveIdentityWithUserId:(const NSString*)userId
                              password:(const NSString*)password
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param userId The ID of the userId.
 * @param password The password to encrypt the key.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSData*` containing the retrieved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveIdentityAsyncWithUserId:(const NSString*)userId
                                password:(const NSString*)password
                       completionHandler:(void (^)(NSData* identity, NSError*_Nullable error))completionHandler;

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param userId The ID of the userId.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param error Error pointer.
 * @return A NSData containing the retrieved identity
 */
- (NSData*) retrieveIdentityWithUserId:(const NSString*)userId
                         rawStorageKey:(const NSString*)rawStorageKey
                      rawEncryptionKey:(const NSData*)rawEncryptionKey
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
 *
 * If you use an incorrect password multiple times, the server may throttle your requests. In this
 * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
 * of seconds during which you cannot try again.
 *
 * @param userId The ID of the userId.
 * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
 * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSData*` containing the retrieved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveIdentityAsyncWithUserId:(const NSString*)userId
                           rawStorageKey:(const NSString*)rawStorageKey
                        rawEncryptionKey:(const NSData*)rawEncryptionKey
                       completionHandler:(void (^)(NSData* identity,NSError*_Nullable error))completionHandler;

/**
 * Change the password used to encrypt the identity for the userId.
 *
 * @param userId The ID of the userId.
 * @param currentPassword The user's current password.
 * @param newPassword The new password.
 * @param error Error pointer.
 * @return A NSString containing the new SSKS ID of the stored identity.
 */
- (NSString*) changeIdentityPasswordWithUserId:(const NSString*)userId
                               currentPassword:(const NSString*)currentPassword
                                   newPassword:(const NSString*)newPassword
                                         error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Change the password used to encrypt the identity for the userId.
 *
 * @param userId The ID of the userId.
 * @param currentPassword The user's current password.
 * @param newPassword The new password.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `NSString*` containing the new SSKS ID of the stored identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) changeIdentityPasswordAsyncWithUserId:(const NSString*)userId
                               currentPassword:(const NSString*)currentPassword
                                   newPassword:(const NSString*)newPassword
                             completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler;
@end

NS_ASSUME_NONNULL_END

#endif /* SealdSsksPasswordPlugin_h */
