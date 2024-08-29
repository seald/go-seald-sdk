//
//  SealdSsksTMRPlugin.h
//  SealdSdk
//
//  Created by Clement Congard on 31/05/2023.
//

#ifndef SealdSsksTMRPlugin_h
#define SealdSsksTMRPlugin_h

#import <SealdSdkInternals/SealdSdkInternals.h>
#import "SealdSsksHelpers.h"
#import "Helpers.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * The SealdSSKSTmrPlugin class allows to use the SSKS key storage service to store Seald identities
 * easily and securely, encrypted by a key stored on your back-end server.
 */
@interface SealdSsksTMRPlugin : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileSSKSTMR* ssksTMRPlugin;
    /** \endcond */
}
/**
 * Initialize an instance of Seald SSKS TMR plugin.
 *
 * @param ssksURL The URL of the SSKS Identity Key Storage to which it should connect.
 * @param appId The application ID to use.
 * @param instanceName An arbitrary name to give to this SSKS Plugin. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
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
 * Save the Seald account to SSKS.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param error Error pointer.
 * @return A SealdSsksSaveIdentityResponse instance, containing the SSKS ID of the stored identity, which can be used by your backend to manage it, and if a challenge was passed `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
 */
- (SealdSsksSaveIdentityResponse*) saveIdentity:(const NSString*)sessionId
                                     authFactor:(const SealdTmrAuthFactor*)authFactor
                                   rawTMRSymKey:(const NSData*)rawTMRSymKey
                                       identity:(const NSData*)identity
                                      challenge:(const NSString*_Nullable)challenge
                                          error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Save the Seald account to SSKS.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param error Error pointer.
 * @return A SealdSsksSaveIdentityResponse instance, containing the SSKS ID of the stored identity, which can be used by your backend to manage it, and if a challenge was passed `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
 */
- (SealdSsksSaveIdentityResponse*) saveIdentity:(const NSString*)sessionId
                                     authFactor:(const SealdTmrAuthFactor*)authFactor
                                   rawTMRSymKey:(const NSData*)rawTMRSymKey
                                       identity:(const NSData*)identity
                                          error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Save the Seald account to SSKS.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksSaveIdentityResponse*` containing the SSKS ID of the saved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) saveIdentityAsync:(const NSString*)sessionId
                authFactor:(const SealdTmrAuthFactor*)authFactor
              rawTMRSymKey:(const NSData*)rawTMRSymKey
                  identity:(const NSData*)identity
                 challenge:(const NSString*_Nullable)challenge
         completionHandler:(void (^)(SealdSsksSaveIdentityResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Save the Seald account to SSKS.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param identity The identity to save.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksSaveIdentityResponse*` containing the SSKS ID of the saved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) saveIdentityAsync:(const NSString*)sessionId
                authFactor:(const SealdTmrAuthFactor*)authFactor
              rawTMRSymKey:(const NSData*)rawTMRSymKey
                  identity:(const NSData*)identity
         completionHandler:(void (^)(SealdSsksSaveIdentityResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Retrieve the Seald account previously saved with `[ssksTMRPluginInstance saveIdentity]`.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param error Error pointer.
 * @return A SealdSsksRetrieveIdentityResponse instance, containing `identity`, the retrieved identity, `shouldRenewKey`, a boolean set to true is the user private key should be renewed (using [sealdSDKInstance renewKeys]), and `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
 */
- (SealdSsksRetrieveIdentityResponse*) retrieveIdentity:(const NSString*)sessionId
                                             authFactor:(const SealdTmrAuthFactor*)authFactor
                                           rawTMRSymKey:(const NSData*)rawTMRSymKey
                                              challenge:(const NSString*_Nullable)challenge
                                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve the Seald account previously saved with `[ssksTMRPluginInstance saveIdentity]`.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param error Error pointer.
 * @return A SealdSsksRetrieveIdentityResponse instance, containing `identity`, the retrieved identity, `shouldRenewKey`, a boolean set to true is the user private key should be renewed (using [sealdSDKInstance renewKeys]), and `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
 */
- (SealdSsksRetrieveIdentityResponse*) retrieveIdentity:(const NSString*)sessionId
                                             authFactor:(const SealdTmrAuthFactor*)authFactor
                                           rawTMRSymKey:(const NSData*)rawTMRSymKey
                                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Retrieve the Seald account previously saved with `[ssksTMRPluginInstance saveIdentity]`.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksRetrieveIdentityResponse*` containing the retrieved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveIdentityAsync:(const NSString*)sessionId
                    authFactor:(const SealdTmrAuthFactor*)authFactor
                  rawTMRSymKey:(const NSData*)rawTMRSymKey
                     challenge:(const NSString*_Nullable)challenge
             completionHandler:(void (^)(SealdSsksRetrieveIdentityResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Retrieve the Seald account previously saved with `[ssksTMRPluginInstance saveIdentity]`.
 *
 * @param sessionId The user's session ID.
 * @param authFactor The authentication factor to use.
 * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random NSData of 64 bytes.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksRetrieveIdentityResponse*` containing the retrieved identity, and a `NSError*` that indicates if any error occurred.
 */
- (void) retrieveIdentityAsync:(const NSString*)sessionId
                    authFactor:(const SealdTmrAuthFactor*)authFactor
                  rawTMRSymKey:(const NSData*)rawTMRSymKey
             completionHandler:(void (^)(SealdSsksRetrieveIdentityResponse* response, NSError*_Nullable error))completionHandler;

/**
 * Retrieve the TMR JWT associated with an authentication factor.
 *
 * @param sessionId Session ID given by SSKS to your app's server.
 * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param error Error pointer.
 * @return An [GetFactorTokenResponse] instance, containing the retrieved authentication factor token.
 */
- (SealdSsksGetFactorTokenResponse*) getFactorToken:(const NSString*)sessionId
                                         authFactor:(const SealdTmrAuthFactor*)authFactor
                                          challenge:(const NSString*_Nullable)challenge
                                              error:(NSError*_Nullable*)error
    __attribute__((swift_error(nonnull_error)))
    __attribute__((swift_async_name("getFactorToken(sessionId:authFactor:challenge:)")));

/**
 * Retrieve the TMR JWT associated with an authentication factor.
 *
 * @param sessionId Session ID given by SSKS to your app's server.
 * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @param error Error pointer.
 * @return An [GetFactorTokenResponse] instance, containing the retrieved authentication factor token.
 */
- (SealdSsksGetFactorTokenResponse*) getFactorToken:(const NSString*)sessionId
                                         authFactor:(const SealdTmrAuthFactor*)authFactor
                                              error:(NSError*_Nullable*)error
    __attribute__((swift_error(nonnull_error)))
    __attribute__((swift_async_name("getFactorToken(sessionId:authFactor:)")));

/**
 * Retrieve the TMR JWT associated with an authentication factor.
 *
 * @param sessionId Session ID given by SSKS to your app's server.
 * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksGetFactorTokenResponse*` containing the retrieved token, and a `NSError*` that indicates if any error occurred.
 */
- (void) getFactorTokenAsync:(const NSString*)sessionId
                  authFactor:(const SealdTmrAuthFactor*)authFactor
                   challenge:(const NSString*_Nullable)challenge
           completionHandler:(void (^)(SealdSsksGetFactorTokenResponse* response, NSError*_Nullable error))completionHandler
    __attribute__((swift_async_name("getFactorTokenAsync(sessionId:authFactor:challenge:)")));

/**
 * Retrieve the TMR JWT associated with an authentication factor.
 *
 * @param sessionId Session ID given by SSKS to your app's server.
 * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a `SealdSsksGetFactorTokenResponse*` containing the retrieved token, and a `NSError*` that indicates if any error occurred.
 */
- (void) getFactorTokenAsync:(const NSString*)sessionId
                  authFactor:(const SealdTmrAuthFactor*)authFactor
           completionHandler:(void (^)(SealdSsksGetFactorTokenResponse* response, NSError*_Nullable error))completionHandler
    __attribute__((swift_async_name("getFactorTokenAsync(sessionId:authFactor:)")));
@end

NS_ASSUME_NONNULL_END

#endif /* SealdSsksTMRPlugin_h */
