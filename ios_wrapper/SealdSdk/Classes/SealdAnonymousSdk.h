//
//  SealdAnonymousSdk.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 20/05/2025.
//  Copyright © 2025 Seald SAS. All rights reserved.
//

#ifndef SealdAnonymousSdk_h
#define SealdAnonymousSdk_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>
#import "Helpers.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * This is the main class for the anonymous Seald SDK. It represents an instance of the Anonymous Seald SDK.
 */
@interface SealdAnonymousSdk : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileAnonymousSDK* anonymousSdkInstance;
    /** \endcond */
}
/**
 * Initialize a Seald Anonymous SDK Instance.
 *
 * @param apiUrl The Seald server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `NO` if you want to enable colors in the log output, `YES` if you don't.
 * @param error Error pointer.
 */
- (instancetype) initWithApiUrl:(const NSString*)apiUrl
                          appId:(const NSString*)appId
                   instanceName:(const NSString*)instanceName
                       logLevel:(const NSInteger)logLevel
                     logNoColor:(const BOOL)logNoColor
                          error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Create an anonymous encryption session, and returns the associated SealdAnonymousEncryptionSession instance,
 * with which you can then encrypt / decrypt multiple messages.
 *
 * @param encryptionToken Mandatory. The JWT used for EncryptionSession creation.
 * @param getKeysToken Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
 * @param recipients The Seald IDs of users who should be able to retrieve this session.
 * @param tmrRecipients Array of TMR recipients of the session to create.
 * @param error The error that occurred while creating the session, if any.
 * @return The created SealdAnonymousEncryptionSession, or null if an error occurred.
 */
- (SealdAnonymousEncryptionSession*) createAnonymousEncryptionSessionWithEncryptionToken:(const NSString*)encryptionToken
                                                                            getKeysToken:(const NSString*_Nullable)getKeysToken
                                                                              recipients:(const NSArray<NSString*>*)recipients
                                                                           tmrRecipients:(const NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients
                                                                                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Create an anonymous encryption session, and returns the associated SealdAnonymousEncryptionSession instance,
 * with which you can then encrypt / decrypt multiple messages.
 *
 * @param encryptionToken Mandatory. The JWT used for EncryptionSession creation.
 * @param getKeysToken Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
 * @param recipients The Seald IDs of users who should be able to retrieve this session.
 * @param tmrRecipients Array of TMR recipients of the session to create.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a SealdAnonymousEncryptionSession* containing the created anonymous encryption session, and a `NSError*` that indicates if any error occurred.
 */
- (void) createAnonymousEncryptionSessionAsyncWithEncryptionToken:(const NSString*)encryptionToken
                                                     getKeysToken:(const NSString*_Nullable)getKeysToken
                                                       recipients:(const NSArray<NSString*>*)recipients
                                                    tmrRecipients:(const NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients
                                                completionHandler:(void (^)(SealdAnonymousEncryptionSession* anonymousEncryptionSession, NSError*_Nullable error))completionHandler;

/**
 * Deserialize a serialized session.
 * For advanced use.
 *
 * @param serializedSession The serialized encryption session to deserialize.
 * @param error The error that occurred while retrieving the session, if any.
 * @return The deserialized SealdAnonymousEncryptionSession, or null if an error occurred.
 */
- (SealdAnonymousEncryptionSession*) deserializeAnonymousEncryptionSession:(const NSString*_Nonnull)serializedSession
                                                                     error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
@end

NS_ASSUME_NONNULL_END

#endif /* SealdAnonymousSdk_h */
