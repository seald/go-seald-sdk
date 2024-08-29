//
//  SsksBackend.h
//  SealdSDK demo app ios
//
//  Created by Seald on 28/04/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#ifndef SsksBackend_h
#define SsksBackend_h

#import "Helpers.h"

@interface SealdSsksBackendChallengeResponse : NSObject

@property (nonatomic, readonly) NSString* sessionId;
@property (nonatomic, readonly) BOOL mustAuthenticate;

- (instancetype) initWithSessionId:(NSString*)sessionId
                  mustAuthenticate:(BOOL)mustAuthenticate;
@end

@interface DemoAppSsksBackend : NSObject

@property (nonatomic, copy, readonly) NSString* ssksURL;
@property (nonatomic, copy, readonly) NSString* appId;
@property (nonatomic, copy, readonly) NSString* appKey;

- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           AppId:(const NSString*)appId
                          AppKey:(const NSString*)appKey;

- (NSString*) postAPIWithURL:(NSString*)endpoint
                        data:(NSData*)data
                       error:(NSError**)error;

- (SealdSsksBackendChallengeResponse*) challengeSendWithUserId:(const NSString*)userId
                                                    authFactor:(const SealdTmrAuthFactor*)authFactor
                                                    createUser:(const BOOL)createUser
                                                     forceAuth:(const BOOL)forceAuth
                                                       fakeOtp:(const BOOL)fakeOtp
                                                         error:(NSError**)error;
@end

#endif /* SsksBackend_h */
