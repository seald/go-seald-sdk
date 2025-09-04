//
//  SealdAnonymousSdk.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 20/05/2025.
//  Copyright © 2025 Seald SAS. All rights reserved.
//

#import "SealdSdk.h"
#import <Security/Security.h>

@implementation SealdAnonymousSdk
- (instancetype) initWithApiUrl:(const NSString*)apiUrl
                          appId:(const NSString*)appId
                   instanceName:(const NSString*)instanceName
                       logLevel:(const NSInteger)logLevel
                     logNoColor:(const BOOL)logNoColor
                          error:(NSError*_Nullable*)error
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkAnonymousInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkAnonymousInitializeOptions alloc] init];
        initOpts.apiURL = (NSString*)apiUrl;
        initOpts.appId = (NSString*)appId;
        initOpts.instanceName = (NSString*)instanceName;
        initOpts.platform = @"ios";
        initOpts.logLevel = logLevel;
        initOpts.logNoColor = logNoColor;

        anonymousSdkInstance = SealdSdkInternalsMobile_sdkCreateAnonymousSDK(initOpts);
    }
    return self;
}

// EncryptionSession
- (SealdAnonymousEncryptionSession*) createAnonymousEncryptionSessionWithEncryptionToken:(const NSString*)encryptionToken
                                                                            getKeysToken:(const NSString*_Nullable)getKeysToken
                                                                              recipients:(const NSArray<NSString*>*)recipients
                                                                           tmrRecipients:(const NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients
                                                                                   error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;

    SealdSdkInternalsMobile_sdkAnonymousTmrRecipientArray* nativeTmrR = [SealdAnonymousTmrRecipient toMobileSdkArray:(NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession* aes = [anonymousSdkInstance createAnonymousEncryptionSession:(NSString*)encryptionToken
                                                                                                                 getKeysToken:(NSString*)getKeysToken
                                                                                                                   recipients:arrayToStringArray((NSArray<NSString*>*)recipients) tmrRecipients:nativeTmrR
                                                                                                                        error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdAnonymousEncryptionSession fromMobileSdk:aes];
}

- (void) createAnonymousEncryptionSessionAsyncWithEncryptionToken:(const NSString*)encryptionToken
                                                     getKeysToken:(const NSString*_Nullable)getKeysToken
                                                       recipients:(const NSArray<NSString*>*)recipients
                                                    tmrRecipients:(const NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients
                                                completionHandler:(void (^)(SealdAnonymousEncryptionSession* anonymousEncryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdAnonymousEncryptionSession* res = [self createAnonymousEncryptionSessionWithEncryptionToken:encryptionToken
                                                                                            getKeysToken:getKeysToken
                                                                                              recipients:recipients
                                                                                           tmrRecipients:tmrRecipients
                                                                                                   error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdAnonymousEncryptionSession*) deserializeAnonymousEncryptionSession:(const NSString*_Nonnull)serializedSession
                                                                     error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession* aes = [anonymousSdkInstance deserializeAnonymousEncryptionSession:(NSString*)serializedSession error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdAnonymousEncryptionSession fromMobileSdk:aes];
}
@end
