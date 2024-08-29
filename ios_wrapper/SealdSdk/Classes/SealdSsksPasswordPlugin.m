//
//  SealdSsksPasswordPlugin.m
//  SealdSdk
//
//  Created by Clément Congard on 27/04/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSsksPasswordPlugin.h"

@implementation SealdSsksPasswordPlugin
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId
                    instanceName:(const NSString*)instanceName
                        logLevel:(const NSInteger)logLevel
                      logNoColor:(const BOOL)logNoColor
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkSsksPasswordInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkSsksPasswordInitializeOptions alloc] init];
        initOpts.ssksURL = (NSString*)ssksURL;
        initOpts.appId = (NSString*)appId;
        initOpts.instanceName = (NSString*)instanceName;
        initOpts.platform = @"ios";
        initOpts.logLevel = logLevel;
        initOpts.logNoColor = logNoColor;

        ssksPasswordPlugin = SealdSdkInternalsMobile_sdkNewSSKSPasswordPlugin(initOpts);
    }
    return self;
}
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkSsksPasswordInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkSsksPasswordInitializeOptions alloc] init];
        initOpts.ssksURL = (NSString*)ssksURL;
        initOpts.appId = (NSString*)appId;
        initOpts.instanceName = @"sdkSsksPasswordInstance";
        initOpts.platform = @"ios";
        initOpts.logLevel = 0;
        initOpts.logNoColor = true;

        ssksPasswordPlugin = SealdSdkInternalsMobile_sdkNewSSKSPasswordPlugin(initOpts);
    }
    return self;
}

- (NSString*) saveIdentityWithUserId:(const NSString*)userId
                            password:(const NSString*)password
                            identity:(const NSData*)identity
                               error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [ssksPasswordPlugin saveIdentityFromPassword:(NSString*)userId
                                                        password:(NSString*)password
                                                        identity:(NSData*)identity
                                                           error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) saveIdentityAsyncWithUserId:(const NSString*)userId
                            password:(const NSString*)password
                            identity:(const NSData*)identity
                   completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* res = [self saveIdentityWithUserId:userId
                                            password:password
                                            identity:identity
                                               error:&localError];
        completionHandler(res, localError);
    });
}

- (NSString*) saveIdentityWithUserId:(const NSString*)userId
                       rawStorageKey:(const NSString*)rawStorageKey
                    rawEncryptionKey:(const NSData*)rawEncryptionKey
                            identity:(const NSData*)identity
                               error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [ssksPasswordPlugin saveIdentityFromRawKeys:(NSString*)userId
                                                  rawStorageKey:(NSString*)rawStorageKey
                                               rawEncryptionKey:(NSData*)rawEncryptionKey
                                                       identity:(NSData*)identity
                                                          error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) saveIdentityAsyncWithUserId:(const NSString*)userId
                       rawStorageKey:(const NSString*)rawStorageKey
                    rawEncryptionKey:(const NSData*)rawEncryptionKey
                            identity:(const NSData*)identity
                   completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* res = [self saveIdentityWithUserId:userId
                                       rawStorageKey:rawStorageKey
                                    rawEncryptionKey:rawEncryptionKey
                                            identity:identity
                                               error:&localError];
        completionHandler(res, localError);
    });
}

- (NSData*) retrieveIdentityWithUserId:(const NSString*)userId
                              password:(const NSString*)password
                                 error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSData* res = [ssksPasswordPlugin retrieveIdentityFromPassword:(NSString*)userId
                                                          password:(NSString*)password
                                                             error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) retrieveIdentityAsyncWithUserId:(const NSString*)userId
                                password:(const NSString*)password
                       completionHandler:(void (^)(NSData* identity, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSData* identity = [self retrieveIdentityWithUserId:userId
                                                   password:password
                                                      error:&localError];
        completionHandler(identity, localError);
    });
}

- (NSData*) retrieveIdentityWithUserId:(const NSString*)userId
                         rawStorageKey:(const NSString*)rawStorageKey
                      rawEncryptionKey:(const NSData*)rawEncryptionKey
                                 error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSData* res =  [ssksPasswordPlugin retrieveIdentityFromRawKeys:(NSString*)userId
                                                     rawStorageKey:(NSString*)rawStorageKey
                                                  rawEncryptionKey:(NSData*)rawEncryptionKey
                                                             error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) retrieveIdentityAsyncWithUserId:(const NSString*)userId
                           rawStorageKey:(const NSString*)rawStorageKey
                        rawEncryptionKey:(const NSData*)rawEncryptionKey
                       completionHandler:(void (^)(NSData* identity,NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSData* res = [self retrieveIdentityWithUserId:userId
                                         rawStorageKey:rawStorageKey
                                      rawEncryptionKey:rawEncryptionKey
                                                 error:&localErr];
        completionHandler(res, localErr);
    });
}

- (NSString*) changeIdentityPasswordWithUserId:(const NSString*)userId
                               currentPassword:(const NSString*)currentPassword
                                   newPassword:(const NSString*)newPassword
                                         error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [ssksPasswordPlugin changeIdentityPassword:(NSString*)userId
                                               currentPassword:(NSString*)currentPassword
                                                   newPassword:(NSString*)newPassword
                                                         error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) changeIdentityPasswordAsyncWithUserId:(const NSString*)userId
                               currentPassword:(const NSString*)currentPassword
                                   newPassword:(const NSString*)newPassword
                             completionHandler:(void (^)(NSString* ssksId, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* res = [self changeIdentityPasswordWithUserId:userId
                                               currentPassword:currentPassword
                                                   newPassword:newPassword
                                                         error:&localError];
        completionHandler(res, localError);
    });
}
@end
