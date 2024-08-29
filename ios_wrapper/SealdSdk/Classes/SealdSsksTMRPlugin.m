//
//  SealdSsksTMRPlugin.m
//  SealdSdk
//
//  Created by Clément Congard on 31/05/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSsksTMRPlugin.h"

@implementation SealdSsksTMRPlugin
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId
                    instanceName:(const NSString*)instanceName
                        logLevel:(const NSInteger)logLevel
                      logNoColor:(const BOOL)logNoColor
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkSsksTMRInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkSsksTMRInitializeOptions alloc] init];
        initOpts.ssksURL = (NSString*)ssksURL;
        initOpts.appId = (NSString*)appId;
        initOpts.instanceName = (NSString*)instanceName;
        initOpts.platform = @"ios";
        initOpts.logLevel = logLevel;
        initOpts.logNoColor = logNoColor;

        ssksTMRPlugin = SealdSdkInternalsMobile_sdkNewSSKSTMRPlugin(initOpts);
    }
    return self;
}

- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           appId:(const NSString*)appId
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkSsksTMRInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkSsksTMRInitializeOptions alloc] init];
        initOpts.ssksURL = (NSString*)ssksURL;
        initOpts.appId = (NSString*)appId;
        initOpts.instanceName = @"sdkSsksTMRInstance";
        initOpts.platform = @"ios";
        initOpts.logLevel = 0;
        initOpts.logNoColor = true;

        ssksTMRPlugin = SealdSdkInternalsMobile_sdkNewSSKSTMRPlugin(initOpts);
    }
    return self;
}

- (SealdSsksSaveIdentityResponse*) saveIdentity:(const NSString*)sessionId
                                     authFactor:(const SealdTmrAuthFactor*)authFactor
                                   rawTMRSymKey:(const NSData*)rawTMRSymKey
                                       identity:(const NSData*)identity
                                      challenge:(const NSString*_Nullable)challenge
                                          error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkSaveIdentityResponse* internalResp = [ssksTMRPlugin saveIdentity:(NSString*)sessionId
                                                                                     authFactor:[authFactor toMobileSdk]
                                                                                      challenge:(NSString*)challenge
                                                                                   rawTMRSymKey:(NSData*)rawTMRSymKey
                                                                                       identity:(NSData*)identity
                                                                                          error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksSaveIdentityResponse fromMobileSdk:internalResp];
}

- (SealdSsksSaveIdentityResponse*) saveIdentity:(const NSString*)sessionId
                                     authFactor:(const SealdTmrAuthFactor*)authFactor
                                   rawTMRSymKey:(const NSData*)rawTMRSymKey
                                       identity:(const NSData*)identity
                                          error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkSaveIdentityResponse* internalResp = [ssksTMRPlugin saveIdentity:(NSString*)sessionId
                                                                                     authFactor:[authFactor toMobileSdk]
                                                                                      challenge:nil
                                                                                   rawTMRSymKey:(NSData*)rawTMRSymKey
                                                                                       identity:(NSData*)identity
                                                                                          error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksSaveIdentityResponse fromMobileSdk:internalResp];
}

- (void) saveIdentityAsync:(const NSString*)sessionId
                authFactor:(const SealdTmrAuthFactor*)authFactor
              rawTMRSymKey:(const NSData*)rawTMRSymKey
                  identity:(const NSData*)identity
                 challenge:(const NSString*_Nullable)challenge
         completionHandler:(void (^)(SealdSsksSaveIdentityResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksSaveIdentityResponse* resp = [self saveIdentity:sessionId
                                                      authFactor:authFactor
                                                    rawTMRSymKey:rawTMRSymKey
                                                        identity:identity
                                                       challenge:challenge
                                                           error:&localError];

        completionHandler(resp, localError);
    });
}

- (void) saveIdentityAsync:(const NSString*)sessionId
                authFactor:(const SealdTmrAuthFactor*)authFactor
              rawTMRSymKey:(const NSData*)rawTMRSymKey
                  identity:(const NSData*)identity
         completionHandler:(void (^)(SealdSsksSaveIdentityResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksSaveIdentityResponse* resp = [self saveIdentity:sessionId
                                                      authFactor:authFactor
                                                    rawTMRSymKey:rawTMRSymKey
                                                        identity:identity
                                                           error:&localError];

        completionHandler(resp, localError);
    });
}

- (SealdSsksRetrieveIdentityResponse*) retrieveIdentity:(const NSString*)sessionId
                                             authFactor:(const SealdTmrAuthFactor*)authFactor
                                           rawTMRSymKey:(const NSData*)rawTMRSymKey
                                              challenge:(const NSString*_Nullable)challenge
                                                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkRetrieveIdentityResponse* internalResp = [ssksTMRPlugin retrieveIdentity:(NSString*)sessionId
                                                                                             authFactor:[authFactor toMobileSdk]
                                                                                              challenge:(NSString*)challenge
                                                                                           rawTMRSymKey:(NSData*)rawTMRSymKey
                                                                                                  error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksRetrieveIdentityResponse fromMobileSdk:internalResp];
}

- (SealdSsksRetrieveIdentityResponse*) retrieveIdentity:(const NSString*)sessionId
                                             authFactor:(const SealdTmrAuthFactor*)authFactor
                                           rawTMRSymKey:(const NSData*)rawTMRSymKey
                                                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkRetrieveIdentityResponse* internalResp = [ssksTMRPlugin retrieveIdentity:(NSString*)sessionId
                                                                                             authFactor:[authFactor toMobileSdk]
                                                                                              challenge:nil
                                                                                           rawTMRSymKey:(NSData*)rawTMRSymKey
                                                                                                  error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksRetrieveIdentityResponse fromMobileSdk:internalResp];
}

- (void) retrieveIdentityAsync:(const NSString*)sessionId
                    authFactor:(const SealdTmrAuthFactor*)authFactor
                  rawTMRSymKey:(const NSData*)rawTMRSymKey
                     challenge:(const NSString*_Nullable)challenge
             completionHandler:(void (^)(SealdSsksRetrieveIdentityResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksRetrieveIdentityResponse* resp = [self retrieveIdentity:sessionId
                                                              authFactor:authFactor
                                                            rawTMRSymKey:rawTMRSymKey
                                                               challenge:challenge
                                                                   error:&localError];

        completionHandler(resp, localError);
    });
}

- (void) retrieveIdentityAsync:(const NSString*)sessionId
                    authFactor:(const SealdTmrAuthFactor*)authFactor
                  rawTMRSymKey:(const NSData*)rawTMRSymKey
             completionHandler:(void (^)(SealdSsksRetrieveIdentityResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksRetrieveIdentityResponse* resp = [self retrieveIdentity:sessionId
                                                              authFactor:authFactor
                                                            rawTMRSymKey:rawTMRSymKey
                                                                   error:&localError];

        completionHandler(resp, localError);
    });
}

- (SealdSsksGetFactorTokenResponse*) getFactorToken:(const NSString*)sessionId
                                         authFactor:(const SealdTmrAuthFactor*)authFactor
                                          challenge:(const NSString*_Nullable)challenge
                                              error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkGetFactorTokenResponse* internalResp = [ssksTMRPlugin getFactorToken:(NSString*)sessionId
                                                                                         authFactor:[authFactor toMobileSdk]
                                                                                          challenge:(NSString*)challenge
                                                                                              error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksGetFactorTokenResponse fromMobileSdk:internalResp];
}

- (SealdSsksGetFactorTokenResponse*) getFactorToken:(const NSString*)sessionId
                                         authFactor:(const SealdTmrAuthFactor*)authFactor
                                              error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkGetFactorTokenResponse* internalResp = [ssksTMRPlugin getFactorToken:(NSString*)sessionId
                                                                                         authFactor:[authFactor toMobileSdk]
                                                                                          challenge:nil
                                                                                              error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }

    return [SealdSsksGetFactorTokenResponse fromMobileSdk:internalResp];
}

- (void) getFactorTokenAsync:(const NSString*)sessionId
                  authFactor:(const SealdTmrAuthFactor*)authFactor
                   challenge:(const NSString*_Nullable)challenge
           completionHandler:(void (^)(SealdSsksGetFactorTokenResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksGetFactorTokenResponse* resp = [self getFactorToken:sessionId
                                                          authFactor:authFactor
                                                           challenge:challenge
                                                               error:&localError];

        completionHandler(resp, localError);
    });
}

- (void) getFactorTokenAsync:(const NSString*)sessionId
                  authFactor:(const SealdTmrAuthFactor*)authFactor
           completionHandler:(void (^)(SealdSsksGetFactorTokenResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdSsksGetFactorTokenResponse* resp = [self getFactorToken:sessionId
                                                          authFactor:authFactor
                                                               error:&localError];

        completionHandler(resp, localError);
    });
}
@end
