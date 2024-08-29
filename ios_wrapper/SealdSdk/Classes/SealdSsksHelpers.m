//
//  SealdSSKSHelpers.m
//  SealdSdk
//
//  Created by Clément Congard on 31/05/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSsksHelpers.h"

@implementation SealdSsksSaveIdentityResponse
- (instancetype) initWithSsksId:(NSString*)ssksId
         authenticatedSessionId:(NSString*_Nullable)authenticatedSessionId
{
    if (self = [super init]) {
        _ssksId = ssksId;
        _authenticatedSessionId = authenticatedSessionId;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkSaveIdentityResponse*)saveIdentityResponse
{
    return [[SealdSsksSaveIdentityResponse alloc] initWithSsksId:saveIdentityResponse.ssksId
                                          authenticatedSessionId:(saveIdentityResponse.authenticatedSessionId.length > 0 ? saveIdentityResponse.authenticatedSessionId : nil)
    ];
}
@end

@implementation SealdSsksRetrieveIdentityResponse
- (instancetype) initWithIdentity:(NSData*)identity
                   shouldRenewKey:(BOOL)shouldRenewKey
           authenticatedSessionId:(NSString*)authenticatedSessionId
{
    if (self = [super init]) {
        _identity = identity;
        _shouldRenewKey = shouldRenewKey;
        _authenticatedSessionId = authenticatedSessionId;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkRetrieveIdentityResponse*)retrieveIdentityResponse
{
    return [[SealdSsksRetrieveIdentityResponse alloc] initWithIdentity:retrieveIdentityResponse.identity
                                                        shouldRenewKey:retrieveIdentityResponse.shouldRenewKey
                                                authenticatedSessionId:retrieveIdentityResponse.authenticatedSessionId
    ];
}
@end

@implementation SealdSsksGetFactorTokenResponse
- (instancetype) initWithToken:(NSString*)token
        authenticatedSessionId:(NSString*)authenticatedSessionId
{
    if (self = [super init]) {
        _token = token;
        _authenticatedSessionId = authenticatedSessionId;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGetFactorTokenResponse*)getFactorTokenResponse
{
    return [[SealdSsksGetFactorTokenResponse alloc] initWithToken:getFactorTokenResponse.token
                                           authenticatedSessionId:getFactorTokenResponse.authenticatedSessionId];
}
@end
