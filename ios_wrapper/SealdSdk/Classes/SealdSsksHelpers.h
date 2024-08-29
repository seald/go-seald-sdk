//
//  SealdSsksHelpers.h
//  SealdSdk
//
//  Created by Clément Congard on 27/04/2023.
//

#ifndef SealdSsksHelpers_h
#define SealdSsksHelpers_h

#import <SealdSdkInternals/SealdSdkInternals.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * SealdSsksSaveIdentityResponse is returned by `[SealdSsksTMRPlugin saveIdentity]` when an identity has been successfully saved
 */
@interface SealdSsksSaveIdentityResponse : NSObject
/** The SSKS ID of the stored identity, which can be used by your backend to manage it */
@property (nonatomic, readonly) NSString* ssksId;
/** If a challenge was passed, an authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge */
@property (nonatomic, readonly) NSString*_Nullable authenticatedSessionId;

/** \cond */
- (instancetype) initWithSsksId:(NSString*)ssksId
         authenticatedSessionId:(NSString*_Nullable)authenticatedSessionId;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkSaveIdentityResponse*)saveIdentityResponse;
/** \endcond */
@end

/**
 * SealdSsksRetrievedIdentityResponse holds a retrieved identity
 */
@interface SealdSsksRetrieveIdentityResponse : NSObject
/** The retrieved identity. It can be used with `[sdkInstance importIdentity]` */
@property (nonatomic, readonly) NSData* identity;
/** If the boolean shouldRenewKey is set to `true`, the account MUST renew its private key using `[sealdSdk renewKeys]` */
@property (nonatomic, readonly) BOOL shouldRenewKey;
/** An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge */
@property (nonatomic, readonly) NSString* authenticatedSessionId;

/** \cond */
- (instancetype) initWithIdentity:(NSData*)identity
                   shouldRenewKey:(BOOL)shouldRenewKey
           authenticatedSessionId:(NSString*)authenticatedSessionId;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkRetrieveIdentityResponse*)retrieveIdentityResponse;
/** \endcond */
@end

/**
 * SealdSsksGetFactorTokenResponse holds a retrieved authentication factor token
 */
@interface SealdSsksGetFactorTokenResponse : NSObject
/** The retrieved token. It can be used with `[sdkInstance retrieveEncryptionSessionByTmr]` and `[sdkInstance convertTmrAccesses]`. */
@property (nonatomic, readonly) NSString* token;
/** An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge */
@property (nonatomic, readonly) NSString* authenticatedSessionId;
/** \cond */
- (instancetype) initWithToken:(NSString*)token
        authenticatedSessionId:(NSString*)authenticatedSessionId;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGetFactorTokenResponse*)getFactorTokenResponse;
/** \endcond */
@end

NS_ASSUME_NONNULL_END

#endif /* SealdSsksHelpers_h */
