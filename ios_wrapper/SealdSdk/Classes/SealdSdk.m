//
//  SealdSdk.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSdk.h"
#import <Security/Security.h>

@implementation SealdSdk
- (instancetype) initWithApiUrl:(const NSString*)apiUrl
                          appId:(const NSString*)appId
                   databasePath:(const NSString*_Nullable)databasePath
          databaseEncryptionKey:(const NSData*_Nullable)databaseEncryptionKey
                   instanceName:(const NSString*)instanceName
                       logLevel:(const NSInteger)logLevel
                     logNoColor:(const BOOL)logNoColor
      encryptionSessionCacheTTL:(const NSTimeInterval)encryptionSessionCacheTTL
                        keySize:(const NSInteger)keySize
                          error:(NSError*_Nullable*)error
{
    self = [super init];
    if (self) {
        SealdSdkInternalsMobile_sdkSdkInitializeOptions* initOpts = [[SealdSdkInternalsMobile_sdkSdkInitializeOptions alloc] init];
        initOpts.apiURL = (NSString*)apiUrl;
        initOpts.appId = (NSString*)appId;
        initOpts.databasePath = (NSString*)databasePath;
        initOpts.databaseEncryptionKey = (NSData*)databaseEncryptionKey;
        initOpts.instanceName = (NSString*)instanceName;
        initOpts.platform = @"ios";
        initOpts.logLevel = logLevel;
        initOpts.logNoColor = logNoColor;
        initOpts.encryptionSessionCacheTTL = (int64_t)(encryptionSessionCacheTTL * 1000);
        initOpts.keySize = keySize == 0 ? 4096 : keySize;

        NSError* localErr = nil;
        sdkInstance = SealdSdkInternalsMobile_sdkInitialize(initOpts, &localErr);
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return nil;
        }
        self->keySize = keySize;
    }
    return self;
}

- (void) closeWithError:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance close:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) closeAsyncWithCompletionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self closeWithError:&localErr];

        completionHandler(localErr);
    });
}

- (void) _generateRSAKey:(void (^)(NSData* keyRawData, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* error;
        NSDictionary* parameters = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeySizeInBits: @(self->keySize),
            (__bridge id)kSecPrivateKeyAttrs: @{
                (__bridge id)kSecAttrIsPermanent: @NO,
            }
        };

        CFErrorRef cfError = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)parameters, &cfError);
        if (!privateKey) {
            error = (__bridge_transfer NSError*)cfError;
            completionHandler(nil, error);
            return;
        }

        CFDataRef keyData = SecKeyCopyExternalRepresentation(privateKey, &cfError);
        if (!keyData) {
            error = (__bridge_transfer NSError*)cfError;
            completionHandler(nil, error);
            return;
        }
        // This is in PKCS1 DER format, not the usual PKCS8, because this is what iOS natively supports
        NSData* keyRawData = (__bridge_transfer NSData*)keyData;

        CFRelease(privateKey);

        completionHandler(keyRawData, error);
    });
}

- (SealdGeneratedPrivateKeys*) generatePrivateKeysWithError:(NSError*_Nullable*)error
{
    __block NSData* encryptionKey;
    __block NSData* signingKey;

    dispatch_group_t group = dispatch_group_create();

    __block NSError* firstThreadError = nil;
    dispatch_group_enter(group);
    [self _generateRSAKey:^(NSData* keyRawData, NSError* error) {
        if (error != nil) {
            firstThreadError = error;
        }
        encryptionKey = keyRawData;
        dispatch_group_leave(group);
    }];

    __block NSError* secondThreadError = nil;
    dispatch_group_enter(group);
    [self _generateRSAKey:^(NSData* keyRawData, NSError* error) {
        if (error != nil) {
            secondThreadError = error;
        }
        signingKey = keyRawData;
        dispatch_group_leave(group);
    }];

    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);

    if (firstThreadError != nil) {
        _SealdInternal_ConvertError(firstThreadError, error);
        return nil;
    }
    if (secondThreadError != nil) {
        _SealdInternal_ConvertError(secondThreadError, error);
        return nil;
    }

    NSError* localErr = nil;
    SealdGeneratedPrivateKeys* preGeneratedKeys = SealdSdkInternalsMobile_sdkPreGeneratedKeysFromPKCS1DER(encryptionKey, signingKey, &localErr);
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return preGeneratedKeys;
}

- (void) generatePrivateKeysAsyncWithCompletionHandler:(void (^)(SealdGeneratedPrivateKeys* privateKeys, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdGeneratedPrivateKeys* res = [self generatePrivateKeysWithError:&localErr];

        completionHandler(res, localErr);
    });
}


// Account
- (SealdAccountInfo*) createAccountWithSignupJwt:(const NSString*)signupJwt
                                      deviceName:(const NSString*)deviceName
                                     displayName:(const NSString*)displayName
                                     privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                     expireAfter:(const NSTimeInterval)expireAfter
                                           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    SealdSdkInternalsMobile_sdkCreateAccountOptions* createAccountOpts = [[SealdSdkInternalsMobile_sdkCreateAccountOptions alloc] init];
    createAccountOpts.signupJWT = (NSString*)signupJwt;
    createAccountOpts.deviceName = (NSString*)deviceName;
    createAccountOpts.displayName = (NSString*)displayName;
    createAccountOpts.expireAfter = expireAfter == 0 ? 5 * 365 * 24 * 60 * 60 : (int64_t)(expireAfter * 1000);
    NSError* localErr = nil;
    if (privateKeys == nil) {
        createAccountOpts.preGeneratedKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return nil;
        }
    } else {
        createAccountOpts.preGeneratedKeys = privateKeys;
    }

    SealdSdkInternalsMobile_sdkAccountInfo* accountInfo = [sdkInstance createAccount:createAccountOpts error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdAccountInfo fromMobileSdk:accountInfo];
}

- (void) createAccountAsyncWithSignupJwt:(const NSString*)signupJwt
                              deviceName:(const NSString*)deviceName
                             displayName:(const NSString*)displayName
                             privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                             expireAfter:(const NSTimeInterval)expireAfter
                       completionHandler:(void (^)(SealdAccountInfo* accountInfo, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdAccountInfo* res = [self createAccountWithSignupJwt:signupJwt deviceName:deviceName displayName:displayName privateKeys:privateKeys expireAfter:expireAfter error:&localErr];
        completionHandler(res, localErr);
    });
}

- (SealdAccountInfo*) getCurrentAccountInfo
{
    SealdSdkInternalsMobile_sdkAccountInfo* accountInfo = [sdkInstance getCurrentAccountInfo];
    return [SealdAccountInfo fromMobileSdk:accountInfo];
}

- (void) getCurrentAccountInfoAsyncWithCompletionHandler:(void (^)(SealdAccountInfo*))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        SealdAccountInfo* res = [self getCurrentAccountInfo];
        completionHandler(res);
    });
}

- (void) updateCurrentDeviceWithError:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance updateCurrentDevice:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) updateCurrentDeviceAsyncWithCompletionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self updateCurrentDeviceWithError:&localErr];

        completionHandler(localErr);
    });
}

- (NSData*) prepareRenewWithPrivateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    if (privateKeys == nil) {
        privateKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return nil;
        }
    }
    NSData* res = [sdkInstance prepareRenew:privateKeys error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) prepareRenewAsyncWithPrivateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                        completionHandler:(void (^)(NSData* preparedRenewal, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSData* res = [self prepareRenewWithPrivateKeys:privateKeys error:&localErr];

        completionHandler(res, localErr);
    });
}

- (void) renewKeysWithPreparedRenewal:(nullable const NSData*)preparedRenewal
                          privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                          expireAfter:(const NSTimeInterval)expireAfter
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    if (preparedRenewal == nil && privateKeys == nil) {
        privateKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return;
        }
    }

    const int64_t expire = expireAfter == 0 ? 5 * 365 * 24 * 60 * 60 : (int64_t)(expireAfter * 1000);

    SealdSdkInternalsMobile_sdkRenewKeysOptions* renewKeysOpts = [[SealdSdkInternalsMobile_sdkRenewKeysOptions alloc] init];
    renewKeysOpts.expireAfter = expire;
    renewKeysOpts.preGeneratedKeys = privateKeys;
    renewKeysOpts.preparedRenewal = (NSData*)preparedRenewal;

    [sdkInstance renewKeys:renewKeysOpts error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) renewKeysAsyncWithPreparedRenewal:(nullable const NSData*)preparedRenewal
                               privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                               expireAfter:(const NSTimeInterval)expireAfter
                         completionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self renewKeysWithPreparedRenewal:preparedRenewal privateKeys:privateKeys expireAfter:expireAfter error:&localErr];

        completionHandler(localErr);
    });
}

- (SealdCreateSubIdentityResponse*) createSubIdentityWithDeviceName:(const NSString*)deviceName
                                                        privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                                        expireAfter:(const NSTimeInterval)expireAfter
                                                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    SealdSdkInternalsMobile_sdkCreateSubIdentityOptions* createSubIdentityOpts = [[SealdSdkInternalsMobile_sdkCreateSubIdentityOptions alloc] init];
    createSubIdentityOpts.deviceName = (NSString*)deviceName;
    createSubIdentityOpts.expireAfter = expireAfter == 0 ? 5 * 365 * 24 * 60 * 60 : (int64_t)(expireAfter * 1000);
    NSError* localErr = nil;
    if (privateKeys == nil) {
        createSubIdentityOpts.preGeneratedKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return nil;
        }
    } else {
        createSubIdentityOpts.preGeneratedKeys = privateKeys;
    }

    SealdSdkInternalsMobile_sdkCreateSubIdentityResponse* createSubIdentityResponse = [sdkInstance createSubIdentity:createSubIdentityOpts error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [[SealdCreateSubIdentityResponse alloc] initWithDeviceId:createSubIdentityResponse.deviceId backupKey:createSubIdentityResponse.backupKey];
}

- (void) createSubIdentityAsyncWithDeviceName:(const NSString*)deviceName
                                  privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                  expireAfter:(const NSTimeInterval)expireAfter
                            completionHandler:(void (^)(SealdCreateSubIdentityResponse* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdCreateSubIdentityResponse* res = [self createSubIdentityWithDeviceName:deviceName privateKeys:privateKeys expireAfter:expireAfter error:&localErr];

        completionHandler(res, localErr);
    });
}

- (void) importIdentity:(const NSData*)identity
                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance importIdentity:(NSData*)identity error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) importIdentityAsyncWithIdentity:(const NSData*)identity
                       completionHandler:(void (^)(NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self importIdentity:identity error:&localErr];

        completionHandler(localErr);
    });
}


- (NSData*) exportIdentityWithError:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSData* res = [sdkInstance exportIdentity:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) exportIdentityAsyncWithCompletionHandler:(void (^)(NSData* identity, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSData* res = [self exportIdentityWithError:&localErr];

        completionHandler(res, localErr);
    });
}


- (void) pushJWT:(const NSString*)jwt
           error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance pushJWT:(NSString*)jwt error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) pushJWTAsyncWithJWT:(const NSString*)jwt
           completionHandler:(void (^)(NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self pushJWT:jwt error:&localErr];

        completionHandler(localErr);
    });
}


- (void) heartbeatWithError:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance heartbeat:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) heartbeatAsyncWithCompletionHandler:(void (^)(NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self heartbeatWithError:&localErr];

        completionHandler(localErr);
    });
}


// Groups
- (NSString*) createGroupWithGroupName:(const NSString*)groupName
                               members:(const NSArray<NSString*>*)members
                                admins:(const NSArray<NSString*>*)admins
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    if (privateKeys == nil) {
        privateKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return nil;
        }
    }
    NSString* groupId = [sdkInstance createGroup:(NSString*)groupName
                                         members:arrayToStringArray((NSArray<NSString*>*)members)
                                          admins:arrayToStringArray((NSArray<NSString*>*)admins)
                                preGeneratedKeys:privateKeys
                                           error:&localErr
                        ];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return groupId;
}

- (void) createGroupAsyncWithGroupName:(const NSString*)groupName
                               members:(const NSArray<NSString*>*)members
                                admins:(const NSArray<NSString*>*)admins
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                     completionHandler:(void (^)(NSString* groupId, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSString* res = [self createGroupWithGroupName:groupName
                                               members:members
                                                admins:admins
                                           privateKeys:privateKeys
                                                 error:&localErr];
        completionHandler(res, localErr);
    });
}


- (void) addGroupMembersWithGroupId:(const NSString*)groupId
                       membersToAdd:(const NSArray<NSString*>*)membersToAdd
                        adminsToSet:(const NSArray<NSString*>*)adminsToSet
                        privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                              error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    BOOL shouldRenew;
    [sdkInstance shouldRenewGroup:(NSString*)groupId ret0_:&shouldRenew error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return;
    }
    if (shouldRenew) {
        if (privateKeys == nil) {
            privateKeys = [self generatePrivateKeysWithError:&localErr];
            if (localErr) {
                _SealdInternal_ConvertError(localErr, error);
                return;
            }
        }
        [sdkInstance renewGroupKey:(NSString*)groupId
                  preGeneratedKeys:privateKeys
                             error:&localErr
        ];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return;
        }
    }
    [sdkInstance addGroupMembers:(NSString*)groupId
                    membersToAdd:arrayToStringArray(((NSArray<NSString*>*)membersToAdd))
                     adminsToSet:arrayToStringArray(((NSArray<NSString*>*)adminsToSet))
                           error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) addGroupMembersAsyncWithGroupId:(const NSString*)groupId
                            membersToAdd:(const NSArray<NSString*>*)membersToAdd
                             adminsToSet:(const NSArray<NSString*>*)adminsToSet
                             privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                       completionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self addGroupMembersWithGroupId:groupId membersToAdd:membersToAdd adminsToSet:adminsToSet privateKeys:privateKeys error:&localErr];

        completionHandler(localErr);
    });
}
- (void) removeGroupMembersWithGroupId:(const NSString*)groupId
                       membersToRemove:(const NSArray<NSString*>*)membersToRemove
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                                 error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    BOOL shouldRenew;
    [sdkInstance shouldRenewGroup:(NSString*)groupId ret0_:&shouldRenew error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return;
    }
    if (shouldRenew) {
        if (privateKeys == nil) {
            privateKeys = [self generatePrivateKeysWithError:&localErr];
            if (localErr) {
                _SealdInternal_ConvertError(localErr, error);
                return;
            }
        }
        [sdkInstance renewGroupKey:(NSString*)groupId
                  preGeneratedKeys:privateKeys
                             error:&localErr
        ];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return;
        }
    }
    [sdkInstance removeGroupMembers:(NSString*)groupId membersToRemove:arrayToStringArray(((NSArray<NSString*>*)membersToRemove)) error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) removeGroupMembersAsyncWithGroupId:(const NSString*)groupId
                            membersToRemove:(const NSArray<NSString*>*)membersToRemove
                                privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                          completionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self removeGroupMembersWithGroupId:groupId membersToRemove:membersToRemove privateKeys:privateKeys error:&localErr];

        completionHandler(localErr);
    });
}

- (void) renewGroupKeyWithGroupId:(const NSString*)groupId
                      privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                            error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    if (privateKeys == nil) {
        privateKeys = [self generatePrivateKeysWithError:&localErr];
        if (localErr) {
            _SealdInternal_ConvertError(localErr, error);
            return;
        }
    }
    [sdkInstance renewGroupKey:(NSString*)groupId
              preGeneratedKeys:privateKeys
                         error:&localErr
    ];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) renewGroupKeyAsyncWithGroupId:(const NSString*)groupId
                           privateKeys:(nullable SealdGeneratedPrivateKeys*)privateKeys
                     completionHandler:(void (^)(NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self renewGroupKeyWithGroupId:groupId privateKeys:privateKeys error:&localErr];

        completionHandler(localErr);
    });
}

- (void) setGroupAdminsWithGroupId:(const NSString*)groupId
                       addToAdmins:(const NSArray<NSString*>*)addToAdmins
                  removeFromAdmins:(const NSArray<NSString*>*)removeFromAdmins
                             error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [sdkInstance setGroupAdmins:(NSString*)groupId
                    addToAdmins:arrayToStringArray((NSArray<NSString*>*)addToAdmins)
               removeFromAdmins:arrayToStringArray((NSArray<NSString*>*)removeFromAdmins)
                          error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) setGroupAdminsAsyncWithGroupId:(const NSString*)groupId
                            addToAdmins:(const NSArray<NSString*>*)addToAdmins
                       removeFromAdmins:(const NSArray<NSString*>*)removeFromAdmins
                      completionHandler:(void (^)(NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        [self setGroupAdminsWithGroupId:groupId addToAdmins:addToAdmins removeFromAdmins:removeFromAdmins error:&localErr];

        completionHandler(localErr);
    });
}

// EncryptionSession
- (SealdEncryptionSession*) createEncryptionSessionWithRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                                         useCache:(const BOOL)useCache
                                                            error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [sdkInstance createEncryptionSession:[SealdRecipientWithRights toMobileSdkArray:(NSArray<SealdRecipientWithRights*>*)recipients] useCache:useCache error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) createEncryptionSessionAsyncWithRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                           useCache:(const BOOL)useCache
                                  completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self createEncryptionSessionWithRecipients:recipients useCache:useCache error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdEncryptionSession*) retrieveEncryptionSessionWithSessionId:(const NSString*)sessionId
                                                          useCache:(const BOOL)useCache
                                                    lookupProxyKey:(const BOOL)lookupProxyKey
                                                    lookupGroupKey:(const BOOL)lookupGroupKey
                                                             error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [sdkInstance retrieveEncryptionSession:(NSString*)sessionId
                                                                                           useCache:useCache
                                                                                     lookupProxyKey:lookupProxyKey
                                                                                     lookupGroupKey:lookupGroupKey
                                                                                              error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) retrieveEncryptionSessionAsyncWithSessionId:(const NSString*)sessionId
                                            useCache:(const BOOL)useCache
                                      lookupProxyKey:(const BOOL)lookupProxyKey
                                      lookupGroupKey:(const BOOL)lookupGroupKey
                                   completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self retrieveEncryptionSessionWithSessionId:sessionId
                                                                          useCache:useCache
                                                                    lookupProxyKey:lookupProxyKey
                                                                    lookupGroupKey:lookupGroupKey
                                                                             error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdEncryptionSession*) retrieveEncryptionSessionFromMessage:(const NSString*_Nonnull)message
                                                        useCache:(const BOOL)useCache
                                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                                  lookupGroupKey:(const BOOL)lookupGroupKey
                                                           error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [sdkInstance retrieveEncryptionSessionFromMessage:(NSString*)message
                                                                                                      useCache:useCache
                                                                                                lookupProxyKey:lookupProxyKey
                                                                                                lookupGroupKey:lookupGroupKey
                                                                                                         error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) retrieveEncryptionSessionAsyncFromMessage:(const NSString*_Nonnull)message
                                          useCache:(const BOOL)useCache
                                    lookupProxyKey:(const BOOL)lookupProxyKey
                                    lookupGroupKey:(const BOOL)lookupGroupKey
                                 completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self retrieveEncryptionSessionFromMessage:message
                                                                        useCache:useCache
                                                                  lookupProxyKey:lookupProxyKey
                                                                  lookupGroupKey:lookupGroupKey
                                                                           error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdEncryptionSession*) retrieveEncryptionSessionFromFile:(const NSString*_Nonnull)fileURI
                                                     useCache:(const BOOL)useCache
                                               lookupProxyKey:(const BOOL)lookupProxyKey
                                               lookupGroupKey:(const BOOL)lookupGroupKey
                                                        error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [sdkInstance retrieveEncryptionSessionFromFile:(NSString*)fileURI
                                                                                                   useCache:useCache
                                                                                             lookupProxyKey:lookupProxyKey
                                                                                             lookupGroupKey:lookupGroupKey
                                                                                                      error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) retrieveEncryptionSessionAsyncFromFile:(const NSString*_Nonnull)fileURI
                                       useCache:(const BOOL)useCache
                                 lookupProxyKey:(const BOOL)lookupProxyKey
                                 lookupGroupKey:(const BOOL)lookupGroupKey
                              completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self retrieveEncryptionSessionFromFile:fileURI
                                                                     useCache:useCache
                                                               lookupProxyKey:lookupProxyKey
                                                               lookupGroupKey:lookupGroupKey
                                                                        error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdEncryptionSession*) retrieveEncryptionSessionFromBytes:(const NSData*_Nonnull)fileBytes
                                                      useCache:(const BOOL)useCache
                                                lookupProxyKey:(const BOOL)lookupProxyKey
                                                lookupGroupKey:(const BOOL)lookupGroupKey
                                                         error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [sdkInstance retrieveEncryptionSessionFromBytes:(NSData*)fileBytes
                                                                                                    useCache:useCache
                                                                                              lookupProxyKey:lookupProxyKey
                                                                                              lookupGroupKey:lookupGroupKey
                                                                                                       error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) retrieveEncryptionSessionAsyncFromBytes:(const NSData*_Nonnull)fileBytes
                                        useCache:(const BOOL)useCache
                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                  lookupGroupKey:(const BOOL)lookupGroupKey
                               completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self retrieveEncryptionSessionFromBytes:fileBytes
                                                                      useCache:useCache
                                                                lookupProxyKey:lookupProxyKey
                                                                lookupGroupKey:lookupGroupKey
                                                                         error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdEncryptionSession*) retrieveEncryptionSessionByTmr:(const NSString*)tmrJWT
                                                 sessionId:(const NSString*)sessionId
                                         overEncryptionKey:(const NSData*)overEncryptionKey
                                        tmrAccessesFilters:(const SealdTmrAccessesRetrievalFilters*_Nullable)tmrAccessesFilters
                                             tryIfMultiple:(const BOOL)tryIfMultiple
                                                  useCache:(const BOOL)useCache
                                                     error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkTmrAccessesRetrievalFilters* nativeFilter = [tmrAccessesFilters toMobileSdk];
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* es =
        [sdkInstance retrieveEncryptionSessionByTmr:(NSString*)tmrJWT
                                          sessionId:(NSString*)sessionId
                                  overEncryptionKey:(NSData*)overEncryptionKey
                                 tmrAccessesFilters:nativeFilter
                                      tryIfMultiple:tryIfMultiple
                                           useCache:(BOOL)useCache
                                              error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdk:es];
}

- (void) retrieveEncryptionSessionAsyncByTmr:(const NSString*)tmrJWT
                                   sessionId:(const NSString*)sessionId
                           overEncryptionKey:(const NSData*)overEncryptionKey
                          tmrAccessesFilters:(const SealdTmrAccessesRetrievalFilters*_Nullable)tmrAccessesFilters
                               tryIfMultiple:(const BOOL)tryIfMultiple
                                    useCache:(const BOOL)useCache
                           completionHandler:(void (^)(SealdEncryptionSession* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdEncryptionSession* res = [self retrieveEncryptionSessionByTmr:tmrJWT
                                                                 sessionId:sessionId
                                                         overEncryptionKey:overEncryptionKey
                                                        tmrAccessesFilters:tmrAccessesFilters
                                                             tryIfMultiple:tryIfMultiple
                                                                  useCache:useCache
                                                                     error:&localErr];

        completionHandler(res, localErr);
    });
}

- (NSArray<SealdEncryptionSession*>*) retrieveMultipleEncryptionSessions:(const NSArray<NSString*>*)sessionIds
                                                                useCache:(const BOOL)useCache
                                                          lookupProxyKey:(const BOOL)lookupProxyKey
                                                          lookupGroupKey:(const BOOL)lookupGroupKey
                                                                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMobileEncryptionSessionArray* array =
        [sdkInstance retrieveMultipleEncryptionSessions:arrayToStringArray((NSArray<NSString*>*)sessionIds)
                                               useCache:(BOOL)useCache
                                         lookupProxyKey:(BOOL)lookupProxyKey
                                         lookupGroupKey:(BOOL)lookupGroupKey
                                                  error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdEncryptionSession fromMobileSdkArray:array];
}

- (void) retrieveMultipleEncryptionSessionsAsync:(const NSArray<NSString*>*)sessionIds
                                        useCache:(const BOOL)useCache
                                  lookupProxyKey:(const BOOL)lookupProxyKey
                                  lookupGroupKey:(const BOOL)lookupGroupKey
                               completionHandler:(void (^)(NSArray<SealdEncryptionSession*>* encryptionSessions, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSArray<SealdEncryptionSession*>* res = [self retrieveMultipleEncryptionSessions:sessionIds
                                                                                useCache:useCache
                                                                          lookupProxyKey:lookupProxyKey
                                                                          lookupGroupKey:lookupGroupKey
                                                                                   error:&localErr];

        completionHandler(res, localErr);
    });
}

// Connectors
- (NSArray<NSString*>*) getSealdIdsFromConnectors:(const NSArray<SealdConnectorTypeValue*>*)connectorTypeValues
                                            error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkStringArray* res = [sdkInstance getSealdIdsFromConnectors:[SealdConnectorTypeValue toMobileSdkArray:(NSArray<SealdConnectorTypeValue*>*)connectorTypeValues] error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return stringArrayToArray(res);
}

- (void) getSealdIdsAsyncFromConnectors:(const NSArray<SealdConnectorTypeValue*>*)connectorTypeValues
                      completionHandler:(void (^)(NSArray<NSString*>* sealdIds, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSArray<NSString*>* res = [self getSealdIdsFromConnectors:connectorTypeValues error:&localErr];

        completionHandler(res, localErr);
    });
}

- (NSArray<SealdConnector*>*) getConnectorsFromSealdId:(const NSString*)sealdId
                                                 error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnectorsArray* res = [sdkInstance getConnectorsFromSealdId:(NSString*)sealdId error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdkArray:res];
}

- (void) getConnectorsAsyncFromSealdId:(const NSString*)sealdId
                     completionHandler:(void (^)(NSArray<SealdConnector*>* connectors, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSArray<SealdConnector*>* res = [self getConnectorsFromSealdId:sealdId error:&localErr];

        completionHandler(res, localErr);
    });
}


- (SealdConnector*) addConnectorWithValue:(const NSString*)value
                            connectorType:(const NSString*)connectorType
                       preValidationToken:(const SealdPreValidationToken*)preValidationToken
                                    error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnector* res = [sdkInstance addConnector:(NSString*)value
                                                            connectorType:(NSString*)connectorType
                                                       preValidationToken:(SealdSdkInternalsMobile_sdkPreValidationToken*)[preValidationToken toMobileSdk]
                                                                    error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdk:res];
}

- (void) addConnectorAsyncWithValue:(const NSString*)value
                      connectorType:(const NSString*)connectorType
                 preValidationToken:(const SealdPreValidationToken*)preValidationToken
                  completionHandler:(void (^)(SealdConnector* connector, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdConnector* res = [self addConnectorWithValue:value connectorType:connectorType preValidationToken:preValidationToken error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdConnector*) validateConnector:(const NSString*)connectorId
                            challenge:(const NSString*)challenge
                                error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnector* res = [sdkInstance validateConnector:(NSString*)connectorId
                                                                     challenge:(NSString*)challenge
                                                                         error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdk:res];
}

- (void) validateConnectorAsyncWithConnectorId:(const NSString*)connectorId
                                     challenge:(const NSString*)challenge
                             completionHandler:(void (^)(SealdConnector* connector, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdConnector* res = [self validateConnector:connectorId challenge:challenge error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdConnector*) removeConnector:(const NSString*)connectorId
                              error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnector* res = [sdkInstance removeConnector:(NSString*)connectorId error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdk:res];
}

- (void) removeConnectorAsyncWithConnectorId:(const NSString*)connectorId
                           completionHandler:(void (^)(SealdConnector* connector, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdConnector* res = [self removeConnector:connectorId error:&localErr];

        completionHandler(res, localErr);
    });
}

- (NSArray<SealdConnector*>*) listConnectorsWithError:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnectorsArray* res = [sdkInstance listConnectors:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdkArray:res];
}

- (void) listConnectorsAsyncWithCompletionHandler:(void (^)(NSArray<SealdConnector*>* connectors, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSArray<SealdConnector*>* res = [self listConnectorsWithError:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdConnector*) retrieveConnector:(const NSString*)connectorId
                                error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkConnector* res = [sdkInstance retrieveConnector:(NSString*)connectorId error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConnector fromMobileSdk:res];
}

- (void) retrieveConnectorAsyncWithConnectorId:(const NSString*)connectorId
                             completionHandler:(void (^)(SealdConnector* connector, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdConnector* res = [self retrieveConnector:connectorId error:&localErr];

        completionHandler(res, localErr);
    });
}

// Reencrypt
- (SealdMassReencryptResponse*) massReencryptWithDeviceId:(const NSString*)deviceId
                                                  options:(const SealdMassReencryptOptions*)options
                                                    error:(NSError*_Nullable*)error
{
    SealdSdkInternalsMobile_sdkMassReencryptOptions* mobileOptions = options != nil ? [options toMobileSdk] : [[SealdMassReencryptOptions new] toMobileSdk];

    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkMassReencryptResponse* mobileResponse = [sdkInstance massReencrypt:(NSString*)deviceId
                                                                                          options:mobileOptions
                                                                                            error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdMassReencryptResponse fromMobileSdk:mobileResponse];
}

- (void) massReencryptAsyncWithDeviceId:(const NSString*)deviceId
                                options:(const SealdMassReencryptOptions*)options
                      completionHandler:(void (^)(SealdMassReencryptResponse* response, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdMassReencryptResponse* res = [self massReencryptWithDeviceId:deviceId options:options error:&localErr];

        completionHandler(res, localErr);
    });
}

- (NSArray<SealdDeviceMissingKeys*>*) devicesMissingKeysWithForceLocalAccountUpdate:(const BOOL)forceLocalAccountUpdate
                                                                              error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkDevicesMissingKeysArray* mobileResponse = [sdkInstance devicesMissingKeys:forceLocalAccountUpdate error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdDeviceMissingKeys fromMobileSdkArray:mobileResponse];
}

- (void) devicesMissingKeysAsyncWithForceLocalAccountUpdate:(const BOOL)forceLocalAccountUpdate
                                          completionHandler:(void (^)(NSArray<SealdDeviceMissingKeys*>* devices, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        NSArray<SealdDeviceMissingKeys*>* res = [self devicesMissingKeysWithForceLocalAccountUpdate:forceLocalAccountUpdate error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdGetSigchainResponse*) getSigchainHashWithUserId:(const NSString*)userId
                                               position:(const long)position
                                                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkGetSigchainResponse* resp = [sdkInstance getSigchainHash:(NSString*)userId position:position error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdGetSigchainResponse fromMobileSdk:resp];
}

- (void) getSigchainHashAsyncWithUserId:(const NSString*)userId
                               position:(const long)position
                      completionHandler:(void (^)(SealdGetSigchainResponse* encryptionSession, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdGetSigchainResponse* res = [self getSigchainHashWithUserId:(NSString*)userId position:position error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdCheckSigchainResponse*) checkSigchainHashWithUserId:(const NSString*)userId
                                               expectedHash:(const NSString*)expectedHash
                                                   position:(const long)position
                                                      error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkCheckSigchainResponse* resp = [sdkInstance checkSigchainHash:(NSString*)userId
                                                                               sigchainHash:(NSString*)expectedHash
                                                                                   position:position
                                                                                      error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdCheckSigchainResponse fromMobileSdk:resp];
}

- (void) checkSigchainHashAsyncWithUserId:(const NSString*)userId
                             expectedHash:(const NSString*)expectedHash
                                 position:(const long)position
                        completionHandler:(void (^)(SealdCheckSigchainResponse* response, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdCheckSigchainResponse* res = [self checkSigchainHashWithUserId:(NSString*)userId
                                                               expectedHash:expectedHash
                                                                   position:position
                                                                      error:&localErr];

        completionHandler(res, localErr);
    });
}

- (SealdConvertTmrAccessesResult*) convertTmrAccesses:(const NSString*)tmrJWT
                                    overEncryptionKey:(const NSData*)overEncryptionKey
                                    conversionFilters:(const SealdTmrAccessesConvertFilters*_Nullable)conversionFilters
                                      deleteOnConvert:(const BOOL)deleteOnConvert
                                                error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkTmrAccessesConvertFilters* nativeFilter = [conversionFilters toMobileSdk];
    SealdSdkInternalsMobile_sdkConvertTmrAccessesResponse* convertedNative =
        [sdkInstance convertTmrAccesses:(NSString*)tmrJWT
                      overEncryptionKey:(NSData*)overEncryptionKey
                      conversionFilters:nativeFilter
                        deleteOnConvert:deleteOnConvert
                                  error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdConvertTmrAccessesResult fromMobileSdk:convertedNative];
}

- (void) convertTmrAccessesAsync:(const NSString*)tmrJWT
               overEncryptionKey:(const NSData*)overEncryptionKey
               conversionFilters:(const SealdTmrAccessesConvertFilters*_Nullable)conversionFilters
                 deleteOnConvert:(const BOOL)deleteOnConvert
               completionHandler:(void (^)(SealdConvertTmrAccessesResult* response, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localErr = nil;
        SealdConvertTmrAccessesResult* res = [self convertTmrAccesses:tmrJWT
                                                    overEncryptionKey:overEncryptionKey
                                                    conversionFilters:conversionFilters
                                                      deleteOnConvert:deleteOnConvert
                                                                error:&localErr];

        completionHandler(res, localErr);
    });
}

- (void) dealloc
{
    NSError* localErr = nil;
    [self closeWithError:&localErr];
    if (localErr != nil) {
        NSLog(@"SealdSDK instance failed to close with error: %@", localErr);
    }
}
@end
