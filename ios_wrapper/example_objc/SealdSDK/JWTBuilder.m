//
//  JWTBuilder.m
//  SealdSdk
//
//  Created by Clement on 03/10/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <JWT/JWT.h>
#import "JWTBuilder.h"

typedef NS_ENUM (NSInteger, JWTPermission) {
    ALL = -1,
    ANONYMOUS_CREATE_MESSAGE = 0,
    ANONYMOUS_FIND_KEY = 1,
    ANONYMOUS_FIND_SIGCHAIN = 2,
    JOIN_TEAM = 3,
    ADD_CONNECTOR = 4
};

@implementation DemoAppJWTBuilder
- (instancetype) initWithJWTSharedSecretId:(const NSString*)JWTSharedSecretId
                           JWTSharedSecret:(const NSString*)JWTSharedSecret
{
    if (self = [super init]) {
        _JWTSharedSecretId = JWTSharedSecretId;
        _JWTSharedSecret = JWTSharedSecret;
        _JWTAlgorithm = [JWTAlgorithmFactory algorithmByName:@"HS256"];
    }
    return self;
}

- (NSString*) signupJWT
{
    NSDate* now = [NSDate date];
    NSDictionary* headers = @{@"alg" : @"HS256", @"typ" : @"JWT"};
    NSDictionary* payload = @{@"join_team": @YES,
                              @"scopes": @(JOIN_TEAM),
                              @"jti" : [[NSUUID UUID] UUIDString],
                              @"iss" : _JWTSharedSecretId,
                              @"iat" : @((NSInteger)now.timeIntervalSince1970)};

    NSString* token = [JWT encodePayload:payload].headers(headers).secret((NSString*)_JWTSharedSecret).algorithm(_JWTAlgorithm).encode;

    return token;
}

- (NSString*) connectorJWTWithCustomUserId:(const NSString*)customUserId
                                     appId:(const NSString*)appId
{
    NSDate* now = [NSDate date];

    NSDictionary* headers = @{@"alg" : @"HS256", @"typ" : @"JWT"};
    NSDictionary* payload = @{@"scopes": @(ADD_CONNECTOR),
                              @"connector_add": @{@"type": @"AP", @"value": [NSString stringWithFormat:@"%@@%@", customUserId, appId]},
                              @"jti" : [[NSUUID UUID] UUIDString],
                              @"iss" : _JWTSharedSecretId,
                              @"iat" : @((NSInteger)now.timeIntervalSince1970)};
    NSString* token = [JWT encodePayload:payload].headers(headers).secret((NSString*)_JWTSharedSecret).algorithm(_JWTAlgorithm).encode;

    return token;
}

- (NSString*) anonymousFindKeyJWTWithRecipients:(const NSArray<NSString*>*)recipients
{
    NSDate* now = [NSDate date];
    NSDictionary* headers = @{@"alg" : @"HS256", @"typ" : @"JWT"};
    NSDictionary* payload = @{@"scopes": @(ANONYMOUS_FIND_KEY),
                              @"iss" : _JWTSharedSecretId,
                              @"iat" : @((NSInteger)now.timeIntervalSince1970),
                              @"recipients" : recipients};

    NSString* token = [JWT encodePayload:payload].headers(headers).secret((NSString*)_JWTSharedSecret).algorithm(_JWTAlgorithm).encode;

    return token;
}

- (NSString*) anonymousCreateMessageJWTWithOwnerId:(NSString*)ownerId
                                        recipients:(const NSArray<NSString*>*)recipients
                                     tmrRecipients:(const NSArray<SealdAnonymousTmrRecipient*>*)tmrRecipients
{
    NSDate* now = [NSDate date];
    NSDictionary* headers = @{@"alg" : @"HS256", @"typ" : @"JWT"};
    NSMutableArray* serializedTmrRecipients = [NSMutableArray array];
    for (SealdAnonymousTmrRecipient* recipient in tmrRecipients) {
        [serializedTmrRecipients addObject:@{
             @"auth_factor_value": recipient.authFactor.value,
             @"auth_factor_type": recipient.authFactor.type
         }];
    }
    NSDictionary* payload = @{@"scopes": @(ANONYMOUS_CREATE_MESSAGE),
                              @"jti" : [[NSUUID UUID] UUIDString],
                              @"iss" : _JWTSharedSecretId,
                              @"iat" : @((NSInteger)now.timeIntervalSince1970),
                              @"owner" : ownerId,
                              @"recipients" : recipients,
                              @"tmr_recipients": serializedTmrRecipients};

    NSString* token = [JWT encodePayload:payload].headers(headers).secret((NSString*)_JWTSharedSecret).algorithm(_JWTAlgorithm).encode;

    return token;
}
@end
