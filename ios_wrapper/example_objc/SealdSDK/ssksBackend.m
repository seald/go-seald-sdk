//
//  ssksBackend.m
//  SealdSDK demo app ios_Example
//
//  Created by Seald on 28/04/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <SealdSdk/SealdSsksHelpers.h>
#import "ssksBackend.h"

@implementation DemoAppSsksBackend
- (instancetype) initWithSsksURL:(const NSString*)ssksURL
                           AppId:(const NSString*)appId
                          AppKey:(const NSString*)appKey
{
    if (self = [super init]) {
        _ssksURL = (NSString*)ssksURL;
        _appId = (NSString*)appId;
        _appKey = (NSString*)appKey;
    }
    return self;
}

- (NSString*) postAPIWithURL:(NSString*)endpoint
                        data:(NSData*)data
                       error:(NSError**)error
{
    NSString* fullURL = [NSString stringWithFormat:@"%@%@", _ssksURL, endpoint];
    // Create a mutable URL request
    NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:fullURL]];

    // Set the request method to POST
    [request setHTTPMethod:@"POST"];

    // Set the content type to application/json
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:_appId forHTTPHeaderField:@"X-SEALD-APPID"];
    [request setValue:_appKey forHTTPHeaderField:@"X-SEALD-APIKEY"];

    // Set the content length
    [request setValue:[NSString stringWithFormat:@"%lu", (unsigned long)[data length]] forHTTPHeaderField:@"Content-Length"];

    // Set the request body
    [request setHTTPBody:data];

    // Create a session configuration
    NSURLSessionConfiguration* configuration = [NSURLSessionConfiguration defaultSessionConfiguration];

    // Create a session using the configuration
    NSURLSession* session = [NSURLSession sessionWithConfiguration:configuration];

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    // Create a data task with the request
    __block NSString* responseString = NULL;
    __block NSError* tempError = NULL; // This is to avoid an autorelease problem
    NSURLSessionDataTask* dataTask = [session dataTaskWithRequest:request completionHandler:^(NSData*_Nullable data, NSURLResponse*_Nullable response, NSError*_Nullable err) {
        if (err) {
            // Handle the error
            NSLog(@"Error in HTTP request: %@", err);
            tempError = err;
            dispatch_semaphore_signal(semaphore);
            return;
        } else {
            // Handle the response data
            responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            dispatch_semaphore_signal(semaphore);
        }
    }];

    // Start the data task
    [dataTask resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (tempError) {
        *error = tempError;
        return nil;
    }

    // Return the response string
    return responseString;
}

- (SealdSsksBackendChallengeResponse*) challengeSendWithUserId:(const NSString*)userId
                                                    authFactor:(const SealdTmrAuthFactor*)authFactor
                                                    createUser:(const bool)createUser
                                                     forceAuth:(const bool)forceAuth
                                                       fakeOtp:(const BOOL)fakeOtp
                                                         error:(NSError**)error
{

    NSDictionary* auth = @{
        @"type": authFactor.type,
        @"value": authFactor.value
    };
    NSDictionary* parameters = @{
        @"user_id": @"userId",
        @"auth_factor": auth,
        @"create_user": @(createUser),
        @"force_auth": @(forceAuth),
        @"fake_otp": @(fakeOtp),
    };
    NSData* data = [NSJSONSerialization dataWithJSONObject:parameters options:NSJSONWritingPrettyPrinted error:error];
    if (*error) {
        NSLog(@"Error in JSON serialization: %@", [* error localizedDescription]);
        return nil;
    }

    NSLog(@"Request data: %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);

    NSString* responseString = [self postAPIWithURL:@"tmr/back/challenge_send/" data:data error:error];
    if (*error) {
        NSLog(@"Error in HTTP request: %@", [* error localizedDescription]);
        return nil;
    }

    NSLog(@"Response data: %@", responseString);

    id json = [NSJSONSerialization JSONObjectWithData:[responseString dataUsingEncoding:NSUTF8StringEncoding] options:0 error:error];
    if (*error) {
        NSLog(@"Error parsing JSON data: %@", [* error localizedDescription]);
        return nil;
    }

    // Use the parsed JSON object
    NSDictionary* jsonDictionary = (NSDictionary*)json;
    NSLog(@"Parsed JSON: %@", jsonDictionary);

    SealdSsksBackendChallengeResponse* r = [[SealdSsksBackendChallengeResponse alloc]
                                            initWithSessionId:[jsonDictionary objectForKey:@"session_id"]
                                             mustAuthenticate:[[jsonDictionary objectForKey:@"must_authenticate"] boolValue]];
    return r;
}
@end

@implementation SealdSsksBackendChallengeResponse
- (instancetype) initWithSessionId:(NSString*)sessionId
                  mustAuthenticate:(BOOL)mustAuthenticate
{
    if (self = [super init]) {
        _sessionId = sessionId;
        _mustAuthenticate = mustAuthenticate;
    }
    return self;
}
@end
