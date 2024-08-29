//
//  Utils.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 21/11/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "Helpers.h"
#import "Utils.h"

@implementation SealdUtils
+ (NSString*) parseSessionIdFromFile:(const NSString*_Nonnull)file
                               error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))) {
    NSError* localErr = nil;
    NSString* res = SealdSdkInternalsMobile_sdkParseSessionIdFromFile((NSString*)file, error);
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}
+ (NSString*) parseSessionIdFromBytes:(const NSData*_Nonnull)bytes
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))){
    NSError* localErr = nil;
    NSString* res = SealdSdkInternalsMobile_sdkParseSessionIdFromBytes((NSData*)bytes, error);
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}
+ (NSString*) parseSessionIdFromMessage:(const NSString*_Nonnull)message
                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error))){
    NSError* localErr = nil;
    NSString* res = SealdSdkInternalsMobile_sdkParseSessionIdFromMessage((NSString*)message, error);
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}
@end
