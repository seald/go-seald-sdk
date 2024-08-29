//
//  Utils.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 21/11/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#ifndef Utils_h
#define Utils_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * SealdUtils is an interface with utility class methods.
 */
@interface SealdUtils : NSObject
/**
 * Takes the path to an encrypted file, and returns the session id.
 *
 * @param file Path to the encrypted file.
 * @param error The error that occurred, if any.
 * @return The session id.
 */
+ (NSString*) parseSessionIdFromFile:(const NSString*_Nonnull)file
                               error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Takes an encrypted file as bytes, and returns the session id.
 *
 * @param bytes The encrypted file as bytes.
 * @param error The error that occurred, if any.
 * @return The session id.
 */
+ (NSString*) parseSessionIdFromBytes:(const NSData*_Nonnull)bytes
                                error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
/**
 * Takes an encrypted message, and returns the session id.
 *
 * @param message The encrypted message.
 * @param error The error that occurred, if any.
 * @return The session id.
 */
+ (NSString*) parseSessionIdFromMessage:(const NSString*_Nonnull)message
                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
@end

NS_ASSUME_NONNULL_END

#endif /* Utils_h */
