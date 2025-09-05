//
//  SealdAnonymousEncryptionSession.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 20/05/2025.
//  Copyright © 2025 Seald SAS. All rights reserved.
//

#ifndef SealdAnonymousEncryptionSession_h
#define SealdAnonymousEncryptionSession_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>
#import "Helpers.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * An anonymous encryption session, with which you can then encrypt / decrypt multiple messages or files.
 * This should not be instantiated directly, and should be created with SealdAnonymousSdk.createAnonymousEncryptionSession:error:
 */
@interface SealdAnonymousEncryptionSession : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession* anonymousEncryptionSession;
    /** \endcond */
}
/** The ID of this encryptionSession. Read-only. */
@property (atomic, readonly) NSString* sessionId;
/** \cond */
- (instancetype) initWithAnonymousEncryptionSession:(const SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession*)aes;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession*)aes;
/** \endcond */

/**
 * Encrypt a clear-text string into an encrypted message, for the recipients of this session.
 *
 * @param clearMessage The message to encrypt.
 * @param error The error that occurred while encrypting the message, if any.
 * @return The encrypted message
 */
- (NSString*) encryptMessage:(const NSString*)clearMessage
                       error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Encrypt a clear-text string into an encrypted message, for the recipients of this session.
 *
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a NSString* containing the encrypted string, and a `NSError*` that indicates if any error occurred.
 */
- (void) encryptMessageAsync:(const NSString*)clearMessage
           completionHandler:(void (^)(NSString* encryptedString, NSError*_Nullable error))completionHandler;

/**
 * Decrypt an encrypted message string into the corresponding clear-text string.
 *
 * @param encryptedMessage The encrypted message to decrypt.
 * @param error The error that occurred while decrypting the message, if any.
 * @return The decrypted clear-text message.
 */
- (NSString*) decryptMessage:(const NSString*)encryptedMessage
                       error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Decrypt an encrypted message string into the corresponding clear-text string.
 *
 * @param encryptedMessage The encrypted message to decrypt.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a NSString* containing the decrypted string, and a `NSError*` that indicates if any error occurred.
 */
- (void) decryptMessageAsync:(const NSString*)encryptedMessage
           completionHandler:(void (^)(NSString* decryptedString, NSError*_Nullable error))completionHandler;

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param clearFile A `NSData*` of the clear-text content of the file to encrypt.
 * @param filename The name of the file to encrypt.
 * @param error The error that occurred while encrypting the file, if any.
 * @return A `NSData*` of the content of the encrypted file.
 */
- (NSData*) encryptFile:(const NSData*)clearFile
               filename:(const NSString*)filename
                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param clearFile A `NSData*` of the clear-text content of the file to encrypt.
 * @param filename The name of the file to encrypt.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a NSData containing the encrypted file, and a `NSError*` that indicates if any error occurred.
 */
- (void) encryptFileAsync:(const NSData*)clearFile
                 filename:(const NSString*)filename
        completionHandler:(void (^)(NSData* encryptedFile, NSError*_Nullable error))completionHandler;

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param encryptedFile A `NSData*` of the content of the encrypted file to decrypt.
 * @param error The error that occurred while decrypting the file, if any.
 * @return A SealdClearFile instance, containing the filename and the fileContent of the decrypted file.
 */
- (SealdClearFile*) decryptFile:(const NSData*)encryptedFile
                          error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param encryptedFile A `NSData*` of the content of the encrypted file to decrypt.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a SealdClearFile containing the decrypted file, and a `NSError*` that indicates if any error occurred.
 */
- (void) decryptFileAsync:(const NSData*)encryptedFile
        completionHandler:(void (^)(SealdClearFile* clearFile, NSError*_Nullable error))completionHandler;

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param clearFileURI A `NSString*` of an URI of the file to encrypt.
 * @param error The error that occurred while encrypting the file, if any.
 * @return A `NSString*` of the URI of the encrypted file.
 */
- (NSString*) encryptFileFromURI:(const NSString*)clearFileURI
                           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
 *
 * @param clearFileURI A `NSString*` of an URI of the file to encrypt.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a NSString containing the URI of the encrypted file, and a `NSError*` that indicates if any error occurred.
 */
- (void) encryptFileAsyncFromURI:(const NSString*)clearFileURI
               completionHandler:(void (^)(NSString* encryptedFileURI, NSError*_Nullable error))completionHandler;

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param encryptedFileURI A `NSString*` of an URI of the encrypted file to decrypt.
 * @param error The error that occurred while decrypting the file, if any.
 * @return A `NSString*` of the URI of the decrypted file.
 */
- (NSString*) decryptFileFromURI:(const NSString*)encryptedFileURI
                           error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Decrypts an encrypted file into the corresponding clear-text file.
 *
 * @param encryptedFileURI A `NSString*` of an URI of the encrypted file to decrypt.
 * @param completionHandler A callback called after function execution. This callback takes two arguments, a NSString containing the URI of the decrypted file, and a `NSError*` that indicates if any error occurred.
 */
- (void) decryptFileAsyncFromURI:(const NSString*)encryptedFileURI
               completionHandler:(void (^)(NSString* clearFileURI, NSError*_Nullable error))completionHandler;

/**
 * Serialize the SealdAnonymousEncryptionSession to a string.
 * This is for advanced use.
 * May be used to keep sessions in a cache.
 * WARNING: a user could use this cache to work around being revoked. Use with caution.
 * WARNING: if the cache is accessible to another user, they could use it to decrypt messages they are not supposed
 * to have access to. Make sure only the current user in question can access this cache, for example by encrypting it.
 *
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return Returns the serialized encryption session as a `NSString*`.
 */
- (NSString*) serializeWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));
@end

NS_ASSUME_NONNULL_END

#endif /* SealdAnonymousEncryptionSession_h */
