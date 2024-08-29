//
//  SealdEncryptionSession.h
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#ifndef EncryptionSession_h
#define EncryptionSession_h

#import <Foundation/Foundation.h>
#import <SealdSdkInternals/SealdSdkInternals.h>
#import "Helpers.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * An encryption session, with which you can then encrypt / decrypt multiple messages.
 * This should not be created directly, and should be retrieved with SealdSdk.retrieveEncryptionSessionWithSessionId:useCache:error:
 * or SealdSdk.retrieveEncryptionSessionFromMessage:useCache:error:.
 */
@interface SealdEncryptionSession : NSObject {
    /** \cond */
    SealdSdkInternalsMobile_sdkMobileEncryptionSession* encryptionSession;
    /** \endcond */
}
/** The ID of this encryptionSession. Read-only. */
@property (atomic, readonly) NSString* sessionId;
/** Details about how this session was retrieved: through a group, a proxy, or directly. Read-only. */
@property (atomic, readonly) SealdEncryptionSessionRetrievalDetails* retrievalDetails;
/** \cond */
- (instancetype) initWithEncryptionSession:(const SealdSdkInternalsMobile_sdkMobileEncryptionSession*)es;
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkMobileEncryptionSession*)es;
+ (NSArray<SealdEncryptionSession*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkMobileEncryptionSessionArray*)array;
/** \endcond */

/**
 * Add new recipients to this session.
 * These recipients will be able to read all encrypted messages of this session.
 *
 * @param recipients The Seald IDs with the associated rights of users to add to this session.
 * @param error The error that occurred while adding the recipients, if any.
 * @return A [NSMutableDictionary<NSString*, SealdActionStatus*>*] instance.
 */
- (NSDictionary<NSString*, SealdActionStatus*>*) addRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                                         error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add new recipients to this session.
 * These recipients will be able to read all encrypted messages of this session.
 *
 * @param recipients The Seald IDs with the associated rights of users to add to this session.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [NSMutableDictionary<NSString*, SealdActionStatus*>*] instance. and a `NSError*` that indicates if any error occurred.
 */
- (void) addRecipientsAsync:(const NSArray<SealdRecipientWithRights*>*)recipients
          completionHandler:(void (^)(NSDictionary<NSString*, SealdActionStatus*>* result, NSError*_Nullable error))completionHandler;

/**
 * Add a proxy session as a recipient of this session.
 * Any recipient of the proxy session will also be able to retrieve this session.
 * The current user has to be a direct recipient of the proxy session.
 *
 * @param proxySessionId The ID of the session to add as proxy.
 * @param rights The rights to assign to this proxy.
 * @param error The error that occurred while adding the proxy, if any.
 */
- (void) addProxySession:(const NSString*)proxySessionId
                  rights:(const SealdRecipientRights*)rights
                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add a proxy session as a recipient of this session.
 * Any recipient of the proxy session will also be able to retrieve this session.
 * The current user has to be a direct recipient of the proxy session.
 *
 * @param proxySessionId The ID of the session to add as proxy. It will be given default `RecipientsRights`.
 * @param error The error that occurred while adding the proxy, if any.
 */
- (void) addProxySession:(const NSString*)proxySessionId
                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add a proxy session as a recipient of this session.
 * Any recipient of the proxy session will also be able to retrieve this session.
 * The current user has to be a direct recipient of the proxy session.
 *
 * @param proxySessionId The ID of the session to add as proxy.
 * @param rights The rights to assign to this proxy.
 * @param completionHandler A callback called after function execution. This callback take a `NSError*` that indicates if any error occurred.
 */
- (void) addProxySessionAsync:(const NSString*)proxySessionId
                       rights:(const SealdRecipientRights*)rights
            completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Add a proxy session as a recipient of this session.
 * Any recipient of the proxy session will also be able to retrieve this session.
 * The current user has to be a direct recipient of the proxy session.
 *
 * @param proxySessionId The ID of the session to add as proxy. It will be given default `RecipientsRights`.
 * @param completionHandler A callback called after function execution. This callback take a `NSError*` that indicates if any error occurred.
 */
- (void) addProxySessionAsync:(const NSString*)proxySessionId
            completionHandler:(void (^)(NSError*_Nullable error))completionHandler;

/**
 * Revoke some recipients or proxy sessions from this session.
 * If you want to revoke all recipients, see SealdEncryptionSession.revokeAll: instead.
 * If you want to revoke all recipients besides yourself, see SealdEncryptionSession.revokeOthers:.
 *
 * @param recipientsIds The Seald IDs of users to revoke from this session.
 * @param proxySessionsIds The IDs of proxy sessions to revoke from this session.
 * @param error The error that occurred while revoking, if any.
 * @return A [SealdRevokeResult] instance.
 */
- (SealdRevokeResult*) revokeRecipientsIds:(const NSArray<NSString*>*)recipientsIds
                          proxySessionsIds:(const NSArray<NSString*>*)proxySessionsIds
                                     error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Revoke some recipients or proxy sessions from this session.
 * If you want to revoke all recipients, see SealdEncryptionSession.revokeAll: instead.
 * If you want to revoke all recipients besides yourself, see SealdEncryptionSession.revokeOthers:.
 *
 * @param recipientsIds The Seald IDs of users to revoke from this session.
 * @param proxySessionsIds The IDs of proxy sessions to revoke from this session.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [SealdRevokeResult] instance. and a `NSError*` that indicates if any error occurred.
 */
- (void) revokeRecipientsIdsAsync:(const NSArray<NSString*>*)recipientsIds
                 proxySessionsIds:(const NSArray<NSString*>*)proxySessionsIds
                completionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler;

/**
 * Revoke this session entirely.
 *
 * @param error The error that occurred while revoking, if any.
 * @return A [SealdRevokeResult] instance.
 */
- (SealdRevokeResult*) revokeAll:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Revoke this session entirely.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [SealdRevokeResult] instance. and a `NSError*` that indicates if any error occurred.
 */
- (void) revokeAllAsyncWithCompletionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler;

/**
 * Revoke all recipients besides yourself from this session.
 *
 * @param error The error that occurred while revoking, if any.
 * @return A [SealdRevokeResult] instance.
 */
- (SealdRevokeResult*) revokeOthers:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Revoke all recipients besides yourself from this session.
 *
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [SealdRevokeResult] instance. and a `NSError*` that indicates if any error occurred.
 */
- (void) revokeOthersAsyncWithCompletionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler;

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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSString* containing the encrypted string, and a `NSError*` that indicates if any error occurred.
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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSString* containing the decrypted string, and a `NSError*` that indicates if any error occurred.
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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSData containing the encrypted file, and a `NSError*` that indicates if any error occurred.
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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSData containing the decrypted file, and a `NSError*` that indicates if any error occurred.
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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSString containing the URI of the encrypted file, and a `NSError*` that indicates if any error occurred.
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
 * @param completionHandler A callback called after function execution. This callback take two arguments, a NSString containing the URI of the decrypted file, and a `NSError*` that indicates if any error occurred.
 */
- (void) decryptFileAsyncFromURI:(const NSString*)encryptedFileURI
               completionHandler:(void (^)(NSString* clearFileURI, NSError*_Nullable error))completionHandler;

/**
 * Add a TMR access to this session for the given authentication factor.
 *
 * @param recipient A TMR recipient with its associated rights.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return A [NSString*] containing the Id of the created TMR access.
 */
- (NSString*) addTmrAccess:(const SealdTmrRecipientWithRights*)recipient
                     error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add a TMR access to this session for the given authentication factor.
 *
 * @param recipient A TMR recipient with its associated rights.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [NSString*] instance, and a `NSError*` that indicates if any error occurred.
 */
- (void) addTmrAccessAsync:(const SealdTmrRecipientWithRights*)recipient
         completionHandler:(void (^)(NSString* result, NSError*_Nullable error))completionHandler;

/**
 * Add multiple  TMR accesses to this session for the given authentication factors.
 *
 * @param recipients The TMR recipients with their associated rights.
 * @param error A pointer to a SealdError* where details will be stored in case of error.
 * @return A [NSMutableDictionary<NSString*, SealdActionStatus*>*] instance.
 */
- (NSDictionary<NSString*, SealdActionStatus*>*) addMultipleTmrAccesses:(const NSArray<SealdTmrRecipientWithRights*>*)recipients
                                                                  error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)));

/**
 * Add multiple TMR accesses to this session for the given authentication factors.
 *
 * @param recipients The TMR recipients with their associated rights.
 * @param completionHandler A callback called after function execution. This callback take two arguments, a [NSMutableDictionary<NSString*, SealdActionStatus*>*] instance, and a `NSError*` that indicates if any error occurred.
 */
- (void) addMultipleTmrAccessesAsync:(const NSArray<SealdTmrRecipientWithRights*>*)recipients
                   completionHandler:(void (^)(NSDictionary<NSString*, SealdActionStatus*>* result, NSError*_Nullable error))completionHandler;
@end

NS_ASSUME_NONNULL_END

#endif /* EncryptionSession_h */
