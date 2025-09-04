//
//  SealdAnonymousEncryptionSession.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 20/05/2025.
//  Copyright © 2025 Seald SAS. All rights reserved.
//

#import "SealdSdk.h"

@implementation SealdAnonymousEncryptionSession
- (instancetype) initWithAnonymousEncryptionSession:(SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession*)aes
{
    self = [super init];
    if (self) {
        anonymousEncryptionSession = aes;
    }
    return self;
}

+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkMobileAnonymousEncryptionSession*)aes
{
    return [[SealdAnonymousEncryptionSession alloc] initWithAnonymousEncryptionSession:aes];
}

- (NSString*) sessionId
{
    return anonymousEncryptionSession.sessionId;
}

- (NSString*) encryptMessage:(const NSString*)clearMessage
                       error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [anonymousEncryptionSession encryptMessage:(NSString*)clearMessage error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) encryptMessageAsync:(const NSString*)clearMessage
           completionHandler:(void (^)(NSString* encryptedString, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* encryptedString = [self encryptMessage:clearMessage error:&localError];
        completionHandler(encryptedString, localError);
    });
}

- (NSString*) decryptMessage:(const NSString*)encryptedMessage
                       error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [anonymousEncryptionSession decryptMessage:(NSString*)encryptedMessage error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) decryptMessageAsync:(const NSString*)encryptedMessage
           completionHandler:(void (^)(NSString* decryptedString, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* decryptedString = [self decryptMessage:encryptedMessage error:&localError];
        completionHandler(decryptedString, localError);
    });
}

- (NSData*) encryptFile:(const NSData*)clearFile
               filename:(const NSString*)filename
                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSData* res = [anonymousEncryptionSession encryptFile:(NSData*)clearFile filename:(NSString*)filename error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) encryptFileAsync:(const NSData*)clearFile
                 filename:(const NSString*)filename
        completionHandler:(void (^)(NSData* encryptedFile, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSData* encryptedFile = [self encryptFile:clearFile filename:filename error:&localError];
        completionHandler(encryptedFile, localError);
    });
}

- (SealdClearFile*) decryptFile:(const NSData*)encryptedFile
                          error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkClearFile* clearFile = [anonymousEncryptionSession decryptFile:(NSData*)encryptedFile error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [[SealdClearFile alloc] initWithFilename:clearFile.filename messageId:clearFile.sessionId fileContent:clearFile.fileContent];
}

- (void) decryptFileAsync:(const NSData*)encryptedFile
        completionHandler:(void (^)(SealdClearFile* clearFile, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdClearFile* clearFile = [self decryptFile:encryptedFile error:&localError];
        completionHandler(clearFile, localError);
    });
}

- (NSString*) encryptFileFromURI:(const NSString*)clearFileURI
                           error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [anonymousEncryptionSession encryptFileFromURI:(NSString*)clearFileURI error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) encryptFileAsyncFromURI:(const NSString*)clearFileURI
               completionHandler:(void (^)(NSString* encryptedFileURI, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* encryptedFileURI = [self encryptFileFromURI:clearFileURI error:&localError];
        completionHandler(encryptedFileURI, localError);
    });
}

- (NSString*) decryptFileFromURI:(const NSString*)encryptedFileURI
                           error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [anonymousEncryptionSession decryptFileFromURI:(NSString*)encryptedFileURI error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}

- (void) decryptFileAsyncFromURI:(const NSString*)encryptedFileURI
               completionHandler:(void (^)(NSString* clearFileURI, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* clearFileURI = [self decryptFileFromURI:encryptedFileURI error:&localError];
        completionHandler(clearFileURI, localError);
    });
}

- (NSString*) serializeWithError:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    NSString* res = [anonymousEncryptionSession serialize:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return res;
}
@end
