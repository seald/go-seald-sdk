//
//  EncryptionSession.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSdk.h"

@implementation SealdEncryptionSession
- (instancetype) initWithEncryptionSession:(SealdSdkInternalsMobile_sdkMobileEncryptionSession*)es
{
    self = [super init];
    if (self) {
        encryptionSession = es;
    }
    return self;
}

+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkMobileEncryptionSession*)es
{
    return [[SealdEncryptionSession alloc] initWithEncryptionSession:es];
}

+ (NSArray<SealdEncryptionSession*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkMobileEncryptionSessionArray*)nativeESArray
{
    NSMutableArray<SealdEncryptionSession*>* result = [NSMutableArray arrayWithCapacity:[nativeESArray size]];
    for (int i = 0; i < [nativeESArray size]; i++) {
        SealdSdkInternalsMobile_sdkMobileEncryptionSession* es = [nativeESArray get:i];
        [result addObject:[SealdEncryptionSession fromMobileSdk:es]];
    }
    return result;
}

- (NSString*) sessionId
{
    return encryptionSession.id_;
}

- (SealdEncryptionSessionRetrievalDetails*) retrievalDetails
{
    return [SealdEncryptionSessionRetrievalDetails fromMobileSdk:encryptionSession.retrievalDetails];
}

- (NSDictionary<NSString*, SealdActionStatus*>*) addRecipients:(const NSArray<SealdRecipientWithRights*>*)recipients
                                                         error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkActionStatusArray* resp = [encryptionSession addRecipients:[SealdRecipientWithRights toMobileSdkArray:(NSArray<SealdRecipientWithRights*>*)recipients] error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdActionStatus fromMobileSdkArray:resp];
}

- (void) addRecipientsAsync:(const NSArray<SealdRecipientWithRights*>*)recipients
          completionHandler:(void (^)(NSDictionary<NSString*, SealdActionStatus*>* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSDictionary<NSString*, SealdActionStatus*>* result = [self addRecipients:recipients
                                                                            error:&localError];
        completionHandler(result, localError);
    });
}

- (void) addProxySession:(const NSString*)proxySessionId
                  rights:(const SealdRecipientRights*)rights
                   error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    [encryptionSession addProxySession:(NSString*)proxySessionId
                                rights:[rights toMobileSdk]
                                 error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) addProxySession:(const NSString*)proxySessionId
                   error:(NSError*_Nullable*)error __attribute__((swift_error(nonnull_error)))
{
    NSError* localErr = nil;
    [encryptionSession addProxySession:(NSString*)proxySessionId
                                rights:[[[SealdRecipientRights alloc] initWithDefaultRights] toMobileSdk]
                                 error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
    }
}

- (void) addProxySessionAsync:(const NSString*)proxySessionId
                       rights:(const SealdRecipientRights*)rights
            completionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        [self addProxySession:proxySessionId
                       rights:rights
                        error:&localError];
        completionHandler(localError);
    });
}

- (void) addProxySessionAsync:(const NSString*)proxySessionId
            completionHandler:(void (^)(NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        [self addProxySession:proxySessionId
                        error:&localError];
        completionHandler(localError);
    });
}

- (SealdRevokeResult*) revokeRecipientsIds:(const NSArray<NSString*>*)recipientsIds
                          proxySessionsIds:(const NSArray<NSString*>*)proxySessionsIds
                                     error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkRevokeResult* resp = [encryptionSession revokeRecipients:arrayToStringArray(recipientsIds)
                                                                       proxySessionsIds:arrayToStringArray(proxySessionsIds)
                                                                                  error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdRevokeResult fromMobileSdk:resp];
}

- (void) revokeRecipientsIdsAsync:(const NSArray<NSString*>*)recipientsIds
                 proxySessionsIds:(const NSArray<NSString*>*)proxySessionsIds
                completionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdRevokeResult* result = [self revokeRecipientsIds:recipientsIds proxySessionsIds:proxySessionsIds error:&localError];
        completionHandler(result, localError);
    });
}

- (SealdRevokeResult*) revokeAll:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkRevokeResult* resp = [encryptionSession revokeAll:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdRevokeResult fromMobileSdk:resp];
}

- (void) revokeAllAsyncWithCompletionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdRevokeResult* result = [self revokeAll:&localError];
        completionHandler(result, localError);
    });
}

- (SealdRevokeResult*) revokeOthers:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkRevokeResult* resp = [encryptionSession revokeOthers:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdRevokeResult fromMobileSdk:resp];
}

- (void) revokeOthersAsyncWithCompletionHandler:(void (^)(SealdRevokeResult* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        SealdRevokeResult* result = [self revokeOthers:&localError];
        completionHandler(result, localError);
    });
}

- (NSString*) encryptMessage:(const NSString*)clearMessage
                       error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    NSString* res = [encryptionSession encryptMessage:(NSString*)clearMessage error:&localErr];
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
    NSString* res = [encryptionSession decryptMessage:(NSString*)encryptedMessage error:&localErr];
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
    NSData* res = [encryptionSession encryptFile:(NSData*)clearFile filename:(NSString*)filename error:&localErr];
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
    SealdSdkInternalsMobile_sdkClearFile* clearFile = [encryptionSession decryptFile:(NSData*)encryptedFile error:&localErr];
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
    NSString* res = [encryptionSession encryptFileFromURI:(NSString*)clearFileURI error:&localErr];
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
    NSString* res = [encryptionSession decryptFileFromURI:(NSString*)encryptedFileURI error:&localErr];
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

- (NSString*) addTmrAccess:(const SealdTmrRecipientWithRights*)recipient
                     error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkTmrRecipientWithRights* nativeR = [recipient toMobileSdk];
    NSString* tmrAccessId = [encryptionSession addTmrAccess:nativeR error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return tmrAccessId;
}

- (void) addTmrAccessAsync:(const SealdTmrRecipientWithRights*)recipient
         completionHandler:(void (^)(NSString* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSString* tmrAccessId = [self addTmrAccess:recipient
                                             error:&localError];
        completionHandler(tmrAccessId, localError);
    });
}

- (NSDictionary<NSString*, SealdActionStatus*>*) addMultipleTmrAccesses:(const NSArray<SealdTmrRecipientWithRights*>*)recipients
                                                                  error:(NSError*_Nullable*)error
{
    NSError* localErr = nil;
    SealdSdkInternalsMobile_sdkTmrRecipientWithRightsArray* nativeR = [SealdTmrRecipientWithRights toMobileSdkArray:(NSArray<SealdTmrRecipientWithRights*>*)recipients error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    SealdSdkInternalsMobile_sdkActionStatusArray* resp = [encryptionSession addMultipleTmrAccesses:nativeR error:&localErr];
    if (localErr) {
        _SealdInternal_ConvertError(localErr, error);
        return nil;
    }
    return [SealdActionStatus fromMobileSdkArray:resp];
}

- (void) addMultipleTmrAccessesAsync:(const NSArray<SealdTmrRecipientWithRights*>*)recipients
                   completionHandler:(void (^)(NSDictionary<NSString*, SealdActionStatus*>* result, NSError*_Nullable error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* localError = nil;
        NSDictionary<NSString*, SealdActionStatus*>* result = [self addMultipleTmrAccesses:recipients
                                                                                     error:&localError];
        completionHandler(result, localError);
    });
}
@end
