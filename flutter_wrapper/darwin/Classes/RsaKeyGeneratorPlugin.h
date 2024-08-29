#if TARGET_OS_IOS
#import <Flutter/Flutter.h>
#elif TARGET_OS_MAC
#import <FlutterMacOS/FlutterMacOS.h>
#endif

@interface RsaKey : NSObject
@property (atomic, strong, readonly) NSString* encryptionKey;
@property (atomic, strong, readonly) NSString* signingKey;
- (instancetype) initWithEncryptionKey:(NSString*)encryptionKey
                            signingKey:(NSString*)signingKey;
- (NSDictionary*) toDict;
@end


@interface RsaKeyGeneratorPlugin : NSObject<FlutterPlugin>
- (void) _generateRSAKey:(NSInteger) keySize
       completionHandler:(void (^)(NSData* keyRawData, NSError* error))completionHandler;
- (void) _generateKeyPair:(NSInteger) keySize
        completionHandler:(void (^)(NSDictionary* keyPair, NSError* error))completionHandler;
@end
