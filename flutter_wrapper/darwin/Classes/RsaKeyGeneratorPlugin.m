#import "RsaKeyGeneratorPlugin.h"

@implementation RsaKey
- (instancetype) initWithEncryptionKey:(NSString*)encryptionKey
                            signingKey:(NSString*)signingKey
{
    self = [super init];
    if (self) {
        _encryptionKey = encryptionKey;
        _signingKey = signingKey;
    }
    return self;
}

- (NSDictionary*) toDict
{
    return @{@"encryptionKey": self.encryptionKey, @"signingKey": self.signingKey, @"format": @"PKCS1DER"};
}
@end


@implementation RsaKeyGeneratorPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  FlutterMethodChannel* channel = [FlutterMethodChannel
      methodChannelWithName:@"io.seald.seald_sdk_flutter.native_rsa_key_generator"
            binaryMessenger:[registrar messenger]];
  RsaKeyGeneratorPlugin* instance = [[RsaKeyGeneratorPlugin alloc] init];
  [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
  if ([@"generateRSAKeys" isEqualToString:call.method]) {
    NSNumber* sizeArgument = call.arguments[@"size"];
    NSInteger keySize;
    if (sizeArgument != nil) {
        keySize = [sizeArgument integerValue];
        NSLog(@"RsaKeyGeneratorPlugin: Generating keys... Size is %ld", (long)keySize);
    } else {
        keySize = 4096;
        NSLog(@"RsaKeyGeneratorPlugin: Generating keys... No size passed. Defaulting to %ld", (long)keySize);
    }

    // Generate keys
    [self _generateKeyPair:keySize completionHandler:^(NSDictionary* keyPair, NSError* error) {
      if (error == nil) {
        result(keyPair);
      } else {
        result([FlutterError errorWithCode:@"RSA_KEY_GEN_ERROR"
                                   message:@"Failed to generate RSA keys"
                                   details:nil]);
      }
    }];
  } else {
    result(FlutterMethodNotImplemented);
  }
}

- (void) _generateRSAKey:(NSInteger) keySize
       completionHandler:(void (^)(NSData* keyRawData, NSError* error))completionHandler
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* error;
        NSDictionary* parameters = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeySizeInBits: @(keySize),
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

- (void) _generateKeyPair:(NSInteger) keySize
        completionHandler:(void (^)(NSDictionary* keyPair, NSError* error))completionHandler
{
    __block NSData* encryptionKey;
    __block NSData* signingKey;

    dispatch_group_t group = dispatch_group_create();

    __block NSError* firstThreadError = nil;
    dispatch_group_enter(group);
    [self _generateRSAKey:keySize completionHandler:^(NSData* keyRawData, NSError* error) {
        if (error != nil) {
            firstThreadError = error;
        }
        encryptionKey = keyRawData;
        dispatch_group_leave(group);
    }];

    __block NSError* secondThreadError = nil;
    dispatch_group_enter(group);
    [self _generateRSAKey:keySize completionHandler:^(NSData* keyRawData, NSError* error) {
        if (error != nil) {
            secondThreadError = error;
        }
        signingKey = keyRawData;
        dispatch_group_leave(group);
    }];

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        if (firstThreadError != nil) {
            completionHandler(nil, firstThreadError);
            return;
        }
        if (secondThreadError != nil) {
            completionHandler(nil, secondThreadError);
            return;
        }
        RsaKey* res = [[RsaKey alloc] initWithEncryptionKey:[encryptionKey base64EncodedStringWithOptions:0]
                                                 signingKey:[signingKey base64EncodedStringWithOptions:0]
                      ];
        completionHandler([res toDict], nil);
    });
}

@end
