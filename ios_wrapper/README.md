# Seald SDK for iOS

This package is the Seald SDK for iOS.

The current version is `##VERSION##`.

You can install it either with [Cocoapods](https://cocoapods.org/), or with the [Swift Package Manager](https://www.swift.org/documentation/package-manager/).

## Install with Cocoapods

Here is how you can add it to your `Podfile`:

```ruby{2}
target 'YourApp' do
  pod 'SealdSdk', '##VERSION##'
end
```

Then, you can install with `pod install`.

## Install with Swift Package Manager

You can add the repository <https://github.com/seald/seald-sdk-ios> to your `Package.swift`, or to your XCode _Package dependencies_.

> ⚠️ This repository <https://github.com/seald/seald-sdk-ios> is only for distribution of the release version of the SDK.
> To access the source code, see <https://github.com/seald/go-seald-sdk>.

## Import 

You can then import it in your code with:

::: code-group
```objc [ObjC]
#import <SealdSdk/SealdSdk.h>
```

```swift [Swift]
import SealdSdk
```

:::

You can also see the [example app for Objective-C](https://github.com/seald/seald-sdk-demo-app-ios/),
or the [example app for Swift](https://github.com/seald/seald-sdk-demo-app-ios-swift/).

This package contains the main [SealdSdk](./SealdSdk.md) class,
the [SealdEncryptionSession](./SealdEncryptionSession.md) class,
as well as multiple helper classes.

## `SealdSdk`

[SealdSdk](./SealdSdk.md) is the main class for the Seald SDK.
It represents an instance of the Seald SDK.

You can instantiate it this way:

::: code-group
```objc [ObjC]
SealdSdk* seald = [[SealdSdk alloc] initWithApiUrl:@"https://api.seald.io/"
                                             appId:@"YourAppId"
                                      databasePath:@"/myApp/seald_db"
                             databaseEncryptionKey:[NSData dataWithBytes:&SYM_KEY_DATA length:sizeof(64)]
                                      instanceName:@"my-instance"
                                          logLevel:0
                                        logNoColor:true
                         encryptionSessionCacheTTL:0
                                           keySize:4096
                                            error:&error];
```

```swift [Swift]
let seald = try! SealdSdk.init(
  apiUrl: "https://api.seald.io/",
  appId: "YourAppId",
  databasePath: "/myApp/seald_db", 
  databaseEncryptionKey: Data(SYM_KEY_DATA),
  instanceName: "my-instance",
  logLevel: 0,
  logNoColor: true,
  encryptionSessionCacheTTL: 0,
  keySize: 4096
)
```

:::

This class then allows you to [create an account](./SealdSdk.md#createaccountwithsignupjwt-devicename-displayname-privatekeys-expireafter-error),
create or retrieve a [SealdEncryptionSession](./SealdEncryptionSession.md),
etc.

See [the `SealdSdk` reference](./SealdSdk.md) for more information.

## `SealdEncryptionSession`

A [SealdEncryptionSession](./SealdEncryptionSession.md) allows you to encrypt / decrypt multiple messages or files.

This should not be instantiated directly, and should be either created with [`-[SealdSdk createEncryptionSessionWithRecipients:useCache:error:]`](./SealdSdk.md#createencryptionsessionwithrecipients-usecache-error)
or retrieved with [`-[SealdSdk retrieveEncryptionSessionWithSessionId:useCache:error:]`](./SealdSdk.md#retrieveencryptionsessionwithsessionid-usecache-error)
or [`-[SealdSdk retrieveEncryptionSessionFromMessage:useCache:error:]`](./SealdSdk.md#retrieveencryptionsessionfrommessage-usecache-error).

© 2024 Seald SAS

You can find the license information of Open Source libraries used in Seald SDK for mobile at <https://download.seald.io/download/mobile_dependencies_licenses_##VERSION##.txt>.
