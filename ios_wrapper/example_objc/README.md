# Seald SDK demo app iOS Objective-C

This is a basic app, demonstrating use of the Seald SDK for iOS in Objective-C.

You can check the reference documentation at <https://docs.seald.io/sdk/seald-sdk-ios/>.

The main file you could be interested in reading is [`./SealdSDK/SEALDSDKAppDelegate.m`](./SealdSDK/SEALDSDKAppDelegate.m).

Before running the app, you have to install the Cocoapods, with the command `pod install`.

Also, to run the example app, you must copy `./SealdSDK/credentials.m_template` to `./SealdSDK/credentials.m`, and set
the values of `apiURL`, `appId`, `JWTSharedSecretId`, `JWTSharedSecret`, `ssksURL` and `ssksBackendAppKey`.

To get these values, you must create your own Seald team on <https://www.seald.io/create-sdk>. Then, you can get the
values of `apiURL`, `appId`, `JWTSharedSecretId`, and `JWTSharedSecret`, on the `SDK` tab of the Seald dashboard
settings, and you can get `ssksURL` and `ssksBackendAppKey` on the `SSKS` tab.

Finally, to run the app, open `SealdSDK demo app ios.xcworkspace` in XCode, then run it.
