# Seald SDK demo app iOS Swift

This is a basic app, demonstrating use of the Seald SDK for iOS in Swift.

You can check the reference documentation at <https://docs.seald.io/sdk/seald-sdk-ios/>.

The main file you could be interested in reading is [`./seald-sdk-demo-app-ios-swift/ContentView.swift`](./seald-sdk-demo-app-ios-swift/ContentView.swift).

Before running the app, you have to install the Cocoapods, with the command `pod install`.

Also, to run the example app, you must copy `./seald-sdk-demo-app-ios-swift/credentials.swift_template` to `./seald-sdk-demo-app-ios-swift/credentials.swift`, and set
the values of `apiURL`, `appId`, `JWTSharedSecretId`, `JWTSharedSecret`, `ssksURL` and `ssksBackendAppKey`.

To get these values, you must create your own Seald team on <https://www.seald.io/create-sdk>. Then, you can get the
values of `apiURL`, `appId`, `JWTSharedSecretId`, and `JWTSharedSecret`, on the `SDK` tab of the Seald dashboard
settings, and you can get `ssksURL` and `ssksBackendAppKey` on the `SSKS` tab.

Finally, to run the app, open `SealdSDK demo app ios swift.xcworkspace` in XCode, then run it.
