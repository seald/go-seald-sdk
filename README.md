# Seald SDK

This repo hosts the code for the Seald SDK.

It is written in GoLang.

There are also bindings for:
- iOS, written in Objective-C in [the `./ios_wrapper` folder](./ios_wrapper), published on [Cocoapods](https://cocoapods.org/), with an example app available in Objective-C [here](https://github.com/seald/seald-sdk-demo-app-ios) and in Swift [here](https://github.com/seald/seald-sdk-demo-app-ios-swift);
- Android, written in Kotlin in [the `./kotlin_wrapper` folder](./kotlin_wrapper), published on [Maven Central](https://central.sonatype.com/artifact/io.seald/seald_sdk_android), with an example app available [here](https://github.com/seald/seald-sdk-demo-app-android);
- Flutter, written in C and Dart in [the `./c_sdk` folder](./c_sdk) and [the `./flutter_wrapper` folder](./flutter_wrapper) respectively, published on [Pub Dev](https://pub.dev/packages/seald_sdk_flutter), with an example app available [here](https://github.com/seald/seald-sdk-demo-app-flutter).

You will find more information about our GoLang code style rules and other development conventions in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

For the bindings, more information about the code style and development conventions is available as needed inside the binding's folder.

## Test Credentials

This repository does not contain credentials to run the tests. If you want to contribute to the development,
you will need credentials on our dev environment. To get them, contact us at [contact@seald.io](mailto:contact@seald.io).
Then, copy `test_credentials.template.json` to `test_credentials.json`, and fill this template with the credentials.
After this, you will be able to run the tests.
