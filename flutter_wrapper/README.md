# seald_sdk_flutter

SealdSDK allows you to use the full power of Seald encryption, directly in your Flutter application.

You can create and retrieve Seald identities for your app's users, encrypt and decrypt files,
create encryption sessions, add or revoke recipients...

SealdSDK for Flutter requires Flutter >= 3.10.0.

For more information, visit our website : https://seald.io .

This package is published on pub.dev at https://pub.dev/packages/seald_sdk_flutter .

A full example app is available at https://github.com/seald/seald-sdk-demo-app-flutter/ .

## Basic Example

```dart
import 'package:seald_sdk_flutter/seald_sdk.dart';

Future<void> main() async {
  final SealdSdk seald = SealdSdk(
    apiURL: apiURL,
    appId: appId,
  );

  // Creating a Seald identity
  final SealdAccountInfo info = await seald.createAccountAsync(jwt);

  // Encrypting / Decrypting data
  final SealdEncryptionSession es = await seald.createEncryptionSessionAsync([info.userId]);
  final Uint8List encryptedFile = await es.encryptFileAsync(
    Uint8List.fromList(utf8.encode('Secret file content')),
    'SecretFile.txt',
  );
  final Uint8List decryptedFile = await es.decryptFileAsync(encryptedFile);
}
```

## Installation on iOS

For installation on iOS, you will have to set a global platform of at least iOS 13 for your project.
To do that, edit your `./ios/Podfile`, and add the following line:

```ruby
platform :ios, '13.0'
```

## Hot-Reload / Hot-Restart

The Seald SDK is not compatible with Flutter's Hot-Reload / Hot-Restart features.
If you try using them, you will likely encounter a `DATABASE_LOCKED` error.

This is due to a limitation of the Dart VM, which does not allow to access to lifecycle hooks, in order to perform
proper cleanup on the existing instance during a Hot-Restart.

© 2024 Seald SAS

You can find the license information of Open Source libraries used in Seald SDK for mobile at https://download.seald.io/download/mobile_dependencies_licenses_##VERSION##.txt .
