# Package io.seald.seald_sdk

This package is the Seald SDK for Android.

To install it, you need to add the package `io.seald:seald_sdk_android`, available on Maven Central,
to your dependencies.

The current version is `##VERSION##`. Here is how you can add it to your `app/build.gradle`:

```groovy{3}
dependencies {
    /* ... */
    implementation 'io.seald:seald_sdk_android:##VERSION##'
}
```

You can then import it in your code with:
```kotlin
import io.seald.seald_sdk.SealdSDK
```

You can also see the [example app](https://github.com/seald/seald-sdk-demo-app-android/).

This package contains the main [SealdSDK] class,
the [EncryptionSession] class,
as well as multiple helper classes.

## `SealdSDK`

[SealdSDK] is the main class for the Seald SDK.
It represents an instance of the Seald SDK.

You can instantiate it this way:
```kotlin
val seald = SealdSDK(
    apiURL = "https://api.seald.io/",
    appId = "YourAppId",
    databasePath = "/myApp/seald_db",
    databaseEncryptionKey = "A Secret Key to encrypt the local database, encoded in b64"
)
```

This class then allows you to [create an account](SealdSDK.createAccount),
create or retrieve an [EncryptionSession],
etc.

See [the `SealdSDK` reference](SealdSDK) for more information.

## `EncryptionSession`

An [EncryptionSession] allows you to encrypt / decrypt multiple messages or files.

This should not be instantiated directly, and should be either created with [SealdSDK.createEncryptionSession]
or retrieved with [SealdSDK.retrieveEncryptionSession]
or [SealdSDK.retrieveEncryptionSessionFromMessage].

© 2024 Seald SAS

You can find the license information of Open Source libraries used in Seald SDK for mobile at <https://download.seald.io/download/mobile_dependencies_licenses_##VERSION##.txt>.
