part of 'seald_sdk.dart';

/// SealdSsksPasswordPlugin represents the Seald SSKS Password plugin.
///
/// {@category SealdSsksPasswordPlugin}
class SealdSsksPasswordPlugin implements Finalizable {
  late final _TransferablePointer<NativeSealdSsksPasswordPlugin> _ptr;

  static final _finalizer = NativeFinalizer(_bindings.addresses
      .SealdSsksPasswordPlugin_Free as Pointer<NativeFinalizerFunction>);

  // This is used to re-create the SealdSsksPasswordPlugin from inside an isolate WITHOUT the finalizer, to avoid double-frees
  SealdSsksPasswordPlugin._(this._ptr);

  /// Initialize an instance of Seald SSKS Password plugin.
  ///
  /// [ssksURL] - The URL of the SSKS Identity Key Storage to which it should connect.
  /// [appId] - The ID given by the Seald server to your app. This value is given on your Seald dashboard.
  /// [logLevel] - The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. Defaults to 0.
  /// [logNoColor] - Whether to disable colors in the log output. `true` to disable colors, `false` to enable colors. Defaults to false.
  /// [instanceName] - An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. Defaults to an empty string.
  SealdSsksPasswordPlugin({
    required String ssksURL,
    required String appId,
    int logLevel = 0,
    bool logNoColor = false,
    String instanceName = "",
  }) {
    final Pointer<NativeSealdSsksPasswordPluginInitializeOptions> initOpts =
        calloc<NativeSealdSsksPasswordPluginInitializeOptions>();
    final String platform = "c-flutter-${Platform.operatingSystem}";
    initOpts.ref
      ..SsksURL = ssksURL.toNativeUtf8()
      ..AppId = appId.toNativeUtf8()
      ..LogLevel = logLevel
      ..LogNoColor = logNoColor ? 1 : 0
      ..InstanceName = instanceName.toNativeUtf8()
      ..Platform = platform.toNativeUtf8();

    final Pointer<Pointer<NativeSealdSsksPasswordPlugin>> result =
        calloc<Pointer<NativeSealdSsksPasswordPlugin>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_Initialize(initOpts, result, err);

    calloc.free(initOpts.ref.SsksURL);
    calloc.free(initOpts.ref.AppId);
    calloc.free(initOpts.ref.InstanceName);
    calloc.free(initOpts.ref.Platform);
    calloc.free(initOpts);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      _ptr = _TransferablePointer<NativeSealdSsksPasswordPlugin>(result.value);
      _finalizer.attach(this, _ptr.pointer() as Pointer<Void>);
      calloc.free(result);
      calloc.free(err);
    }
  }

  /// Save the given identity for the given userId, encrypted with the given password.
  ///
  /// [userId] - The ID of the user.
  /// [password] - The password to encrypt the key.
  /// [identity] - The identity to save.
  ///
  /// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
  String saveIdentityFromPassword(
      String userId, String password, Uint8List identity) {
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativePassword = password.toNativeUtf8();
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeIdentity = calloc<Uint8>(identity.length);
    final pointerListIdentity = nativeIdentity.asTypedList(identity.length);
    pointerListIdentity.setAll(0, identity);
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_SaveIdentityFromPassword(
            _ptr.pointer(),
            nativeUserId,
            nativePassword,
            nativeIdentity,
            identity.length,
            result,
            err);

    calloc.free(nativeUserId);
    calloc.free(nativePassword);
    calloc.free(nativeIdentity);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String res = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Save the given identity for the given userId, encrypted with the given password.
  ///
  /// [userId] - The ID of the user.
  /// [password] - The password to encrypt the key.
  /// [identity] - The identity to save.
  ///
  /// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
  Future<String> saveIdentityFromPasswordAsync(
      String userId, String password, Uint8List identity) {
    final _TransferablePointer<NativeSealdSsksPasswordPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksPasswordPlugin._(tPtr)
            .saveIdentityFromPassword(
                args["userId"], args["password"], args["identity"]),
        {"userId": userId, "password": password, "identity": identity});
  }

  /// Save the given identity for the given userId, encrypted with the given raw keys.
  ///
  /// [userId] - The ID of the user.
  /// [rawStorageKey] - The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
  /// [rawEncryptionKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [identity] - The identity to save.
  ///
  /// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
  String saveIdentityFromRawKeys(String userId, String rawStorageKey,
      Uint8List rawEncryptionKey, Uint8List identity) {
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativeRawStorageKey = rawStorageKey.toNativeUtf8();
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawEncryptionKey =
        calloc<Uint8>(rawEncryptionKey.length);
    final pointerListRawEncryptionKey =
        nativeRawEncryptionKey.asTypedList(rawEncryptionKey.length);
    pointerListRawEncryptionKey.setAll(0, rawEncryptionKey);
    final Pointer<Uint8> nativeIdentity = calloc<Uint8>(identity.length);
    final pointerListIdentity = nativeIdentity.asTypedList(identity.length);
    pointerListIdentity.setAll(0, identity);
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_SaveIdentityFromRawKeys(
            _ptr.pointer(),
            nativeUserId,
            nativeRawStorageKey,
            nativeRawEncryptionKey,
            rawEncryptionKey.length,
            nativeIdentity,
            identity.length,
            result,
            err);

    calloc.free(nativeUserId);
    calloc.free(nativeRawStorageKey);
    calloc.free(nativeRawEncryptionKey);
    calloc.free(nativeIdentity);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      final String res = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Save the given identity for the given userId, encrypted with the given raw keys.
  ///
  /// [userId] - The ID of the user.
  /// [rawStorageKey] - The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
  /// [rawEncryptionKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [identity] - The identity to save.
  ///
  /// Returns the SSKS ID of the stored identity, which can be used by your backend to manage it.
  Future<String> saveIdentityFromRawKeysAsync(String userId,
      String rawStorageKey, Uint8List rawEncryptionKey, Uint8List identity) {
    final _TransferablePointer<NativeSealdSsksPasswordPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksPasswordPlugin._(tPtr)
            .saveIdentityFromRawKeys(args["userId"], args["rawStorageKey"],
                args["rawEncryptionKey"], args["identity"]),
        {
          "userId": userId,
          "rawStorageKey": rawStorageKey,
          "rawEncryptionKey": rawEncryptionKey,
          "identity": identity
        });
  }

  /// Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
  ///
  /// If you use an incorrect password multiple times, the server may throttle your requests. In this case, you will
  /// receive an error `Request throttled, retry after {N}s`, with `{N}` the number of seconds during which you
  /// cannot try again.
  ///
  /// [userId] - The ID of the user.
  /// [password] - The password to encrypt the key.
  /// [identity] - The identity to save.
  ///
  /// Returns a [Uint8List] containing the retrieved identity.
  Uint8List retrieveIdentityFromPassword(String userId, String password) {
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativePassword = password.toNativeUtf8();
    final Pointer<Pointer<Uint8>> result = calloc<Pointer<Uint8>>();
    final Pointer<Int> resultLen = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(
            _ptr.pointer(),
            nativeUserId,
            nativePassword,
            result,
            resultLen,
            err);

    calloc.free(nativeUserId);
    calloc.free(nativePassword);

    if (resultCode != 0) {
      calloc.free(result);
      calloc.free(resultLen);
      throw SealdException._fromCPtr(err);
    } else {
      final Uint8List cIdentityExport =
          result.value.asTypedList(resultLen.value);
      // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
      final Uint8List res = Uint8List.fromList(cIdentityExport);
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(resultLen);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
  ///
  /// If you use an incorrect password multiple times, the server may throttle your requests. In this case, you will
  /// receive an error `Request throttled, retry after {N}s`, with `{N}` the number of seconds during which you
  /// cannot try again.
  ///
  /// [userId] - The ID of the user.
  /// [password] - The password to encrypt the key.
  /// [identity] - The identity to save.
  ///
  /// Returns a [Uint8List] containing the retrieved identity.
  Future<Uint8List> retrieveIdentityFromPasswordAsync(
      String userId, String password) {
    final _TransferablePointer<NativeSealdSsksPasswordPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksPasswordPlugin._(tPtr)
            .retrieveIdentityFromPassword(args["userId"], args["password"]),
        {"userId": userId, "password": password});
  }

  /// Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
  ///
  /// If you use an incorrect password multiple times, the server may throttle your requests. In this case, you will
  /// receive an error `Request throttled, retry after {N}s`, with `{N}` the number of seconds during which you
  /// cannot try again.
  ///
  /// [userId] - The ID of the user.
  /// [rawStorageKey] - The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
  /// [rawEncryptionKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  ///
  /// Returns a [Uint8List] containing the retrieved identity.
  Uint8List retrieveIdentityFromRawKeys(
      String userId, String rawStorageKey, Uint8List rawEncryptionKey) {
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativeRawStorageKey = rawStorageKey.toNativeUtf8();
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawEncryptionKey =
        calloc<Uint8>(rawEncryptionKey.length);
    final pointerListRawEncryptionKey =
        nativeRawEncryptionKey.asTypedList(rawEncryptionKey.length);
    pointerListRawEncryptionKey.setAll(0, rawEncryptionKey);
    final Pointer<Pointer<Uint8>> result = calloc<Pointer<Uint8>>();
    final Pointer<Int> resultLen = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys(
            _ptr.pointer(),
            nativeUserId,
            nativeRawStorageKey,
            nativeRawEncryptionKey,
            rawEncryptionKey.length,
            result,
            resultLen,
            err);

    calloc.free(nativeUserId);
    calloc.free(nativeRawStorageKey);
    calloc.free(nativeRawEncryptionKey);

    if (resultCode != 0) {
      calloc.free(result);
      calloc.free(resultLen);
      throw SealdException._fromCPtr(err);
    } else {
      final Uint8List cIdentityExport =
          result.value.asTypedList(resultLen.value);
      // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
      final Uint8List res = Uint8List.fromList(cIdentityExport);
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(resultLen);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
  ///
  /// If you use an incorrect password multiple times, the server may throttle your requests. In this case, you will
  /// receive an error `Request throttled, retry after {N}s`, with `{N}` the number of seconds during which you
  /// cannot try again.
  ///
  /// [userId] - The ID of the user.
  /// [rawStorageKey] - The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
  /// [rawEncryptionKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  ///
  /// Returns a [Uint8List] containing the retrieved identity.
  Future<Uint8List> retrieveIdentityFromRawKeysAsync(
      String userId, String rawStorageKey, Uint8List rawEncryptionKey) {
    final _TransferablePointer<NativeSealdSsksPasswordPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksPasswordPlugin._(tPtr)
            .retrieveIdentityFromRawKeys(args["userId"], args["rawStorageKey"],
                args["rawEncryptionKey"]),
        {
          "userId": userId,
          "rawStorageKey": rawStorageKey,
          "rawEncryptionKey": rawEncryptionKey
        });
  }

  /// Change the password use to encrypt the identity for the userId.
  ///
  /// [userId] - The ID of the user.
  /// [currentPassword] - The user's current password.
  /// [newPassword] - The new password.
  ///
  /// Returns the new SSKS ID of the stored identity
  String changeIdentityPassword(
      String userId, String currentPassword, String newPassword) {
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativeCurrentPassword = currentPassword.toNativeUtf8();
    final Pointer<Utf8> nativeNewPassword = newPassword.toNativeUtf8();
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksPasswordPlugin_ChangeIdentityPassword(
            _ptr.pointer(),
            nativeUserId,
            nativeCurrentPassword,
            nativeNewPassword,
            result,
            err);

    calloc.free(nativeUserId);
    calloc.free(nativeCurrentPassword);
    calloc.free(nativeNewPassword);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      final String res = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Change the password use to encrypt the identity for the userId.
  ///
  /// [userId] - The ID of the user.
  /// [currentPassword] - The user's current password.
  /// [newPassword] - The new password.
  ///
  /// Returns the new SSKS ID of the stored identity
  Future<String> changeIdentityPasswordAsync(
      String userId, String currentPassword, String newPassword) {
    final _TransferablePointer<NativeSealdSsksPasswordPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksPasswordPlugin._(tPtr)
            .changeIdentityPassword(
                args["userId"], args["currentPassword"], args["newPassword"]),
        {
          "userId": userId,
          "currentPassword": currentPassword,
          "newPassword": newPassword
        });
  }
}
