import 'dart:async';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'dart:io';
import 'seald_sdk_c_bindings_generated.dart';

part 'bindings.dart';

part 'helpers.dart';

part 'encryption_session.dart';

part 'ssks_tmr.dart';

part 'ssks_password.dart';

part 'utils.dart';

/// The version of the Seald SDK.
///
/// {@category Utils}
final String sealdSdkVersion = (() {
  final Pointer<Utf8> v = _bindings.SealdSdk_Version();
  final String res = v.toDartString();
  calloc.free(v);
  return res;
})();

/// This is the main class for the Seald SDK. It represents an instance of the Seald SDK.
/// This must be instantiated from the root isolate, or you must pass the `rootIsolateToken` argument.
///
/// {@category SealdSdk}
class SealdSdk {
  late final _TransferablePointer<NativeSealdSdk> _ptr;
  late final RootIsolateToken _rootIsolateToken;
  bool _closed = false;
  int _keySize = 4096;

  /// Creates a new instance of SealdSdk.
  ///
  /// [apiURL] - The Seald server for this instance to use. This value is given on your Seald dashboard.
  /// [appId] - The ID given by the Seald server to your app. This value is given on your Seald dashboard.
  /// [keySize] - The Asymmetric key size for newly generated keys. Defaults to 4096. Warning: for security, it is extremely not recommended to lower this value. For advanced use only.
  /// [databasePath] - The path where to store the local Seald database. Defaults to an empty string.
  /// [databaseEncryptionKey] - The encryption key with which to encrypt the local Seald database. This *MUST* be a cryptographically random buffer of 64 bytes. Defaults to an empty string.
  /// [encryptionSessionCacheTTL] - The duration of cache lifetime. `-1` to cache forever. `0` for no cache. Defaults to 0.
  /// [logLevel] - The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. Defaults to 0.
  /// [logNoColor] - Whether to disable colors in the log output. `true` to disable colors, `false` to enable colors. Defaults to false.
  /// [instanceName] - An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. Defaults to an empty string.
  /// [rootIsolateToken] - The `rootIsolateToken` that you can retrieve from the root isolate with `ServicesBinding.rootIsolateToken`.
  SealdSdk(
      {required String apiURL,
      required String appId,
      int keySize = 4096,
      String databasePath = "",
      Uint8List? databaseEncryptionKey,
      Duration encryptionSessionCacheTTL = Duration.zero,
      int logLevel = 0,
      bool logNoColor = false,
      String instanceName = "",
      RootIsolateToken? rootIsolateToken}) {
    if (rootIsolateToken != null) {
      _rootIsolateToken = rootIsolateToken;
    } else if (ServicesBinding.rootIsolateToken != null) {
      _rootIsolateToken = ServicesBinding.rootIsolateToken!;
    } else {
      throw SealdException(
          code: "REQUIRES_ROOT_ISOLATE_TOKEN",
          id: "FLUTTER_REQUIRES_ROOT_ISOLATE_TOKEN",
          description:
              "The Seald SDK for Flutter must be instantiated from the root isolate, or `rootIsolateToken` must me passed.");
    }

    final Pointer<NativeSealdInitializeOptions> initOpts =
        calloc<NativeSealdInitializeOptions>();
    final String platform = "c-flutter-${Platform.operatingSystem}";

    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeDatabaseEncryptionKey =
        databaseEncryptionKey != null
            ? calloc<Uint8>(databaseEncryptionKey.length)
            : nullptr;
    final pointerListDatabaseEncryptionKey = databaseEncryptionKey != null
        ? nativeDatabaseEncryptionKey.asTypedList(databaseEncryptionKey.length)
        : null;
    pointerListDatabaseEncryptionKey?.setAll(0, databaseEncryptionKey!);

    initOpts.ref
      ..ApiURL = apiURL.toNativeUtf8()
      ..AppId = appId.toNativeUtf8()
      ..KeySize = keySize
      ..DatabasePath = databasePath.toNativeUtf8()
      ..DatabaseEncryptionKey = nativeDatabaseEncryptionKey
      ..DatabaseEncryptionKeyLen = databaseEncryptionKey?.length ?? 0
      ..EncryptionSessionCacheTTL = encryptionSessionCacheTTL.inMilliseconds
      ..LogLevel = logLevel
      ..LogNoColor = logNoColor ? 1 : 0
      ..InstanceName = instanceName.toNativeUtf8()
      ..Platform = platform.toNativeUtf8();
    _keySize = keySize;

    final Pointer<Pointer<NativeSealdSdk>> result =
        calloc<Pointer<NativeSealdSdk>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_Initialize(initOpts, result, err);

    calloc.free(initOpts.ref.ApiURL);
    calloc.free(initOpts.ref.AppId);
    calloc.free(initOpts.ref.DatabasePath);
    calloc.free(initOpts.ref.DatabaseEncryptionKey);
    calloc.free(initOpts.ref.InstanceName);
    calloc.free(initOpts.ref.Platform);
    calloc.free(initOpts);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      _ptr = _TransferablePointer<NativeSealdSdk>(result.value);
      calloc.free(result);
      calloc.free(err);
    }
  }

  /// Close the current SDK instance. This frees any lock on the current database, and frees the memory.
  /// After calling close, the instance cannot be used anymore.
  void close() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    _closed = true;
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final int resultCode = _bindings.SealdSdk_Close(_ptr.pointer(), err);
    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Generate private keys.
  ///
  /// Returns a SealdGeneratedPrivateKeys instance that can be used with synchronous methods.
  Future<SealdGeneratedPrivateKeys> generatePrivateKeysAsync() async {
    if (Platform.isMacOS || Platform.isIOS || Platform.isAndroid) {
      BackgroundIsolateBinaryMessenger.ensureInitialized(_rootIsolateToken);
      const MethodChannel channel =
          MethodChannel('io.seald.seald_sdk_flutter.native_rsa_key_generator');
      Map<Object?, Object?> res =
          await channel.invokeMethod('generateRSAKeys', {'size': _keySize});
      Object? encryptionKey = res['encryptionKey'];
      Object? signingKey = res['signingKey'];
      Object? format = res['format'];
      if (encryptionKey is String && signingKey is String && format is String) {
        if (format == 'PKCS8') {
          return SealdGeneratedPrivateKeys(encryptionKey, signingKey);
        } else if (format == 'PKCS1DER') {
          return SealdGeneratedPrivateKeys(
              _pkcs1DerToPkcs8(encryptionKey), _pkcs1DerToPkcs8(signingKey));
        } else {
          throw SealdException(code: "INVALID_GENERATED_KEY_FORMAT");
        }
      } else {
        throw SealdException(code: "INVALID_GENERATED_KEYS");
      }
    } else {
      return SealdGeneratedPrivateKeys(
          await compute((_) => _generatePrivateKey(4096), null),
          await compute((_) => _generatePrivateKey(4096), null));
    }
  }

  /* Account */

  /// Creates a new Seald SDK Account for this Seald SDK instance.
  /// This function can only be called if the current SDK instance does not have an account yet.
  ///
  /// [signupJwt] - The JWT to allow this SDK instance to create an account.
  /// [displayName] - A name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user. Defaults to "User".
  /// [deviceName] - A name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Defaults to "Device".
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
  ///
  /// Returns a [SealdAccountInfo] instance containing the Seald ID of the newly created Seald user, the device ID, and the date at which the current device keys will expire.
  SealdAccountInfo createAccount(String signupJwt,
      {String displayName = "User",
      String deviceName = "Device",
      SealdGeneratedPrivateKeys? privateKeys,
      Duration expireAfter = Duration.zero}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdAccountInfo>> result =
        calloc<Pointer<NativeSealdAccountInfo>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final Pointer<Utf8> nativeSignupJwt = signupJwt.toNativeUtf8();
    final Pointer<Utf8> nativeDisplayName = displayName.toNativeUtf8();
    final Pointer<Utf8> nativeDeviceName = deviceName.toNativeUtf8();
    final Pointer<Utf8> nativeEncryptionKey =
        privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey =
        privateKeys?.signingKey.toNativeUtf8() ?? nullptr;

    final int resultCode = _bindings.SealdSdk_CreateAccount(
        _ptr.pointer(),
        nativeDisplayName,
        nativeDeviceName,
        nativeSignupJwt,
        expireAfter.inSeconds,
        nativeEncryptionKey,
        nativeSigningKey,
        result,
        err);
    calloc.free(nativeSignupJwt);
    calloc.free(nativeDisplayName);
    calloc.free(nativeDeviceName);
    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);
    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
      final res = SealdAccountInfo._fromC(result.value);
      calloc.free(result);
      return res;
    }
  }

  /// Creates a new Seald SDK Account for this Seald SDK instance.
  /// This function can only be called if the current SDK instance does not have an account yet.
  ///
  /// [signupJwt] - The JWT to allow this SDK instance to create an account.
  /// [displayName] - A name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user. Defaults to "User".
  /// [deviceName] - A name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Defaults to "Device".
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
  ///
  /// Returns a [SealdAccountInfo] instance containing the Seald ID of the newly created Seald user, and the device ID.
  Future<SealdAccountInfo> createAccountAsync(String signupJwt,
      {String displayName = "User",
      String deviceName = "Device",
      SealdGeneratedPrivateKeys? privateKeys,
      Duration expireAfter = Duration.zero}) {
    return compute((Map<String, dynamic> args) async {
      privateKeys ??= await generatePrivateKeysAsync();
      return createAccount(args["signupJwt"],
          displayName: args["displayName"],
          deviceName: args["deviceName"],
          expireAfter: args["expireAfter"],
          privateKeys: privateKeys);
    }, {
      "signupJwt": signupJwt,
      "displayName": displayName,
      "deviceName": deviceName,
      "expireAfter": expireAfter
    });
  }

  /// Returns information about the current account, or `null` if there is none.
  ///
  /// Returns a [SealdAccountInfo] containing the Seald ID of the local Seald user, the device ID, and the date at which the current device keys will expire. `null` if there is no local user.
  SealdAccountInfo? getCurrentAccountInfo() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<NativeSealdAccountInfo> result =
        _bindings.SealdSdk_GetCurrentAccountInfo(_ptr.pointer());
    if (result.address == nullptr.address) {
      return null;
    } else {
      final accountInfo = SealdAccountInfo._fromC(result);
      return accountInfo;
    }
  }

  /// Updates the locally known information about the current device.
  ///
  /// You should never have to call this manually, except if you getting `null` in [SealdAccountInfo.deviceExpires],
  /// which can happen if migrating from an older version of the SDK,
  /// or if the internal call to [SealdSdk.updateCurrentDevice] failed when calling [SealdSdk.importIdentity].
  void updateCurrentDevice() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final int resultCode =
        _bindings.SealdSdk_UpdateCurrentDevice(_ptr.pointer(), err);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew
  ///
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  ///
  /// Returns a [Uint8List] containing a prepared renewal.
  Uint8List prepareRenew({SealdGeneratedPrivateKeys? privateKeys}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeEncryptionKey =
        privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey =
        privateKeys?.signingKey.toNativeUtf8() ?? nullptr;
    final Pointer<Pointer<Uint8>> result = calloc<Pointer<Uint8>>();
    final Pointer<Int> resultLen = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_PrepareRenew(_ptr.pointer(),
        nativeEncryptionKey, nativeSigningKey, result, resultLen, err);

    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);
    if (resultCode != 0) {
      calloc.free(result);
      calloc.free(resultLen);
      throw SealdException._fromCPtr(err);
    } else {
      final Uint8List cPreparedRenew =
          result.value.asTypedList(resultLen.value);
      // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
      final Uint8List res = Uint8List.fromList(cPreparedRenew);
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(resultLen);
      calloc.free(err);
      return res;
    }
  }

  /// Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew
  ///
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  ///
  /// Returns a [Uint8List] containing a prepared renewal.
  Future<Uint8List> prepareRenewAsync(
      {SealdGeneratedPrivateKeys? privateKeys}) {
    return compute((_) async {
      privateKeys ??= await generatePrivateKeysAsync();
      return prepareRenew(privateKeys: privateKeys);
    }, null);
  }

  /// Renews the keys of the current device, extending their validity.
  /// If the current device has expired, you will need to call [renewKeys] before you are able to do anything else.
  /// Warning: if the identity of the current device is stored externally, for example on SSKS,
  /// you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
  ///
  /// [preparedRenewal] - Optional. A prepared renewal, returned by a call to [SealdSdk.prepareRenew]. If preparedRenewal is given, privateKeys will be ignored.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
  void renewKeys({
    Uint8List? preparedRenewal,
    SealdGeneratedPrivateKeys? privateKeys,
    Duration expireAfter = const Duration(days: 5 * 365),
  }) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final Pointer<Utf8> nativeEncryptionKey = preparedRenewal != null
        ? nullptr
        : privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey = preparedRenewal != null
        ? nullptr
        : privateKeys?.signingKey.toNativeUtf8() ?? nullptr;

    Pointer<Uint8> nativePreparedRenewal = nullptr;
    if (preparedRenewal != null) {
      // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
      nativePreparedRenewal = calloc<Uint8>(preparedRenewal.length);
      final pointerList =
          nativePreparedRenewal.asTypedList(preparedRenewal.length);
      pointerList.setAll(0, preparedRenewal);
    }

    final int resultCode = _bindings.SealdSdk_RenewKeys(
        _ptr.pointer(),
        expireAfter.inSeconds,
        nativeEncryptionKey,
        nativeSigningKey,
        nativePreparedRenewal,
        preparedRenewal?.length ?? 0,
        err);
    calloc.free(nativePreparedRenewal);
    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);
    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Renews the keys of the current device, extending their validity.
  /// If the current device has expired, you will need to call [renewKeys] before you are able to do anything else.
  /// Warning: if the identity of the current device is stored externally, for example on SSKS,
  /// you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
  ///
  /// [preparedRenewal] - Optional. A prepared renewal, returned by a call to [SealdSdk.prepareRenew]. If preparedRenewal is given, privateKeys will be ignored.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
  Future<void> renewKeysAsync({
    Uint8List? preparedRenewal,
    SealdGeneratedPrivateKeys? privateKeys,
    Duration expireAfter = const Duration(days: 5 * 365),
  }) {
    return compute((Map<String, dynamic> args) async {
      privateKeys ??=
          preparedRenewal != null ? null : await generatePrivateKeysAsync();
      renewKeys(
          expireAfter: args["expireAfter"],
          preparedRenewal: args["preparedRenewal"],
          privateKeys: privateKeys);
    }, {"expireAfter": expireAfter, "preparedRenewal": preparedRenewal});
  }

  /// Creates a new sub-identity, or new device, for the current user account.
  /// After creating this new device, you will probably want to call [massReencrypt],
  /// so that the newly created device will be able to decrypt [SealdEncryptionSession]s previously created for this account.
  ///
  /// [deviceName] - An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
  ///
  /// Returns a [SealdCreateSubIdentityResponse] instance, containing the ID of the newly created device, and the identity export of the newly created sub-identity.
  SealdCreateSubIdentityResponse createSubIdentity(
      {String deviceName = "",
      SealdGeneratedPrivateKeys? privateKeys,
      Duration expireAfter = const Duration(days: 5 * 365)}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdCreateSubIdentityResponse>> result =
        calloc<Pointer<NativeSealdCreateSubIdentityResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final Pointer<Utf8> nativeDeviceName = deviceName.toNativeUtf8();
    final Pointer<Utf8> nativeEncryptionKey =
        privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey =
        privateKeys?.signingKey.toNativeUtf8() ?? nullptr;

    final int resultCode = _bindings.SealdSdk_CreateSubIdentity(
        _ptr.pointer(),
        nativeDeviceName,
        expireAfter.inSeconds,
        nativeEncryptionKey,
        nativeSigningKey,
        result,
        err);

    calloc.free(nativeDeviceName);
    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);
    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
      final res = SealdCreateSubIdentityResponse._fromC(result.value);
      calloc.free(result);
      return res;
    }
  }

  /// Creates a new sub-identity, or new device, for the current user account.
  /// After creating this new device, you will probably want to call [massReencrypt],
  /// so that the newly created device will be able to decrypt [SealdEncryptionSession]s previously created for this account.
  ///
  /// [deviceName] - An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  /// [expireAfter] - The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
  ///
  /// Returns a [SealdCreateSubIdentityResponse] instance, containing the ID of the newly created device, and the identity export of the newly created sub-identity.
  Future<SealdCreateSubIdentityResponse> createSubIdentityAsync(
      {String deviceName = "",
      SealdGeneratedPrivateKeys? privateKeys,
      Duration expireAfter = const Duration(days: 5 * 365)}) {
    return compute((Map<String, dynamic> args) async {
      privateKeys ??= await generatePrivateKeysAsync();
      return createSubIdentity(
          deviceName: args["deviceName"],
          expireAfter: args["expireAfter"],
          privateKeys: privateKeys);
    }, {"deviceName": deviceName, "expireAfter": expireAfter});
  }

  /// Loads an identity export into the current SDK instance.
  /// This function can only be called if the current SDK instance does not have an account yet.
  ///
  /// [identity] - The identity export that this SDK instance should import.
  void importIdentity(Uint8List identity) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeIdentity = calloc<Uint8>(identity.length);
    final pointerList = nativeIdentity.asTypedList(identity.length);
    pointerList.setAll(0, identity);
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    final int resultCode = _bindings.SealdSdk_ImportIdentity(
        _ptr.pointer(), nativeIdentity, identity.length, err);
    calloc.free(nativeIdentity);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Loads an identity export into the current SDK instance.
  /// This function can only be called if the current SDK instance does not have an account yet.
  ///
  /// [identity] - The identity export that this SDK instance should import.
  Future<void> importIdentityAsync(Uint8List identity) {
    return compute(importIdentity, identity);
  }

  /// Exports the current device as an identity export.
  ///
  /// Returns a [Uint8List] containing the identity export of the current identity of this SDK instance.
  Uint8List exportIdentity() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<Uint8>> result = calloc<Pointer<Uint8>>();
    final Pointer<Int> resultLen = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_ExportIdentity(
        _ptr.pointer(), result, resultLen, err);

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

  /// Pushes a given JWT to the Seald server, for example, to add a connector to the current account.
  ///
  /// [jwt] - The JWT to push.
  void pushJWT(String jwt) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeJwt = jwt.toNativeUtf8();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSdk_PushJWT(_ptr.pointer(), nativeJwt, err);

    calloc.free(nativeJwt);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Pushes a given JWT to the Seald server, for example, to add a connector to the current account.
  ///
  /// [jwt] - The JWT to push.
  Future<void> pushJWTAsync(String jwt) {
    return compute(pushJWT, jwt);
  }

  /// Just call the Seald server, without doing anything.
  /// This may be used, for example, to verify that the current instance has a valid identity.
  void heartbeat() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_Heartbeat(_ptr.pointer(), err);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Just call the Seald server, without doing anything.
  /// This may be used, for example, to verify that the current instance has a valid identity.
  Future<void> heartbeatAsync() {
    return compute((_) => heartbeat(), null);
  }

  // Groups

  /// Create a group and return the created group's ID.
  /// `admins` must also be members.
  /// `admins` must include yourself.
  ///
  /// [groupName] - A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
  /// [members] - The Seald IDs of the members to add to the group. Must include yourself.
  /// [admins] - The Seald IDs of the members to also add as group admins. Must include yourself.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  ///
  /// Returns the ID of the created group.
  String createGroup(
      {String groupName = "",
      required List<String> members,
      required List<String> admins,
      SealdGeneratedPrivateKeys? privateKeys}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupName = groupName.toNativeUtf8();
    final Pointer<NativeSealdStringArray> nativeMembers =
        _sealdStringArrayFromList(members);
    final Pointer<NativeSealdStringArray> nativeAdmins =
        _sealdStringArrayFromList(admins);
    final Pointer<Utf8> nativeEncryptionKey =
        privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey =
        privateKeys?.signingKey.toNativeUtf8() ?? nullptr;
    final Pointer<Pointer<Utf8>> groupId = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_CreateGroup(
        _ptr.pointer(),
        nativeGroupName,
        nativeMembers,
        nativeAdmins,
        nativeEncryptionKey,
        nativeSigningKey,
        groupId,
        err);

    calloc.free(nativeGroupName);
    _bindings.SealdStringArray_Free(nativeMembers);
    _bindings.SealdStringArray_Free(nativeAdmins);
    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      final String createdGroupId = groupId.value.toDartString();
      calloc.free(groupId.value);
      calloc.free(groupId);
      calloc.free(err);
      return createdGroupId;
    }
  }

  /// Create a group and return the created group's ID.
  /// `admins` must also be members.
  /// `admins` must include yourself.
  ///
  /// [groupName] - A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
  /// [members] - The Seald IDs of the members to add to the group. Must include yourself.
  /// [admins] - The Seald IDs of the members to also add as group admins. Must include yourself.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  ///
  /// Returns the ID of the created group.
  Future<String> createGroupAsync(
      {String groupName = "",
      required List<String> members,
      required List<String> admins,
      SealdGeneratedPrivateKeys? privateKeys}) {
    return compute((Map<String, dynamic> args) async {
      privateKeys ??= await generatePrivateKeysAsync();
      return createGroup(
          groupName: args["groupName"],
          members: args["members"],
          admins: args["admins"],
          privateKeys: privateKeys);
    }, {"groupName": groupName, "members": members, "admins": admins});
  }

  /// Internal method.
  /// Returns a boolean that indicates whether or not this group should be renewed.
  ///
  /// [groupId] - The group for which to check if renewal is necessary.
  ///
  /// Returns true if the group expires in less than 6 months, false otherwise.
  bool _shouldRenewGroup(String groupId) {
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<Int> shouldRenew = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCodeShould = _bindings.SealdSdk_ShouldRenewGroup(
        _ptr.pointer(), nativeGroupId, shouldRenew, err);

    calloc.free(nativeGroupId);

    if (resultCodeShould != 0) {
      calloc.free(shouldRenew);
      throw SealdException._fromCPtr(err);
    } else {
      final bool res = shouldRenew.value != 0;
      calloc.free(shouldRenew);
      calloc.free(err);
      return res;
    }
  }

  /// Adds members to a group.
  /// Can only be done by a group administrator.
  /// Can also specify which of these newly added group members should also be admins.
  ///
  /// [groupId] - The group in which to add members.
  /// [membersToAdd] - The Seald IDs of the members to add to the group.
  /// [adminsToSet] - The Seald IDs of the newly added members to also set as group admins.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  void addGroupMembers(String groupId,
      {required List<String> membersToAdd,
      List<String> adminsToSet = const [],
      SealdGeneratedPrivateKeys? privateKeys}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    if (_shouldRenewGroup(groupId)) {
      renewGroupKey(groupId, privateKeys: privateKeys);
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<NativeSealdStringArray> nativeMembersToAdd =
        _sealdStringArrayFromList(membersToAdd);
    final Pointer<NativeSealdStringArray> nativeAdminsToSet =
        _sealdStringArrayFromList(adminsToSet);
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_AddGroupMembers(_ptr.pointer(),
        nativeGroupId, nativeMembersToAdd, nativeAdminsToSet, err);

    calloc.free(nativeGroupId);
    _bindings.SealdStringArray_Free(nativeMembersToAdd);
    _bindings.SealdStringArray_Free(nativeAdminsToSet);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Adds members to a group.
  /// Can only be done by a group administrator.
  /// Can also specify which of these newly added group members should also be admins.
  ///
  /// [groupId] - The group in which to add members.
  /// [membersToAdd] - The Seald IDs of the members to add to the group.
  /// [adminsToSet] - The Seald IDs of the newly added members to also set as group admins.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  Future<void> addGroupMembersAsync(String groupId,
      {required List<String> membersToAdd,
      List<String> adminsToSet = const [],
      SealdGeneratedPrivateKeys? privateKeys}) {
    return compute(
        (Map<String, dynamic> args) => addGroupMembers(args["groupId"],
            membersToAdd: args["membersToAdd"],
            adminsToSet: args["adminsToSet"],
            privateKeys: args["privateKeys"]),
        {
          "groupId": groupId,
          "membersToAdd": membersToAdd,
          "adminsToSet": adminsToSet,
          "privateKeys": privateKeys
        });
  }

  /// Removes members from the group.
  /// Can only be done by a group administrator.
  /// You should call [renewGroupKey] after this.
  ///
  /// [groupId] - The group from which to remove members.
  /// [membersToRemove] - The Seald IDs of the members to remove from the group.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  void removeGroupMembers(String groupId,
      {required List<String> membersToRemove,
      SealdGeneratedPrivateKeys? privateKeys}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    if (_shouldRenewGroup(groupId)) {
      renewGroupKey(groupId, privateKeys: privateKeys);
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<NativeSealdStringArray> nativeMembersToRemove =
        _sealdStringArrayFromList(membersToRemove);
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_RemoveGroupMembers(
        _ptr.pointer(), nativeGroupId, nativeMembersToRemove, err);

    calloc.free(nativeGroupId);
    _bindings.SealdStringArray_Free(nativeMembersToRemove);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Removes members from the group.
  /// Can only be done by a group administrator.
  /// You should call [renewGroupKey] after this.
  ///
  /// [groupId] - The group from which to remove members.
  /// [membersToRemove] - The Seald IDs of the members to remove from the group.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  Future<void> removeGroupMembersAsync(String groupId,
      {required List<String> membersToRemove,
      SealdGeneratedPrivateKeys? privateKeys}) {
    return compute(
        (Map<String, dynamic> args) => removeGroupMembers(args["groupId"],
            membersToRemove: args["membersToRemove"],
            privateKeys: args["privateKeys"]),
        {
          "groupId": groupId,
          "membersToRemove": membersToRemove,
          "privateKeys": privateKeys
        });
  }

  /// Renews the group's private key.
  /// Can only be done by a group administrator.
  /// Should be called after removing members from the group.
  ///
  /// [groupId] - The group for which to renew the private key.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  void renewGroupKey(String groupId, {SealdGeneratedPrivateKeys? privateKeys}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<Utf8> nativeEncryptionKey =
        privateKeys?.encryptionKey.toNativeUtf8() ?? nullptr;
    final Pointer<Utf8> nativeSigningKey =
        privateKeys?.signingKey.toNativeUtf8() ?? nullptr;
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_RenewGroupKey(_ptr.pointer(),
        nativeGroupId, nativeEncryptionKey, nativeSigningKey, err);

    calloc.free(nativeGroupId);
    calloc.free(nativeEncryptionKey);
    calloc.free(nativeSigningKey);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Renews the group's private key.
  /// Can only be done by a group administrator.
  /// Should be called after removing members from the group.
  ///
  /// [groupId] - The group for which to renew the private key.
  /// [privateKeys] - Optional. Pre-generated private keys, returned by a call to [SealdSdk.generatePrivateKeysAsync].
  Future<void> renewGroupKeyAsync(String groupId,
      {SealdGeneratedPrivateKeys? privateKeys}) {
    return compute((String groupId) async {
      privateKeys ??= await generatePrivateKeysAsync();
      return renewGroupKey(groupId, privateKeys: privateKeys);
    }, groupId);
  }

  /// Adds some existing group members to the group admins, and/or removes admin status from some existing group admins.
  /// Can only be done by a group administrator.
  ///
  /// [groupId] - The group for which to set admins.
  /// [addToAdmins] - The Seald IDs of existing group members to add as group admins.
  /// [removeFromAdmins] - The Seald IDs of existing group members to remove from group admins.
  void setGroupAdmins(String groupId,
      {List<String> addToAdmins = const [],
      List<String> removeFromAdmins = const []}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<NativeSealdStringArray> nativeAddToAdmins =
        _sealdStringArrayFromList(addToAdmins);
    final Pointer<NativeSealdStringArray> nativeRemoveFromAdmins =
        _sealdStringArrayFromList(removeFromAdmins);
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_SetGroupAdmins(_ptr.pointer(),
        nativeGroupId, nativeAddToAdmins, nativeRemoveFromAdmins, err);

    calloc.free(nativeGroupId);
    _bindings.SealdStringArray_Free(nativeAddToAdmins);
    _bindings.SealdStringArray_Free(nativeRemoveFromAdmins);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Adds some existing group members to the group admins, and/or removes admin status from some existing group admins.
  /// Can only be done by a group administrator.
  ///
  /// [groupId] - The group for which to set admins.
  /// [addToAdmins] - The Seald IDs of existing group members to add as group admins.
  /// [removeFromAdmins] - The Seald IDs of existing group members to remove from group admins.
  Future<void> setGroupAdminsAsync(String groupId,
      {List<String> addToAdmins = const [],
      List<String> removeFromAdmins = const []}) {
    return compute(
        (Map<String, dynamic> args) => setGroupAdmins(args["groupId"],
            removeFromAdmins: args["removeFromAdmins"]),
        {"groupId": groupId, "removeFromAdmins": removeFromAdmins});
  }

  /* SealdEncryptionSession */

  // SealdEncryptionSession is Finalizable, so I can't transfer it between isolates
  // This means we need to transfer a _TransferablePointer
  _TransferablePointer<NativeSealdEncryptionSession> _createEncryptionSession(
      List<SealdRecipientWithRights> recipients,
      {String? metadata,
      bool useCache = true}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<NativeSealdRecipientsWithRightsArray> nativeRecipients =
        SealdRecipientWithRights._toCArray(recipients);
    final Pointer<Utf8> nativeMetadata = metadata?.toNativeUtf8() ?? nullptr;
    final int useCacheInt = useCache ? 1 : 0;
    final Pointer<Pointer<NativeSealdEncryptionSession>> result =
        calloc<Pointer<NativeSealdEncryptionSession>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_CreateEncryptionSession(
        _ptr.pointer(),
        nativeRecipients,
        nativeMetadata,
        useCacheInt,
        result,
        err);

    _bindings.SealdRecipientsWithRightsArray_Free(nativeRecipients);
    calloc.free(nativeMetadata);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final _TransferablePointer<NativeSealdEncryptionSession> res =
          _TransferablePointer<NativeSealdEncryptionSession>(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Create an encryption session, and returns the associated SealdEncryptionSession instance,
  /// with which you can then encrypt/decrypt multiple messages.
  /// Warning: if you want to be able to retrieve the session later,
  /// you must put your own Seald ID in the [recipients] argument.
  ///
  /// [recipients] - The Seald IDs of users who should be able to retrieve this session.
  /// [metadata] - Arbitrary metadata string, not encrypted, for later reference. Max 1024 characters long.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// Returns the created SealdEncryptionSession instance.
  SealdEncryptionSession createEncryptionSession(
      List<SealdRecipientWithRights> recipients,
      {String? metadata,
      bool useCache = true}) {
    return SealdEncryptionSession._fromC(_createEncryptionSession(recipients,
            metadata: metadata, useCache: useCache)
        .pointer());
  }

  /// Create an encryption session, and returns the associated SealdEncryptionSession instance,
  /// with which you can then encrypt/decrypt multiple messages.
  /// Warning: if you want to be able to retrieve the session later,
  /// you must put your own Seald ID in the [recipients] argument.
  ///
  /// [recipients] - The Seald IDs of users who should be able to retrieve this session.
  /// [metadata] - Arbitrary metadata string, not encrypted, for later reference. Max 1024 characters long.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// Returns the created SealdEncryptionSession instance.
  Future<SealdEncryptionSession> createEncryptionSessionAsync(
      List<SealdRecipientWithRights> recipients,
      {String? metadata,
      bool useCache = true}) async {
    final _TransferablePointer<NativeSealdEncryptionSession> res =
        await compute(
            (Map<String, dynamic> args) => _createEncryptionSession(
                args["recipients"],
                metadata: args["metadata"],
                useCache: args["useCache"]),
            {
          "recipients": recipients,
          "metadata": metadata,
          "useCache": useCache
        });
    return SealdEncryptionSession._fromC(res.pointer());
  }

  // This intermediate function is required because, for the Async version, we cannot transfer an EncryptionSession between isolates
  _TransferablePointer<NativeSealdEncryptionSession> _retrieveEncryptionSession(
      {String? sessionId,
      String? message,
      String? filePath,
      Uint8List? fileBytes,
      bool useCache = true,
      bool lookupProxyKey = false,
      bool lookupGroupKey = true}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final int argCount = [message, filePath, fileBytes, sessionId]
        .where((element) => element != null)
        .length;
    if (argCount == 0) {
      throw ArgumentError(
          "One of sessionId, message, fileBytes, or filePath must be provided.");
    }
    if (argCount > 1) {
      throw ArgumentError(
          "Only one of sessionId, message, fileBytes, or filePath can be provided.");
    }

    final int useCacheInt = useCache ? 1 : 0;
    final int lookupProxyKeyInt = lookupProxyKey ? 1 : 0;
    final int lookupGroupKeyInt = lookupGroupKey ? 1 : 0;
    final Pointer<Pointer<NativeSealdEncryptionSession>> result =
        calloc<Pointer<NativeSealdEncryptionSession>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();
    int resultCode = 0;

    if (sessionId != null) {
      final Pointer<Utf8> nativeSessionId = sessionId.toNativeUtf8();
      resultCode = _bindings.SealdSdk_RetrieveEncryptionSession(
          _ptr.pointer(),
          nativeSessionId,
          useCacheInt,
          lookupProxyKeyInt,
          lookupGroupKeyInt,
          result,
          err);
      calloc.free(nativeSessionId);
    } else if (message != null) {
      final Pointer<Utf8> nativeMessage = message.toNativeUtf8();
      resultCode = _bindings.SealdSdk_RetrieveEncryptionSessionFromMessage(
          _ptr.pointer(),
          nativeMessage,
          useCacheInt,
          lookupProxyKeyInt,
          lookupGroupKeyInt,
          result,
          err);
      calloc.free(nativeMessage);
    } else if (filePath != null) {
      final Pointer<Utf8> nativeFilePath = filePath.toNativeUtf8();
      resultCode = _bindings.SealdSdk_RetrieveEncryptionSessionFromFile(
          _ptr.pointer(),
          nativeFilePath,
          useCacheInt,
          lookupProxyKeyInt,
          lookupGroupKeyInt,
          result,
          err);
      calloc.free(nativeFilePath);
    } else if (fileBytes != null) {
      // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
      final Pointer<Uint8> nativeFileBytes = calloc<Uint8>(fileBytes.length);
      final pointerList = nativeFileBytes.asTypedList(fileBytes.length);
      pointerList.setAll(0, fileBytes);
      resultCode = _bindings.SealdSdk_RetrieveEncryptionSessionFromBytes(
          _ptr.pointer(),
          nativeFileBytes,
          fileBytes.length,
          useCacheInt,
          lookupProxyKeyInt,
          lookupGroupKeyInt,
          result,
          err);
      calloc.free(nativeFileBytes);
    }

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final _TransferablePointer<NativeSealdEncryptionSession> res =
          _TransferablePointer<NativeSealdEncryptionSession>(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve an encryption session, and returns the associated
  /// SealdEncryptionSession instance, with which you can then encrypt/decrypt multiple messages.
  ///
  /// [sessionId] - The ID of the session to retrieve.
  /// [message] - Any message belonging to the session to retrieve.
  /// [filePath] - The path to an encrypted file belonging to the session to retrieve.
  /// [fileBytes] - The bytes of an encrypted file belonging to the session to retrieve.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// [lookupProxyKey] - Whether or not to try retrieving the session via a proxy.
  /// [lookupGroupKey] - Whether or not to try retrieving the session via a group.
  /// Returns the retrieved SealdEncryptionSession instance.
  SealdEncryptionSession retrieveEncryptionSession(
      {String? sessionId,
      String? message,
      String? filePath,
      Uint8List? fileBytes,
      bool useCache = true,
      bool lookupProxyKey = false,
      bool lookupGroupKey = true}) {
    return SealdEncryptionSession._fromC(_retrieveEncryptionSession(
            sessionId: sessionId,
            message: message,
            filePath: filePath,
            fileBytes: fileBytes,
            useCache: useCache,
            lookupProxyKey: lookupProxyKey,
            lookupGroupKey: lookupGroupKey)
        .pointer());
  }

  /// Retrieve an encryption session, and returns the associated
  /// SealdEncryptionSession instance, with which you can then encrypt/decrypt multiple messages.
  ///
  /// [sessionId] - The ID of the session to retrieve.
  /// [message] - Any message belonging to the session to retrieve.
  /// [filePath] - The path to an encrypted file belonging to the session to retrieve.
  /// [fileBytes] - The bytes of an encrypted file belonging to the session to retrieve.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// [lookupProxyKey] - Whether or not to try retrieving the session via a proxy.
  /// [lookupGroupKey] - Whether or not to try retrieving the session via a group.
  /// Returns the retrieved SealdEncryptionSession instance.
  Future<SealdEncryptionSession> retrieveEncryptionSessionAsync(
      {String? sessionId,
      String? message,
      String? filePath,
      Uint8List? fileBytes,
      bool useCache = true,
      bool lookupProxyKey = false,
      bool lookupGroupKey = true}) async {
    final _TransferablePointer<NativeSealdEncryptionSession> res =
        await compute(
            (Map<String, dynamic> args) => _retrieveEncryptionSession(
                fileBytes: args["fileBytes"],
                sessionId: args["sessionId"],
                message: args["message"],
                filePath: args["filePath"],
                useCache: args["useCache"],
                lookupProxyKey: args["lookupProxyKey"],
                lookupGroupKey: args["lookupGroupKey"]),
            {
          "sessionId": sessionId,
          "message": message,
          "filePath": filePath,
          "fileBytes": fileBytes,
          "useCache": useCache,
          "lookupProxyKey": lookupProxyKey,
          "lookupGroupKey": lookupGroupKey
        });
    return SealdEncryptionSession._fromC(res.pointer());
  }

  // This intermediate function is required because, for the Async version, we cannot transfer an EncryptionSession between isolates
  _TransferablePointer<NativeSealdEncryptionSession>
      _retrieveEncryptionSessionByTmr(
          String tmrJWT, String sessionId, Uint8List overEncryptionKey,
          {SealdTmrAccessesRetrievalFilters? tmrAccessesFilters,
          bool tryIfMultiple = true,
          bool useCache = true}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeTmrJWT = tmrJWT.toNativeUtf8();
    final Pointer<Utf8> nativeSessionId = sessionId.toNativeUtf8();
    final int useCacheInt = useCache ? 1 : 0;
    final int tryIfMultipleInt = tryIfMultiple ? 1 : 0;
    final Pointer<NativeSealdTmrAccessesRetrievalFilters> nativeFilters =
        tmrAccessesFilters?._toC() ?? nullptr;

    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeOverEncryptionKey =
        calloc<Uint8>(overEncryptionKey.length);
    final pointerListOverEncryptionKey =
        nativeOverEncryptionKey.asTypedList(overEncryptionKey.length);
    pointerListOverEncryptionKey.setAll(0, overEncryptionKey);

    final Pointer<Pointer<NativeSealdEncryptionSession>> result =
        calloc<Pointer<NativeSealdEncryptionSession>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_RetrieveEncryptionSessionByTmr(
        _ptr.pointer(),
        nativeTmrJWT,
        nativeSessionId,
        nativeOverEncryptionKey,
        overEncryptionKey.length,
        nativeFilters,
        tryIfMultipleInt,
        useCacheInt,
        result,
        err);

    calloc.free(nativeTmrJWT);
    calloc.free(nativeSessionId);
    calloc.free(nativeOverEncryptionKey);
    _bindings.SealdTmrAccessesRetrievalFilters_Free(nativeFilters);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final _TransferablePointer<NativeSealdEncryptionSession> res =
          _TransferablePointer<NativeSealdEncryptionSession>(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve an encryption session with a  TMR access JWT.
  ///
  /// [tmrJWT] - The TMR JWT.
  /// [sessionId] - The ID of the session to retrieve.
  /// [overEncryptionKey] - The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [tmrAccessesFilters] - Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
  /// [tryIfMultiple] - If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// Returns the retrieved SealdEncryptionSession instance.
  SealdEncryptionSession retrieveEncryptionSessionByTmr(
      String tmrJWT,
      String sessionId,
      Uint8List overEncryptionKey,
      SealdTmrAccessesRetrievalFilters tmrAccessesFilters,
      {bool tryIfMultiple = true,
      bool useCache = true}) {
    return SealdEncryptionSession._fromC(_retrieveEncryptionSessionByTmr(
            tmrJWT, sessionId, overEncryptionKey,
            tmrAccessesFilters: tmrAccessesFilters,
            tryIfMultiple: tryIfMultiple,
            useCache: useCache)
        .pointer());
  }

  /// Retrieve an encryption session with a  TMR access JWT.
  ///
  /// [tmrJWT] - The TMR JWT.
  /// [sessionId] - The ID of the session to retrieve.
  /// [overEncryptionKey] - The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [tmrAccessesFilters] - Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
  /// [tryIfMultiple] - If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// Returns the retrieved SealdEncryptionSession instance.
  Future<SealdEncryptionSession> retrieveEncryptionSessionByTmrAsync(
      String tmrJWT, String sessionId, Uint8List overEncryptionKey,
      {SealdTmrAccessesRetrievalFilters? tmrAccessesFilters,
      bool tryIfMultiple = true,
      bool useCache = true}) async {
    final _TransferablePointer<NativeSealdEncryptionSession> res =
        await compute(
            (Map<String, dynamic> args) => _retrieveEncryptionSessionByTmr(
                args["tmrJWT"], args["sessionId"], args["overEncryptionKey"],
                tmrAccessesFilters: args["tmrAccessesFilters"],
                tryIfMultiple: args["tryIfMultiple"],
                useCache: args["useCache"]),
            {
          "tmrJWT": tmrJWT,
          "sessionId": sessionId,
          "overEncryptionKey": overEncryptionKey,
          "tmrAccessesFilters": tmrAccessesFilters,
          "tryIfMultiple": tryIfMultiple,
          "useCache": useCache
        });
    return SealdEncryptionSession._fromC(res.pointer());
  }

  // This intermediate function is required because, for the Async version, we cannot transfer a List<EncryptionSession> between isolates
  _TransferablePointer<NativeSealdEncryptionSessionArray>
      _retrieveMultipleEncryptionSessions(List<String> sessionIds,
          {bool useCache = true,
          bool lookupProxyKey = false,
          bool lookupGroupKey = true}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<NativeSealdStringArray> nativeSessionIds =
        _sealdStringArrayFromList(sessionIds);
    final int useCacheInt = useCache ? 1 : 0;
    final int lookupProxyKeyInt = lookupProxyKey ? 1 : 0;
    final int lookupGroupKeyInt = lookupGroupKey ? 1 : 0;

    final Pointer<Pointer<NativeSealdEncryptionSessionArray>> result =
        calloc<Pointer<NativeSealdEncryptionSessionArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSdk_RetrieveMultipleEncryptionSessions(
            _ptr.pointer(),
            nativeSessionIds,
            useCacheInt,
            lookupProxyKeyInt,
            lookupGroupKeyInt,
            result,
            err);

    _bindings.SealdStringArray_Free(nativeSessionIds);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final _TransferablePointer<NativeSealdEncryptionSessionArray> res =
          _TransferablePointer<NativeSealdEncryptionSessionArray>(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve multiple encryption sessions with a List of sessionIds, and return a
  /// List of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
  /// The returned List of EncryptionSession instances is in the same order as the input List.
  ///
  /// [sessionIds] - The IDs of sessions to retrieve.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// [lookupProxyKey] - Whether or not to try retrieving the session via a proxy.
  /// [lookupGroupKey] - Whether or not to try retrieving the session via a group.
  /// Returns the List of retrieved SealdEncryptionSession instances.
  List<SealdEncryptionSession> retrieveMultipleEncryptionSessions(
      List<String> sessionIds,
      {bool useCache = true,
      bool lookupProxyKey = false,
      bool lookupGroupKey = true}) {
    return SealdEncryptionSession._fromCArray(
        _retrieveMultipleEncryptionSessions(sessionIds,
                useCache: useCache,
                lookupProxyKey: lookupProxyKey,
                lookupGroupKey: lookupGroupKey)
            .pointer());
  }

  /// Retrieve multiple encryption sessions with a List of sessionIds, and return a
  /// List of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
  /// The returned List of EncryptionSession instances is in the same order as the input List.
  ///
  /// [sessionIds] - The IDs of sessions to retrieve.
  /// [useCache] - Whether or not to use the cache (if enabled globally).
  /// [lookupProxyKey] - Whether or not to try retrieving the session via a proxy.
  /// [lookupGroupKey] - Whether or not to try retrieving the session via a group.
  /// Returns the List of retrieved SealdEncryptionSession instances.
  Future<List<SealdEncryptionSession>> retrieveMultipleEncryptionSessionsAsync(
      List<String> sessionIds,
      {bool useCache = true,
      bool lookupProxyKey = false,
      bool lookupGroupKey = true}) async {
    final _TransferablePointer<NativeSealdEncryptionSessionArray> res =
        await compute(
            (Map<String, dynamic> args) => _retrieveMultipleEncryptionSessions(
                args["sessionIds"],
                useCache: args["useCache"],
                lookupProxyKey: args["lookupProxyKey"],
                lookupGroupKey: args["lookupGroupKey"]),
            {
          "sessionIds": sessionIds,
          "useCache": useCache,
          "lookupProxyKey": lookupProxyKey,
          "lookupGroupKey": lookupGroupKey
        });
    return SealdEncryptionSession._fromCArray(res.pointer());
  }

  /* Connectors */

  /// Get all the info for the given connectors to look for, updates the local cache of connectors,
  /// and returns a list with the corresponding Seald IDs. Seald IDs are not de-duped and can appear for multiple connector values.
  /// If one of the connectors is not assigned to a Seald user, this will throw a SealdException with the details of the missing connector.
  ///
  /// [connectorTypeValues] - A List of SealdConnectorTypeValue instances.
  /// Returns a list of Seald IDs of the users corresponding to these connectors.
  List<String> getSealdIdsFromConnectors(
      List<SealdConnectorTypeValue> connectorTypeValues) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<NativeSealdConnectorTypeValueArray>
        nativeConnectorTypeValues =
        SealdConnectorTypeValue._toCArray(connectorTypeValues);
    final Pointer<Pointer<NativeSealdStringArray>> result =
        calloc<Pointer<NativeSealdStringArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_GetSealdIdsFromConnectors(
        _ptr.pointer(), nativeConnectorTypeValues, result, err);

    _bindings.SealdConnectorTypeValueArray_Free(nativeConnectorTypeValues);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final List<String> sealdIds = _listFromSealdStringArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return sealdIds;
    }
  }

  /// Get all the info for the given connectors to look for, updates the local cache of connectors,
  /// and returns a list with the corresponding Seald IDs. Seald IDs are not de-duped and can appear for multiple connector values.
  /// If one of the connectors is not assigned to a Seald user, this will throw a SealdException with the details of the missing connector.
  ///
  /// [connectorTypeValues] - A List of SealdConnectorTypeValue instances.
  /// Returns a list of Seald IDs of the users corresponding to these connectors.
  Future<List<String>> getSealdIdsFromConnectorsAsync(
      List<SealdConnectorTypeValue> connectorTypeValues) {
    return compute(getSealdIdsFromConnectors, connectorTypeValues);
  }

  /// List all connectors known locally for a given Seald ID.
  ///
  /// [sealdId] - The Seald ID for which to list connectors.
  /// Returns a SealdConnectorsArray instance.
  List<SealdConnector> getConnectorsFromSealdId(String sealdId) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeSealdId = sealdId.toNativeUtf8();
    final Pointer<Pointer<NativeSealdConnectorsArray>> result =
        calloc<Pointer<NativeSealdConnectorsArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_GetConnectorsFromSealdId(
        _ptr.pointer(), nativeSealdId, result, err);

    calloc.free(nativeSealdId);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final List<SealdConnector> res = SealdConnector._fromCArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// List all connectors known locally for a given Seald ID.
  ///
  /// [sealdId] - The Seald ID for which to list connectors.
  /// Returns a SealdConnectorsArray instance.
  Future<List<SealdConnector>> getConnectorsFromSealdIdAsync(String sealdId) {
    return compute(getConnectorsFromSealdId, sealdId);
  }

  /// Add a connector to the current identity.
  /// If no preValidationToken is given, the connector will need to be validated before use.
  ///
  /// [connectorType] - The type of the connector to add.
  /// [connectorValue] - The value of the connector to add.
  /// [preValidationToken] - Given by your server to authorize the adding of a connector.
  /// Returns the created SealdConnector instance.
  SealdConnector addConnector(String connectorType, String connectorValue,
      {SealdPreValidationToken? preValidationToken}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeConnectorType = connectorType.toNativeUtf8();
    final Pointer<Utf8> nativeConnectorValue = connectorValue.toNativeUtf8();
    final Pointer<NativeSealdPreValidationToken> nativePreValidationToken =
        preValidationToken?._toC() ?? nullptr;
    final Pointer<Pointer<NativeSealdConnector>> result =
        calloc<Pointer<NativeSealdConnector>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_AddConnector(
        _ptr.pointer(),
        nativeConnectorValue,
        nativeConnectorType,
        nativePreValidationToken,
        result,
        err);

    calloc.free(nativeConnectorType);
    calloc.free(nativeConnectorValue);
    _bindings.SealdPreValidationToken_Free(nativePreValidationToken);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdConnector connector = SealdConnector._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return connector;
    }
  }

  /// Add a connector to the current identity.
  /// If no preValidationToken is given, the connector will need to be validated before use.
  ///
  /// [connectorType] - The type of the connector to add.
  /// [connectorValue] - The value of the connector to add.
  /// [preValidationToken] - Given by your server to authorize the adding of a connector.
  /// Returns the created SealdConnector instance.
  Future<SealdConnector> addConnectorAsync(
      String connectorType, String connectorValue,
      {SealdPreValidationToken? preValidationToken}) {
    return compute(
        (Map<String, dynamic> args) => addConnector(
            args["connectorType"], args["connectorValue"],
            preValidationToken: args["preValidationToken"]),
        {
          "connectorType": connectorType,
          "connectorValue": connectorValue,
          "preValidationToken": preValidationToken
        });
  }

  /// Validate an added connector that was added without a preValidationToken.
  ///
  /// [connectorId] - The ID of the connector to validate.
  /// [challenge] - The challenge.
  /// Returns the validated SealdConnector instance.
  SealdConnector validateConnector(String connectorId, String challenge) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeConnectorId = connectorId.toNativeUtf8();
    final Pointer<Utf8> nativeChallenge = challenge.toNativeUtf8();
    final Pointer<Pointer<NativeSealdConnector>> result =
        calloc<Pointer<NativeSealdConnector>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_ValidateConnector(
        _ptr.pointer(), nativeConnectorId, nativeChallenge, result, err);

    calloc.free(nativeConnectorId);
    calloc.free(nativeChallenge);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdConnector c = SealdConnector._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return c;
    }
  }

  /// Validate an added connector that was added without a preValidationToken.
  ///
  /// [connectorId] - The ID of the connector to validate.
  /// [challenge] - The challenge.
  /// Returns the validated SealdConnector instance.
  Future<SealdConnector> validateConnectorAsync(
      String connectorId, String challenge) {
    return compute(
        (Map<String, dynamic> args) =>
            validateConnector(args["connectorId"], args["challenge"]),
        {"connectorId": connectorId, "challenge": challenge});
  }

  /// Remove a connector belonging to the current account.
  ///
  /// [connectorId] - The ID of the connector to remove.
  /// Returns the removed SealdConnector instance.
  SealdConnector removeConnector(String connectorId) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeConnectorId = connectorId.toNativeUtf8();
    final Pointer<Pointer<NativeSealdConnector>> result =
        calloc<Pointer<NativeSealdConnector>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_RemoveConnector(
        _ptr.pointer(), nativeConnectorId, result, err);

    calloc.free(nativeConnectorId);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdConnector c = SealdConnector._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return c;
    }
  }

  /// Remove a connector belonging to the current account.
  ///
  /// [connectorId] - The ID of the connector to remove.
  /// Returns the removed SealdConnector instance.
  Future<SealdConnector> removeConnectorAsync(String connectorId) {
    return compute(removeConnector, connectorId);
  }

  /// List connectors associated with the current account.
  ///
  /// Returns a list of SealdConnector instances.
  List<SealdConnector> listConnectors() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdConnectorsArray>> result =
        calloc<Pointer<NativeSealdConnectorsArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSdk_ListConnectors(_ptr.pointer(), result, err);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final List<SealdConnector> connectors =
          SealdConnector._fromCArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return connectors;
    }
  }

  /// List connectors associated with the current account.
  ///
  /// Returns a list of SealdConnector instances.
  Future listConnectorsAsync() {
    return compute((_) => listConnectors(), null);
  }

  /// Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
  ///
  /// [connectorId] - The ID of the connector to retrieve.
  /// Returns the retrieved SealdConnector instance.
  SealdConnector retrieveConnector(String connectorId) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeConnectorId = connectorId.toNativeUtf8();
    final Pointer<Pointer<NativeSealdConnector>> result =
        calloc<Pointer<NativeSealdConnector>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_RetrieveConnector(
        _ptr.pointer(), nativeConnectorId, result, err);

    calloc.free(nativeConnectorId);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdConnector c = SealdConnector._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return c;
    }
  }

  /// Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
  ///
  /// [connectorId] - The ID of the connector to retrieve.
  /// Returns the retrieved SealdConnector instance.
  Future<SealdConnector> retrieveConnectorAsync(String connectorId) {
    return compute(retrieveConnector, connectorId);
  }

  /* Reencrypt */

  /// List which of the devices of the current account are missing keys,
  /// so you can call [massReencrypt] for them.
  ///
  /// [forceLocalAccountUpdate] - Whether to update the local account. `true` to update, `false` to not update.
  /// Returns a list of SealdDeviceMissingKeys instances.
  List<SealdDeviceMissingKeys> devicesMissingKeys(
      {bool forceLocalAccountUpdate = false}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Pointer<NativeSealdDeviceMissingKeysArray>> result =
        calloc<Pointer<NativeSealdDeviceMissingKeysArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_DevicesMissingKeys(
        _ptr.pointer(), forceLocalAccountUpdate ? 1 : 0, result, err);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final List<SealdDeviceMissingKeys> missingKeys =
          SealdDeviceMissingKeys._fromCArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return missingKeys;
    }
  }

  /// List which of the devices of the current account are missing keys,
  /// so you can call [massReencrypt] for them.
  ///
  /// [forceLocalAccountUpdate] - Whether to update the local account. `true` to update, `false` to not update.
  /// Returns a list of SealdDeviceMissingKeys instances.
  Future<List<SealdDeviceMissingKeys>> devicesMissingKeysAsync(
      {bool forceLocalAccountUpdate = false}) {
    return compute(
        (bool forceLocalAccountUpdate) => devicesMissingKeys(
            forceLocalAccountUpdate: forceLocalAccountUpdate),
        forceLocalAccountUpdate);
  }

  /// Retrieve, re-encrypt, and add missing keys for a certain device.
  ///
  /// [deviceId] - The ID of the device for which to re-rencrypt.
  /// [retries] - Number of times to retry. Defaults to 3.
  /// [retrieveBatchSize] - Defaults to 1000.
  /// [waitBetweenRetries] - Time to wait between retries. Defaults to 3 seconds.
  /// [waitProvisioning] - Whether to wait for provisioning (new behaviour) or not. `true` to wait, `false` to not wait. Defaults to `true`.
  /// [waitProvisioningTime] - Time to wait if device is not provisioned on the server yet. The actual wait time will be increased on subsequent tries, by `waitProvisioningTimeStep`, up to `waitProvisioningTimeMax`. Defaults to 5 seconds.
  /// [waitProvisioningTimeMax] - Maximum time to wait if device is not provisioned on the server yet. Defaults to 10 seconds.
  /// [waitProvisioningTimeStep] - Amount to increase the time to wait if device is not provisioned on the server yet. Defaults to 1 second.
  /// [waitProvisioningRetries] - Maximum number of tries to check if the device is provisioned yet. Defaults to 100.
  /// [forceLocalAccountUpdate] - Whether to update the local account before trying the reencryption. `true` to update, `false` to not update. Defaults to `false`.
  /// Returns a SealdMassReencryptResponse instance, which will be populated with the number of re-encrypted keys, and the number of keys for which re-encryption failed.
  SealdMassReencryptResponse massReencrypt(String deviceId,
      {int retries = 3,
      int retrieveBatchSize = 1000,
      Duration waitBetweenRetries = const Duration(seconds: 3),
      bool waitProvisioning = true,
      Duration waitProvisioningTime = const Duration(seconds: 5),
      Duration waitProvisioningTimeMax = const Duration(seconds: 10),
      Duration waitProvisioningTimeStep = const Duration(seconds: 1),
      int waitProvisioningRetries = 100,
      bool forceLocalAccountUpdate = false}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeDeviceId = deviceId.toNativeUtf8();
    final Pointer<NativeSealdMassReencryptOptions> options =
        calloc<NativeSealdMassReencryptOptions>();
    options.ref
      ..Retries = retries
      ..RetrieveBatchSize = retrieveBatchSize
      ..WaitBetweenRetries = waitBetweenRetries.inMilliseconds
      ..WaitProvisioning = waitProvisioning ? 1 : 0
      ..WaitProvisioningTime = waitProvisioningTime.inMilliseconds
      ..WaitProvisioningTimeMax = waitProvisioningTimeMax.inMilliseconds
      ..WaitProvisioningTimeStep = waitProvisioningTimeStep.inMilliseconds
      ..WaitProvisioningRetries = waitProvisioningRetries
      ..ForceLocalAccountUpdate = forceLocalAccountUpdate ? 1 : 0;
    final Pointer<NativeSealdMassReencryptResponse> result =
        calloc<NativeSealdMassReencryptResponse>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_MassReencrypt(
        _ptr.pointer(), nativeDeviceId, options.ref, result, err);

    calloc.free(nativeDeviceId);
    calloc.free(options);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdMassReencryptResponse response =
          SealdMassReencryptResponse._fromC(result);
      calloc.free(err);
      return response;
    }
  }

  /// Retrieve, re-encrypt, and add missing keys for a certain device.
  ///
  /// [deviceId] - The ID of the device for which to re-rencrypt.
  /// [retries] - Number of times to retry. Defaults to 3.
  /// [retrieveBatchSize] - Defaults to 1000.
  /// [waitBetweenRetries] - Time to wait between retries. Defaults to 3 seconds.
  /// [waitProvisioning] - Whether to wait for provisioning (new behaviour) or not. `true` to wait, `false` to not wait. Defaults to `true`.
  /// [waitProvisioningTime] - Time to wait if device is not provisioned on the server yet. The actual wait time will be increased on subsequent tries, by `waitProvisioningTimeStep`, up to `waitProvisioningTimeMax`. Defaults to 5 seconds.
  /// [waitProvisioningTimeMax] - Maximum time to wait if device is not provisioned on the server yet. Defaults to 10 seconds.
  /// [waitProvisioningTimeStep] - Amount to increase the time to wait if device is not provisioned on the server yet. Defaults to 1 second.
  /// [waitProvisioningRetries] - Maximum number of tries to check if the device is provisioned yet. Defaults to 100.
  /// [forceLocalAccountUpdate] - Whether to update the local account before trying the reencryption. `true` to update, `false` to not update. Defaults to `false`.
  /// Returns a SealdMassReencryptResponse instance, which will be populated with the number of re-encrypted keys, and the number of keys for which re-encryption failed.
  Future<SealdMassReencryptResponse> massReencryptAsync(String deviceId,
      {int retries = 3,
      int retrieveBatchSize = 1000,
      Duration waitBetweenRetries = const Duration(seconds: 3),
      bool waitProvisioning = true,
      Duration waitProvisioningTime = const Duration(seconds: 5),
      Duration waitProvisioningTimeMax = const Duration(seconds: 10),
      Duration waitProvisioningTimeStep = const Duration(seconds: 1),
      int waitProvisioningRetries = 100,
      bool forceLocalAccountUpdate = false}) {
    return compute(
        (Map<String, dynamic> args) => massReencrypt(args["deviceId"],
            retries: args["retries"],
            retrieveBatchSize: args["retrieveBatchSize"],
            waitBetweenRetries: args["waitBetweenRetries"],
            waitProvisioning: args["waitProvisioning"],
            waitProvisioningTime: args["waitProvisioningTime"],
            waitProvisioningTimeMax: args["waitProvisioningTimeMax"],
            waitProvisioningTimeStep: args["waitProvisioningTimeStep"],
            waitProvisioningRetries: args["waitProvisioningRetries"],
            forceLocalAccountUpdate: args["forceLocalAccountUpdate"]),
        {
          "deviceId": deviceId,
          "retries": retries,
          "retrieveBatchSize": retrieveBatchSize,
          "waitBetweenRetries": waitBetweenRetries,
          "waitProvisioning": waitProvisioning,
          "waitProvisioningTime": waitProvisioningTime,
          "waitProvisioningTimeMax": waitProvisioningTimeMax,
          "waitProvisioningTimeStep": waitProvisioningTimeStep,
          "waitProvisioningRetries": waitProvisioningRetries,
          "forceLocalAccountUpdate": forceLocalAccountUpdate
        });
  }

  /// Get a user's sigchain transaction hash at index `position`.
  ///
  /// [userId] - The Seald ID of the concerned user.
  /// [position] - Get the hash at the given position. -1 to get the last. Default to -1.
  /// Returns a SealdGetSigchainResponse instance.
  SealdGetSigchainResponse getSigchainHash(String userId, {int position = -1}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Pointer<NativeSealdGetSigchainResponse>> result =
        calloc<Pointer<NativeSealdGetSigchainResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_GetSigchainHash(
        _ptr.pointer(), nativeUserId, position, result, err);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdGetSigchainResponse sigchainInfo =
          SealdGetSigchainResponse._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return sigchainInfo;
    }
  }

  /// Get a user's sigchain transaction hash at index `position`.
  ///
  /// [userId] - The Seald ID of the concerned user.
  /// [position] - Get the hash at the given position. -1 to get the last. Default to -1.
  /// Returns a SealdGetSigchainResponse instance.
  Future<SealdGetSigchainResponse> getSigchainHashAsync(String userId,
      {int position = -1}) {
    return compute(
        (Map<String, dynamic> args) =>
            getSigchainHash(args["userId"], position: args["position"]),
        {"userId": userId, "position": position});
  }

  /// Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
  ///
  /// [userId] - The Seald ID of the concerned user.
  /// [expectedHash] - The expected sigchain hash.
  /// [position] - Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
  /// Returns a SealdCheckSigchainResponse instance.
  SealdCheckSigchainResponse checkSigchainHash(
      String userId, String expectedHash,
      {int position = -1}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeUserId = userId.toNativeUtf8();
    final Pointer<Utf8> nativeExpectedHash = expectedHash.toNativeUtf8();
    final Pointer<Pointer<NativeSealdCheckSigchainResponse>> result =
        calloc<Pointer<NativeSealdCheckSigchainResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_CheckSigchainHash(_ptr.pointer(),
        nativeUserId, nativeExpectedHash, position, result, err);

    calloc.free(nativeUserId);
    calloc.free(nativeExpectedHash);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdCheckSigchainResponse sigchainInfo =
          SealdCheckSigchainResponse._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return sigchainInfo;
    }
  }

  /// Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
  ///
  /// [userId] - The Seald ID of the concerned user.
  /// [expectedHash] - The expected sigchain hash.
  /// [position] - Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
  /// Returns a SealdCheckSigchainResponse instance.
  Future<SealdCheckSigchainResponse> checkSigchainHashAsync(
      String userId, String expectedHash,
      {int position = -1}) {
    return compute(
        (Map<String, dynamic> args) => checkSigchainHash(
            args["userId"], args["expectedHash"],
            position: args["position"]),
        {"userId": userId, "expectedHash": expectedHash, "position": position});
  }

  /// Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
  /// All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
  ///
  /// [tmrJWT] - The TMR JWT.
  /// [overEncryptionKey] - The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [conversionFilters] - Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
  /// [deleteOnConvert] - Whether or not to delete the TMR access after conversion.
  /// Returns the retrieved SealdConvertTmrAccessesResult instance.
  SealdConvertTmrAccessesResult convertTmrAccesses(
      String tmrJWT, Uint8List overEncryptionKey,
      {SealdTmrAccessesConvertFilters? conversionFilters,
      bool deleteOnConvert = true}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeTmrJWT = tmrJWT.toNativeUtf8();
    final int deleteOnConvertInt = deleteOnConvert ? 1 : 0;
    final Pointer<NativeSealdTmrAccessesConvertFilters> nativeFilters =
        conversionFilters?._toC() ?? nullptr;
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeOverEncryptionKey =
        calloc<Uint8>(overEncryptionKey.length);
    final pointerListOverEncryptionKey =
        nativeOverEncryptionKey.asTypedList(overEncryptionKey.length);
    pointerListOverEncryptionKey.setAll(0, overEncryptionKey);

    final Pointer<Pointer<NativeSealdConvertTmrAccessesResult>> result =
        calloc<Pointer<NativeSealdConvertTmrAccessesResult>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_ConvertTmrAccesses(
        _ptr.pointer(),
        nativeTmrJWT,
        nativeOverEncryptionKey,
        overEncryptionKey.length,
        nativeFilters,
        deleteOnConvertInt,
        result,
        err);

    calloc.free(nativeTmrJWT);
    calloc.free(nativeOverEncryptionKey);
    _bindings.SealdTmrAccessesConvertFilters_Free(nativeFilters);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdConvertTmrAccessesResult conversionResult =
          SealdConvertTmrAccessesResult._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return conversionResult;
    }
  }

  /// Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
  /// All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
  ///
  /// [tmrJWT] - The TMR JWT.
  /// [overEncryptionKey] - The TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [conversionFilters] - Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
  /// [deleteOnConvert] - Whether or not to delete the TMR access after conversion.
  /// Returns the retrieved SealdConvertTmrAccessesResult instance.
  Future<SealdConvertTmrAccessesResult> convertTmrAccessesAsync(
      String tmrJWT, Uint8List overEncryptionKey,
      {SealdTmrAccessesConvertFilters? conversionFilters,
      bool deleteOnConvert = true}) {
    return compute(
        (Map<String, dynamic> args) => convertTmrAccesses(
            args["tmrJWT"], args["overEncryptionKey"],
            conversionFilters: args["conversionFilters"],
            deleteOnConvert: args["deleteOnConvert"]),
        {
          "tmrJWT": tmrJWT,
          "overEncryptionKey": overEncryptionKey,
          "conversionFilters": conversionFilters,
          "deleteOnConvert": deleteOnConvert
        });
  }

  /// Create a group TMR temporary key, and returns the created SealdGroupTMRTemporaryKey instance.
  ///
  /// [groupId] The Id of the group for which to create a TMR key.
  /// [authFactorType] The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] The value of authentication factor.
  /// [rawOverEncryptionKey] The raw encryption key to use. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [isAdmin] Should this TMR temporary key give the group admin status.
  /// Returns a SealdGroupTMRTemporaryKey instance.
  SealdGroupTMRTemporaryKey createGroupTMRTemporaryKey(
      String groupId,
      String authFactorType,
      String authFactorValue,
      Uint8List rawOverEncryptionKey,
      {bool isAdmin = false}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorType = authFactorType.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorValue = authFactorValue.toNativeUtf8();
    final int isAdminInt = isAdmin ? 1 : 0;
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawOverEncryptionKey =
        calloc<Uint8>(rawOverEncryptionKey.length);
    final pointerListRawOverEncryptionKey =
        nativeRawOverEncryptionKey.asTypedList(rawOverEncryptionKey.length);
    pointerListRawOverEncryptionKey.setAll(0, rawOverEncryptionKey);

    final Pointer<Pointer<NativeSealdGroupTMRTemporaryKey>> result =
        calloc<Pointer<NativeSealdGroupTMRTemporaryKey>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_CreateGroupTMRTemporaryKey(
        _ptr.pointer(),
        nativeGroupId,
        nativeAuthFactorType,
        nativeAuthFactorValue,
        isAdminInt,
        nativeRawOverEncryptionKey,
        rawOverEncryptionKey.length,
        result,
        err);

    calloc.free(nativeGroupId);
    calloc.free(nativeAuthFactorType);
    calloc.free(nativeAuthFactorValue);
    calloc.free(nativeRawOverEncryptionKey);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdGroupTMRTemporaryKey gTMRtempKey =
          SealdGroupTMRTemporaryKey._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return gTMRtempKey;
    }
  }

  /// Create a group TMR temporary key, and returns the created SealdGroupTMRTemporaryKey instance.
  ///
  /// [groupId] The Id of the group for which to create a TMR key.
  /// [authFactorType] The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] The value of authentication factor.
  /// [rawOverEncryptionKey] The raw encryption key to use. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [isAdmin] Should this TMR temporary key give the group admin status.
  /// Returns a SealdGroupTMRTemporaryKey instance.
  Future<SealdGroupTMRTemporaryKey> createGroupTMRTemporaryKeyAsync(
      String groupId,
      String authFactorType,
      String authFactorValue,
      Uint8List rawOverEncryptionKey,
      {bool isAdmin = false}) {
    return compute(
        (Map<String, dynamic> args) => createGroupTMRTemporaryKey(
            args["groupId"],
            args["authFactorType"],
            args["authFactorValue"],
            args["rawOverEncryptionKey"],
            isAdmin: args["isAdmin"]),
        {
          "groupId": groupId,
          "authFactorType": authFactorType,
          "authFactorValue": authFactorValue,
          "rawOverEncryptionKey": rawOverEncryptionKey,
          "isAdmin": isAdmin
        });
  }

  /// List group TMR temporary keys.
  ///
  /// [groupId] The Id of the group for which to list TMR keys.
  /// [page] Page number to fetch.
  /// [all] Should list all pages after `page`.
  /// Returns a SealdListedGroupTMRTemporaryKey instance holding the found temporary keys.
  SealdListedGroupTMRTemporaryKey listGroupTMRTemporaryKeys(String groupId,
      {int page = 1, bool all = false}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final int allInt = all ? 1 : 0;

    final Pointer<Int> nbPageFound = calloc<Int>();
    final Pointer<Pointer<NativeSealdGroupTMRTemporaryKeysArray>> result =
        calloc<Pointer<NativeSealdGroupTMRTemporaryKeysArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_ListGroupTMRTemporaryKeys(
        _ptr.pointer(), nativeGroupId, page, allInt, nbPageFound, result, err);

    calloc.free(nativeGroupId);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdListedGroupTMRTemporaryKey gTMRtempKeys =
          SealdListedGroupTMRTemporaryKey._fromC(result.value, nbPageFound);
      calloc.free(result);
      calloc.free(nbPageFound);
      calloc.free(err);
      return gTMRtempKeys;
    }
  }

  /// List group TMR temporary keys.
  ///
  /// [groupId] The Id of the group for which to list TMR keys.
  /// [page] Page number to fetch.
  /// [all] Should list all pages after `page`.
  /// Returns a SealdListedGroupTMRTemporaryKey instance holding the found temporary keys.
  Future<SealdListedGroupTMRTemporaryKey> listGroupTMRTemporaryKeysAsync(
      String groupId,
      {int page = 1,
      bool all = false}) {
    return compute(
        (Map<String, dynamic> args) => listGroupTMRTemporaryKeys(
            args["groupId"],
            page: args["page"],
            all: args["all"]),
        {"groupId": groupId, "page": page, "all": all});
  }

  /// Search group TMR temporary keys that can be used with the TMR JWT.
  ///
  /// [tmrJWT] TMR JWT to use.
  /// [opts] Option to filter the search results.
  /// Returns a SealdListedGroupTMRTemporaryKey instance holding the found temporary keys.
  SealdListedGroupTMRTemporaryKey searchGroupTMRTemporaryKeys(String tmrJWT,
      {SealdSearchGroupTMRTemporaryKeysOpts? opts}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeTmrJWT = tmrJWT.toNativeUtf8();
    final Pointer<NativeSealdSearchGroupTMRTemporaryKeysOpts> nativeOpts =
        opts?._toC() ?? nullptr;

    final Pointer<Int> nbPageFound = calloc<Int>();
    final Pointer<Pointer<NativeSealdGroupTMRTemporaryKeysArray>> result =
        calloc<Pointer<NativeSealdGroupTMRTemporaryKeysArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_SearchGroupTMRTemporaryKeys(
        _ptr.pointer(), nativeTmrJWT, nativeOpts, nbPageFound, result, err);

    calloc.free(nativeTmrJWT);
    _bindings.SealdSearchGroupTMRTemporaryKeysOpts_Free(nativeOpts);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdListedGroupTMRTemporaryKey gTMRtempKeys =
          SealdListedGroupTMRTemporaryKey._fromC(result.value, nbPageFound);
      calloc.free(result);
      calloc.free(nbPageFound);
      calloc.free(err);
      return gTMRtempKeys;
    }
  }

  /// Search group TMR temporary keys that can be used with the TMR JWT.
  ///
  /// [tmrJWT] TMR JWT to use.
  /// [opts] Option to filter the search results.
  /// Returns a SealdListedGroupTMRTemporaryKey instance holding the found temporary keys.
  Future<SealdListedGroupTMRTemporaryKey> searchGroupTMRTemporaryKeysAsync(
      String tmrJWT,
      {SealdSearchGroupTMRTemporaryKeysOpts? opts}) {
    return compute(
        (Map<String, dynamic> args) =>
            searchGroupTMRTemporaryKeys(args["tmrJWT"], opts: args["opts"]),
        {"tmrJWT": tmrJWT, "opts": opts});
  }

  /// Convert a group TMR temporary key to become a group member.
  ///
  /// [groupId] The Id of the group for which to convert a TMR key.
  /// [temporaryKeyId] The Id of the temporary key to convert.
  /// [tmrJWT] TMR JWT to use.
  /// [rawOverEncryptionKey] The raw encryption key to use. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [deleteOnConvert] Should the key be deleted after conversion.
  void convertGroupTMRTemporaryKey(String groupId, String temporaryKeyId,
      String tmrJWT, Uint8List rawOverEncryptionKey,
      {bool deleteOnConvert = false}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<Utf8> nativeTemporaryKeyId = temporaryKeyId.toNativeUtf8();
    final Pointer<Utf8> nativeTmrJWT = tmrJWT.toNativeUtf8();
    final int deleteOnConvertInt = deleteOnConvert ? 1 : 0;
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawOverEncryptionKey =
        calloc<Uint8>(rawOverEncryptionKey.length);
    final pointerListRawOverEncryptionKey =
        nativeRawOverEncryptionKey.asTypedList(rawOverEncryptionKey.length);
    pointerListRawOverEncryptionKey.setAll(0, rawOverEncryptionKey);

    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_ConvertGroupTMRTemporaryKey(
        _ptr.pointer(),
        nativeGroupId,
        nativeTemporaryKeyId,
        nativeTmrJWT,
        nativeRawOverEncryptionKey,
        rawOverEncryptionKey.length,
        deleteOnConvertInt,
        err);

    calloc.free(nativeGroupId);
    calloc.free(nativeTemporaryKeyId);
    calloc.free(nativeTmrJWT);
    calloc.free(nativeRawOverEncryptionKey);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Convert a group TMR temporary key to become a group member.
  ///
  /// [groupId] The Id of the group for which to convert a TMR key.
  /// [temporaryKeyId] The Id of the temporary key to convert.
  /// [tmrJWT] TMR JWT to use.
  /// [rawOverEncryptionKey] The raw encryption key to use. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [deleteOnConvert] Should the temporary key be deleted after conversion.
  Future<void> convertGroupTMRTemporaryKeyAsync(String groupId,
      String temporaryKeyId, String tmrJWT, Uint8List rawOverEncryptionKey,
      {bool deleteOnConvert = false}) {
    return compute(
        (Map<String, dynamic> args) => convertGroupTMRTemporaryKey(
            args["groupId"],
            args["temporaryKeyId"],
            args["tmrJWT"],
            args["rawOverEncryptionKey"],
            deleteOnConvert: args["deleteOnConvert"]),
        {
          "groupId": groupId,
          "temporaryKeyId": temporaryKeyId,
          "tmrJWT": tmrJWT,
          "rawOverEncryptionKey": rawOverEncryptionKey,
          "deleteOnConvert": deleteOnConvert
        });
  }

  /// Delete a group TMR temporary key.
  ///
  /// [groupId] The Id of the group for which to delete a TMR key.
  /// [temporaryKeyId] The Id of the temporary key to delete.
  void deleteGroupTMRTemporaryKey(String groupId, String temporaryKeyId) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeGroupId = groupId.toNativeUtf8();
    final Pointer<Utf8> nativeTemporaryKeyId = temporaryKeyId.toNativeUtf8();

    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSdk_DeleteGroupTMRTemporaryKey(
        _ptr.pointer(), nativeGroupId, nativeTemporaryKeyId, err);

    calloc.free(nativeGroupId);
    calloc.free(nativeTemporaryKeyId);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Delete a group TMR temporary key.
  ///
  /// [groupId] The Id of the group for which to delete a TMR key.
  /// [temporaryKeyId] The Id of the temporary key to delete.
  Future<void> deleteGroupTMRTemporaryKeyAsync(
      String groupId, String temporaryKeyId) {
    return compute(
        (Map<String, dynamic> args) =>
            deleteGroupTMRTemporaryKey(args["groupId"], args["temporaryKeyId"]),
        {"groupId": groupId, "temporaryKeyId": temporaryKeyId});
  }
}
