part of 'seald_sdk.dart';

/// SealdSsksTMRPluginSaveIdentityResponse is returned by [SealdSsksTMRPlugin.saveIdentity] when an identity has been successfully saved.
///
/// {@category SealdSsksTMRPlugin}
class SealdSsksTMRPluginSaveIdentityResponse {
  /// The SSKS ID of the stored identity, which can be used by your backend to manage it.
  final String ssksId;

  ///  If a challenge was passed, an authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
  final String? authenticatedSessionId;

  SealdSsksTMRPluginSaveIdentityResponse._fromC(
      Pointer<NativeSealdSsksTMRPluginSaveIdentityResponse> r)
      : ssksId = r.ref.SsksId.toDartString(),
        authenticatedSessionId = r.ref.AuthenticatedSessionId.address != 0
            ? r.ref.AuthenticatedSessionId.toDartString()
            : null {
    // Cleanup what we don't need anymore
    _bindings.SealdSsksTMRPluginSaveIdentityResponse_Free(r);
  }
}

/// SealdSsksTMRPluginRetrieveIdentityResponse holds a retrieved identity.
///
/// {@category SealdSsksTMRPlugin}
class SealdSsksTMRPluginRetrieveIdentityResponse {
  /// If the boolean shouldRenewKey is set to true, the account MUST renew its private key using [SealdSdk.renewKeys]
  final bool shouldRenewKey;

  /// The retrieved identity. It can be used with [SealdSdk.importIdentity].
  final Uint8List identity;

  /// An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
  final String authenticatedSessionId;

  SealdSsksTMRPluginRetrieveIdentityResponse._fromC(
      Pointer<NativeSealdSsksTMRPluginRetrieveIdentityResponse> r)
      : shouldRenewKey = r.ref.ShouldRenewKey != 0,
        // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
        identity =
            Uint8List.fromList(r.ref.Identity.asTypedList(r.ref.IdentityLen)),
        authenticatedSessionId = r.ref.AuthenticatedSessionId.toDartString() {
    // Cleanup what we don't need anymore
    _bindings.SealdSsksTMRPluginRetrieveIdentityResponse_Free(r);
  }
}

/// SealdSsksTMRPluginGetFactorTokenResponse holds a retrieved tmr JWT.
///
/// {@category SealdSsksTMRPlugin}
class SealdSsksTMRPluginGetFactorTokenResponse {
  /// The retrieved token. It can be used with [SealdSdk.retrieveEncryptionSessionByTmr] and [SealdSdk.convertTmrAccesses]
  final String token;

  /// An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
  final String authenticatedSessionId;

  SealdSsksTMRPluginGetFactorTokenResponse._fromC(
      Pointer<NativeSealdSsksTMRPluginGetFactorTokenResponse> r)
      : token = r.ref.Token.toDartString(),
        authenticatedSessionId = r.ref.AuthenticatedSessionId.toDartString() {
    // Cleanup what we don't need anymore
    _bindings.SealdSsksTMRPluginGetFactorTokenResponse_Free(r);
  }
}

/// The SealdSSKSTmrPlugin class allows to use the SSKS key storage service to store Seald identities
/// easily and securely, encrypted by a key stored on your back-end server.
///
/// {@category SealdSsksTMRPlugin}
class SealdSsksTMRPlugin implements Finalizable {
  late final _TransferablePointer<NativeSealdSsksTMRPlugin> _ptr;

  static final _finalizer = NativeFinalizer(_bindings
      .addresses.SealdSsksTMRPlugin_Free as Pointer<NativeFinalizerFunction>);

  // This is used to re-create the SealdSsksTMRPlugin from inside an isolate WITHOUT the finalizer, to avoid double-frees
  SealdSsksTMRPlugin._(this._ptr);

  /// Initialize an instance of Seald SSKS TMR plugin.
  ///
  /// [ssksURL] - The URL of the SSKS Identity Key Storage to which it should connect.
  /// [appId] - The ID given by the Seald server to your app. This value is given on your Seald dashboard.
  /// [logLevel] - The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. Defaults to 0.
  /// [logNoColor] - Whether to disable colors in the log output. `true` to disable colors, `false` to enable colors. Defaults to false.
  /// [instanceName] - An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. Defaults to an empty string.
  SealdSsksTMRPlugin({
    required String ssksURL,
    required String appId,
    int logLevel = 0,
    bool logNoColor = false,
    String instanceName = "",
  }) {
    final Pointer<NativeSealdSsksTMRPluginInitializeOptions> initOpts =
        calloc<NativeSealdSsksTMRPluginInitializeOptions>();
    final String platform = "c-flutter-${Platform.operatingSystem}";
    initOpts.ref
      ..SsksURL = ssksURL.toNativeUtf8()
      ..AppId = appId.toNativeUtf8()
      ..LogLevel = logLevel
      ..LogNoColor = logNoColor ? 1 : 0
      ..InstanceName = instanceName.toNativeUtf8()
      ..Platform = platform.toNativeUtf8();

    final Pointer<Pointer<NativeSealdSsksTMRPlugin>> result =
        calloc<Pointer<NativeSealdSsksTMRPlugin>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdSsksTMRPlugin_Initialize(initOpts, result, err);

    calloc.free(initOpts.ref.SsksURL);
    calloc.free(initOpts.ref.AppId);
    calloc.free(initOpts.ref.InstanceName);
    calloc.free(initOpts.ref.Platform);
    calloc.free(initOpts);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      _ptr = _TransferablePointer<NativeSealdSsksTMRPlugin>(result.value);
      _finalizer.attach(this, _ptr.pointer() as Pointer<Void>);
      calloc.free(result);
      calloc.free(err);
    }
  }

  /// Save the Seald account to SSKS.
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [rawTMRSymKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [identity] - The identity to save.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method.
  ///
  /// Returns a [SealdSsksTMRPluginSaveIdentityResponse] containing the SSKS ID of the stored identity.
  SealdSsksTMRPluginSaveIdentityResponse saveIdentity(
      String sessionId,
      String authFactorType,
      String authFactorValue,
      Uint8List rawTMRSymKey,
      Uint8List identity,
      {String? challenge}) {
    final Pointer<Utf8> nativeSessionId = sessionId.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorType = authFactorType.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorValue = authFactorValue.toNativeUtf8();
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawTMRSymKey =
        calloc<Uint8>(rawTMRSymKey.length);
    final pointerListRawTMRSymKey =
        nativeRawTMRSymKey.asTypedList(rawTMRSymKey.length);
    pointerListRawTMRSymKey.setAll(0, rawTMRSymKey);
    final Pointer<Uint8> nativeIdentity = calloc<Uint8>(identity.length);
    final pointerListIdentity = nativeIdentity.asTypedList(identity.length);
    pointerListIdentity.setAll(0, identity);
    final Pointer<Utf8> nativeChallenge = challenge?.toNativeUtf8() ?? nullptr;

    final Pointer<Pointer<NativeSealdSsksTMRPluginSaveIdentityResponse>>
        result =
        calloc<Pointer<NativeSealdSsksTMRPluginSaveIdentityResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSsksTMRPlugin_SaveIdentity(
        _ptr.pointer(),
        nativeSessionId,
        nativeAuthFactorType,
        nativeAuthFactorValue,
        nativeRawTMRSymKey,
        rawTMRSymKey.length,
        nativeIdentity,
        identity.length,
        nativeChallenge,
        result,
        err);

    calloc.free(nativeSessionId);
    calloc.free(nativeAuthFactorType);
    calloc.free(nativeAuthFactorValue);
    calloc.free(nativeChallenge);
    calloc.free(nativeRawTMRSymKey);
    calloc.free(nativeIdentity);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdSsksTMRPluginSaveIdentityResponse res =
          SealdSsksTMRPluginSaveIdentityResponse._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Save the Seald account to SSKS.
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [rawTMRSymKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [identity] - The identity to save.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method.
  ///
  /// Returns a [SealdSsksTMRPluginSaveIdentityResponse] containing the SSKS ID of the stored identity.
  Future<SealdSsksTMRPluginSaveIdentityResponse> saveIdentityAsync(
      String sessionId,
      String authFactorType,
      String authFactorValue,
      Uint8List rawTMRSymKey,
      Uint8List identity,
      {String? challenge}) {
    final _TransferablePointer<NativeSealdSsksTMRPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksTMRPlugin._(tPtr).saveIdentity(
              args["sessionId"],
              args["authFactorType"],
              args["authFactorValue"],
              args["rawTMRSymKey"],
              args["identity"],
              challenge: args["challenge"],
            ),
        {
          "sessionId": sessionId,
          "authFactorType": authFactorType,
          "authFactorValue": authFactorValue,
          "rawTMRSymKey": rawTMRSymKey,
          "identity": identity,
          "challenge": challenge
        });
  }

  /// Retrieve the Seald account previously saved with [saveIdentity].
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [rawTMRSymKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method.
  ///
  /// Returns a [SealdSsksTMRPluginRetrieveIdentityResponse] containing the retrieved identity.
  SealdSsksTMRPluginRetrieveIdentityResponse retrieveIdentity(String sessionId,
      String authFactorType, String authFactorValue, Uint8List rawTMRSymKey,
      {String? challenge}) {
    final Pointer<Utf8> nativeSessionId = sessionId.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorType = authFactorType.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorValue = authFactorValue.toNativeUtf8();
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeRawTMRSymKey =
        calloc<Uint8>(rawTMRSymKey.length);
    final pointerListRawTMRSymKey =
        nativeRawTMRSymKey.asTypedList(rawTMRSymKey.length);
    pointerListRawTMRSymKey.setAll(0, rawTMRSymKey);
    final Pointer<Utf8> nativeChallenge = challenge?.toNativeUtf8() ?? nullptr;

    final Pointer<Pointer<NativeSealdSsksTMRPluginRetrieveIdentityResponse>>
        result =
        calloc<Pointer<NativeSealdSsksTMRPluginRetrieveIdentityResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSsksTMRPlugin_RetrieveIdentity(
        _ptr.pointer(),
        nativeSessionId,
        nativeAuthFactorType,
        nativeAuthFactorValue,
        nativeRawTMRSymKey,
        rawTMRSymKey.length,
        nativeChallenge,
        result,
        err);

    calloc.free(nativeSessionId);
    calloc.free(nativeAuthFactorType);
    calloc.free(nativeAuthFactorValue);
    calloc.free(nativeChallenge);
    calloc.free(nativeRawTMRSymKey);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdSsksTMRPluginRetrieveIdentityResponse res =
          SealdSsksTMRPluginRetrieveIdentityResponse._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve the Seald account previously saved with [saveIdentity].
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [rawTMRSymKey] - The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method.
  ///
  /// Returns a [SealdSsksTMRPluginRetrieveIdentityResponse] containing the retrieved identity.
  Future<SealdSsksTMRPluginRetrieveIdentityResponse> retrieveIdentityAsync(
      String sessionId,
      String authFactorType,
      String authFactorValue,
      Uint8List rawTMRSymKey,
      {String? challenge}) {
    final _TransferablePointer<NativeSealdSsksTMRPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksTMRPlugin._(tPtr)
            .retrieveIdentity(args["sessionId"], args["authFactorType"],
                args["authFactorValue"], args["rawTMRSymKey"],
                challenge: args["challenge"]),
        {
          "sessionId": sessionId,
          "authFactorType": authFactorType,
          "authFactorValue": authFactorValue,
          "rawTMRSymKey": rawTMRSymKey,
          "challenge": challenge
        });
  }

  /// Retrieve the TMR JWT associated with an authentication factor.
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method if any.
  ///
  /// Returns a [SealdSsksTMRPluginGetFactorTokenResponse] containing the retrieved token.
  SealdSsksTMRPluginGetFactorTokenResponse getAuthFactorToken(
      String sessionId, String authFactorType, String authFactorValue,
      {String? challenge}) {
    final Pointer<Utf8> nativeSessionId = sessionId.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorType = authFactorType.toNativeUtf8();
    final Pointer<Utf8> nativeAuthFactorValue = authFactorValue.toNativeUtf8();
    final Pointer<Utf8> nativeChallenge = challenge?.toNativeUtf8() ?? nullptr;

    final Pointer<Pointer<NativeSealdSsksTMRPluginGetFactorTokenResponse>>
        result =
        calloc<Pointer<NativeSealdSsksTMRPluginGetFactorTokenResponse>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdSsksTMRPlugin_GetFactorToken(
        _ptr.pointer(),
        nativeSessionId,
        nativeAuthFactorType,
        nativeAuthFactorValue,
        nativeChallenge,
        result,
        err);

    calloc.free(nativeSessionId);
    calloc.free(nativeAuthFactorType);
    calloc.free(nativeAuthFactorValue);
    calloc.free(nativeChallenge);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdSsksTMRPluginGetFactorTokenResponse res =
          SealdSsksTMRPluginGetFactorTokenResponse._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Retrieve the TMR JWT associated with an authentication factor.
  ///
  /// [sessionId] - The user's session ID.
  /// [authFactorType] - The type of authentication factor. Can be "EM" or "SMS".
  /// [authFactorValue] - The value of authentication factor.
  /// [challenge] - The challenge sent by SSKS to the user's authentication method if any.
  ///
  /// Returns a [SealdSsksTMRPluginGetFactorTokenResponse] containing the retrieved token.
  Future<SealdSsksTMRPluginGetFactorTokenResponse> getAuthFactorTokenAsync(
      String sessionId, String authFactorType, String authFactorValue,
      {String? challenge}) {
    final _TransferablePointer<NativeSealdSsksTMRPlugin> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdSsksTMRPlugin._(tPtr)
            .getAuthFactorToken(args["sessionId"], args["authFactorType"],
                args["authFactorValue"],
                challenge: args["challenge"]),
        {
          "sessionId": sessionId,
          "authFactorType": authFactorType,
          "authFactorValue": authFactorValue,
          "challenge": challenge
        });
  }
}
