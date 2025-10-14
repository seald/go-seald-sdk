part of 'seald_sdk.dart';

/// This is the main class for the Seald anonymous SDK. It represents an instance of the Seald anonymous SDK.
/// This must be instantiated from the root isolate, or you must pass the `rootIsolateToken` argument.
///
/// {@category SealdAnonymousSdk}
class SealdAnonymousSdk {
  late final _TransferablePointer<NativeSealdAnonymousSdk> _ptr;
  bool _closed = false;

  /// Creates a new instance of SealdAnonymousSdk.
  ///
  /// [apiURL] - The Seald server for this instance to use. This value is given on your Seald dashboard.
  /// [appId] - The ID given by the Seald server to your app. This value is given on your Seald dashboard.
  /// [maxParallelRequests] - Maximum number of concurrent network requests allowed for this instance. Defaults to 10. Set a negative value to disable the limit.
  /// [logLevel] - The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled. Defaults to 0.
  /// [logNoColor] - Whether to disable colors in the log output. `true` to disable colors, `false` to enable colors. Defaults to false.
  /// [instanceName] - An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs. Defaults to an empty string.
  ///
  /// {@category SealdAnonymousSdk}
  SealdAnonymousSdk(
      {required String apiURL,
      required String appId,
      int maxParallelRequests = 10,
      int logLevel = 0,
      bool logNoColor = false,
      String instanceName = ""}) {
    final Pointer<NativeSealdAnonymousInitializeOptions> initOpts =
        calloc<NativeSealdAnonymousInitializeOptions>();
    final String platform = "c-flutter-anonymous-${Platform.operatingSystem}";

    initOpts.ref
      ..ApiURL = apiURL.toNativeUtf8()
      ..AppId = appId.toNativeUtf8()
      ..MaxParallelRequests = maxParallelRequests
      ..LogLevel = logLevel
      ..LogNoColor = logNoColor ? 1 : 0
      ..InstanceName = instanceName.toNativeUtf8()
      ..Platform = platform.toNativeUtf8();

    final Pointer<Pointer<NativeSealdAnonymousSdk>> result =
        calloc<Pointer<NativeSealdAnonymousSdk>>();

    _bindings.SealdAnonymousSdk_CreateAnonymousSDK(initOpts, result);

    calloc.free(initOpts.ref.ApiURL);
    calloc.free(initOpts.ref.AppId);
    calloc.free(initOpts.ref.InstanceName);
    calloc.free(initOpts.ref.Platform);
    calloc.free(initOpts);

    _ptr = _TransferablePointer<NativeSealdAnonymousSdk>(result.value);
    calloc.free(result);
  }

  /// Close the current SDK instance.
  /// After calling close, the instance cannot be used anymore.
  void close() {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    _closed = true;
    _bindings.SealdAnonymousSdk_Close(_ptr.pointer());
  }

  /* SealdAnonymousEncryptionSession */

  // SealdAnonymousEncryptionSession is Finalizable, so I can't transfer it between isolates
  // This means we need to transfer a _TransferablePointer
  _TransferablePointer<NativeSealdAnonymousEncryptionSession>
      _createAnonymousEncryptionSession(
          String encryptionToken, String getKeysToken, List<String> recipients,
          {List<SealdAnonymousTmrRecipient>? tmrRecipients}) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }

    final Pointer<Utf8> nativeEncryptionToken = encryptionToken.toNativeUtf8();
    final Pointer<Utf8> nativeGetKeysToken = getKeysToken.toNativeUtf8();

    final Pointer<NativeSealdStringArray> nativeRecipients =
        _sealdStringArrayFromList(recipients);

    final Pointer<NativeSealdAnonymousTmrRecipientsArray> nativeTmrRecipients =
        SealdAnonymousTmrRecipient._toCArray(tmrRecipients);

    final Pointer<Pointer<NativeSealdAnonymousEncryptionSession>> result =
        calloc<Pointer<NativeSealdAnonymousEncryptionSession>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdAnonymousSdk_CreateAnonymousEncryptionSession(
            _ptr.pointer(),
            nativeEncryptionToken,
            nativeGetKeysToken,
            nativeRecipients,
            nativeTmrRecipients,
            result,
            err);

    calloc.free(nativeEncryptionToken);
    calloc.free(nativeGetKeysToken);
    _bindings.SealdStringArray_Free(nativeRecipients);
    _bindings.SealdAnonymousTmrRecipientsArray_Free(nativeTmrRecipients);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final _TransferablePointer<NativeSealdAnonymousEncryptionSession> res =
          _TransferablePointer<NativeSealdAnonymousEncryptionSession>(
              result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Create an anonymous encryption session, and returns the associated SealdAnonymousEncryptionSession instance,
  /// with which you can then encrypt/decrypt multiple messages.
  ///
  /// [encryptionToken] - Mandatory. The JWT used for EncryptionSession creation.
  /// [getKeysToken] - Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
  /// [recipients] - The Seald IDs of users who should be able to retrieve this session.
  /// [tmrRecipients] - Array of TMR recipients of the session to create.
  /// Returns the created SealdAnonymousEncryptionSession instance.
  SealdAnonymousEncryptionSession createAnonymousEncryptionSession(
      String encryptionToken, String getKeysToken, List<String> recipients,
      {List<SealdAnonymousTmrRecipient>? tmrRecipients}) {
    return SealdAnonymousEncryptionSession._fromC(
        _createAnonymousEncryptionSession(
                encryptionToken, getKeysToken, recipients,
                tmrRecipients: tmrRecipients)
            .pointer());
  }

  /// Create an anonymous encryption session, and returns the associated SealdAnonymousEncryptionSession instance,
  /// with which you can then encrypt/decrypt multiple messages.
  ///
  /// [encryptionToken] - Mandatory. The JWT used for EncryptionSession creation.
  /// [getKeysToken] - Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
  /// [recipients] - The Seald IDs of users who should be able to retrieve this session.
  /// [tmrRecipients] - Array of TMR recipients of the session to create.
  /// Returns the created SealdAnonymousEncryptionSession instance.
  Future<SealdAnonymousEncryptionSession> createAnonymousEncryptionSessionAsync(
      String encryptionToken, String getKeysToken, List<String> recipients,
      {List<SealdAnonymousTmrRecipient>? tmrRecipients}) async {
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> res =
        await compute(
            (Map<String, dynamic> args) => _createAnonymousEncryptionSession(
                args["encryptionToken"],
                args["getKeysToken"],
                args["recipients"],
                tmrRecipients: args["tmrRecipients"]),
            {
          "encryptionToken": encryptionToken,
          "getKeysToken": getKeysToken,
          "recipients": recipients,
          "tmrRecipients": tmrRecipients
        });
    return SealdAnonymousEncryptionSession._fromC(res.pointer());
  }

  /// Deserialize a serialized session.
  /// For advanced use.
  ///
  /// [serializedSession] - The serialized encryption session to deserialize.
  /// Returns the deserialized SealdAnonymousEncryptionSession instance.
  SealdAnonymousEncryptionSession deserializeAnonymousEncryptionSession(
      String serializedSession) {
    if (_closed) {
      throw SealdException(
          code: "INSTANCE_CLOSED",
          id: "FLUTTER_INSTANCE_CLOSED",
          description: "Instance already closed.");
    }
    final Pointer<Utf8> nativeSerializedSession =
        serializedSession.toNativeUtf8();
    final Pointer<Pointer<NativeSealdAnonymousEncryptionSession>> nativeResult =
        calloc<Pointer<NativeSealdAnonymousEncryptionSession>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdAnonymousSdk_DeserializeAnonymousEncryptionSession(
            _ptr.pointer(), nativeSerializedSession, nativeResult, err);

    calloc.free(nativeSerializedSession);

    if (resultCode != 0) {
      calloc.free(nativeResult);
      throw SealdException._fromCPtr(err);
    } else {
      SealdAnonymousEncryptionSession result =
          SealdAnonymousEncryptionSession._fromC(nativeResult.value);
      calloc.free(nativeResult);
      calloc.free(err);
      return result;
    }
  }
}
