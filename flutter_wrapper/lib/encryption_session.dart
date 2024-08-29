part of 'seald_sdk.dart';

/// Represents an encryption session, with which you can then encrypt / decrypt multiple messages / files.
/// This should not be created directly, and should be retrieved with [SealdSdk.retrieveEncryptionSession].
///
/// {@category SealdEncryptionSession}
class SealdEncryptionSession implements Finalizable {
  final _TransferablePointer<NativeSealdEncryptionSession> _ptr;

  /// The ID of this encryption session.
  late final String id;

  /// Details about how this session was retrieved: through a group, a proxy, or directly.
  late final SealdEncryptionSessionRetrievalDetails retrievalDetails;

  static final _finalizer = NativeFinalizer(_bindings.addresses
      .SealdEncryptionSession_Free as Pointer<NativeFinalizerFunction>);

  SealdEncryptionSession._(this._ptr) {
    // This is used to re-create the SealdEncryptionSession from inside an isolate WITHOUT the finalizer, to avoid double-frees
    final Pointer<Utf8> nativeId =
        _bindings.SealdEncryptionSession_Id(_ptr.pointer());
    id = nativeId.toDartString();
    // retrieval details are not necessary from inside the isolate.
    calloc.free(nativeId);
  }

  SealdEncryptionSession._fromC(Pointer<NativeSealdEncryptionSession> es)
      : _ptr = _TransferablePointer<NativeSealdEncryptionSession>(es) {
    final Pointer<Utf8> nativeId = _bindings.SealdEncryptionSession_Id(es);
    id = nativeId.toDartString();
    calloc.free(nativeId);
    final Pointer<NativeSealdEncryptionSessionRetrievalDetails>
        nativeRetrievalDetails =
        _bindings.SealdEncryptionSession_RetrievalDetails(es);
    retrievalDetails =
        SealdEncryptionSessionRetrievalDetails._fromC(nativeRetrievalDetails);
    // Set finalizer to auto cleanup memory
    _finalizer.attach(this, _ptr.pointer() as Pointer<Void>);
  }

  static List<SealdEncryptionSession> _fromCArray(
      Pointer<NativeSealdEncryptionSessionArray> nativeArray) {
    final int size = _bindings.SealdEncryptionSessionArray_Size(nativeArray);
    final List<SealdEncryptionSession> encryptionSessions = [];
    for (int i = 0; i < size; i++) {
      final Pointer<NativeSealdEncryptionSession> nativeEncryptionSession =
          _bindings.SealdEncryptionSessionArray_Get(nativeArray, i);
      final SealdEncryptionSession es =
          SealdEncryptionSession._fromC(nativeEncryptionSession);
      encryptionSessions.add(es);
    }
    // We HAVE to call the specific SealdEncryptionSessionArray_Free function, because it's actually a Go instance
    _bindings.SealdEncryptionSessionArray_Free(nativeArray);
    return encryptionSessions;
  }

  /// Revokes some recipients or proxy sessions from this session.
  /// If you want to revoke all recipients, see [SealdEncryptionSession.revokeAll] instead.
  /// If you want to revoke all recipients besides yourself, see [SealdEncryptionSession.revokeOthers].
  ///
  /// [recipientsIds] - The Seald IDs of users to revoke from this session.
  /// [proxySessionsIds] - The IDs of proxy sessions to revoke from this session.
  /// Returns a [SealdRevokeResult].
  SealdRevokeResult revokeRecipients(
      {List<String>? recipientsIds, List<String>? proxySessionsIds}) {
    final Pointer<NativeSealdStringArray> nativeRecipientsIds =
        _sealdStringArrayFromList(recipientsIds);
    final Pointer<NativeSealdStringArray> nativeProxySessionsIds =
        _sealdStringArrayFromList(proxySessionsIds);
    final Pointer<Pointer<NativeSealdRevokeResult>> result =
        calloc<Pointer<NativeSealdRevokeResult>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_RevokeRecipients(
        _ptr.pointer(),
        nativeRecipientsIds,
        nativeProxySessionsIds,
        result,
        err);

    if (nativeRecipientsIds != nullptr) {
      _bindings.SealdStringArray_Free(nativeRecipientsIds);
    }
    if (nativeProxySessionsIds != nullptr) {
      _bindings.SealdStringArray_Free(nativeProxySessionsIds);
    }

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdRevokeResult res = SealdRevokeResult._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Revokes some recipients or proxy sessions from this session.
  /// If you want to revoke all recipients, see [SealdEncryptionSession.revokeAll] instead.
  /// If you want to revoke all recipients besides yourself, see [SealdEncryptionSession.revokeOthers].
  ///
  /// [recipientsIds] - The Seald IDs of users to revoke from this session.
  /// [proxySessionsIds] - The IDs of proxy sessions to revoke from this session.
  /// Returns a [SealdRevokeResult].
  Future<SealdRevokeResult> revokeRecipientsAsync(
      {List<String>? recipientsIds, List<String>? proxySessionsIds}) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdEncryptionSession._(tPtr)
            .revokeRecipients(
                recipientsIds: args["recipientsIds"],
                proxySessionsIds: args["proxySessionsIds"]),
        {"recipientsIds": recipientsIds, "proxySessionsIds": proxySessionsIds});
  }

  /// Revokes this session entirely.
  ///
  /// Returns a [SealdRevokeResult].
  SealdRevokeResult revokeAll() {
    final Pointer<Pointer<NativeSealdRevokeResult>> result =
        calloc<Pointer<NativeSealdRevokeResult>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdEncryptionSession_RevokeAll(_ptr.pointer(), result, err);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdRevokeResult res = SealdRevokeResult._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Revokes this session entirely.
  ///
  /// Returns a [SealdRevokeResult].
  Future<SealdRevokeResult> revokeAllAsync() {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute((_) => SealdEncryptionSession._(tPtr).revokeAll(), null);
  }

  /// Revokes all recipients besides yourself from this session.
  ///
  /// Returns a [SealdRevokeResult].
  SealdRevokeResult revokeOthers() {
    final Pointer<Pointer<NativeSealdRevokeResult>> result =
        calloc<Pointer<NativeSealdRevokeResult>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_RevokeOthers(
        _ptr.pointer(), result, err);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final SealdRevokeResult res = SealdRevokeResult._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Revokes all recipients besides yourself from this session.
  ///
  /// Returns a [SealdRevokeResult].
  Future<SealdRevokeResult> revokeOthersAsync() {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute((_) => SealdEncryptionSession._(tPtr).revokeOthers(), null);
  }

  /// Adds new recipients to this session.
  /// These recipients will be able to read all encrypted messages of this session.
  ///
  /// [recipients] - The Seald IDs of users to add to this session.
  /// Returns a Map which gives the result of the adding as a [SealdActionStatus] for each of the added recipient's devices. The keys of the Map correspond to the deviceIds of the recipients you are trying to add.
  Map<String, SealdActionStatus> addRecipients(
      List<SealdRecipientWithRights> recipients) {
    final Pointer<NativeSealdRecipientsWithRightsArray> nativeRecipients =
        SealdRecipientWithRights._toCArray(recipients);
    final Pointer<Pointer<NativeSealdActionStatusArray>> result =
        calloc<Pointer<NativeSealdActionStatusArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_AddRecipients(
        _ptr.pointer(), nativeRecipients, result, err);

    _bindings.SealdRecipientsWithRightsArray_Free(nativeRecipients);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final Map<String, SealdActionStatus> res =
          SealdActionStatus._fromCArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Adds new recipients to this session.
  /// These recipients will be able to read all encrypted messages of this session.
  ///
  /// [recipients] - The Seald IDs of users to add to this session.
  /// Returns a Map which gives the result of the adding as a [SealdActionStatus] for each of the added recipient's devices. The keys of the Map correspond to the deviceIds of the recipients you are trying to add.
  Future<Map<String, SealdActionStatus>> addRecipientsAsync(
      List<SealdRecipientWithRights> recipients) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (List<SealdRecipientWithRights> recipients) =>
            SealdEncryptionSession._(tPtr).addRecipients(recipients),
        recipients);
  }

  /// Add a proxy session as a recipient of this session.
  /// Any recipient of the proxy session will also be able to retrieve this session.
  /// The current user has to be a direct recipient of the proxy session.
  ///
  /// [proxySessionId] - The ID of the session to add as proxy.
  /// [rights] - The rights to assign to this proxy.
  void addProxySession(String proxySessionId, [SealdRecipientRights? rights]) {
    final Pointer<Utf8> nativeProxySessionId = proxySessionId.toNativeUtf8();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final SealdRecipientRights currentRights = rights ?? SealdRecipientRights();
    final int resultCode = _bindings.SealdEncryptionSession_AddProxySession(
        _ptr.pointer(),
        nativeProxySessionId,
        currentRights.read ? 1 : 0,
        currentRights.forward ? 1 : 0,
        currentRights.revoke ? 1 : 0,
        err);

    calloc.free(nativeProxySessionId);

    if (resultCode != 0) {
      throw SealdException._fromCPtr(err);
    } else {
      calloc.free(err);
    }
  }

  /// Add a proxy session as a recipient of this session.
  /// Any recipient of the proxy session will also be able to retrieve this session.
  /// The current user has to be a direct recipient of the proxy session.
  ///
  /// [proxySessionId] - The ID of the session to add as proxy.
  /// [rights] - The rights to assign to this proxy.
  Future<void> addProxySessionAsync(String proxySessionId,
      [SealdRecipientRights? rights]) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdEncryptionSession._(tPtr)
            .addProxySession(args["proxySessionId"], args["rights"]),
        {"proxySessionId": proxySessionId, "rights": rights});
  }

  /// Encrypts a clear-text string into an encrypted message, for the recipients of this session.
  ///
  /// [clearMessage] - The message to encrypt.
  /// Returns the encrypted message as a String.
  String encryptMessage(String clearMessage) {
    final Pointer<Utf8> nativeClearMessage = clearMessage.toNativeUtf8();
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_EncryptMessage(
        _ptr.pointer(), nativeClearMessage, result, err);

    calloc.free(nativeClearMessage);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String encryptedMessage = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return encryptedMessage;
    }
  }

  /// Encrypts a clear-text string into an encrypted message, for the recipients of this session.
  ///
  /// [clearMessage] - The message to encrypt.
  /// Returns the encrypted message as a String.
  Future<String> encryptMessageAsync(String clearMessage) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (String clearMessage) =>
            SealdEncryptionSession._(tPtr).encryptMessage(clearMessage),
        clearMessage);
  }

  /// Decrypts an encrypted message string into the corresponding clear-text string.
  ///
  /// [encryptedMessage] - The encrypted message to decrypt.
  /// Returns the decrypted message as a String.
  String decryptMessage(String encryptedMessage) {
    final Pointer<Utf8> nativeEncryptedMessage =
        encryptedMessage.toNativeUtf8();
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_DecryptMessage(
        _ptr.pointer(), nativeEncryptedMessage, result, err);

    calloc.free(nativeEncryptedMessage);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String decryptedMessage = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return decryptedMessage;
    }
  }

  /// Decrypts an encrypted message string into the corresponding clear-text string.
  ///
  /// [encryptedMessage] - The encrypted message to decrypt.
  /// Returns the decrypted message as a String.
  Future<String> decryptMessageAsync(String encryptedMessage) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (String encryptedMessage) =>
            SealdEncryptionSession._(tPtr).decryptMessage(encryptedMessage),
        encryptedMessage);
  }

  /// Encrypt a clear-text file into an encrypted file, for the recipients of this session.
  ///
  /// [clearFile] - A Uint8List of the clear-text content of the file to encrypt.
  /// [filename] - The name of the file to encrypt.
  /// Returns the encrypted file as a Uint8List.
  Uint8List encryptFile(Uint8List clearFile, String filename) {
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeClearFile = calloc<Uint8>(clearFile.length);
    final pointerList = nativeClearFile.asTypedList(clearFile.length);
    pointerList.setAll(0, clearFile);
    final Pointer<Utf8> nativeFilename = filename.toNativeUtf8();
    final Pointer<Pointer<Uint8>> result = calloc<Pointer<Uint8>>();
    final Pointer<Int> resultLen = calloc<Int>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_EncryptFile(
        _ptr.pointer(),
        nativeClearFile,
        clearFile.length,
        nativeFilename,
        result,
        resultLen,
        err);

    calloc.free(nativeClearFile);
    calloc.free(nativeFilename);

    if (resultCode != 0) {
      calloc.free(result);
      calloc.free(resultLen);
      throw SealdException._fromCPtr(err);
    } else {
      // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
      // Cannot use the `finalizer` argument of `asTypedList` because of https://github.com/dart-lang/sdk/issues/55800
      final Uint8List encryptedFile =
          Uint8List.fromList(result.value.asTypedList(resultLen.value));
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(resultLen);
      calloc.free(err);
      return encryptedFile;
    }
  }

  /// Encrypt a clear-text file into an encrypted file, for the recipients of this session.
  ///
  /// [clearFile] - A Uint8List of the clear-text content of the file to encrypt.
  /// [filename] - The name of the file to encrypt.
  /// Returns the encrypted file as a Uint8List.
  Future<Uint8List> encryptFileAsync(Uint8List clearFile, String filename) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdEncryptionSession._(tPtr)
            .encryptFile(args["clearFile"], args["filename"]),
        {"clearFile": clearFile, "filename": filename});
  }

  /// Decrypts an encrypted file into the corresponding clear-text file.
  ///
  /// [encryptedFile] - A Uint8List of the content of the encrypted file to decrypt.
  /// Returns a SealdClearFile instance, containing the decrypted file.
  SealdClearFile decryptFile(Uint8List encryptedFile) {
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeEncryptedFile =
        calloc<Uint8>(encryptedFile.length);
    final pointerList = nativeEncryptedFile.asTypedList(encryptedFile.length);
    pointerList.setAll(0, encryptedFile);
    final Pointer<Pointer<NativeSealdClearFile>> result =
        calloc<Pointer<NativeSealdClearFile>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_DecryptFile(
        _ptr.pointer(), nativeEncryptedFile, encryptedFile.length, result, err);

    calloc.free(nativeEncryptedFile);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final clearFile = SealdClearFile._fromC(result.value);
      calloc.free(result);
      calloc.free(err);
      return clearFile;
    }
  }

  /// Decrypts an encrypted file into the corresponding clear-text file.
  ///
  /// [encryptedFile] - A Uint8List of the content of the encrypted file to decrypt.
  /// Returns a SealdClearFile instance, containing the decrypted file.
  Future<SealdClearFile> decryptFileAsync(Uint8List encryptedFile) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Uint8List encryptedFile) =>
            SealdEncryptionSession._(tPtr).decryptFile(encryptedFile),
        encryptedFile);
  }

  /// Encrypt a clear-text file into an encrypted file, for the recipients of this session.
  ///
  /// [clearFilePath] - The path of the file to encrypt.
  /// Returns the path of the encrypted file.
  String encryptFileFromPath(String clearFilePath) {
    final Pointer<Utf8> nativeClearFilePath = clearFilePath.toNativeUtf8();
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_EncryptFileFromPath(
        _ptr.pointer(), nativeClearFilePath, result, err);

    calloc.free(nativeClearFilePath);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String encryptedFilePath = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return encryptedFilePath;
    }
  }

  /// Encrypt a clear-text file into an encrypted file, for the recipients of this session.
  ///
  /// [clearFilePath] - The path of the file to encrypt.
  /// Returns the path of the encrypted file.
  Future<String> encryptFileFromPathAsync(String clearFilePath) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (String clearFilePath) =>
            SealdEncryptionSession._(tPtr).encryptFileFromPath(clearFilePath),
        clearFilePath);
  }

  /// Decrypts an encrypted file into the corresponding clear-text file.
  ///
  /// [encryptedFilePath] - The path of the encrypted file to decrypt.
  /// Returns the path of the decrypted file.
  String decryptFileFromPath(String encryptedFilePath) {
    final Pointer<Utf8> nativeEncryptedFilePath =
        encryptedFilePath.toNativeUtf8();
    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdEncryptionSession_DecryptFileFromPath(
        _ptr.pointer(), nativeEncryptedFilePath, result, err);

    calloc.free(nativeEncryptedFilePath);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String decryptedFilePath = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return decryptedFilePath;
    }
  }

  /// Decrypts an encrypted file into the corresponding clear-text file.
  ///
  /// [encryptedFilePath] - The path of the encrypted file to decrypt.
  /// Returns the path of the decrypted file.
  Future<String> decryptFileFromPathAsync(String encryptedFilePath) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (String encryptedFilePath) => SealdEncryptionSession._(tPtr)
            .decryptFileFromPath(encryptedFilePath),
        encryptedFilePath);
  }

  /// Add a TMR access to this session for the given authentication factor.
  ///
  /// [recipients] - A TMR recipient with its associated rights.
  /// Returns the ID of the created TMR access.
  String addTmrAccess(SealdTmrRecipientWithRights recipient) {
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeOverEncryptionKey =
        calloc<Uint8>(recipient.overEncryptionKey.length);
    final pointerListOverEncryptionKey =
        nativeOverEncryptionKey.asTypedList(recipient.overEncryptionKey.length);
    pointerListOverEncryptionKey.setAll(0, recipient.overEncryptionKey);

    final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final Pointer<Utf8> nativeRecipientType = recipient.type.toNativeUtf8();
    final Pointer<Utf8> nativeRecipientValue = recipient.value.toNativeUtf8();

    final SealdRecipientRights currentRights =
        recipient.rights ?? SealdRecipientRights();
    final int resultCode = _bindings.SealdEncryptionSession_AddTmrAccess(
        _ptr.pointer(),
        nativeRecipientType,
        nativeRecipientValue,
        nativeOverEncryptionKey,
        recipient.overEncryptionKey.length,
        currentRights.read ? 1 : 0,
        currentRights.forward ? 1 : 0,
        currentRights.revoke ? 1 : 0,
        result,
        err);

    calloc.free(nativeRecipientType);
    calloc.free(nativeRecipientValue);
    calloc.free(nativeOverEncryptionKey);
    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final String accessId = result.value.toDartString();
      calloc.free(result.value);
      calloc.free(result);
      calloc.free(err);
      return accessId;
    }
  }

  /// Add a TMR access to this session for the given authentication factor.
  ///
  /// [recipients] - A TMR recipient with its associated rights.
  /// Returns the ID of the created TMR access.
  Future<String> addTmrAccessAsync(SealdTmrRecipientWithRights recipient) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) =>
            SealdEncryptionSession._(tPtr).addTmrAccess(args["recipient"]),
        {"recipient": recipient});
  }

  /// Add multiple TMR accesses to this session for the given authentication factors.
  ///
  /// [recipients] - The TMR recipients with their associated rights.
  /// Returns a Map which gives the result of the adding as a [SealdActionStatus] for each of the added TMR recipients.
  Map<String, SealdActionStatus> addMultipleTmrAccesses(
      List<SealdTmrRecipientWithRights> recipients) {
    final Pointer<NativeSealdTmrRecipientsWithRightsArray> nativeRecipients =
        SealdTmrRecipientWithRights._toCArray(recipients);

    final Pointer<Pointer<NativeSealdActionStatusArray>> result =
        calloc<Pointer<NativeSealdActionStatusArray>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode =
        _bindings.SealdEncryptionSession_AddMultipleTmrAccesses(
            _ptr.pointer(), nativeRecipients, result, err);

    _bindings.SealdTmrRecipientsWithRightsArray_Free(nativeRecipients);

    if (resultCode != 0) {
      calloc.free(result);
      throw SealdException._fromCPtr(err);
    } else {
      final Map<String, SealdActionStatus> res =
          SealdActionStatus._fromCArray(result.value);
      calloc.free(result);
      calloc.free(err);
      return res;
    }
  }

  /// Add multiple TMR accesses to this session for the given authentication factors.
  ///
  /// [recipients] - The TMR recipients with their associated rights.
  /// Returns a Map which gives the result of the adding as a [SealdActionStatus] for each of the added TMR recipients.
  Future<Map<String, SealdActionStatus>> addMultipleTmrAccessesAsync(
      List<SealdTmrRecipientWithRights> recipients) {
    final _TransferablePointer<NativeSealdEncryptionSession> tPtr = _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdEncryptionSession._(tPtr)
            .addMultipleTmrAccesses(args["recipients"]),
        {"recipients": recipients});
  }
}
