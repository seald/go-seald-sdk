part of 'seald_sdk.dart';

/// Represents an anonymous encryption session, with which you can then encrypt / decrypt multiple messages / files.
/// This should not be created directly, and should be retrieved with [SealdAnonymousSdk.createAnonymousEncryptionSession].
///
/// {@category SealdAnonymousEncryptionSession}
class SealdAnonymousEncryptionSession implements Finalizable {
  final _TransferablePointer<NativeSealdAnonymousEncryptionSession> _ptr;

  /// The ID of this encryption session.
  late final String id;

  static final _finalizer = NativeFinalizer(
      _bindings.addresses.SealdAnonymousEncryptionSession_Free
          as Pointer<NativeFinalizerFunction>);

  SealdAnonymousEncryptionSession._(this._ptr) {
    // This is used to re-create the SealdAnonymousEncryptionSession from inside an isolate WITHOUT the finalizer, to avoid double-frees
    final Pointer<Utf8> nativeId =
        _bindings.SealdAnonymousEncryptionSession_Id(_ptr.pointer());
    id = nativeId.toDartString();
    calloc.free(nativeId);
  }

  SealdAnonymousEncryptionSession._fromC(
      Pointer<NativeSealdAnonymousEncryptionSession> aes)
      : _ptr =
            _TransferablePointer<NativeSealdAnonymousEncryptionSession>(aes) {
    final Pointer<Utf8> nativeId =
        _bindings.SealdAnonymousEncryptionSession_Id(aes);
    id = nativeId.toDartString();
    calloc.free(nativeId);
    // Set finalizer to auto cleanup memory
    _finalizer.attach(this, _ptr.pointer() as Pointer<Void>);
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_EncryptMessage(
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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (String clearMessage) => SealdAnonymousEncryptionSession._(tPtr)
            .encryptMessage(clearMessage),
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_DecryptMessage(
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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (String encryptedMessage) => SealdAnonymousEncryptionSession._(tPtr)
            .decryptMessage(encryptedMessage),
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_EncryptFile(
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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (Map<String, dynamic> args) => SealdAnonymousEncryptionSession._(tPtr)
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_DecryptFile(_ptr.pointer(),
            nativeEncryptedFile, encryptedFile.length, result, err);

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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (Uint8List encryptedFile) =>
            SealdAnonymousEncryptionSession._(tPtr).decryptFile(encryptedFile),
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_EncryptFileFromPath(
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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (String clearFilePath) => SealdAnonymousEncryptionSession._(tPtr)
            .encryptFileFromPath(clearFilePath),
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

    final int resultCode =
        _bindings.SealdAnonymousEncryptionSession_DecryptFileFromPath(
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
    final _TransferablePointer<NativeSealdAnonymousEncryptionSession> tPtr =
        _ptr;
    return compute(
        (String encryptedFilePath) => SealdAnonymousEncryptionSession._(tPtr)
            .decryptFileFromPath(encryptedFilePath),
        encryptedFilePath);
  }

  /// Serialize the Anonymous EncryptionSession to a string.
  /// This is for advanced use.
  /// May be used to keep sessions in a cache.
  /// WARNING: a user could use this cache to work around being revoked. Use with caution.
  /// WARNING: if the cache is accessible to another user, they could use it to decrypt messages they are not supposed
  /// to have access to. Make sure only the current user in question can access this cache, for example by encrypting it.
  ///
  /// Returns the serialized encryption session as a String.
  String serialize() {
    final Pointer<Pointer<Utf8>> nativeResult = calloc<Pointer<Utf8>>();
    final Pointer<Pointer<NativeSealdError>> err =
        calloc<Pointer<NativeSealdError>>();

    final int resultCode = _bindings.SealdAnonymousEncryptionSession_Serialize(
        _ptr.pointer(), nativeResult, err);

    if (resultCode != 0) {
      calloc.free(nativeResult);
      throw SealdException._fromCPtr(err);
    } else {
      final String result = nativeResult.value.toDartString();
      calloc.free(nativeResult.value);
      calloc.free(nativeResult);
      calloc.free(err);
      return result;
    }
  }
}
