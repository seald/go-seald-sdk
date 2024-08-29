part of 'seald_sdk.dart';

/// Takes the path to an encrypted file, or the bytes of an encrypted file, or a message, and returns the session id.
///
/// [message] - A message to parse.
/// [filePath] - The path to an encrypted file to parse.
/// [fileBytes] - The bytes of an encrypted file to parse.
/// Returns the session id.
/// {@category Utils}
String parseSessionId({
  String? message,
  String? filePath,
  Uint8List? fileBytes,
}) {
  final int argCount =
      [message, filePath, fileBytes].where((element) => element != null).length;
  if (argCount == 0) {
    throw ArgumentError(
        "One of message, fileBytes, or filePath must be provided.");
  }
  if (argCount > 1) {
    throw ArgumentError(
        "Only one of message, fileBytes, or filePath can be provided.");
  }
  final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
  final Pointer<Pointer<NativeSealdError>> err =
      calloc<Pointer<NativeSealdError>>();

  int resultCode = 0;
  if (message != null) {
    final Pointer<Utf8> nativeMessage = message.toNativeUtf8();
    resultCode = _bindings.SealdUtils_ParseSessionIdFromMessage(
        nativeMessage, result, err);
    calloc.free(nativeMessage);
  } else if (filePath != null) {
    final Pointer<Utf8> nativeFilePath = filePath.toNativeUtf8();
    resultCode = _bindings.SealdUtils_ParseSessionIdFromFile(
        nativeFilePath, result, err);
    calloc.free(nativeFilePath);
  } else if (fileBytes != null) {
    // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
    final Pointer<Uint8> nativeFileBytes = calloc<Uint8>(fileBytes.length);
    final pointerList = nativeFileBytes.asTypedList(fileBytes.length);
    pointerList.setAll(0, fileBytes);
    resultCode = _bindings.SealdUtils_ParseSessionIdFromBytes(
        nativeFileBytes, fileBytes.length, result, err);
    calloc.free(nativeFileBytes);
  }

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

/// Represents a set of pre-generated private keys.
/// Returned by [SealdSdk.generatePrivateKeysAsync].
/// Can be passed to sync functions that need private keys.
///
/// {@category Utils}
class SealdGeneratedPrivateKeys {
  final String encryptionKey;
  final String signingKey;

  SealdGeneratedPrivateKeys(this.encryptionKey, this.signingKey);
}
