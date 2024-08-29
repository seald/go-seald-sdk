part of 'seald_sdk.dart';

class _TransferablePointer<T extends NativeType> {
  // Dart arbitrarily blocks Pointers from being transferable : https://github.com/dart-lang/sdk/issues/50457#issuecomment-1313233515
  // So we create a custom class which stores the Pointer address instead of the actual pointer, transfer this class, and reconstruct the pointer
  // in the other Isolate : https://github.com/dart-lang/sdk/issues/50457#issuecomment-1351336090
  final int _ptrAddress;

  _TransferablePointer(Pointer<T> ptr) : _ptrAddress = ptr.address;

  Pointer<T> pointer() {
    return Pointer<T>.fromAddress(_ptrAddress);
  }
}

/// {@category Helpers}
class SealdException implements Exception {
  /// If the error is returned by the Seald server, the HTTP status code.
  final int status;

  /// The error code, which is a machine-readable string that represents this error.
  final String code;

  ///  The error ID, which is a unique string for the precise place this error was thrown from.
  final String id;

  /// A human-readable description of the error.
  final String description;

  /// Details about the error.
  final String details;

  /// The raw underlying error.
  final String raw;

  /// The call stack in Seald native code.
  final String nativeStack;

  SealdException({
    this.status = 0,
    this.code = "",
    this.id = "",
    this.description = "",
    this.details = "",
    this.raw = "",
    this.nativeStack = "",
  });

  SealdException._fromCPtr(Pointer<Pointer<NativeSealdError>> errPtr)
      : status = errPtr.value.ref.Status,
        code = errPtr.value.ref.Code.toDartString(),
        id = errPtr.value.ref.Id.toDartString(),
        description = errPtr.value.ref.Description.toDartString(),
        details = errPtr.value.ref.Details.toDartString(),
        raw = errPtr.value.ref.Raw.toDartString(),
        nativeStack = errPtr.value.ref.NativeStack.toDartString() {
    _bindings.SealdError_Free(errPtr.value);
    calloc.free(errPtr);
  }

  @override
  String toString() {
    return "SealdException: status=$status, code='$code', id='$id', description='$description', details='$details', raw='$raw', nativeStack='$nativeStack'";
  }
}

/// Represents a decrypted file.
///
/// {@category Helpers}
class SealdClearFile {
  /// The filename of the decrypted file.
  final String filename;

  /// The ID of the SealdEncryptionSession to which this file belongs.
  final String sessionId;

  /// The content of the decrypted file.
  final Uint8List fileContent;

  SealdClearFile._fromC(Pointer<NativeSealdClearFile> cf)
      : filename = cf.ref.Filename.toDartString(),
        sessionId = cf.ref.SessionId.toDartString(),
        // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
        // Cannot use the `finalizer` argument of `asTypedList` because of https://github.com/dart-lang/sdk/issues/55800
        fileContent = Uint8List.fromList(
            cf.ref.FileContent.asTypedList(cf.ref.FileContentLen)) {
    // Cleanup what we don't need anymore
    _bindings.SealdClearFile_Free(cf);
  }
}

/// Represents information about the local account.
///
/// Returned when calling [SealdSdk.createAccount] or [SealdSdk.getCurrentAccountInfo].
///
/// {@category Helpers}
class SealdAccountInfo {
  /// The ID of the current user for this SDK instance.
  final String userId;

  /// The ID of the current device for this SDK instance.
  final String deviceId;

  /// The date at which the current device keys expire. For continued operation, renew your device keys before this date. `null` if it is not known locally: use [SealdSdk.updateCurrentDevice]: to retrieve it.
  final DateTime? deviceExpires;

  SealdAccountInfo._fromC(Pointer<NativeSealdAccountInfo> ai)
      : userId = ai.ref.UserId.toDartString(),
        deviceId = ai.ref.DeviceId.toDartString(),
        deviceExpires = ai.ref.DeviceExpires != 0
            ? DateTime.fromMillisecondsSinceEpoch(ai.ref.DeviceExpires * 1000)
            : null {
    // Cleanup
    _bindings.SealdAccountInfo_Free(ai);
  }
}

/// Represents a newly created sub identity.
///
/// {@category Helpers}
class SealdCreateSubIdentityResponse {
  /// The ID of the newly created device.
  final String deviceId;

  /// The identity export of the newly created sub-identity.
  final Uint8List backupKey;

  SealdCreateSubIdentityResponse._fromC(
      Pointer<NativeSealdCreateSubIdentityResponse> si)
      : deviceId = si.ref.DeviceId.toDartString(),
        // Copying the data in a Dart-created Uint8List, to avoid having to free memory later
        backupKey = Uint8List.fromList(
            si.ref.BackupKey.asTypedList(si.ref.BackupKeyLen)) {
    // Cleanup what we don't need anymore
    _bindings.SealdCreateSubIdentityResponse_Free(si);
  }
}

/// Represents all details about a connector.
///
/// {@category Helpers}
class SealdConnector {
  /// The Seald ID.
  final String sealdId;

  /// The connector type.
  final String type;

  /// The connector value.
  final String value;

  /// The connector ID.
  final String id;

  /// The connector state.
  final String state;

  SealdConnector._fromC(Pointer<NativeSealdConnector> c, {bool free = true})
      : sealdId = c.ref.SealdId.toDartString(),
        type = c.ref.Type.toDartString(),
        value = c.ref.Value.toDartString(),
        id = c.ref.Id.toDartString(),
        state = c.ref.State.toDartString() {
    // Cleanup what we don't need anymore
    if (free) _bindings.SealdConnector_Free(c);
  }

  static List<SealdConnector> _fromCArray(
      Pointer<NativeSealdConnectorsArray> nativeArray) {
    final int size = _bindings.SealdConnectorsArray_Size(nativeArray);
    final List<SealdConnector> connectors = [];
    for (int i = 0; i < size; i++) {
      final Pointer<NativeSealdConnector> nativeConnector =
          _bindings.SealdConnectorsArray_Get(nativeArray, i);
      // not freeing connectors here, as they will be freed when calling SealdConnectorsArray_Free
      final SealdConnector connector =
          SealdConnector._fromC(nativeConnector, free: false);
      connectors.add(connector);
    }
    // We HAVE to call the specific SealdConnectorsArray_Free function, because it's actually a Go instance
    _bindings.SealdConnectorsArray_Free(nativeArray);
    return connectors;
  }
}

/// Represents a connector type-value pair.
///
/// {@category Helpers}
class SealdConnectorTypeValue {
  /// The connector type.
  final String type;

  /// The connector value.
  final String value;

  SealdConnectorTypeValue({required this.type, required this.value});

  static Pointer<NativeSealdConnectorTypeValueArray> _toCArray(
      List<SealdConnectorTypeValue> l) {
    final Pointer<NativeSealdConnectorTypeValueArray> cArr =
        _bindings.SealdConnectorTypeValueArray_New();
    for (SealdConnectorTypeValue ctv in l) {
      final Pointer<Utf8> cType = ctv.type.toNativeUtf8();
      final Pointer<Utf8> cValue = ctv.value.toNativeUtf8();
      _bindings.SealdConnectorTypeValueArray_Add(cArr, cType, cValue);
      calloc.free(cType);
      calloc.free(cValue);
    }
    return cArr;
  }
}

/// Represents a way for your server to authorize the adding of a connector.
///
/// {@category Helpers}
class SealdPreValidationToken {
  /// The domain validation key ID.
  final String domainValidationKeyId;

  /// The nonce.
  final String nonce;

  /// The token.
  final String token;

  SealdPreValidationToken({
    required this.domainValidationKeyId,
    required this.nonce,
    required this.token,
  });

  Pointer<NativeSealdPreValidationToken> _toC() {
    final nativeStruct = calloc<NativeSealdPreValidationToken>();

    nativeStruct.ref.DomainValidationKeyId =
        domainValidationKeyId.toNativeUtf8();
    nativeStruct.ref.Nonce = nonce.toNativeUtf8();
    nativeStruct.ref.Token = token.toNativeUtf8();

    return nativeStruct;
  }
}

/// Represents the results of a call to [SealdSdk.massReencrypt].
///
/// {@category Helpers}
class SealdMassReencryptResponse {
  /// The number of session keys that were reencrypted for the given device.
  final int reencrypted;

  /// The The number of session keys that could not be reencrypted for the given device.
  final int failed;

  SealdMassReencryptResponse._fromC(Pointer<NativeSealdMassReencryptResponse> r)
      : reencrypted = r.ref.Reencrypted,
        failed = r.ref.Failed {
    calloc.free(r);
  }
}

/// Represents a device of the current account which is missing some keys,
/// and for which you probably want to call [SealdSdk.massReencrypt].
///
/// {@category Helpers}
class SealdDeviceMissingKeys {
  /// The ID of the device which is missing some keys.
  final String deviceId;

  SealdDeviceMissingKeys._fromC(Pointer<NativeSealdDeviceMissingKeys> dm,
      {bool free = true})
      : deviceId = dm.ref.DeviceId.toDartString() {
    // Cleanup what we don't need anymore
    if (free) _bindings.SealdDeviceMissingKeys_Free(dm);
  }

  static List<SealdDeviceMissingKeys> _fromCArray(
      Pointer<NativeSealdDeviceMissingKeysArray> nativeArray) {
    final int size = _bindings.SealdDeviceMissingKeysArray_Size(nativeArray);
    final List<SealdDeviceMissingKeys> devicesMissingKeys = [];
    for (int i = 0; i < size; i++) {
      final Pointer<NativeSealdDeviceMissingKeys> nativeDeviceMissingKeys =
          _bindings.SealdDeviceMissingKeysArray_Get(nativeArray, i);
      // not freeing connectors here, as they will be freed when calling SealdConnectorsArray_Free
      final SealdDeviceMissingKeys deviceMissingKeys =
          SealdDeviceMissingKeys._fromC(nativeDeviceMissingKeys, free: false);
      devicesMissingKeys.add(deviceMissingKeys);
    }
    // We HAVE to call the specific SealdConnectorsArray_Free function, because it's actually a Go instance
    _bindings.SealdDeviceMissingKeysArray_Free(nativeArray);
    return devicesMissingKeys;
  }
}

/// Represents the status of an operation on single user/device.
///
/// {@category Helpers}
class SealdActionStatus {
  final bool success;

  final String errorCode;

  final String result;

  SealdActionStatus._fromC(Pointer<NativeSealdActionStatus> as)
      : success = as.ref.Success != 0,
        errorCode = as.ref.ErrorCode != nullptr
            ? as.ref.ErrorCode.toDartString()
            : '', // no need to free, it will be done by the Array helper
        result = as.ref.Result != nullptr
            ? as.ref.Result.toDartString()
            : ''; // no need to free, it will be done by the Array helper

  static Map<String, SealdActionStatus> _fromCArray(
      Pointer<NativeSealdActionStatusArray> nativeArray) {
    final int size = _bindings.SealdActionStatusArray_Size(nativeArray);
    final Map<String, SealdActionStatus> map = {};
    for (int i = 0; i < size; i++) {
      final Pointer<NativeSealdActionStatus> nativeAs =
          _bindings.SealdActionStatusArray_Get(nativeArray, i);
      // not freeing ActionStatus here, as they will be freed when calling SealdActionStatusArray_Free
      final SealdActionStatus as = SealdActionStatus._fromC(nativeAs);
      map[nativeAs.ref.Id.toDartString()] = as;
    }
    // We HAVE to call the specific SealdActionStatusArray_Free function, because it's actually a Go instance
    _bindings.SealdActionStatusArray_Free(nativeArray);
    return map;
  }
}

/// The result of a revocation operation.
///
/// {@category Helpers}
class SealdRevokeResult {
  /// The Seald recipients the revocation operation acted on.
  final Map<String, SealdActionStatus> recipients;

  /// The proxy sessions the revocation operation acted on.
  final Map<String, SealdActionStatus> proxySessions;

  SealdRevokeResult._fromC(Pointer<NativeSealdRevokeResult> rr)
      : recipients = SealdActionStatus._fromCArray(rr.ref.Recipients),
        proxySessions = SealdActionStatus._fromCArray(rr.ref.ProxySessions) {
    calloc.free(rr);
  }
}

// There is no class equivalent to SealdStringArray defined here,
// as it corresponds to a simple `List<String>`,
// so we just define functions for helpers
Pointer<NativeSealdStringArray> _sealdStringArrayFromList(List<String>? l) {
  if (l == null) {
    return nullptr;
  }
  final Pointer<NativeSealdStringArray> array =
      _bindings.SealdStringArray_New();
  for (String s in l) {
    final Pointer<Utf8> flutterString = s.toNativeUtf8();
    _bindings.SealdStringArray_Add(array, flutterString);
    calloc.free(flutterString);
  }
  return array;
}

List<String> _listFromSealdStringArray(Pointer<NativeSealdStringArray> arr) {
  final int size = _bindings.SealdStringArray_Size(arr);
  final List<String> l = [];
  for (int i = 0; i < size; i++) {
    final Pointer<Utf8> nativeStr = _bindings.SealdStringArray_Get(arr, i);
    l.add(nativeStr.toDartString());
    calloc.free(nativeStr);
  }
  _bindings.SealdStringArray_Free(arr);
  return l;
}

/// Represents a connector type-value pair.
///
/// {@category Helpers}
class SealdRecipientRights {
  /// The right to read the message.
  final bool read;

  /// The right to forward the message to another user.
  final bool forward;

  /// The right to revoke another user from a message, or to remove rights from them.
  final bool revoke;

  SealdRecipientRights({
    this.read = true,
    this.forward = true,
    this.revoke = false,
  });
}

/// Represents a recipient with the associated rights
/// Default rights are: read: true, forward: true, revoke: false
/// Default rights for the current user when creating an encryptionSession are read: true, forward: true, revoke: true
///
/// {@category Helpers}
class SealdRecipientWithRights {
  /// Internal Seald IDs. Returned for users with  [SealdSdk.getCurrentAccountInfo], for groups when creating them. */
  final String id;

  /// The rights for the associated recipient ID.
  SealdRecipientRights? rights;

  SealdRecipientWithRights({
    required this.id,
    SealdRecipientRights? rights,
  });

  static Pointer<NativeSealdRecipientsWithRightsArray> _toCArray(
      List<SealdRecipientWithRights> l) {
    final Pointer<NativeSealdRecipientsWithRightsArray> array =
        _bindings.SealdRecipientsWithRightsArray_New();
    for (SealdRecipientWithRights rwr in l) {
      final Pointer<Utf8> rId = rwr.id.toNativeUtf8();
      if (rwr.rights != null) {
        _bindings.SealdRecipientsWithRightsArray_Add(
            array,
            rId,
            rwr.rights!.read ? 1 : 0,
            rwr.rights!.forward ? 1 : 0,
            rwr.rights!.revoke ? 1 : 0);
      } else {
        _bindings.SealdRecipientsWithRightsArray_AddWithDefaultRights(
            array, rId);
      }
      calloc.free(rId);
    }
    return array;
  }
}

/// SealdEncryptionSessionRetrievalFlow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session.
enum SealdEncryptionSessionRetrievalFlow {
  /// The session was created locally.
  created, // 0
  /// The session was retrieved as a direct recipient.
  direct, // 1
  /// The session was retrieved as a member of a group.
  viaGroup, // 2
  /// The session was retrieved through a proxy session.
  viaProxy, // 3
  /// The session was retrieved through a TMR access.
  viaTmrAccess, // 4
}

/// SealdEncryptionSessionRetrievalDetails represents the details of how an Encryption Session was retrieved.
class SealdEncryptionSessionRetrievalDetails {
  /// The way the session was retrieved: as a direct recipient, as a member of a group, or through a proxy session.
  final SealdEncryptionSessionRetrievalFlow flow;

  /// If the session was retrieved as a member of a group, the ID of the group in question.
  final String? groupId;

  /// If the session was retrieved through a proxy session, the ID of this proxy session.
  final String? proxySessionId;

  /// Indicates if this session was retrieved from the cache.
  final bool fromCache;

  SealdEncryptionSessionRetrievalDetails._fromC(
      Pointer<NativeSealdEncryptionSessionRetrievalDetails> rd)
      : flow = SealdEncryptionSessionRetrievalFlow.values[rd.ref.Flow],
        groupId =
            rd.ref.GroupId.address != 0 ? rd.ref.GroupId.toDartString() : null,
        proxySessionId = rd.ref.ProxySessionId.address != 0
            ? rd.ref.ProxySessionId.toDartString()
            : null,
        fromCache = rd.ref.FromCache != 0 {
    // Cleanup what we don't need anymore
    _bindings.SealdEncryptionSessionRetrievalDetails_Free(rd);
  }
}

/// SealdGetSigchainResponse is returned when calling [SealdSdk.getSigchainHash] or [SealdSdk.getSigchainHashAsync], containing the hash value and the position of the hash in the sigchain.
class SealdGetSigchainResponse {
  /// The sigchain hash.
  final String hash;

  /// The position of the associated hash in the sigchain.
  final int position;

  SealdGetSigchainResponse._fromC(
      Pointer<NativeSealdGetSigchainResponse> nativeResp)
      : hash = nativeResp.ref.Hash.toDartString(),
        position = nativeResp.ref.Position {
    // Cleanup
    _bindings.SealdGetSigchainResponse_Free(nativeResp);
  }
}

/// CheckSigchainHashResponse is returned when calling [SealdSdk.checkSigchainHash] or [SealdSdk.checkSigchainHashAsync], containing if the hash was found in the sigchain or not.
///
/// If the hash was found, it also contain at which position it was found. 0 otherwise.
class SealdCheckSigchainResponse {
  /// Whether or not the hash was found in the user's sigchain.
  final bool found;

  /// The position in the sigchain where the expected hash was found.
  final int position;

  /// The number of transaction in the sigchain.
  final int lastPosition;

  SealdCheckSigchainResponse._fromC(
      Pointer<NativeSealdCheckSigchainResponse> nativeResp)
      : found = nativeResp.ref.Found != 0,
        position = nativeResp.ref.Position,
        lastPosition = nativeResp.ref.LastPosition {
    // Cleanup
    calloc.free(nativeResp);
  }
}

/// SealdTmrAccessesRetrievalFilters holds the tmr accesses filters used when retrieving an EncryptionSession.
///
class SealdTmrAccessesRetrievalFilters {
  /// SealdId of the user who created the TMR access.
  final String createdById;

  /// Id of the TMR access to use.
  final String tmrAccessId;

  SealdTmrAccessesRetrievalFilters({
    this.createdById = "",
    this.tmrAccessId = "",
  });

  Pointer<NativeSealdTmrAccessesRetrievalFilters> _toC() {
    final nativeStruct = calloc<NativeSealdTmrAccessesRetrievalFilters>();
    nativeStruct.ref.CreatedById = createdById.toNativeUtf8();
    nativeStruct.ref.TmrAccessId = tmrAccessId.toNativeUtf8();
    return nativeStruct;
  }
}

/// SealdTmrAccessesConvertFilters holds the tmr accesses filters used when converting TMR accesses.
///
class SealdTmrAccessesConvertFilters {
  /// Id of the session with the TMR access to convert.
  final String sessionId;

  /// SealdId of the user who created the TMR accesses to convert.
  final String createdById;

  /// Id of the TMR access to convert.
  final String tmrAccessId;

  SealdTmrAccessesConvertFilters({
    this.sessionId = "",
    this.createdById = "",
    this.tmrAccessId = "",
  });

  Pointer<NativeSealdTmrAccessesConvertFilters> _toC() {
    final nativeStruct = calloc<NativeSealdTmrAccessesConvertFilters>();
    nativeStruct.ref.SessionId = sessionId.toNativeUtf8();
    nativeStruct.ref.CreatedById = createdById.toNativeUtf8();
    nativeStruct.ref.TmrAccessId = tmrAccessId.toNativeUtf8();

    return nativeStruct;
  }
}

/// SealdConvertTmrAccessesResult is returned when calling [SealdSdk.convertTmrAccesses].
/// containing the result of conversion
class SealdConvertTmrAccessesResult {
  /// Status of the conversion `ok` or `ko`.
  final String status;

  /// The access that where fully converted.
  final List<String> converted;

  /// The number of conversions that succeeded.
  final int succeeded;

  /// The number of conversions that failed.
  final int errored;

  SealdConvertTmrAccessesResult._fromC(
      Pointer<NativeSealdConvertTmrAccessesResult> nativeResp)
      : status = nativeResp.ref.Status.toDartString(),
        succeeded = nativeResp.ref.Succeeded,
        errored = nativeResp.ref.Errored,
        converted = _listFromSealdStringArray(nativeResp.ref.Converted) {
    // Cleanup
    _bindings.SealdConvertTmrAccessesResult_Free(nativeResp);
  }
}

/// Represents a tmr recipient with the associated rights
///
/// {@category Helpers}
class SealdTmrRecipientWithRights {
  /// Type of authentication factor. Can be `EM` or `SMS`. */
  final String type;

  /// Value of the authentication factor. */
  final String value;

  /// Over encryption key for the authentication factor. */
  final Uint8List overEncryptionKey;

  /// The rights for the associated authentication factor.
  SealdRecipientRights? rights;

  SealdTmrRecipientWithRights({
    required this.type,
    required this.value,
    required this.overEncryptionKey,
    SealdRecipientRights? rights,
  });

  static Pointer<NativeSealdTmrRecipientsWithRightsArray> _toCArray(
      List<SealdTmrRecipientWithRights> l) {
    final Pointer<NativeSealdTmrRecipientsWithRightsArray> array =
        _bindings.SealdTmrRecipientsWithRightsArray_New();
    for (SealdTmrRecipientWithRights rwr in l) {
      final Pointer<Utf8> rType = rwr.type.toNativeUtf8();
      final Pointer<Utf8> rValue = rwr.value.toNativeUtf8();
      // Dart FFI forces us to copy the data from Uint8List to a newly allocated Pointer<Uint8>
      final Pointer<Uint8> nativeOverEncryptionKey =
          calloc<Uint8>(rwr.overEncryptionKey.length);
      final pointerListOverEncryptionKey =
          nativeOverEncryptionKey.asTypedList(rwr.overEncryptionKey.length);
      pointerListOverEncryptionKey.setAll(0, rwr.overEncryptionKey);

      if (rwr.rights != null) {
        _bindings.SealdTmrRecipientsWithRightsArray_Add(
            array,
            rType,
            rValue,
            nativeOverEncryptionKey,
            rwr.overEncryptionKey.length,
            rwr.rights!.read ? 1 : 0,
            rwr.rights!.forward ? 1 : 0,
            rwr.rights!.revoke ? 1 : 0);
      } else {
        _bindings.SealdTmrRecipientsWithRightsArray_AddWithDefaultRights(
            array,
            rType,
            rValue,
            nativeOverEncryptionKey,
            rwr.overEncryptionKey.length);
      }

      calloc.free(rType);
      calloc.free(rValue);
      calloc.free(nativeOverEncryptionKey);
    }
    return array;
  }
}

String _pkcs1DerToPkcs8(String key) {
  final Pointer<Utf8> nativeKey = key.toNativeUtf8();
  final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
  final Pointer<Pointer<NativeSealdError>> err =
      calloc<Pointer<NativeSealdError>>();

  final int resultCode =
      _bindings.SealdUtils_PKCS1DERtoPKCS8(nativeKey, result, err);

  calloc.free(nativeKey);
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

String _generatePrivateKey(int size) {
  final Pointer<Pointer<Utf8>> result = calloc<Pointer<Utf8>>();
  final Pointer<Pointer<NativeSealdError>> err =
      calloc<Pointer<NativeSealdError>>();

  final int resultCode =
      _bindings.SealdUtils_GeneratePrivateKey(size, result, err);

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
