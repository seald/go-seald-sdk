// You can find the full repository for this example at https://github.com/seald/seald-sdk-demo-app-flutter/

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart' as path_provider;
import 'package:path/path.dart' as path;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

import 'package:seald_sdk_flutter/seald_sdk.dart';
import 'package:seald_sdk_flutter_example/ssks_backend.dart';
import 'package:seald_sdk_flutter_example/credentials.dart';

void main() {
  runApp(const MyApp());
}

class BlinkingWidget extends StatefulWidget {
  const BlinkingWidget({super.key});

  @override
  BlinkingWidgetState createState() => BlinkingWidgetState();
}

class BlinkingWidgetState extends State<BlinkingWidget> {
  bool _isVisible = true;

  @override
  void initState() {
    super.initState();
    // start the blinking animation
    Timer.periodic(const Duration(milliseconds: 500), (timer) {
      setState(() {
        _isVisible = !_isVisible;
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedOpacity(
      opacity: _isVisible ? 1.0 : 0.0,
      duration: const Duration(milliseconds: 50),
      child: Container(
        width: 20.0,
        height: 20.0,
        color: Colors.red,
      ),
    );
  }
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

Uint8List randomBuffer(int length) {
  final random = Random.secure();
  final buffer = Uint8List(length);
  for (var i = 0; i < length; ++i) {
    buffer[i] = random.nextInt(256);
  }
  return buffer;
}

String randomString(int length) {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  var random = Random();
  return List.generate(length, (_) => chars[random.nextInt(chars.length)])
      .join();
}

String getRegistrationJwt() {
  // Create a json web token
  final JWT jwt = JWT({
    "iss": testCredentials["jwt_shared_secret_id"]!,
    "jti": base64.encode(randomBuffer(16)),
    "iat": DateTime.now().millisecondsSinceEpoch ~/ 1000,
    "scopes": [3],
    "join_team": true
  });

  return jwt.sign(SecretKey(testCredentials["jwt_shared_secret"]!),
      algorithm: JWTAlgorithm.HS256);
}

String getConnectorJwt(customUserId) {
  // Create a json web token
  final JWT jwt = JWT({
    "iss": testCredentials["jwt_shared_secret_id"]!,
    "jti": base64.encode(randomBuffer(16)),
    "iat": DateTime.now().millisecondsSinceEpoch ~/ 1000,
    "scopes": [4],
    "connector_add": {
      "type": "AP",
      "value": "$customUserId@${testCredentials["app_id"]}"
    }
  });

  return jwt.sign(SecretKey(testCredentials["jwt_shared_secret"]!),
      algorithm: JWTAlgorithm.HS256);
}

void assertEqual(actual, expected) {
  if (actual != expected) {
    print('Assert fail: expected $expected, got $actual');
    throw AssertionError('Assertion failed');
  }
}

void assertListEquals(actual, expected) {
  if (!listEquals(actual, expected)) {
    print('Assert fail: expected $expected, got $actual');
    throw AssertionError('Assertion failed');
  }
}

void assertNotEqual(actual, expected) {
  if (actual == expected) {
    print('Assert fail: expected to be not equal to $expected, got $actual');
    throw AssertionError('Assertion failed');
  }
}

typedef ErrorAssertion = void Function(Object err);

void assertThrows(Function func, ErrorAssertion assertion) {
  try {
    func();
  } catch (err) {
    assertion(err);
    return; // Got expected error
  }
  print('Assert fail: expected function to throw, but succeeded');
  throw AssertionError('Assertion failed');
}

Future<void> assertThrowsAsync(
    Future<void> Function() func, ErrorAssertion assertion) async {
  try {
    await func();
  } catch (err) {
    assertion(err);
    return; // Got expected error
  }
  print('Assert fail: expected async function to throw, but succeeded');
  throw AssertionError('Assertion failed');
}

Future<bool> testSealdSdk() async {
  print('Starting SDK tests...');
  try {
    // The SealdSDK uses a local database. This database should be written to a permanent directory.
    // For Flutter apps, the recommended path is the one returned by `path_provider.getApplicationDocumentsDirectory();
    final Directory tmpDir =
        await path_provider.getApplicationDocumentsDirectory();
    final Directory dbDir = Directory(path.join(tmpDir.path, 'seald-test-db'));

    // The Seald SDK uses a local database that will persist on disk.
    // When instantiating a SealdSDK, it is highly recommended to set a symmetric key to encrypt this database.
    // In an actual app, it should be generated at signup,
    // either on the server and retrieved from your backend at login,
    // or on the client-side directly and stored in the system's keychain.
    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    Uint8List databaseEncryptionKey = randomBuffer(64);

    // This demo expects a clean database path to create it's own data, so we need to clean what previous runs left.
    // In a real app, it should never be done.
    if (dbDir.existsSync()) {
      dbDir.deleteSync(recursive: true);
    }

    // Seald uses JWT to manage licenses and identity.
    // JWTs should be generated by your backend, and sent to the user at signup.
    // The JWT secretId and secret can be generated from your administration dashboard.
    // They should NEVER be on client side.
    // However, as this is a demo without a backend, we will use them on the frontend.
    // JWT documentation: https://docs.seald.io/en/sdk/guides/jwt.html
    // identity documentation: https://docs.seald.io/en/sdk/guides/4-identities.html

    // let's instantiate 3 SealdSDK. They will correspond to 3 users that will exchange messages.
    final SealdSdk sdk1 = SealdSdk(
      apiURL: testCredentials["api_url"]!,
      appId: testCredentials["app_id"]!,
      databasePath: Directory(path.join(dbDir.path, 'sdk1')).path,
      databaseEncryptionKey: databaseEncryptionKey,
      logLevel: -1,
      instanceName: "Dart-Instance-1",
    );
    final SealdSdk sdk2 = SealdSdk(
      apiURL: testCredentials["api_url"]!,
      appId: testCredentials["app_id"]!,
      databasePath: Directory(path.join(dbDir.path, 'sdk2')).path,
      databaseEncryptionKey: databaseEncryptionKey,
      logLevel: -1,
      instanceName: "Dart-Instance-2",
    );
    final SealdSdk sdk3 = SealdSdk(
      apiURL: testCredentials["api_url"]!,
      appId: testCredentials["app_id"]!,
      databasePath: Directory(path.join(dbDir.path, 'sdk3')).path,
      databaseEncryptionKey: databaseEncryptionKey,
      logLevel: -1,
      instanceName: "Dart-Instance-3",
    );

    // retrieve info about current user before creating a user should return null
    final SealdAccountInfo? retrieveNoAccount = sdk1.getCurrentAccountInfo();
    assertEqual(retrieveNoAccount, null);

    // Create the 3 accounts. Again, the signupJWT should be generated by your backend
    final SealdAccountInfo user1AccountInfo = await sdk1.createAccountAsync(
        getRegistrationJwt(),
        displayName: "Dart-demo-user-1",
        deviceName: "Dart-demo-device-1");
    final SealdAccountInfo user2AccountInfo = await sdk2.createAccountAsync(
        getRegistrationJwt(),
        displayName: "Dart-demo-user-2",
        deviceName: "Dart-demo-device-2");
    final SealdAccountInfo user3AccountInfo = await sdk3.createAccountAsync(
        getRegistrationJwt(),
        displayName: "Dart-demo-user-3",
        deviceName: "Dart-demo-device-3");

    // retrieve info about current user after creating a user should return account info:
    final SealdAccountInfo? retrieveAccountInfo = sdk1.getCurrentAccountInfo();
    assertNotEqual(retrieveAccountInfo, null);
    assertEqual(retrieveAccountInfo?.userId, user1AccountInfo.userId);
    assertEqual(retrieveAccountInfo?.deviceId, user1AccountInfo.deviceId);
    assertNotEqual(retrieveAccountInfo?.deviceExpires, 0);
    assertEqual(
        retrieveAccountInfo?.deviceExpires, user1AccountInfo.deviceExpires);

    // Create group: https://docs.seald.io/sdk/guides/5-groups.html
    final String groupId = await sdk1.createGroupAsync(
        groupName: "group-1",
        members: [user1AccountInfo.userId],
        admins: [user1AccountInfo.userId]);

    // Manage group members and admins
    // Add user2 as group member
    await sdk1
        .addGroupMembersAsync(groupId, membersToAdd: [user2AccountInfo.userId]);
    // user1 add user3 as group member and group admin
    await sdk1.addGroupMembersAsync(groupId,
        membersToAdd: [user3AccountInfo.userId],
        adminsToSet: [user3AccountInfo.userId]);
    // user3 can remove user2
    await sdk3.removeGroupMembersAsync(groupId,
        membersToRemove: [user2AccountInfo.userId]);
    // user3 can remove user1 from admins
    await sdk3.setGroupAdminsAsync(groupId,
        addToAdmins: [], removeFromAdmins: [user1AccountInfo.userId]);

    // Create encryption session: https://docs.seald.io/sdk/guides/6-encryption-sessions.html
    // user1, user2, and group as recipients
    // Default rights for the session creator (if included as recipients without RecipientRights)  read = true, forward = true, revoke = true
    // Default rights for any other recipient:  read = true, forward = true, revoke = false
    final List<SealdRecipientWithRights> recipientsES1 = [
      SealdRecipientWithRights(
        id: user1AccountInfo.userId,
      ),
      SealdRecipientWithRights(
        id: user2AccountInfo.userId,
      ),
      SealdRecipientWithRights(
        id: groupId,
      )
    ];
    final SealdEncryptionSession es1SDK1 =
        await sdk1.createEncryptionSessionAsync(recipientsES1,
            useCache: false); // user1, user2, and group as recipients
    assertEqual(es1SDK1.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.created);

    // Using two-man-rule accesses

    // Add TMR accesses to the session, then, retrieve the session using it.
    // Create TMR a recipient
    String authFactorType = "EM";
    String authFactorValue = "tmr-em-flutter-${randomString(5)}@test.com";

    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    Uint8List overEncryptionKey = randomBuffer(64);

    // Add the TMR access
    final String addedTMRId =
        await es1SDK1.addTmrAccessAsync(SealdTmrRecipientWithRights(
      type: authFactorType,
      value: authFactorValue,
      overEncryptionKey: overEncryptionKey,
    ));
    assertEqual(addedTMRId.length, 36);

    // Retrieve the TMR JWT
    SealdSsksTMRPlugin ssksPlugin = SealdSsksTMRPlugin(
      ssksURL: testCredentials["ssks_url"]!,
      appId: testCredentials["app_id"]!,
      logLevel: -1,
      instanceName: "TMRPlugin1",
    );
    SsksBackend yourCompanyDummyBackend = SsksBackend(
        testCredentials["ssks_url"]!,
        testCredentials["app_id"]!,
        testCredentials["ssks_backend_app_key"]!);

    // The app backend creates an SSKS authentication session.
    // This is the first time that this email is authenticating onto SSKS, so `mustAuthenticate` would be false, but we force auth because we want to convert TMR accesses.
    ChallengeSendResponse authSession = await yourCompanyDummyBackend.challengeSend(
        authFactorValue, authFactorType, authFactorValue, true, true,
        fakeOtp:
            true // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'. In production, you cannot use this.
        );
    assertEqual(authSession.mustAuthenticate, true);

    // Retrieve a JWT associated with the authentication factor from SSKS
    SealdSsksTMRPluginGetFactorTokenResponse tmrJWT =
        await ssksPlugin.getAuthFactorTokenAsync(
            authSession.sessionId, authFactorType, authFactorValue,
            challenge: testCredentials["ssks_tmr_challenge"]!);

    // Retrieve the encryption session using the JWT
    final SealdEncryptionSession tmrES =
        await sdk2.retrieveEncryptionSessionByTmrAsync(
            tmrJWT.token, es1SDK1.id, overEncryptionKey);
    assertEqual(tmrES.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.viaTmrAccess);

    // Convert the TMR accesses
    SealdConvertTmrAccessesResult conversionResult =
        await sdk2.convertTmrAccessesAsync(tmrJWT.token, overEncryptionKey);
    assertEqual(conversionResult.status, "ok");
    assertEqual(conversionResult.converted.length, 1);

    // After conversion, sdk2 can retrieve the encryption session directly.
    final SealdEncryptionSession classicES =
        await sdk2.retrieveEncryptionSessionAsync(
            sessionId: es1SDK1.id,
            useCache: false,
            lookupProxyKey: false,
            lookupGroupKey: false);
    assertEqual(classicES.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.direct);

    // Using proxy sessions: https://docs.seald.io/sdk/guides/proxy-sessions.html

    // Create proxy sessions: user1 needs to be a recipient of this session in order to be able to add it as a proxy session
    final SealdEncryptionSession proxySession1 =
        await sdk1.createEncryptionSessionAsync([
      SealdRecipientWithRights(
        id: user1AccountInfo.userId,
      ),
      SealdRecipientWithRights(
        id: user3AccountInfo.userId,
      )
    ]);
    await es1SDK1.addProxySessionAsync(proxySession1.id);

    // user1 needs to be a recipient of this session in order to be able to add it as a proxy session
    final SealdEncryptionSession proxySession2 =
        await sdk1.createEncryptionSessionAsync([
      SealdRecipientWithRights(
        id: user1AccountInfo.userId,
      ),
      SealdRecipientWithRights(
        id: user2AccountInfo.userId,
      )
    ]);
    await es1SDK1.addProxySessionAsync(proxySession2.id);

    // The SealdEncryptionSession object can encrypt and decrypt for user1
    const String initialString = "a message that needs to be encrypted!";
    final String encryptedMessage =
        await es1SDK1.encryptMessageAsync(initialString);
    final String decryptedMessage =
        await es1SDK1.decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessage, initialString);

    // user1 can parse/retrieve the SealdEncryptionSession from the encrypted message
    final String es1SDK1RetrieveFromMessId =
        parseSessionId(message: encryptedMessage);
    assertEqual(es1SDK1RetrieveFromMessId, es1SDK1.id);
    final SealdEncryptionSession es1SDK1RetrieveFromMess =
        await sdk1.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false);
    assertEqual(es1SDK1RetrieveFromMess.id, es1SDK1.id);
    assertEqual(es1SDK1RetrieveFromMess.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.direct);
    final String decryptedMessageFromMess =
        await es1SDK1RetrieveFromMess.decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessageFromMess, initialString);

    // Encrypt/Decrypt file from bytes
    final Uint8List clearFileBytes = randomBuffer(1024);
    final Uint8List encryptedFileFromBytes =
        await es1SDK1.encryptFileAsync(clearFileBytes, 'test.bin');
    final SealdClearFile decryptedFileFromBytes =
        await es1SDK1.decryptFileAsync(encryptedFileFromBytes);
    assertListEquals(clearFileBytes, decryptedFileFromBytes.fileContent);

    // Create a test file on disk that we will encrypt/decrypt
    final Directory directory =
        await path_provider.getApplicationDocumentsDirectory();
    await removeAllFilesInDirectory(directory.path);
    final String testFilePath = "${directory.path}/test.txt";
    final File testFile = File(testFilePath);
    await testFile.writeAsString(initialString);

    // Encrypt the test file. Resulting file will be written alongside the source file, with `.seald` extension added
    final String encryptedFilePath =
        await es1SDK1.encryptFileFromPathAsync(testFilePath);
    assertEqual(encryptedFilePath, "${directory.path}/test.txt.seald");

    // user1 can retrieve the encryptionSession directly from the encrypted file
    final String es1SDK1RetrieveFromFileId =
        parseSessionId(message: encryptedMessage);
    assertEqual(es1SDK1RetrieveFromFileId, es1SDK1.id);
    final SealdEncryptionSession es1SDK1RetrieveFromFile =
        await sdk1.retrieveEncryptionSessionAsync(
            filePath: encryptedFilePath, useCache: false);
    assertEqual(es1SDK1RetrieveFromFile.id, es1SDK1.id);
    assertEqual(es1SDK1RetrieveFromFile.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.direct);

    // user1 can retrieve the SealdEncryptionSession from the encrypted file
    // The decrypted file will be named with the name it had at encryption. Any renaming of the encrypted file will be ignore.
    // NOTE: In this example, the decrypted file will have `(1)` suffix to avoid overwriting the original clear file.
    final String decryptedFilePath = await es1SDK1RetrieveFromFile
        .decryptFileFromPathAsync(encryptedFilePath);
    assertEqual(decryptedFilePath, "${directory.path}/test (1).txt");
    final File decryptedFile = File(decryptedFilePath);
    assertEqual(await decryptedFile.exists(), true);
    final String decryptedFileAsString = await decryptedFile.readAsString();
    assertEqual(decryptedFileAsString, initialString);

    // user1 can parse/retrieve the SealdEncryptionSession from the encrypted file bytes
    final File encryptedFile = File(encryptedFilePath);
    final Uint8List encryptedFileBytes = await encryptedFile.readAsBytes();
    final String es1SDK1RetrieveFromFileBytesId =
        parseSessionId(message: encryptedMessage);
    assertEqual(es1SDK1RetrieveFromFileBytesId, es1SDK1.id);
    final SealdEncryptionSession es1SDK1RetrieveFromFileBytes =
        await sdk1.retrieveEncryptionSessionAsync(
            fileBytes: encryptedFileBytes, useCache: false);
    assertEqual(es1SDK1RetrieveFromFileBytes.id, es1SDK1.id);
    assertEqual(es1SDK1RetrieveFromFileBytes.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.direct);
    final String decryptedMessageFromFileBytes =
        await es1SDK1RetrieveFromFileBytes
            .decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessageFromFileBytes, initialString);

    // user2 can retrieve the SealdEncryptionSession from the session ID.
    final SealdEncryptionSession es1SDK2 = await sdk2
        .retrieveEncryptionSessionAsync(sessionId: es1SDK1.id, useCache: false);
    assertEqual(es1SDK2.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.direct);
    final String decryptedMessageSDK2 =
        await es1SDK2.decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessageSDK2, initialString);

    // user3 cannot retrieve the SealdEncryptionSession with lookupGroupKey set to false.
    await assertThrowsAsync(
        () async => sdk3.retrieveEncryptionSessionAsync(
            message: encryptedMessage,
            useCache: false,
            lookupGroupKey: false), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.id, "GOSDK_NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.description, "Can't decipher this session");
    });

    // user3 can retrieve the SealdEncryptionSession from the encrypted message through the group.
    final SealdEncryptionSession es1SDK3FromGroup =
        await sdk3.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false);
    assertEqual(es1SDK3FromGroup.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.viaGroup);
    assertEqual(es1SDK3FromGroup.retrievalDetails.groupId, groupId);
    final String decryptedMessageSDK3 =
        await es1SDK3FromGroup.decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessageSDK3, initialString);

    // user3 removes all members of "group-1". A group without member is deleted.
    await sdk3.removeGroupMembersAsync(groupId,
        membersToRemove: [user1AccountInfo.userId, user3AccountInfo.userId]);

    // user3 could retrieve the previous encryption session only because "group-1" was set as recipient.
    // As the group was deleted, it can no longer access it.
    // user3 still has the encryption session in its cache, but we can disable it.
    await assertThrowsAsync(
        () async => sdk3.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.id, "GOSDK_NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.description, "Can't decipher this session");
    });

    // user3 can still retrieve the session via proxy
    final SealdEncryptionSession es1SDK3FromProxy =
        await sdk3.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false, lookupProxyKey: true);
    assertEqual(es1SDK3FromProxy.retrievalDetails.flow,
        SealdEncryptionSessionRetrievalFlow.viaProxy);
    assertEqual(
        es1SDK3FromProxy.retrievalDetails.proxySessionId, proxySession1.id);

    // user2 adds user3 as recipient of the encryption session.
    final List<SealdRecipientWithRights> addRecipient3 = [
      SealdRecipientWithRights(
        id: user3AccountInfo.userId,
      )
    ];
    final Map<String, SealdActionStatus> asMapAdd =
        await es1SDK2.addRecipientsAsync(addRecipient3);
    assertEqual(asMapAdd.length, 1);
    assertEqual(asMapAdd.containsKey(user3AccountInfo.deviceId),
        true); // Note that addRecipient return DeviceId, not UserId
    assertEqual(asMapAdd[user3AccountInfo.deviceId]!.success, true);

    // user3 can now retrieve it without group or proxy.
    final SealdEncryptionSession es1SDK3 =
        await sdk3.retrieveEncryptionSessionAsync(
            sessionId: es1SDK1.id,
            useCache: false,
            lookupProxyKey: false,
            lookupGroupKey: false);
    final String decryptedMessageAfterAdd =
        await es1SDK3.decryptMessageAsync(encryptedMessage);
    assertEqual(decryptedMessageAfterAdd, initialString);

    // user1 revokes user3 and proxy1 from the encryption session.
    final SealdRevokeResult resultRevoke = await es1SDK1.revokeRecipientsAsync(
        recipientsIds: [user3AccountInfo.userId],
        proxySessionsIds: [proxySession1.id]);
    assertEqual(resultRevoke.recipients.length, 1);
    assertEqual(
        resultRevoke.recipients.containsKey(user3AccountInfo.userId), true);
    assertEqual(
        resultRevoke.recipients[user3AccountInfo.userId]!.success, true);
    assertEqual(resultRevoke.proxySessions.length, 1);
    assertEqual(resultRevoke.proxySessions.containsKey(proxySession1.id), true);
    assertEqual(resultRevoke.proxySessions[proxySession1.id]!.success, true);

    // user3 cannot retrieve the session anymore, even with proxy or group
    await assertThrowsAsync(
        () async => sdk3.retrieveEncryptionSessionAsync(
            message: encryptedMessage,
            useCache: false,
            lookupGroupKey: true,
            lookupProxyKey: true), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.id, "GOSDK_NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.description, "Can't decipher this session");
    });

    // user1 revokes all other recipients from the session
    final SealdRevokeResult resultRevokeOthers = await es1SDK1
        .revokeOthersAsync(); // revoke user2 + group (user3 is already revoked) + proxy2
    assertEqual(resultRevokeOthers.recipients.length, 2);
    assertEqual(
        resultRevokeOthers.recipients.containsKey(user2AccountInfo.userId),
        true);
    assertEqual(
        resultRevokeOthers.recipients[user2AccountInfo.userId]!.success, true);
    assertEqual(resultRevokeOthers.recipients.containsKey(groupId), true);
    assertEqual(resultRevokeOthers.recipients[groupId]!.success, true);
    assertEqual(resultRevokeOthers.proxySessions.length, 1);
    assertEqual(
        resultRevokeOthers.proxySessions.containsKey(proxySession2.id), true);
    assertEqual(
        resultRevokeOthers.proxySessions[proxySession2.id]!.success, true);

    // user2 cannot retrieve the session anymore
    await assertThrowsAsync(
        () async => sdk2.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.id, "GOSDK_NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.description, "Can't decipher this session");
    });

    // user1 revokes all. It can no longer retrieve it.
    final SealdRevokeResult revokeRevokeAll =
        await es1SDK1.revokeAllAsync(); // only user1 is left
    assertEqual(revokeRevokeAll.recipients.length, 1);
    assertEqual(
        revokeRevokeAll.recipients.containsKey(user1AccountInfo.userId), true);
    assertEqual(
        revokeRevokeAll.recipients[user1AccountInfo.userId]!.success, true);
    assertEqual(revokeRevokeAll.proxySessions.length, 0);

    // user1 cannot retrieve anymore
    await assertThrowsAsync(
        () async => sdk1.retrieveEncryptionSessionAsync(
            message: encryptedMessage, useCache: false), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.id, "GOSDK_NO_TOKEN_FOR_YOU");
      assertEqual(sealdErr.description, "Can't decipher this session");
    });

    // Create additional data for user1
    final List<SealdRecipientWithRights> recipientsES234 = [
      SealdRecipientWithRights(
        id: user1AccountInfo.userId,
      )
    ];
    final SealdEncryptionSession es2SDK1 = await sdk1
        .createEncryptionSessionAsync(recipientsES234, useCache: false);
    const String anotherMessage = "nobody should read that!";
    final String secondEncryptedMessage =
        await es2SDK1.encryptMessageAsync(anotherMessage);
    final SealdEncryptionSession es3SDK1 = await sdk1
        .createEncryptionSessionAsync(recipientsES234, useCache: false);
    final SealdEncryptionSession es4SDK1 = await sdk1
        .createEncryptionSessionAsync(recipientsES234, useCache: false);

    // user1 can retrieveMultiple
    final List<SealdEncryptionSession> encryptionSessions = await sdk1
        .retrieveMultipleEncryptionSessionsAsync(
            [es2SDK1.id, es3SDK1.id, es4SDK1.id],
            useCache: false);
    assertEqual(encryptionSessions.length, 3);
    assertEqual(encryptionSessions[0].id, es2SDK1.id);
    assertEqual(encryptionSessions[1].id, es3SDK1.id);
    assertEqual(encryptionSessions[2].id, es4SDK1.id);

    // user1 can renew its key, and still decrypt old messages
    final preparedRenewal = await sdk1.prepareRenewAsync();
    // `preparedRenewal` Can be stored on SSKS as a new identity. That way, a backup will be available is the renewKeys fail.

    await sdk1.renewKeysAsync(preparedRenewal: preparedRenewal);

    final SealdEncryptionSession es2SDK1AfterRenew = await sdk1
        .retrieveEncryptionSessionAsync(sessionId: es2SDK1.id, useCache: false);
    final String decryptedMessageAfterRenew =
        await es2SDK1AfterRenew.decryptMessageAsync(secondEncryptedMessage);
    assertEqual(decryptedMessageAfterRenew, anotherMessage);

    // CONNECTORS https://docs.seald.io/en/sdk/guides/jwt.html#adding-a-userid

    // we can add a custom userId using a JWT
    const String customConnectorJWTValue = "user1-custom-id";
    await sdk1.pushJWTAsync(getConnectorJwt(customConnectorJWTValue));

    final List<SealdConnector> connectors = await sdk1.listConnectorsAsync();
    assertEqual(connectors.length, 1);
    assertEqual(connectors[0].state, "VO");
    assertEqual(connectors[0].type, "AP");
    assertEqual(connectors[0].sealdId, user1AccountInfo.userId);
    assertEqual(connectors[0].value,
        "$customConnectorJWTValue@${testCredentials['app_id']}");

    // Retrieve connector by its id
    final SealdConnector retrieveConnector =
        await sdk1.retrieveConnectorAsync(connectors[0].id);
    assertEqual(retrieveConnector.sealdId, user1AccountInfo.userId);
    assertEqual(retrieveConnector.state, "VO");
    assertEqual(retrieveConnector.type, "AP");
    assertEqual(retrieveConnector.value,
        "$customConnectorJWTValue@${testCredentials['app_id']}");

    // Retrieve connectors from a user id.
    final List<SealdConnector> connectorsFromSealdId =
        await sdk1.getConnectorsFromSealdIdAsync(user1AccountInfo.userId);
    assertEqual(connectorsFromSealdId.length, 1);
    assertEqual(connectorsFromSealdId[0].state, "VO");
    assertEqual(connectorsFromSealdId[0].type, "AP");
    assertEqual(connectorsFromSealdId[0].sealdId, user1AccountInfo.userId);
    assertEqual(connectorsFromSealdId[0].value,
        "$customConnectorJWTValue@${testCredentials['app_id']}");

    // Get sealdId of a user from a connector
    final List<String> sealdIds = await sdk2.getSealdIdsFromConnectorsAsync([
      SealdConnectorTypeValue(
          type: "AP",
          value: "$customConnectorJWTValue@${testCredentials['app_id']}")
    ]);
    assertEqual(sealdIds.length, 1);
    assertEqual(sealdIds[0], user1AccountInfo.userId);

    // user1 can remove a connector
    await sdk1.removeConnectorAsync(connectors[0].id);

    // verify that no connector left
    final List<SealdConnector> connectorListAfterRevoke =
        await sdk1.listConnectorsAsync();
    assertEqual(connectorListAfterRevoke.length, 0);

    // user1 can export its identity
    final Uint8List exportIdentity = sdk1.exportIdentity();

    // We can instantiate a new SealdSDK, import the exported identity
    final SealdSdk sdk1Exported = SealdSdk(
      apiURL: testCredentials["api_url"]!,
      appId: testCredentials["app_id"]!,
      databasePath: Directory(path.join(dbDir.path, 'sdk1exported')).path,
      databaseEncryptionKey: databaseEncryptionKey,
      logLevel: -1,
      instanceName: "Dart1Exported",
    );
    await sdk1Exported.importIdentityAsync(exportIdentity);

    // SDK with imported identity can decrypt
    final SealdEncryptionSession es2SDK1Exported =
        await sdk1Exported.retrieveEncryptionSessionAsync(
            message: secondEncryptedMessage, useCache: false);
    final String clearMessageExportedIdentity =
        await es2SDK1Exported.decryptMessageAsync(secondEncryptedMessage);
    assertEqual(clearMessageExportedIdentity, anotherMessage);
    sdk1Exported.close();

    // user1 can create sub identity
    final SealdCreateSubIdentityResponse subIdentity =
        await sdk1.createSubIdentityAsync(deviceName: "SUB-deviceName");
    assertNotEqual(subIdentity.deviceId, "");

    // first device needs to reencrypt for the new device
    await sdk1.massReencryptAsync(subIdentity.deviceId);
    // We can instantiate a new SealdSDK, import the sub-device identity
    final SealdSdk sdk1SubDevice = SealdSdk(
      apiURL: testCredentials["api_url"]!,
      appId: testCredentials["app_id"]!,
      databasePath: Directory(path.join(dbDir.path, 'sdk1SubDevice')).path,
      databaseEncryptionKey: databaseEncryptionKey,
      logLevel: -1,
      instanceName: "sdk1SubDevice",
    );
    await sdk1SubDevice.importIdentityAsync(subIdentity.backupKey);

    // sub device can decrypt
    final SealdEncryptionSession es2SDK1SubDevice =
        await sdk1SubDevice.retrieveEncryptionSessionAsync(
            message: secondEncryptedMessage, useCache: false);
    final String clearMessageSubdIdentity =
        await es2SDK1SubDevice.decryptMessageAsync(secondEncryptedMessage);
    assertEqual(clearMessageSubdIdentity, anotherMessage);
    sdk1SubDevice.close();

    // Get and Check sigchain hash
    final SealdGetSigchainResponse user1LastSigchainHash =
        await sdk1.getSigchainHashAsync(user1AccountInfo.userId);
    assertEqual(user1LastSigchainHash.position, 2);
    final SealdGetSigchainResponse user1FirstSigchainHash =
        await sdk2.getSigchainHashAsync(user1AccountInfo.userId, position: 0);
    assertEqual(user1FirstSigchainHash.position, 0);
    final SealdCheckSigchainResponse lastHashCheck =
        await sdk2.checkSigchainHashAsync(
            user1AccountInfo.userId, user1LastSigchainHash.hash);
    assertEqual(lastHashCheck.found, true);
    assertEqual(lastHashCheck.position, 2);
    assertEqual(lastHashCheck.lastPosition, 2);
    final SealdCheckSigchainResponse firstHashCheck =
        await sdk1.checkSigchainHashAsync(
            user1AccountInfo.userId, user1FirstSigchainHash.hash);
    assertEqual(firstHashCheck.found, true);
    assertEqual(firstHashCheck.position, 0);
    assertEqual(firstHashCheck.lastPosition, 2);
    final SealdCheckSigchainResponse badPositionCheck =
        await sdk2.checkSigchainHashAsync(
            user1AccountInfo.userId, user1FirstSigchainHash.hash,
            position: 1);
    assertEqual(badPositionCheck.found, false);
    // For badPositionCheck, position cannot be asserted as it is not set when the hash is not found.
    assertEqual(badPositionCheck.lastPosition, 2);

    // Group TMR temporary keys

    // First, create a group to test on. sdk1 create a TMR temporary key to this group, sdk2 will join.
    final String groupTMRId = await sdk1.createGroupAsync(
        groupName: "group-TMR-1",
        members: [user1AccountInfo.userId],
        admins: [user1AccountInfo.userId]);

    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    Uint8List gTMRRawOverEncryptionKey = randomBuffer(64);

    // We defined a two man rule recipient earlier. We will use it again.
    // The authentication factor is defined by `authFactorType` and `authFactorValue`.
    // Also we already have the TMR JWT associated with it: `tmrJWT.token`

    final SealdGroupTMRTemporaryKey gTMRTKCreated =
        await sdk1.createGroupTMRTemporaryKeyAsync(groupTMRId, authFactorType,
            authFactorValue, gTMRRawOverEncryptionKey);

    final SealdListedGroupTMRTemporaryKey gTMRTKListed =
        await sdk1.listGroupTMRTemporaryKeysAsync(groupTMRId);
    assertEqual(gTMRTKListed.nbPage, 1);
    assertEqual(gTMRTKListed.keys[0].id, gTMRTKCreated.id);

    final SealdListedGroupTMRTemporaryKey gTMRTKSearched =
        await sdk2.searchGroupTMRTemporaryKeysAsync(tmrJWT.token);
    assertEqual(gTMRTKSearched.nbPage, 1);
    assertEqual(gTMRTKSearched.keys[0].id, gTMRTKCreated.id);

    await sdk2.convertGroupTMRTemporaryKeyAsync(
        groupTMRId, gTMRTKCreated.id, tmrJWT.token, gTMRRawOverEncryptionKey);
    await sdk1.deleteGroupTMRTemporaryKeyAsync(groupTMRId, gTMRTKCreated.id);

    // Heartbeat can be used to check if proxies and firewalls are configured properly so that the app can reach Seald's servers.
    await sdk1.heartbeatAsync();

    sdk1.close();
    sdk2.close();
    sdk3.close();

    print('SDK tests success!');
    return true;
  } catch (err, stack) {
    print('SDK tests failed');
    print(err);
    print(stack);
    return false;
  }
}

Future<bool> testSealdSsksPassword() async {
  print('Starting testSealdSsksPassword tests...');
  try {
    // Simulating a Seald identity with random data, for a simpler example.
    Uint8List dummyIdentity =
        randomBuffer(64); // should be: sdk.exportIdentity()

    SealdSsksPasswordPlugin ssksPlugin = SealdSsksPasswordPlugin(
      ssksURL: testCredentials["ssks_url"]!,
      appId: testCredentials["app_id"]!,
      logLevel: -1,
      instanceName: "PasswordPlugin",
    );

    // Test with standard password
    String userIdPassword = "user-${randomString(11)}";
    String userPassword = randomString(12);

    // Saving the identity with a password
    String ssksId1 = await ssksPlugin.saveIdentityFromPasswordAsync(
        userIdPassword, userPassword, dummyIdentity);
    assertNotEqual(ssksId1, "");

    // Retrieving the identity with the password
    Uint8List retrievedIdentityPassword = await ssksPlugin
        .retrieveIdentityFromPasswordAsync(userIdPassword, userPassword);
    assertListEquals(retrievedIdentityPassword, dummyIdentity);

    // Changing the password
    String newPassword = "newPassword";
    String ssksId1b = await ssksPlugin.changeIdentityPasswordAsync(
        userIdPassword, userPassword, newPassword);
    assertNotEqual(ssksId1b, ssksId1);

    // The previous password does not work anymore
    await assertThrowsAsync(
        () async => ssksPlugin.retrieveIdentityFromPasswordAsync(
            userIdPassword, userPassword), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "SSKSPASSWORD_CANNOT_FIND_IDENTITY");
    });

    // Retrieving with the new password works
    Uint8List retrievedIdentityNewPassword = await ssksPlugin
        .retrieveIdentityFromPasswordAsync(userIdPassword, newPassword);
    assertListEquals(retrievedIdentityNewPassword, dummyIdentity);

    // Test with raw keys
    String userIdRawKeys = "user-${randomString(11)}";
    String rawStorageKey = randomString(32);
    Uint8List rawEncryptionKey = randomBuffer(64);

    // Saving identity with raw keys
    String ssksId2 = await ssksPlugin.saveIdentityFromRawKeysAsync(
        userIdRawKeys, rawStorageKey, rawEncryptionKey, dummyIdentity);
    assertNotEqual(ssksId2, "");

    // Retrieving the identity with raw keys
    Uint8List retrievedIdentityRawKeys =
        await ssksPlugin.retrieveIdentityFromRawKeysAsync(
            userIdRawKeys, rawStorageKey, rawEncryptionKey);
    assertListEquals(retrievedIdentityRawKeys, dummyIdentity);

    // Deleting the identity by saving an empty `Data`
    String ssksId2b = ssksPlugin.saveIdentityFromRawKeys(
        userIdRawKeys, rawStorageKey, rawEncryptionKey, Uint8List(0));
    assertEqual(ssksId2b, ssksId2);

    // After deleting the identity, cannot retrieve anymore
    await assertThrowsAsync(
        () async => ssksPlugin.retrieveIdentityFromRawKeysAsync(
            userIdRawKeys, rawStorageKey, rawEncryptionKey), (Object err) {
      final SealdException sealdErr = err as SealdException;
      assertEqual(sealdErr.code, "SSKSPASSWORD_CANNOT_FIND_IDENTITY");
    });

    print('SsksPassword tests success!');
    return true;
  } catch (err, stack) {
    print('SsksPassword tests failed');
    print(err);
    print(stack);
    return false;
  }
}

Future<bool> testSealdSsksTMR() async {
  print('Starting testSealdSsksTMR tests...');
  try {
    // rawTMRSymKey is a secret, generated and stored by your _backend_, unique for the user.
    // It can be retrieved by client-side when authenticated (usually as part of signup/sign-in call response).
    // This *MUST* be a cryptographically random Uint8List of 64 bytes.
    Uint8List rawTMRSymKey = randomBuffer(64);

    SsksBackend yourCompanyDummyBackend = SsksBackend(
        testCredentials["ssks_url"]!,
        testCredentials["app_id"]!,
        testCredentials["ssks_backend_app_key"]!);

    // First, we need to simulate a user. For a simpler example, we will use random data.
    // userId is the ID of the user in your app.
    String userId = "user-${randomString(11)}";
    // userIdentity is the user's exported identity that you want to store on SSKS
    Uint8List dummyIdentity =
        randomBuffer(64); // should be: sdk.exportIdentity()

    SealdSsksTMRPlugin ssksPlugin = SealdSsksTMRPlugin(
      ssksURL: testCredentials["ssks_url"]!,
      appId: testCredentials["app_id"]!,
      logLevel: -1,
      instanceName: "TMRPlugin1",
    );

    // Define an authentication factor: the user's email address.
    // An authentication factor type can be an email `EM` or a phone number `SMS`
    String userEM = "email-${randomString(15)}@test.com";

    // The app backend creates an SSKS authentication session to save the identity.
    // This is the first time that this email is storing an identity, so `must_authenticate` is false.
    ChallengeSendResponse authSessionSave = await yourCompanyDummyBackend
        .challengeSend(userId, "EM", userEM, true, false,
            fakeOtp:
                true // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'. In production, you cannot use this.
            );

    assertEqual(authSessionSave.mustAuthenticate, false);

    // Saving the identity. No challenge necessary because `must_authenticate` is false.
    SealdSsksTMRPluginSaveIdentityResponse saveIdentityRes1 =
        await ssksPlugin.saveIdentityAsync(authSessionSave.sessionId, "EM",
            userEM, rawTMRSymKey, dummyIdentity);
    assertNotEqual(saveIdentityRes1.ssksId, "");
    assertEqual(saveIdentityRes1.authenticatedSessionId, null);

    // The app backend creates another session to retrieve the identity.
    // The identity is already saved, so `must_authenticate` is true.
    ChallengeSendResponse authSessionRetrieve = await yourCompanyDummyBackend
        .challengeSend(userId, "EM", userEM, true, false,
            fakeOtp:
                true // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'. In production, you cannot use this.
            );

    assertEqual(authSessionRetrieve.mustAuthenticate, true);
    SealdSsksTMRPluginRetrieveIdentityResponse retrieveNotAuth =
        await ssksPlugin.retrieveIdentityAsync(
            authSessionRetrieve.sessionId, "EM", userEM, rawTMRSymKey,
            challenge: testCredentials["ssks_tmr_challenge"]!);
    assertEqual(retrieveNotAuth.shouldRenewKey, true);
    assertListEquals(retrieveNotAuth.identity, dummyIdentity);

    // If initial key has been saved without being fully authenticated, you should renew the user's private key, and save it again.
    // await sdk1.renewKeysAsync();

    // Let's simulate the renew with another random identity
    Uint8List identitySecondKey = randomBuffer(64);

    // to save the newly renewed identityon the server, you can use the `authenticatedSessionId` from the response to `retrieveIdentityAsync`, with no challenge
    SealdSsksTMRPluginSaveIdentityResponse saveIdentityRes2 =
        await ssksPlugin.saveIdentityAsync(
            retrieveNotAuth.authenticatedSessionId,
            "EM",
            userEM,
            rawTMRSymKey,
            identitySecondKey);
    assertEqual(saveIdentityRes2.ssksId, saveIdentityRes1.ssksId);
    assertEqual(saveIdentityRes2.authenticatedSessionId, null);

    // And now let's retrieve this new saved identity
    ChallengeSendResponse authSessionRetrieve2 = await yourCompanyDummyBackend
        .challengeSend(userId, "EM", userEM, false, false,
            fakeOtp:
                true // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'. In production, you cannot use this.
            );

    assertEqual(authSessionRetrieve2.mustAuthenticate, true);
    SealdSsksTMRPluginRetrieveIdentityResponse retrievedSecondKey =
        await ssksPlugin.retrieveIdentityAsync(
            authSessionRetrieve2.sessionId, "EM", userEM, rawTMRSymKey,
            challenge: testCredentials["ssks_tmr_challenge"]!);
    assertEqual(retrievedSecondKey.shouldRenewKey, false);
    assertListEquals(retrievedSecondKey.identity, identitySecondKey);

    // Try retrieving with another SealdSsksTMRPlugin instance
    SealdSsksTMRPlugin ssksPluginInst2 = SealdSsksTMRPlugin(
      ssksURL: testCredentials["ssks_url"]!,
      appId: testCredentials["app_id"]!,
      logLevel: -1,
      instanceName: "TMRPlugin2",
    );
    ChallengeSendResponse authSessionRetrieve3 = await yourCompanyDummyBackend
        .challengeSend(userId, "EM", userEM, false, false,
            fakeOtp:
                true // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'. In production, you cannot use this.
            );

    assertEqual(authSessionRetrieve3.mustAuthenticate, true);
    SealdSsksTMRPluginRetrieveIdentityResponse inst2Retrieve =
        await ssksPluginInst2.retrieveIdentityAsync(
            authSessionRetrieve3.sessionId, "EM", userEM, rawTMRSymKey,
            challenge: testCredentials["ssks_tmr_challenge"]!);
    assertEqual(inst2Retrieve.shouldRenewKey, false);
    assertListEquals(inst2Retrieve.identity, identitySecondKey);

    print('SsksTMR tests success!');
    return true;
  } catch (err, stack) {
    print('SsksTMR tests failed');
    print(err);
    print(stack);
    return false;
  }
}

Future<void> removeAllFilesInDirectory(String directoryPath) async {
  Directory directory = Directory(directoryPath);
  if (await directory.exists()) {
    List<FileSystemEntity> files = directory.listSync();

    for (var file in files) {
      if (file is File) {
        await file.delete();
        print('File deleted: ${file.path}');
      }
    }

    print('All files removed from directory.');
  } else {
    throw Exception('Directory not found.');
  }
}

class _MyAppState extends State<MyApp> {
  late Future<bool> sdkTestResult;
  late Future<bool> ssksPasswordTestResult;
  late Future<bool> ssksTMRTestResult;

  @override
  void initState() {
    super.initState();
    sdkTestResult = testSealdSdk();
    ssksPasswordTestResult = testSealdSsksPassword();
    ssksTMRTestResult = testSealdSsksTMR();
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 25);
    const spacerSmall = SizedBox(height: 10);
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Native Packages'),
        ),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Column(
              children: [
                const BlinkingWidget(),
                spacerSmall,
                FutureBuilder<bool>(
                  future: sdkTestResult,
                  builder: (BuildContext context, AsyncSnapshot<bool> value) {
                    final String displayValue = (value.hasData)
                        ? (value.data! ? 'success' : 'fail')
                        : 'running';
                    return Text(
                      'test SDK: $displayValue',
                      style: textStyle,
                      textAlign: TextAlign.left,
                    );
                  },
                ),
                FutureBuilder<bool>(
                  future: ssksPasswordTestResult,
                  builder: (BuildContext context, AsyncSnapshot<bool> value) {
                    final String displayValue = (value.hasData)
                        ? (value.data! ? 'success' : 'fail')
                        : 'running';
                    return Text(
                      'test SSKS Password: $displayValue',
                      style: textStyle,
                      textAlign: TextAlign.left,
                    );
                  },
                ),
                FutureBuilder<bool>(
                  future: ssksTMRTestResult,
                  builder: (BuildContext context, AsyncSnapshot<bool> value) {
                    final String displayValue = (value.hasData)
                        ? (value.data! ? 'success' : 'fail')
                        : 'running';
                    return Text(
                      'test SSKS TMR: $displayValue',
                      style: textStyle,
                      textAlign: TextAlign.left,
                    );
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
