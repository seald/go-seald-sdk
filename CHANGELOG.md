# 0.8.0 : Unreleased
- @flutter: \[**breaking change**\] Correctly specify minimum Flutter version as `3.10.0`. Version `0.7.0` was already incompatible with Flutter versions older than `3.10.0`, it just was not specified in `pubspec.yaml`.
- @go:  \[**breaking change**\] In Anonymous SDK, add ability to encrypt for TMR Recipients. This changes the arguments of the `AnonymousSDK.encrypt` function.
- @ios: \[new feature\] The Seald SDK for iOS is now also available through Swift Package Manager, at `https://github.com/seald/seald-sdk-ios`.
- @all: \[new feature\] Add group TMR temporary keys functions to join a group using TMR. `CreateGroupTMRTemporaryKey`, `ListGroupTMRTemporaryKeys`,`DeleteGroupTMRTemporaryKey`, `ConvertGroupTMRTemporaryKey` and `SearchGroupTMRTemporaryKeys`.
- @all: \[enhancement\] Update dependencies
- @go:  \[bug fix\] Fix package name in `go.mod` so the Go SDK can be imported by other projects


# 0.7.1 : 2024/09/12
- @all: \[bug fix\] Log timestamps now correctly have millisecond precision.


# 0.7.0 : 2024/08/29
- @all: \[enhancement\] Add a specific error when given a database encryption key of invalid length.
- @all: \[enhancement\] Add the URL and the method when returning an APIError
- @flutter: \[enhancement\] Now runs on Flutter for macOS
- @flutter: \[bug fix\] Fix sending of SDK version header
- @flutter: \[bug fix\] Now respects configured `keySize` when using native key generation.
- @flutter: \[bug fix\] Fix memory-management of `session.encryptFile` and `session.decryptFile`, and their async versions. 
- @all: \[enhancement\] First release publicly available on GitHub


# 0.6.0 : 2024/05/30
- @all: \[enhancement\] Better performance when retrieving the same session multiple times in parallel when cache is enabled: now only one calls hits the API, while the others wait for it then use the cache.
- @all: \[enhancement\] Add default rights when handling recipients.
- @android: \[**breaking change**\] Change argument order when instantiating `TmrRecipientWithRights`. `overEncryptionKey` now comes before `rights`.
- @all: \[new feature\] In SSKS Password, `SaveIdentityFromPassword`, `SaveIdentityFromRawKeys`, and `ChangeIdentityPassword` now return the SSKS ID of the stored identity, which can be used by your backend to manage it.
- @all: \[new feature\] In SSKS TMR, adding new `SaveIdentityResponse` class, which is returned by `SaveIdentity`.
- @flutter: \[**breaking change**\] In SSKS TMR, `challenge` is now a proper optional argument for all methods. This changes the order of arguments.
- @android: \[**breaking change**\] In SSKS TMR, `challenge` is now a proper optional argument for all methods, and is at the end of the list of arguments.
- @ios: \[**breaking change**\] In SSKS TMR, for all methods, the `challenge` argument was moved at the end of the list of arguments, and a new version of the methods without the challenge argument was created.
- @flutter: \[**breaking change**\]  Change  `String databaseEncryptionKeyB64` argument of SealdSDK constructor to  `Uint8List? databaseEncryptionKey`.
- @ios: \[**breaking change**\] Change `(const NSString*)dbb64SymKey` argument of SealdSDK constructor to  `(const NSData*_Nullable)databaseEncryptionKey`.
- @kotlin: \[**breaking change**\] Change `String? dbb64SymKey` argument of SealdSDK constructor to `ByteArray? databaseEncryptionKey`.
- @all: \[new feature\] Add `sealdSdk.retrieveMultipleEncryption()` method, which takes an array of session IDs as input, and returns an array of EncryptionSession instances.
- @kotlin: \[new feature\] Expose `generatePrivateKeys` and `generatePrivateKeysAsync` functions that natively generate private keys. 
- @kotlin: \[new feature\] Add optional argument `privateKeys` to functions `createAccount`, `renewKeys`, `createSubIdentity`, `createGroup`, `addGroupMembers`, `removeGroupMembers`, `renewGroupKey`, and their async versions, to pass pre-generated private keys.
- @all: \[new feature\] Add `sealdSdk.prepareRenew()` method, which return a prepared key renewal that can be stored on SSKS to avoid any data loss situation during a private key renewal, and add the corresponding `preparedRenewal` argument in method `renewKeys`.
- @ios: \[**breaking change**\] Method `renewKeys` and its async version now have `preparedRenewal` argument in first position.
- @all: \[enhancement\] Send public key hash at login for better performance.
- @flutter: \[new feature\] Also add `privateKeys` argument to methods `addGroupMembers` / `removeGroupMembers`, and to all async methods.
- @flutter \[**breaking change**\] Rename `generatePrivateKeys` to `generatePrivateKeysAsync`.
- @flutter \[**breaking change**\] Order of some optional args has changed, for coherence with other languages.
- @ios: \[new feature\] Add `[SealdSdk generatePrivateKeysWithError:]` and `[SealdSdk generatePrivateKeysAsyncWithCompletionHandler:]` methods. Add new `SealdGeneratedPrivateKeys` type.
- @ios: \[**breaking change**\] Add argument `privateKeys` to functions `createAccount`, `renewKeys`, `createSubIdentity`, `createGroup`, `addGroupMembers`, `removeGroupMembers`, `renewGroupKey`, and their async versions, to pass pre-generated private keys.
- @android: \[enhancement\] In `createSubIdentity` and its async version, make `deviceName` optional.


# 0.5.0-beta.1 : 2024/03/28
- @all: \[packaging\] fix publishing details


# 0.5.0-beta.0 : 2024/03/28
- @all: \[new feature\] Add `GetSigchainHash` and `CheckSigchainHash` methods to verify a users sigchain
- @all: \[bug fix\] Only try renewing group keys automatically if current user is a group admin.
- @flutter: \[enhancement\] Use native private key generation for async methods.
- @flutter: \[new feature\] Add `generatePrivateKeys` method which generates private keys natively and asynchronously, and returns a `SealdGeneratedPrivateKeys` instance, and add `privateKeys` argument to relevant sync methods.
- @flutter: \[**breaking change**\] `SealdSdk` must now be instantiated from the root isolate, or you must pass the `rootIsolateToken` argument.
- @all: \[new feature\] Add the possibility to create TMR access to retrieve `encryptionSession`. Add `convertTmrAccesses` that can convert TMR accesses to classic access for a recipient.


# 0.4.0-beta.2 : 2024/01/05
- @flutter: \[bug fix\] On iOS, fix build of internal library to pass Apple validation.


# 0.4.0-beta.1 : 2023/12/20
- @ios: \[bug fix\] Fix random crash on iOS.


# 0.4.0-beta.0 : 2023/12/15
- @all: \[enhancement\] Automatically renew group keys when calling `AddGroupMembers` / `RemoveGroupMembers` and the group keys expire in less than 6 months.
- @all: \[enhancement\] Optimizing the time taken to retrieve a group for the first time.
- @all: \[enhancement\] Remove unused value `Count` from `DeviceMissingKeys` type.
- @all: \[**breaking change**\] Change arguments to SSKS Plugins initialization to make it more coherent with the main SDK.
- @all: \[enhancement\] Add a header with the version to API requests, to facilitate debugging.
- @all: \[enhancement\] Handle HTTP `423 - Locked` for all API call that can return it. (ie: sigchain handling request).
- @all: \[new feature\] Add `addProxySession` method (and its async version) on `EncryptionSession`, to add a proxy session to an existing session.
- @android: \[**breaking change**\] `encryptionSession.revokeRecipients` method (and its async version) now takes `recipientsIds` and `proxySessionsIds` as arguments, to be able to revoke proxy sessions.
- @ios: \[**breaking change**\] `[sealdEncryptionSession revokeRecipients:error:]` method replaced by `[sealdEncryptionSession revokeRecipientsIds:proxySessionsIds:error:]` (and its async version), to be able to revoke proxy sessions.
- @flutter: \[**breaking change**\] `encryptionSession.revokeRecipients` method (and its async version) now takes `recipientsIds` and `proxySessionsIds` as optional arguments, to be able to revoke proxy sessions.
- @all: \[**breaking change**\] All `EncryptionSession` revocation methods now return an instance of `RevokeResult`, which is a new class.
- @android: \[**breaking change**\] All `SealdSDK` session retrieval methods now take additional `lookupProxyKey` & `lookupGroupKey` optional arguments.
- @ios: \[**breaking change**\] All `SealdSdk` session retrieval methods now take additional `lookupProxyKey` & `lookupGroupKey` arguments.
- @flutter: \[new feature\] `sealdSdk.retrieveEncryptionSession` and `sealdSdk.retrieveEncryptionSessionAsync` methods now take additional `lookupProxyKey` & `lookupGroupKey` optional arguments.
- @all: \[new feature\] Instances of `EncryptionSession` expose how the session was retrieved in a new `retrievalDetails` field, which is an instance the new `EncryptionSessionRetrievalDetails` class.
- @flutter: \[enhancement\] All thrown exceptions are now instances of `SealdException`, with proper exposed error codes and details.
- @android: \[new feature\] Add `parseSessionIdFromFile`/`parseSessionIdFromBytes`/`parseSessionIdFromMessage` util functions.
- @ios: \[new feature\] Add `SealdUtils` class, and `[SealdUtils parseSessionIdFromFile:error:]`/`[SealdUtils parseSessionIdFromBytes:error:]`/`[SealdUtils parseSessionIdFromMessage:error:]` class methods.
- @flutter: \[new feature\] Add `parseSessionId` util function.
- @android: \[enhancement\] Add default value for `RecipientRights`. Default rights are: read: true, forward: true, revoke: false.
- @android: \[enhancement\] Add default api URL value, and empty array value. 
- @all: \[enhancement\] Various optimizations, minor bug fixes, and updates of dependencies.


# 0.3.0-beta.0 : 2023/10/13
- @flutter: \[**breaking change**\] Rename `EncryptionSession` class into `SealdEncryptionSession` for coherence.
- @flutter: \[enhancement\] Cleaner doc.
- @android: \[enhancement\] All thrown exceptions are now instances of `SealdException`, with proper exposed error codes and details.
- @ios: \[enhancement\] All returned errors are now of domain `SealdErrorDomain` and expose a `userInfo` object with proper error codes and details.
- @all: \[bug fix\] Handle edge case when searching for a user in the middle of their sigchain being updated.


# 0.2.0-beta.0 : 2023/09/07
- @all: \[enhancement\] Initial release with new unified build system.
- @ios: \[enhancement\] Auto-close SDK when object is deallocated. Closing manually is still recommended.
- @android: \[enhancement\] Auto-close SDK when object is deallocated. Closing manually is still recommended.
- @android: \[enhancement\] `sdk.close` is now correctly annotated with `@throws`.
- @all: \[new feature\] Add `sdk.retrieveEncryptionSessionFromBytes` method / `fileBytes` argument to `sdk.retrieveEncryptionSession`.
- @all: \[enhancement\] In base64 parsing for `dbb64SymKey`/`databaseEncryptionKeyB64`, now ignores new lines.
- @android: \[enhancement\] Update kotlin runtime.
