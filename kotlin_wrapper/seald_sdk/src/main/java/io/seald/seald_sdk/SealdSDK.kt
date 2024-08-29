package io.seald.seald_sdk

import kotlinx.coroutines.*
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.util.Base64

internal fun getRsaKey(size: Int = 4096): String {
    // Generate the RSA key pair
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(size)
    val keyPair = keyPairGenerator.generateKeyPair()

    val privateKeySpec = PKCS8EncodedKeySpec(keyPair.private.encoded) // Encode in PKCS8
    val privateKeyBase64 =
        Base64.getEncoder().encodeToString(privateKeySpec.encoded) // Convert the key to Base64

    return privateKeyBase64
}

fun generatePrivateKeys(keySize: Int = 4096): PreGeneratedKeys {
    val preGeneratedKeys = io.seald.seald_sdk_internals.mobile_sdk.PreGeneratedKeys()
    preGeneratedKeys.encryptionKey = getRsaKey(keySize)
    preGeneratedKeys.signingKey = getRsaKey(keySize)
    return PreGeneratedKeys(preGeneratedKeys)
}

suspend fun generatePrivateKeysAsync(keySize: Int = 4096): PreGeneratedKeys {
    val preGeneratedKeys = io.seald.seald_sdk_internals.mobile_sdk.PreGeneratedKeys()
    val scope = CoroutineScope(Dispatchers.Default)

    val deferredFirstKey = scope.async { getRsaKey(keySize) }
    val deferredSecondKey = scope.async { getRsaKey(keySize) }
    preGeneratedKeys.encryptionKey = deferredFirstKey.await()
    preGeneratedKeys.signingKey = deferredSecondKey.await()

    return PreGeneratedKeys(preGeneratedKeys)
}

/**
 * This is the main class for the Seald SDK. It represents an instance of the Seald SDK.
 * @param apiURL The Seald server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param databasePath The path where to store the local Seald database. If no path is passed, uses an in-memory only database.
 * @param databaseEncryptionKey The encryption key with which to encrypt the local Seald database. Required when passing `databasePath`. This **must** be the Base64 string encoding of a cryptographically random buffer of 64 bytes.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `false` if you want to enable colors in the log output. Defaults to `true`.
 * @param encryptionSessionCacheTTL The duration of cache lifetime. `null` to cache forever. Default to `0` (no cache).
 * @param keySize The Asymmetric key size for newly generated keys. Defaults to `4096`. Warning: for security, it is extremely not recommended to lower this value. For advanced use only.
 * @throws SealdException
 */
class SealdSDK
    @JvmOverloads
    @Throws(SealdException::class)
    constructor(
        apiURL: String = "https://api.seald.io/",
        appId: String,
        databasePath: String? = null,
        databaseEncryptionKey: ByteArray? = null,
        instanceName: String = "SealdSDK",
        logLevel: Byte = 0,
        logNoColor: Boolean = true,
        encryptionSessionCacheTTL: Duration? = Duration.ZERO,
        private val keySize: Int = 4096,
    ) {
        private var mobileSDK: io.seald.seald_sdk_internals.mobile_sdk.MobileSDK

        init {
            val initOpts = io.seald.seald_sdk_internals.mobile_sdk.SdkInitializeOptions()
            initOpts.apiURL = apiURL
            initOpts.appId = appId
            initOpts.databasePath = databasePath ?: ""
            initOpts.databaseEncryptionKey = databaseEncryptionKey
            initOpts.instanceName = instanceName
            initOpts.platform = "android"
            initOpts.logLevel = logLevel
            initOpts.logNoColor = logNoColor
            initOpts.encryptionSessionCacheTTL = encryptionSessionCacheTTL?.toMillis() ?: -1
            initOpts.keySize = keySize.toLong()
            mobileSDK =
                convertExceptions {
                    io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk.initialize(initOpts)
                }
        }

        /**
         * Close the current SDK instance. This frees any lock on the current database. After calling close, the instance cannot be used anymore.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun close() {
            convertExceptions {
                mobileSDK.close()
            }
        }

        /**
         * Close the current SDK instance. This frees any lock on the current database. After calling close, the instance cannot be used anymore.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun closeAsync() =
            withContext(Dispatchers.Default) {
                close()
            }

        /**
         * Try to close when the instance is garbage collected. It's only implemented as a safety net, you should call `sdk.close()` directly.
         */
        protected fun finalize() {
            close()
        }

        // Account

        /**
         * Create a new Seald SDK account for this Seald SDK instance.
         * This function can only be called if the current SDK instance does not have an account yet.
         * @param signupJWT The JWT to allow this SDK instance to create an account.
         * @param displayName An optional name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user.
         * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
         * @return An [AccountInfo] instance, containing the Seald ID of the newly created Seald user, the device ID, and the date at which the current device keys will expire.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun createAccount(
            signupJWT: String,
            displayName: String = "",
            deviceName: String = "",
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ): AccountInfo {
            convertExceptions {
                val createAccountOpts = io.seald.seald_sdk_internals.mobile_sdk.CreateAccountOptions()
                createAccountOpts.signupJWT = signupJWT
                createAccountOpts.displayName = displayName
                createAccountOpts.deviceName = deviceName
                createAccountOpts.expireAfter = expireAfter.toMillis()
                createAccountOpts.preGeneratedKeys = privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys

                val accountInfo = mobileSDK.createAccount(createAccountOpts)
                return AccountInfo.fromMobileSdk(accountInfo)!!
            }
        }

        /**
         * Create a new Seald SDK account for this Seald SDK instance.
         * This function can only be called if the current SDK instance does not have an account yet.
         * @param signupJWT The JWT to allow this SDK instance to create an account.
         * @param displayName An optional name for the user to create. This is metadata, useful on the Seald Dashboard for recognizing this user.
         * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the created device key will be valid without renewal. Optional, defaults to 5 years.
         * @return An [AccountInfo] instance, containing the Seald ID of the newly created Seald user, the device ID, and the date at which the current device keys will expire.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun createAccountAsync(
            signupJWT: String,
            displayName: String = "",
            deviceName: String = "",
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ): AccountInfo =
            withContext(Dispatchers.Default) {
                return@withContext createAccount(
                    signupJWT,
                    displayName,
                    deviceName,
                    privateKeys ?: generatePrivateKeysAsync(),
                    expireAfter,
                )
            }

        /**
         * Return information about the current account, or `null` if there is none.
         * @return An [AccountInfo] instance, containing the Seald ID of the local Seald user, the device ID, and the date at which the current device keys will expire. `null` if there is no local user.
         */
        fun getCurrentAccountInfo(): AccountInfo? {
            val accountInfo = mobileSDK.getCurrentAccountInfo()
            return AccountInfo.fromMobileSdk(accountInfo)
        }

        /**
         * Return information about the current account, or `null` if there is none.
         * @return An [AccountInfo] instance, containing the Seald ID of the local Seald user, the device ID, and the date at which the current device keys will expire. `null` if there is no local user.
         */
        suspend fun getCurrentAccountInfoAsync(): AccountInfo? =
            withContext(Dispatchers.IO) {
                return@withContext getCurrentAccountInfo()
            }

        /**
         * Updates the locally known information about the current device.
         * You should never have to call this manually, except if you getting `null` in [AccountInfo.deviceExpires],
         * which can happen if migrating from an older version of the SDK,
         * or if the internal call to updateCurrentDevice failed when calling [SealdSDK.importIdentity].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun updateCurrentDevice() {
            convertExceptions {
                mobileSDK.updateCurrentDevice()
            }
        }

        /**
         * Updates the locally known information about the current device.
         * You should never have to call this manually, except if you getting `null` in [AccountInfo.deviceExpires],
         * which can happen if migrating from an older version of the SDK,
         * or if the internal call to updateCurrentDevice failed when calling [SealdSDK.importIdentity].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun updateCurrentDeviceAsync() =
            withContext(Dispatchers.Default) {
                updateCurrentDevice()
            }

        /**
         * Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun prepareRenew(privateKeys: PreGeneratedKeys? = null): ByteArray {
            convertExceptions {
                return mobileSDK.prepareRenew(privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys)
            }
        }

        /**
         * Prepare a private key renewal, so it can be stored on SSKS without risk of loss during the actual renew
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun prepareRenewAsync(privateKeys: PreGeneratedKeys? = null) =
            withContext(Dispatchers.Default) {
                return@withContext prepareRenew(privateKeys ?: generatePrivateKeysAsync())
            }

        /**
         * Renew the keys of the current device, extending their validity.
         * If the current device has expired, you will need to call [renewKeys] before you are able to do anything else.
         * Warning: if the identity of the current device is stored externally, for example on SSKS,
         * you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
         *
         * @param preparedRenewal Optional. The preparedRenewal generated by calling [SealdSDK.prepareRenew]. If preparedRenewal is given, privateKeys will be ignored.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun renewKeys(
            preparedRenewal: ByteArray? = null,
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ) {
            convertExceptions {
                val renewKeysOpts =
                    io.seald.seald_sdk_internals.mobile_sdk.RenewKeysOptions()
                renewKeysOpts.expireAfter = expireAfter.toMillis()
                if (preparedRenewal == null) {
                    renewKeysOpts.preGeneratedKeys = privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys
                }
                renewKeysOpts.preparedRenewal = preparedRenewal
                mobileSDK.renewKeys(renewKeysOpts)
            }
        }

        /**
         * Renew the keys of the current device, extending their validity.
         * If the current device has expired, you will need to call [renewKeys] before you are able to do anything else.
         * Warning: if the identity of the current device is stored externally, for example on SSKS,
         * you will want to re-export it and store it again, otherwise the previously stored identity will not be recognized anymore.
         *
         * @param preparedRenewal Optional. The preparedRenewal generated by calling [SealdSDK.prepareRenew]. If preparedRenewal is given, privateKeys will be ignored.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the renewed device key will be valid without further renewal. Optional, defaults to 5 years.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun renewKeysAsync(
            preparedRenewal: ByteArray? = null,
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ) = withContext(Dispatchers.Default) {
            val preGenKeys = if (preparedRenewal == null) privateKeys ?: generatePrivateKeysAsync() else null
            return@withContext renewKeys(preparedRenewal = preparedRenewal, privateKeys = preGenKeys, expireAfter = expireAfter)
        }

        /**
         * Create a new sub-identity, or new device, for the current user account.
         * After creating this new device, you will probably want to call [SealdSDK.massReencrypt],
         * so that the newly created device will be able to decrypt [EncryptionSession]s previously created for this account.
         * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
         * @return A [CreateSubIdentityResponse] instance, containing `deviceId` (the ID of the newly created device) and `backupKey` (the identity export of the newly created sub-identity).
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun createSubIdentity(
            deviceName: String = "",
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ): CreateSubIdentityResponse {
            convertExceptions {
                val createSubIdentityOpts =
                    io.seald.seald_sdk_internals.mobile_sdk.CreateSubIdentityOptions()
                createSubIdentityOpts.deviceName = deviceName
                createSubIdentityOpts.expireAfter = expireAfter.toMillis()
                createSubIdentityOpts.preGeneratedKeys = privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys

                val createSubIdentityResponse = mobileSDK.createSubIdentity(createSubIdentityOpts)
                return CreateSubIdentityResponse(
                    deviceId = createSubIdentityResponse.deviceId,
                    backupKey = createSubIdentityResponse.backupKey,
                )
            }
        }

        /**
         * Create a new sub-identity, or new device, for the current user account.
         * After creating this new device, you will probably want to call [SealdSDK.massReencrypt],
         * so that the newly created device will be able to decrypt [EncryptionSession]s previously created for this account.
         * @param deviceName An optional name for the device to create. This is metadata, useful on the Seald Dashboard for recognizing this device. Optional.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @param expireAfter The duration during which the device key for the device to create will be valid without renewal. Optional, defaults to 5 years.
         * @return A [CreateSubIdentityResponse] instance, containing `deviceId` (the ID of the newly created device) and `backupKey` (the identity export of the newly created sub-identity).
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun createSubIdentityAsync(
            deviceName: String = "",
            privateKeys: PreGeneratedKeys? = null,
            expireAfter: Duration = Duration.ofDays(365 * 5),
        ): CreateSubIdentityResponse =
            withContext(Dispatchers.Default) {
                return@withContext createSubIdentity(
                    deviceName = deviceName,
                    privateKeys = privateKeys ?: generatePrivateKeysAsync(),
                    expireAfter = expireAfter,
                )
            }

        /**
         * Load an identity export into the current SDK instance.
         * This function can only be called if the current SDK instance does not have an account yet.
         * @param identity The identity export that this SDK instance should import.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun importIdentity(identity: ByteArray) {
            convertExceptions {
                return mobileSDK.importIdentity(identity)
            }
        }

        /**
         * Load an identity export into the current SDK instance.
         * This function can only be called if the current SDK instance does not have an account yet.
         * @param identity The identity export that this SDK instance should import.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun importIdentityAsync(identity: ByteArray) =
            withContext(Dispatchers.Default) {
                importIdentity(identity)
            }

        /**
         * Export the current device as an identity export.
         * @return The identity export of the current identity of this SDK instance.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun exportIdentity(): ByteArray {
            convertExceptions {
                return mobileSDK.exportIdentity()
            }
        }

        /**
         * Export the current device as an identity export.
         * @return The identity export of the current identity of this SDK instance.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun exportIdentityAsync(): ByteArray =
            withContext(Dispatchers.IO) {
                return@withContext exportIdentity()
            }

        /**
         * Push a given JWT to the Seald server, for example to add a connector to the current account.
         * @param jwt The JWT to push
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun pushJWT(jwt: String) {
            convertExceptions {
                mobileSDK.pushJWT(jwt)
            }
        }

        /**
         * Push a given JWT to the Seald server, for example to add a connector to the current account.
         * @param jwt The JWT to push
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun pushJWTAsync(jwt: String) =
            withContext(Dispatchers.IO) {
                pushJWT(jwt)
            }

        /**
         * Just call the Seald server, without doing anything.
         * This may be used for example to verify that the current instance has a valid identity.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun heartbeat() {
            convertExceptions {
                mobileSDK.heartbeat()
            }
        }

        /**
         * Just call the Seald server, without doing anything.
         * This may be used for example to verify that the current instance has a valid identity.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun heartbeatAsync() =
            withContext(Dispatchers.IO) {
                heartbeat()
            }

        // Groups

        /**
         * Create a group, and returns the created group's ID.
         * [admins] must also be members.
         * [admins] must include yourself.
         * @param groupName A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
         * @param members The Seald IDs of the members to add to the group. Must include yourself.
         * @param admins The Seald IDs of the members to also add as group admins. Must include yourself.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @return The ID of the created group.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun createGroup(
            groupName: String,
            members: Array<String>,
            admins: Array<String>,
            privateKeys: PreGeneratedKeys? = null,
        ): String {
            convertExceptions {
                return mobileSDK.createGroup(
                    groupName,
                    arrayToStringArray(members),
                    arrayToStringArray(admins),
                    privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys,
                )
            }
        }

        /**
         * Create a group, and returns the created group's ID.
         * [admins] must also be members.
         * [admins] must include yourself.
         * @param groupName A name for the group. This is metadata, useful on the Seald Dashboard for recognizing this user.
         * @param members The Seald IDs of the members to add to the group. Must include yourself.
         * @param admins The Seald IDs of the members to also add as group admins. Must include yourself.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @return The ID of the created group.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun createGroupAsync(
            groupName: String,
            members: Array<String>,
            admins: Array<String>,
            privateKeys: PreGeneratedKeys? = null,
        ): String =
            withContext(Dispatchers.Default) {
                return@withContext createGroup(groupName, members, admins, privateKeys ?: generatePrivateKeysAsync())
            }

        /**
         * Add members to a group.
         * Can only be done by a group administrator.
         * Can also specify which of these newly added group members should also be admins.
         * @param groupId The group in which to add members.
         * @param membersToAdd The Seald IDs of the members to add to the group.
         * @param adminsToSet The Seald IDs of the newly added members to also set as group admins.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun addGroupMembers(
            groupId: String,
            membersToAdd: Array<String>,
            adminsToSet: Array<String> = emptyArray(),
            privateKeys: PreGeneratedKeys? = null,
        ) {
            convertExceptions {
                if (mobileSDK.shouldRenewGroup(groupId)) {
                    mobileSDK.renewGroupKey(groupId, privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys)
                }
                mobileSDK.addGroupMembers(
                    groupId,
                    arrayToStringArray(membersToAdd),
                    arrayToStringArray(adminsToSet),
                )
            }
        }

        /**
         * Add members to a group.
         * Can only be done by a group administrator.
         * Can also specify which of these newly added group members should also be admins.
         * @param groupId The group in which to add members.
         * @param membersToAdd The Seald IDs of the members to add to the group.
         * @param adminsToSet The Seald IDs of the newly added members to also set as group admins.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun addGroupMembersAsync(
            groupId: String,
            membersToAdd: Array<String>,
            adminsToSet: Array<String> = emptyArray(),
            privateKeys: PreGeneratedKeys? = null,
        ) = withContext(Dispatchers.Default) {
            addGroupMembers(groupId, membersToAdd, adminsToSet, privateKeys)
        }

        /**
         * Remove members from the group.
         * Can only be done by a group administrator.
         * You should call [renewGroupKey] after this.
         * @param groupId The group from which to remove members.
         * @param membersToRemove The Seald IDs of the members to remove from the group.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun removeGroupMembers(
            groupId: String,
            membersToRemove: Array<String>,
            privateKeys: PreGeneratedKeys? = null,
        ) {
            convertExceptions {
                if (mobileSDK.shouldRenewGroup(groupId)) {
                    mobileSDK.renewGroupKey(groupId, privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys)
                }
                mobileSDK.removeGroupMembers(groupId, arrayToStringArray(membersToRemove))
            }
        }

        /**
         * Remove members from the group.
         * Can only be done by a group administrator.
         * You should call [renewGroupKey] after this.
         * @param groupId The group from which to remove members.
         * @param membersToRemove The Seald IDs of the members to remove from the group.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun removeGroupMembersAsync(
            groupId: String,
            membersToRemove: Array<String>,
            privateKeys: PreGeneratedKeys? = null,
        ) = withContext(Dispatchers.Default) {
            removeGroupMembers(groupId, membersToRemove, privateKeys)
        }

        /**
         * Renew the group's private key.
         * Can only be done by a group administrator.
         * Should be called after removing members from the group.
         * @param groupId The group for which to renew the private key.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun renewGroupKey(
            groupId: String,
            privateKeys: PreGeneratedKeys? = null,
        ) {
            convertExceptions {
                mobileSDK.renewGroupKey(groupId, privateKeys?.preGeneratedKeys ?: generatePrivateKeys().preGeneratedKeys)
            }
        }

        /**
         * Renew the group's private key.
         * Can only be done by a group administrator.
         * Should be called after removing members from the group.
         * @param groupId The group for which to renew the private key.
         * @param privateKeys Optional. Pre-generated private keys, returned by a call to [generatePrivateKeys] or [generatePrivateKeysAsync].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun renewGroupKeyAsync(
            groupId: String,
            privateKeys: PreGeneratedKeys? = null,
        ) = withContext(Dispatchers.Default) {
            renewGroupKey(groupId, privateKeys ?: generatePrivateKeysAsync())
        }

        /**
         * Add some existing group members to the group admins, and/or removes admin status from some existing group admins.
         * Can only be done by a group administrator.
         * @param groupId The group for which to set admins.
         * @param addToAdmins The Seald IDs of existing group members to add as group admins.
         * @param removeFromAdmins The Seald IDs of existing group members to remove from group admins.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun setGroupAdmins(
            groupId: String,
            addToAdmins: Array<String> = emptyArray(),
            removeFromAdmins: Array<String> = emptyArray(),
        ) {
            convertExceptions {
                mobileSDK.setGroupAdmins(
                    groupId,
                    arrayToStringArray(addToAdmins),
                    arrayToStringArray(removeFromAdmins),
                )
            }
        }

        /**
         * Add some existing group members to the group admins, and/or removes admin status from some existing group admins.
         * Can only be done by a group administrator.
         * @param groupId The group for which to set admins.
         * @param addToAdmins The Seald IDs of existing group members to add as group admins.
         * @param removeFromAdmins The Seald IDs of existing group members to remove from group admins.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun setGroupAdminsAsync(
            groupId: String,
            addToAdmins: Array<String> = emptyArray(),
            removeFromAdmins: Array<String> = emptyArray(),
        ) = withContext(Dispatchers.IO) {
            setGroupAdmins(groupId, addToAdmins, removeFromAdmins)
        }

        // EncryptionSession

        /**
         * Create an encryption session, and returns the associated [EncryptionSession] instance,
         * with which you can then encrypt / decrypt multiple messages.
         * Warning : if you want to be able to retrieve the session later,
         * you must put your own UserId in the [recipients] argument.
         * @param recipients The Seald IDs with the associated rights of users to retrieve this session.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @return The created [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun createEncryptionSession(
            recipients: Array<RecipientWithRights>,
            useCache: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es = mobileSDK.createEncryptionSession(RecipientWithRights.toMobileSdkArray(recipients), useCache)
                return EncryptionSession(es)
            }
        }

        /**
         * Create an encryption session, and returns the associated [EncryptionSession] instance,
         * with which you can then encrypt / decrypt multiple messages.
         * Warning : if you want to be able to retrieve the session later,
         * you must put your own UserId in the [recipients] argument.
         * @param recipients The Seald IDs with the associated rights of users to retrieve this session.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @return The created [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun createEncryptionSessionAsync(
            recipients: Array<RecipientWithRights>,
            useCache: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext createEncryptionSession(recipients, useCache)
            }

        /**
         * Retrieve an encryption session with the [sessionId], and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt multiple messages.
         * @param sessionId The ID of the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveEncryptionSession(
            sessionId: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es = mobileSDK.retrieveEncryptionSession(sessionId, useCache, lookupProxyKey, lookupGroupKey)
                return EncryptionSession(es)
            }
        }

        /**
         * Retrieve an encryption session with the [sessionId], and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt multiple messages.
         * @param sessionId The ID of the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveEncryptionSessionAsync(
            sessionId: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext retrieveEncryptionSession(sessionId, useCache, lookupProxyKey, lookupGroupKey)
            }

        /**
         * Retrieve an encryption session from a seald message, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt multiple messages.
         * @param message Any message belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveEncryptionSessionFromMessage(
            message: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es = mobileSDK.retrieveEncryptionSessionFromMessage(message, useCache, lookupProxyKey, lookupGroupKey)
                return EncryptionSession(es)
            }
        }

        /**
         * Retrieve an encryption session from a seald message, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt multiple messages.
         * @param message Any message belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveEncryptionSessionFromMessageAsync(
            message: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext retrieveEncryptionSessionFromMessage(message, useCache, lookupProxyKey, lookupGroupKey)
            }

        /**
         * Retrieve an encryption session from a file URI, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param fileUri Any encrypted file belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveEncryptionSessionFromFile(
            fileUri: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es = mobileSDK.retrieveEncryptionSessionFromFile(fileUri, useCache, lookupProxyKey, lookupGroupKey)
                return EncryptionSession(es)
            }
        }

        /**
         * Retrieve an encryption session from a file URI, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param fileUri Any encrypted file belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveEncryptionSessionFromFileAsync(
            fileUri: String,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext retrieveEncryptionSessionFromFile(fileUri, useCache, lookupProxyKey, lookupGroupKey)
            }

        /**
         * Retrieve an encryption session from a ByteArray, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param fileByteArray A ByteArray of an encrypted file belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveEncryptionSessionFromBytes(
            fileByteArray: ByteArray,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es = mobileSDK.retrieveEncryptionSessionFromBytes(fileByteArray, useCache, lookupProxyKey, lookupGroupKey)
                return EncryptionSession(es)
            }
        }

        /**
         * Retrieve an encryption session from a ByteArray, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param fileByteArray A ByteArray of an encrypted file belonging to the session to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the session via a proxy.
         * @param lookupGroupKey Whether or not to try retrieving the session via a group.
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveEncryptionSessionFromBytesAsync(
            fileByteArray: ByteArray,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext retrieveEncryptionSessionFromBytes(fileByteArray, useCache, lookupProxyKey, lookupGroupKey)
            }

        /**
         * Retrieve an encryption session with a  TMR access JWT, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param tmrJWT The TMR JWT.
         * @param sessionId The id of the session to retrieve.
         * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
         * @param tmrAccessesFilters Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
         * @param tryIfMultiple If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveEncryptionSessionByTmr(
            tmrJWT: String,
            sessionId: String,
            overEncryptionKey: ByteArray,
            tmrAccessesFilters: TMRAccessesRetrievalFilters? = null,
            tryIfMultiple: Boolean = true,
            useCache: Boolean = true,
        ): EncryptionSession {
            convertExceptions {
                val es =
                    mobileSDK.retrieveEncryptionSessionByTmr(
                        tmrJWT,
                        sessionId,
                        overEncryptionKey,
                        tmrAccessesFilters?.toMobileSdk(),
                        tryIfMultiple,
                        useCache,
                    )
                return EncryptionSession(es)
            }
        }

        /**
         * Retrieve an encryption session with a  TMR access JWT, and returns the associated
         * [EncryptionSession] instance, with which you can then encrypt / decrypt this file.
         * @param tmrJWT The TMR JWT.
         * @param sessionId The id of the session to retrieve.
         * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
         * @param tmrAccessesFilters Retrieval tmr accesses filters. If multiple TMR Accesses for this session are associated with the auth factor, filter out the unwanted ones.
         * @param tryIfMultiple If multiple accesses are found for this session associated with the auth factor, whether or not to loop over all of them to find the wanted one.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @return The retrieved [EncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveEncryptionSessionByTmrAsync(
            tmrJWT: String,
            sessionId: String,
            overEncryptionKey: ByteArray,
            tmrAccessesFilters: TMRAccessesRetrievalFilters? = null,
            tryIfMultiple: Boolean = true,
            useCache: Boolean = true,
        ): EncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext retrieveEncryptionSessionByTmr(
                    tmrJWT,
                    sessionId,
                    overEncryptionKey,
                    tmrAccessesFilters,
                    tryIfMultiple,
                    useCache,
                )
            }

        /**
         * Retrieve multiple encryption sessions with an Array of sessionIds, and return an
         * Array of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
         * The returned array of EncryptionSession instances is in the same order as the input array.
         *
         * @param sessionIds The IDs of sessions to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the sessions via proxies.
         * @param lookupGroupKey Whether or not to try retrieving the sessions via groups.
         * @return The Array of retrieved [EncryptionSession] instances.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun retrieveMultipleEncryptionSessions(
            sessionIds: Array<String>,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): Array<EncryptionSession> {
            convertExceptions {
                val array =
                    mobileSDK.retrieveMultipleEncryptionSessions(
                        arrayToStringArray(sessionIds),
                        useCache,
                        lookupProxyKey,
                        lookupGroupKey,
                    )
                return EncryptionSession.fromMobileSdkArray(array)
            }
        }

        /**
         * Retrieve multiple encryption sessions with an Array of sessionIds, and return an
         * Array of the associated EncryptionSession instances, with which you can then encrypt / decrypt multiple messages.
         * The returned array of EncryptionSession instances is in the same order as the input array.
         *
         * @param sessionIds The IDs of sessions to retrieve.
         * @param useCache Whether or not to use the cache (if enabled globally).
         * @param lookupProxyKey Whether or not to try retrieving the sessions via proxies.
         * @param lookupGroupKey Whether or not to try retrieving the sessions via groups.
         * @return The Array of retrieved [EncryptionSession] instances.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun retrieveMultipleEncryptionSessionsAsync(
            sessionIds: Array<String>,
            useCache: Boolean = true,
            lookupProxyKey: Boolean = false,
            lookupGroupKey: Boolean = true,
        ): Array<EncryptionSession> =
            withContext(Dispatchers.Default) {
                return@withContext retrieveMultipleEncryptionSessions(
                    sessionIds,
                    useCache,
                    lookupProxyKey,
                    lookupGroupKey,
                )
            }

        // Connectors

        /**
         * Get all the info for the given connectors to look for, updates the local cache of connectors,
         * and returns a slice with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
         * If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
         * with the details of the missing connector.
         *
         * @param connectorTypeValues An Array of [ConnectorTypeValue] instances.
         * @return An Array of Strings with the Seald IDs of the users corresponding to these connectors.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun getSealdIdsFromConnectors(connectorTypeValues: Array<ConnectorTypeValue>): Array<String> {
            convertExceptions {
                val res =
                    mobileSDK.getSealdIdsFromConnectors(
                        ConnectorTypeValue.toMobileSdkArray(connectorTypeValues),
                    )
                return stringArrayToArray(res)
            }
        }

        /**
         * Get all the info for the given connectors to look for, updates the local cache of connectors,
         * and returns a slice with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
         * If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
         * with the details of the missing connector.
         *
         * @param connectorTypeValues An Array of [ConnectorTypeValue] instances.
         * @return An Array of Strings with the Seald IDs of the users corresponding to these connectors.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun getSealdIdsFromConnectorsAsync(connectorTypeValues: Array<ConnectorTypeValue>): Array<String> =
            withContext(Dispatchers.IO) {
                return@withContext getSealdIdsFromConnectors(connectorTypeValues)
            }

        /**
         * List all connectors know locally for a given sealdId.
         *
         * @param sealdId The Seald ID for which to list connectors
         * @return An Array of [Connector] instances.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun getConnectorsFromSealdId(sealdId: String): Array<Connector> {
            convertExceptions {
                val res = mobileSDK.getConnectorsFromSealdId(sealdId)
                return Connector.fromMobileSdkArray(res)
            }
        }

        /**
         * List all connectors know locally for a given sealdId.
         *
         * @param sealdId The Seald ID for which to list connectors
         * @return An Array of [Connector] instances.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun getConnectorsFromSealdIdAsync(sealdId: String): Array<Connector> =
            withContext(Dispatchers.IO) {
                return@withContext getConnectorsFromSealdId(sealdId)
            }

        /**
         * Add a connector to the current identity.
         * If no preValidationToken is given, the connector will need to be validated before use.
         *
         * @param value The value of the connector to add.
         * @param connectorType The type of the connector.
         * @param preValidationToken Given by your server to authorize the adding of a connector.
         * @return The created [Connector].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun addConnector(
            value: String,
            connectorType: ConnectorType,
            preValidationToken: PreValidationToken? = null,
        ): Connector {
            convertExceptions {
                val res =
                    mobileSDK.addConnector(value, connectorType.type, preValidationToken?.toMobileSdk())
                return Connector.fromMobileSdk(res)
            }
        }

        /**
         * Add a connector to the current identity.
         * If no preValidationToken is given, the connector will need to be validated before use.
         *
         * @param value The value of the connector to add.
         * @param connectorType The type of the connector.
         * @param preValidationToken Given by your server to authorize the adding of a connector.
         * @return The created [Connector].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun addConnectorAsync(
            value: String,
            connectorType: ConnectorType,
            preValidationToken: PreValidationToken? = null,
        ): Connector =
            withContext(Dispatchers.IO) {
                return@withContext addConnector(value, connectorType, preValidationToken)
            }

        /**
         * Validate an added connector that was added without a preValidationToken.
         *
         * @param connectorId The ID of the connector to validate.
         * @param challenge The challenge.
         * @return The modified [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun validateConnector(
            connectorId: String,
            challenge: String,
        ): Connector {
            convertExceptions {
                val res = mobileSDK.validateConnector(connectorId, challenge)
                return Connector.fromMobileSdk(res)
            }
        }

        /**
         * Validate an added connector that was added without a preValidationToken.
         *
         * @param connectorId The ID of the connector to validate.
         * @param challenge The challenge.
         * @return The modified [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun validateConnectorAsync(
            connectorId: String,
            challenge: String,
        ): Connector =
            withContext(Dispatchers.IO) {
                return@withContext validateConnector(connectorId, challenge)
            }

        /**
         * Remove a connector belonging to the current account.
         *
         * @param connectorId The ID of the connector to remove.
         * @return The modified [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun removeConnector(connectorId: String): Connector {
            convertExceptions {
                val res = mobileSDK.removeConnector(connectorId)
                return Connector.fromMobileSdk(res)
            }
        }

        /**
         * Remove a connector belonging to the current account.
         *
         * @param connectorId The ID of the connector to remove.
         * @return The modified [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun removeConnectorAsync(connectorId: String): Connector =
            withContext(Dispatchers.IO) {
                return@withContext removeConnector(connectorId)
            }

        /**
         * List connectors associated to the current account.
         *
         * @return The array of connectors associated to the current account.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun listConnectors(): Array<Connector> {
            convertExceptions {
                val res = mobileSDK.listConnectors()
                return Connector.fromMobileSdkArray(res)
            }
        }

        /**
         * List connectors associated to the current account.
         *
         * @return The array of connectors associated to the current account.
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun listConnectorsAsync(): Array<Connector> =
            withContext(Dispatchers.IO) {
                return@withContext listConnectors()
            }

        /**
         * Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
         *
         * @param connectorId The ID of the connector to retrieve.
         * @return The [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun retrieveConnector(connectorId: String): Connector {
            convertExceptions {
                val res = mobileSDK.retrieveConnector(connectorId)
                return Connector.fromMobileSdk(res)
            }
        }

        /**
         * Retrieve a connector by its `connectorId`, then updates the local cache of connectors.
         *
         * @param connectorId The ID of the connector to retrieve.
         * @return The [Connector].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        suspend fun retrieveConnectorAsync(connectorId: String): Connector =
            withContext(Dispatchers.IO) {
                return@withContext retrieveConnector(connectorId)
            }

        // Reencrypt

        /**
         * Retrieve, re-encrypt, and add missing keys for a certain device.
         *
         * @param deviceId The ID of the device for which to re-rencrypt.
         * @param options A [MassReencryptOptions] instance.
         * @return A [MassReencryptResponse] instance, containing the number of re-encrypted keys, and the number of keys for which re-encryption failed.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun massReencrypt(
            deviceId: String,
            options: MassReencryptOptions = MassReencryptOptions(),
        ): MassReencryptResponse {
            convertExceptions {
                val res = mobileSDK.massReencrypt(deviceId, options.toMobileSdk())
                return MassReencryptResponse.fromMobileSdk(res)
            }
        }

        /**
         * Retrieve, re-encrypt, and add missing keys for a certain device.
         *
         * @param deviceId The ID of the device for which to re-rencrypt.
         * @param options A [MassReencryptOptions] instance.
         * @return A [MassReencryptResponse] instance, containing the number of re-encrypted keys, and the number of keys for which re-encryption failed.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun massReencryptAsync(
            deviceId: String,
            options: MassReencryptOptions = MassReencryptOptions(),
        ): MassReencryptResponse =
            withContext(Dispatchers.Default) {
                return@withContext massReencrypt(deviceId, options)
            }

        /**
         * List which of the devices of the current account are missing keys,
         * so you can call [SealdSDK.massReencrypt] for them.
         *
         * @param forceLocalAccountUpdate Whether to update the local account
         * @return An [Array] of [DeviceMissingKeys] instances, containing the ID of the device.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun devicesMissingKeys(forceLocalAccountUpdate: Boolean = false): Array<DeviceMissingKeys> {
            convertExceptions {
                val res = mobileSDK.devicesMissingKeys(forceLocalAccountUpdate)
                return DeviceMissingKeys.fromMobileSdkArray(res)
            }
        }

        /**
         * List which of the devices of the current account are missing keys,
         * so you can call [SealdSDK.massReencrypt] for them.
         *
         * @param forceLocalAccountUpdate Whether to update the local account
         * @return An [Array] of [DeviceMissingKeys] instances, containing the ID of the device.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun devicesMissingKeysAsync(forceLocalAccountUpdate: Boolean = false): Array<DeviceMissingKeys> =
            withContext(Dispatchers.IO) {
                return@withContext devicesMissingKeys(forceLocalAccountUpdate)
            }

        /**
         * Get a user's sigchain transaction hash at index `position`.
         *
         * @param userId The Seald ID of the concerned user.
         * @param position Get the hash at the given position. -1 to get the last. Default to -1.
         * @return A [GetSigchainResponse] instance containing the hash and its position.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun getSigchainHash(
            userId: String,
            position: Long = -1,
        ): GetSigchainResponse {
            convertExceptions {
                val res = mobileSDK.getSigchainHash(userId, position)
                return GetSigchainResponse.fromMobileSdk(res)
            }
        }

        /**
         * Get a user's sigchain transaction hash at index `position`.
         *
         * @param userId The Seald ID of the concerned user.
         * @param position Get the hash at the given position. -1 to get the last. Default to -1.
         * @return A [String] containing the hash.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun getSigchainHashAsync(
            userId: String,
            position: Long = -1,
        ): GetSigchainResponse =
            withContext(Dispatchers.IO) {
                return@withContext getSigchainHash(userId, position)
            }

        /**
         * Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
         *
         * @param userId The Seald ID of the concerned user.
         * @param expectedHash The expected sigchain hash.
         * @param position Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
         * @return A [CheckSigchainResponse] instance containing the response.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun checkSigchainHash(
            userId: String,
            expectedHash: String,
            position: Long = -1,
        ): CheckSigchainResponse {
            convertExceptions {
                val res = mobileSDK.checkSigchainHash(userId, expectedHash, position)
                return CheckSigchainResponse.fromMobileSdk(res)
            }
        }

        /**
         * Verify if a given hash is included in the recipient's sigchain. Use the `position` option to check the hash of a specific sigchain transaction.
         *
         * @param userId The Seald ID of the concerned user.
         * @param expectedHash The expected sigchain hash.
         * @param position Position of the sigchain transaction against which to check the hash. -1 to check if the hash exist in the sigchain. Default to -1.
         * @return A [CheckSigchainResponse] instance containing the response.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun checkSigchainHashAsync(
            userId: String,
            expectedHash: String,
            position: Long = -1,
        ): CheckSigchainResponse =
            withContext(Dispatchers.IO) {
                return@withContext checkSigchainHash(userId, expectedHash, position)
            }

        /**
         * Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
         * All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
         *
         * @param tmrJWT The TMR JWT.
         * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
         * @param conversionFilters Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
         * @param deleteOnConvert Whether or not to delete the TMR access after conversion.
         * @return A [CheckSigchainResponse] instance containing the response.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun convertTmrAccesses(
            tmrJWT: String,
            overEncryptionKey: ByteArray,
            conversionFilters: TMRAccessesConvertFilters? = null,
            deleteOnConvert: Boolean = true,
        ): ConvertTmrAccessesResponse {
            convertExceptions {
                val res = mobileSDK.convertTmrAccesses(tmrJWT, overEncryptionKey, conversionFilters?.toMobileSdk(), deleteOnConvert)
                return ConvertTmrAccessesResponse.fromMobileSdk(res)
            }
        }

        /**
         * Convert all TMR Accesses addressed to a given auth factor and matching specified filters to classic message keys.
         * All TMR accesses matching the specified filters **must** have been encrypted with the same `overEncryptionKey`.
         *
         * @param tmrJWT The TMR JWT.
         * @param overEncryptionKey TMR over-encryption key. This *MUST* be a cryptographically random buffer of 64 bytes.
         * @param conversionFilters Convert tmr accesses filters. If multiple TMR Accesses with the auth factor, filter out the unwanted ones.
         * @param deleteOnConvert Whether or not to delete the TMR access after conversion.
         * @return A [CheckSigchainResponse] instance containing the response.
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun convertTmrAccessesAsync(
            tmrJWT: String,
            overEncryptionKey: ByteArray,
            conversionFilters: TMRAccessesConvertFilters? = null,
            deleteOnConvert: Boolean = true,
        ): ConvertTmrAccessesResponse =
            withContext(Dispatchers.IO) {
                return@withContext convertTmrAccesses(tmrJWT, overEncryptionKey, conversionFilters, deleteOnConvert)
            }
    }
