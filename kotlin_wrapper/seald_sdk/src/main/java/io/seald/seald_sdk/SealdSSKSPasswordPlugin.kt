package io.seald.seald_sdk

import kotlinx.coroutines.*

/**
 * The SealdSSKSPassword class allows to use the SSKS key storage service to store Seald identities
 * easily and securely, encrypted by a user password.
 *
 * @param ssksURL The SSKS server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `false` if you want to enable colors in the log output. Defaults to `true`.
 */
class SealdSSKSPasswordPlugin constructor(
    ssksURL: String = "https://ssks.seald.io/",
    appId: String,
    instanceName: String = "SealdSSKSPasswordPlugin",
    logLevel: Byte = 0,
    logNoColor: Boolean = true,
) {
    private var mobileSSKSPassword: io.seald.seald_sdk_internals.mobile_sdk.MobileSSKSPassword

    /**
     * @suppress
     */
    init {
        val initOpts =
            io.seald.seald_sdk_internals.mobile_sdk
                .SsksPasswordInitializeOptions()
        initOpts.ssksURL = ssksURL
        initOpts.appId = appId
        initOpts.instanceName = instanceName
        initOpts.platform = "android"
        initOpts.logLevel = logLevel
        initOpts.logNoColor = logNoColor

        mobileSSKSPassword =
            io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk
                .newSSKSPasswordPlugin(initOpts)
    }

    /**
     * Save the given identity for the given userId, encrypted with the given password.
     *
     * @param userId The ID of the userId.
     * @param password The password to encrypt the key.
     * @param identity The identity to save.
     * @return The SSKS ID of the stored identity, which can be used by your backend to manage it.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun saveIdentityFromPassword(
        userId: String,
        password: String,
        identity: ByteArray,
    ): String {
        convertExceptions {
            return mobileSSKSPassword.saveIdentityFromPassword(userId, password, identity)
        }
    }

    /**
     * Save the given identity for the given userId, encrypted with the given password.
     *
     * @param userId The ID of the userId.
     * @param password The password to encrypt the key.
     * @param identity The identity to save.
     * @return The SSKS ID of the stored identity, which can be used by your backend to manage it.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun saveIdentityFromPasswordAsync(
        userId: String,
        password: String,
        identity: ByteArray,
    ): String =
        withContext(Dispatchers.Default) {
            return@withContext saveIdentityFromPassword(userId, password, identity)
        }

    /**
     * Save the given identity for the given userId, encrypted with the given raw keys.
     *
     * @param userId The ID of the userId.
     * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
     * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param identity The identity to save.
     * @return The SSKS ID of the stored identity, which can be used by your backend to manage it.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun saveIdentityFromRawKeys(
        userId: String,
        rawStorageKey: String,
        rawEncryptionKey: ByteArray,
        identity: ByteArray,
    ): String {
        convertExceptions {
            return mobileSSKSPassword.saveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey, identity)
        }
    }

    /**
     * Save the given identity for the given userId, encrypted with the given raw keys.
     *
     * @param userId The ID of the userId.
     * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
     * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param identity The identity to save.
     * @return The SSKS ID of the stored identity, which can be used by your backend to manage it.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun saveIdentityFromRawKeysAsync(
        userId: String,
        rawStorageKey: String,
        rawEncryptionKey: ByteArray,
        identity: ByteArray,
    ): String =
        withContext(Dispatchers.Default) {
            return@withContext saveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey, identity)
        }

    /**
     * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
     *
     * If you use an incorrect password multiple times, the server may throttle your requests. In this
     * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
     * of seconds during which you cannot try again.
     *
     * @param userId The ID of the userId.
     * @param password The password to decrypt the key.
     * @return The clear identity as [ByteArray].
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun retrieveIdentityFromPassword(
        userId: String,
        password: String,
    ): ByteArray {
        convertExceptions {
            return mobileSSKSPassword.retrieveIdentityFromPassword(userId, password)
        }
    }

    /**
     * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given password.
     *
     * If you use an incorrect password multiple times, the server may throttle your requests. In this
     * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
     * of seconds during which you cannot try again.
     *
     * @param userId The ID of the userId.
     * @param password The password to decrypt the key.
     * @return The clear identity as [ByteArray].
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun retrieveIdentityFromPasswordAsync(
        userId: String,
        password: String,
    ): ByteArray =
        withContext(Dispatchers.Default) {
            return@withContext retrieveIdentityFromPassword(userId, password)
        }

    /**
     * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
     *
     * If you use an incorrect password multiple times, the server may throttle your requests. In this
     * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
     * of seconds during which you cannot try again.
     *
     * @param userId The ID of the userId.
     * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
     * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @return The clear identity as [ByteArray].
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun retrieveIdentityFromRawKeys(
        userId: String,
        rawStorageKey: String,
        rawEncryptionKey: ByteArray,
    ): ByteArray {
        convertExceptions {
            return mobileSSKSPassword.retrieveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey)
        }
    }

    /**
     * Retrieve the identity stored on the SSKS server for the given userId, and decrypt it with the given raw keys.
     *
     * If you use an incorrect password multiple times, the server may throttle your requests. In this
     * case, you will receive an error `Request throttled, retry after {N}s`, with `{N}` the number
     * of seconds during which you cannot try again.
     *
     * @param userId The ID of the userId.
     * @param rawStorageKey The key under which identity keys are stored. This *MUST* be a secret known only to this user of your app, and never to other users, as learning it will allow deleting the stored identities. Useful to change if you want to store multiple identities for the same `userId`. Allowed characters : `A-Za-z0-9+/=-_@.`. Max length is 256 characters.
     * @param rawEncryptionKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @return The clear identity as [ByteArray].
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun retrieveIdentityFromRawKeysAsync(
        userId: String,
        rawStorageKey: String,
        rawEncryptionKey: ByteArray,
    ): ByteArray =
        withContext(Dispatchers.Default) {
            return@withContext retrieveIdentityFromRawKeys(userId, rawStorageKey, rawEncryptionKey)
        }

    /**
     * Change the password use to encrypt the identity for the userId.
     *
     * @param userId The ID of the userId.
     * @param currentPassword The user's current password.
     * @param newPassword The new password.
     * @return The new SSKS ID of the stored identity.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun changeIdentityPassword(
        userId: String,
        currentPassword: String,
        newPassword: String,
    ): String {
        convertExceptions {
            return mobileSSKSPassword.changeIdentityPassword(userId, currentPassword, newPassword)
        }
    }

    /**
     * Change the password use to encrypt the identity for the userId.
     *
     * @param userId The ID of the userId.
     * @param currentPassword The user's current password.
     * @param newPassword The new password.
     * @return The new SSKS ID of the stored identity.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun changeIdentityPasswordAsync(
        userId: String,
        currentPassword: String,
        newPassword: String,
    ): String =
        withContext(Dispatchers.Default) {
            return@withContext changeIdentityPassword(userId, currentPassword, newPassword)
        }
}
