package io.seald.seald_sdk

import kotlinx.coroutines.*

/**
 * An encryption session, with which you can then encrypt / decrypt multiple messages or files.
 * This should not be instantiated directly, and should be either created with [SealdSDK.createEncryptionSession],
 * or retrieved with [SealdSDK.retrieveEncryptionSession]
 * or [SealdSDK.retrieveEncryptionSessionFromMessage].
 * @property sessionId The ID of this encryptionSession. Read-only.
 * @property retrievalDetails Details about how this session was retrieved: through a group, a proxy, or directly. Read-only.
 */
class EncryptionSession(encryptionSession: io.seald.seald_sdk_internals.mobile_sdk.MobileEncryptionSession) {
    private val es: io.seald.seald_sdk_internals.mobile_sdk.MobileEncryptionSession
    val retrievalDetails: EncryptionSessionRetrievalDetails

    /**
     * @suppress
     */
    init {
        es = encryptionSession
        retrievalDetails = EncryptionSessionRetrievalDetails.fromMobileSdk(encryptionSession.retrievalDetails)
    }

    val sessionId: String
        get() = this.es.id

    internal companion object {
        internal fun fromMobileSdkArray(
            array: io.seald.seald_sdk_internals.mobile_sdk.MobileEncryptionSessionArray,
        ): Array<EncryptionSession> {
            return Array(
                size = array.size().toInt(),
            ) { i -> EncryptionSession(array.get(i.toLong())) }
        }
    }

    /**
     * Add new recipients to this session.
     * These recipients will be able to read all encrypted messages of this session.
     * @param recipients RecipientWithRights The Seald IDs with the associated rights of users to add to this session.
     * @return A [Map<String, ActionStatus>] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun addRecipients(recipients: Array<RecipientWithRights>): Map<String, ActionStatus> {
        convertExceptions {
            val res = es.addRecipients(RecipientWithRights.toMobileSdkArray(recipients))
            return ActionStatus.fromMobileSdkArray(res)
        }
    }

    /**
     * Add new recipients to this session.
     * These recipients will be able to read all encrypted messages of this session.
     * @param recipients The Seald IDs with the associated rights of users to add to this session.
     * @return A [Map<String, ActionStatus>] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun addRecipientsAsync(recipients: Array<RecipientWithRights>): Map<String, ActionStatus> =
        withContext(Dispatchers.Default) {
            return@withContext addRecipients(recipients)
        }

    /**
     * Add a proxy session as a recipient of this session.
     * Any recipient of the proxy session will also be able to retrieve this session.
     * The current user has to be a direct recipient of the proxy session.
     * @param proxySessionId The ID of the session to add as proxy.
     * @param rights The rights to assign to this proxy.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun addProxySession(
        proxySessionId: String,
        rights: RecipientRights = RecipientRights(),
    ) {
        convertExceptions {
            return es.addProxySession(proxySessionId, rights.toMobileSdk())
        }
    }

    /**
     * Add a proxy session as a recipient of this session.
     * Any recipient of the proxy session will also be able to retrieve this session.
     * The current user has to be a direct recipient of the proxy session.
     * @param proxySessionId The ID of the session to add as proxy.
     * @param rights The ID of the session to add as proxy.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun addProxySessionAsync(
        proxySessionId: String,
        rights: RecipientRights = RecipientRights(),
    ) = withContext(Dispatchers.Default) {
        return@withContext addProxySession(proxySessionId, rights)
    }

    /**
     * Revoke some recipients or proxy sessions from this session.
     * If you want to revoke all recipients, see [revokeAll] instead.
     * If you want to revoke all recipients besides yourself, see [revokeOthers].
     * @param recipientsIds The Seald IDs of users to revoke from this session.
     * @param proxySessionsIds The IDs of proxy sessions to revoke from this session.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun revokeRecipients(
        recipientsIds: Array<String>,
        proxySessionsIds: Array<String>,
    ): RevokeResult {
        convertExceptions {
            val res = es.revokeRecipients(arrayToStringArray(recipientsIds), arrayToStringArray(proxySessionsIds))
            return RevokeResult.fromMobileSdk(res)
        }
    }

    /**
     * Revoke some recipients or proxy sessions from this session.
     * If you want to revoke all recipients, see [revokeAll] instead.
     * If you want to revoke all recipients besides yourself, see [revokeOthers].
     * @param recipientsIds The Seald IDs of users to revoke from this session.
     * @param proxySessionsIds The IDs of proxy sessions to revoke from this session.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun revokeRecipientsAsync(
        recipientsIds: Array<String>,
        proxySessionsIds: Array<String>,
    ): RevokeResult =
        withContext(Dispatchers.IO) {
            return@withContext revokeRecipients(recipientsIds, proxySessionsIds)
        }

    /**
     * Revoke this session entirely.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun revokeAll(): RevokeResult {
        convertExceptions {
            val res = es.revokeAll()
            return RevokeResult.fromMobileSdk(res)
        }
    }

    /**
     * Revoke this session entirely.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun revokeAllAsync(): RevokeResult =
        withContext(Dispatchers.IO) {
            return@withContext revokeAll()
        }

    /**
     * Revoke all recipients besides yourself from this session.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun revokeOthers(): RevokeResult {
        convertExceptions {
            val res = es.revokeOthers()
            return RevokeResult.fromMobileSdk(res)
        }
    }

    /**
     * Revoke all recipients besides yourself from this session.
     * @return A [RevokeResult] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun revokeOthersAsync(): RevokeResult =
        withContext(Dispatchers.IO) {
            return@withContext revokeOthers()
        }

    /**
     * Encrypt a clear-text string into an encrypted message, for the recipients of this session.
     * @param clearMessage The message to encrypt.
     * @return The encrypted message
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun encryptMessage(clearMessage: String): String {
        convertExceptions {
            return es.encryptMessage(clearMessage)
        }
    }

    /**
     * Encrypt a clear-text string into an encrypted message, for the recipients of this session.
     * @param clearMessage The message to encrypt.
     * @return The encrypted message
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun encryptMessageAsync(clearMessage: String): String =
        withContext(Dispatchers.Default) {
            return@withContext encryptMessage(clearMessage)
        }

    /**
     * Decrypt an encrypted message string into the corresponding clear-text string.
     * @param encryptedMessage The encrypted message to decrypt.
     * @return The decrypted clear-text message.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun decryptMessage(encryptedMessage: String): String {
        convertExceptions {
            return es.decryptMessage(encryptedMessage)
        }
    }

    /**
     * Decrypt an encrypted message string into the corresponding clear-text string.
     * @param encryptedMessage The encrypted message to decrypt.
     * @return The decrypted clear-text message.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun decryptMessageAsync(encryptedMessage: String): String =
        withContext(Dispatchers.Default) {
            return@withContext decryptMessage(encryptedMessage)
        }

    /**
     * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
     * @param clearFile A [ByteArray] of the clear-text content of the file to encrypt.
     * @param filename The name of the file to encrypt.
     * @return A [ByteArray] of the content of the encrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun encryptFile(
        clearFile: ByteArray,
        filename: String,
    ): ByteArray {
        convertExceptions {
            return es.encryptFile(clearFile, filename)
        }
    }

    /**
     * Encrypt a clear-text file into an encrypted file, for the recipients of this session.
     * @param clearFile A [ByteArray] of the clear-text content of the file to encrypt.
     * @param filename The name of the file to encrypt.
     * @return A [ByteArray] of the content of the encrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun encryptFileAsync(
        clearFile: ByteArray,
        filename: String,
    ): ByteArray =
        withContext(Dispatchers.Default) {
            return@withContext encryptFile(clearFile, filename)
        }

    /**
     * Decrypts an encrypted file into the corresponding clear-text file.
     * @param encryptedFile A [ByteArray] of the content of the encrypted file to decrypt.
     * @return A [ClearFile] instance, containing the filename and the fileContent of the decrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun decryptFile(encryptedFile: ByteArray): ClearFile {
        convertExceptions {
            val cf = es.decryptFile(encryptedFile)
            return ClearFile(
                filename = cf.filename,
                sessionId = cf.sessionId,
                fileContent = cf.fileContent,
            )
        }
    }

    /**
     * Decrypts an encrypted file into the corresponding clear-text file.
     * @param encryptedFile A [ByteArray] of the content of the encrypted file to decrypt.
     * @return A [ClearFile] instance, containing the filename and the fileContent of the decrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun decryptFileAsync(encryptedFile: ByteArray): ClearFile =
        withContext(Dispatchers.Default) {
            return@withContext decryptFile(encryptedFile)
        }

    /**
     * Encrypt a clear file into an encrypted file, for the recipients of this session.
     * @param clearFileURI A [String] URI of the file to encrypt.
     * @return A [String] URI of the encrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun encryptFileFromURI(clearFileURI: String): String {
        convertExceptions {
            return es.encryptFileFromURI(clearFileURI)
        }
    }

    /**
     * Encrypt a clear file into an encrypted file, for the recipients of this session.
     * @param clearFileURI A [String] URI of the file to encrypt.
     * @return A [String] URI of the encrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun encryptFileFromURIAsync(clearFileURI: String): String =
        withContext(Dispatchers.Default) {
            return@withContext encryptFileFromURI(clearFileURI)
        }

    /**
     * Decrypts an encrypted file into the corresponding clear-text file.
     * @param encryptedFileURI A [String] URI of the encrypted file to decrypt.
     * @return A [String] URI of the decrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun decryptFileFromURI(encryptedFileURI: String): String {
        convertExceptions {
            return es.decryptFileFromURI(encryptedFileURI)
        }
    }

    /**
     * Decrypts an encrypted file into the corresponding clear-text file.
     * @param encryptedFileURI A [String] URI of the encrypted file to decrypt.
     * @return A [String] URI of the decrypted file.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun decryptFileFromURIAsync(encryptedFileURI: String): String =
        withContext(Dispatchers.Default) {
            return@withContext decryptFileFromURI(encryptedFileURI)
        }

    /**
     * Add a TMR access to this session for the given authentication factor.
     *
     * @param recipient A TMR recipient with its associated rights.
     * @return A String of the TMR access ID.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun addTmrAccess(recipient: TmrRecipientWithRights): String {
        convertExceptions {
            return es.addTmrAccess(recipient.toMobileSdk())
        }
    }

    /**
     * Add a TMR access to this session for the given authentication factor.
     *
     * @param recipient A TMR recipient with its associated rights.
     * @return A String of the TMR access ID.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun addTmrAccessAsync(recipient: TmrRecipientWithRights): String =
        withContext(Dispatchers.Default) {
            return@withContext addTmrAccess(recipient)
        }

    /**
     * Add multiple TMR accesses to this session for the given authentication factors.
     *
     * @param recipients The TMR recipients with their associated rights.
     * @return A [Map<String, ActionStatus>] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun addMultipleTmrAccesses(recipients: Array<TmrRecipientWithRights>): Map<String, ActionStatus> {
        convertExceptions {
            val res = es.addMultipleTmrAccesses(TmrRecipientWithRights.toMobileSdkArray(recipients))
            return ActionStatus.fromMobileSdkArray(res)
        }
    }

    /**
     * Add multiple TMR accesses to this session for the given authentication factors.
     *
     * @param recipients The TMR recipients with their associated rights.
     * @return A [Map<String, ActionStatus>] instance.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun addMultipleTmrAccessesAsync(recipients: Array<TmrRecipientWithRights>): Map<String, ActionStatus> =
        withContext(Dispatchers.Default) {
            return@withContext addMultipleTmrAccesses(recipients)
        }
}
