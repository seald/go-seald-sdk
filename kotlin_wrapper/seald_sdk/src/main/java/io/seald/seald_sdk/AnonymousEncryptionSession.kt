package io.seald.seald_sdk

import kotlinx.coroutines.*

/**
 * An anonymous encryption session, with which you can then encrypt / decrypt multiple messages or files.
 * This should not be instantiated directly, and should be created with [AnonymousSealdSDK.createAnonymousEncryptionSession].
 * @property sessionId The ID of this encryptionSession. Read-only.
 */
class AnonymousEncryptionSession(
    encryptionSession: io.seald.seald_sdk_internals.mobile_sdk.MobileAnonymousEncryptionSession,
) {
    private val aes: io.seald.seald_sdk_internals.mobile_sdk.MobileAnonymousEncryptionSession

    /**
     * @suppress
     */
    init {
        aes = encryptionSession
    }

    val sessionId: String
        get() = this.aes.sessionId

    internal companion object {
        internal fun fromMobileSdkArray(
            array: io.seald.seald_sdk_internals.mobile_sdk.MobileEncryptionSessionArray,
        ): Array<EncryptionSession> =
            Array(
                size = array.size().toInt(),
            ) { i -> EncryptionSession(array.get(i.toLong())) }
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
            return aes.encryptMessage(clearMessage)
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
            return aes.decryptMessage(encryptedMessage)
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
            return aes.encryptFile(clearFile, filename)
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
            val cf = aes.decryptFile(encryptedFile)
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
            return aes.encryptFileFromURI(clearFileURI)
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
            return aes.decryptFileFromURI(encryptedFileURI)
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
     * Serialize the AnonymousEncryptionSession to a string.
     * This is for advanced use.
     * May be used to keep sessions in a cache.
     * WARNING: a user could use this cache to work around being revoked. Use with caution.
     * WARNING: if the cache is accessible to another user, they could use it to decrypt messages they are not supposed
     * to have access to. Make sure only the current user in question can access this cache, for example by encrypting it.
     *
     * @return Returns the serialized anonymous encryption session as a String.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun serialize(): String {
        convertExceptions {
            return aes.serialize()
        }
    }
}
