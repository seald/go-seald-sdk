@file:JvmName("SealdUtils")

package io.seald.seald_sdk

/**
 * Takes the path to an encrypted file, and returns the session id.
 *
 * @param encryptedFilePath Path to the encrypted file.
 * @return The session id.
 * @throws SealdException
 */
@Throws(SealdException::class)
fun parseSessionIdFromFile(encryptedFilePath: String): String {
    convertExceptions {
        return io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk
            .parseSessionIdFromFile(encryptedFilePath)
    }
}

/**
 * Takes an encrypted file as bytes, and returns the session id.
 *
 * @param fileByteArray The encrypted file as ByteArray.
 * @return The session id.
 * @throws SealdException
 */
@Throws(SealdException::class)
fun parseSessionIdFromBytes(fileByteArray: ByteArray): String {
    convertExceptions {
        return io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk
            .parseSessionIdFromBytes(fileByteArray)
    }
}

/**
 * Takes an encrypted message, and returns the session id.
 *
 * @param message The encrypted message.
 * @return The session id.
 * @throws SealdException
 */
@Throws(SealdException::class)
fun parseSessionIdFromMessage(message: String): String {
    convertExceptions {
        return io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk
            .parseSessionIdFromMessage(message)
    }
}
