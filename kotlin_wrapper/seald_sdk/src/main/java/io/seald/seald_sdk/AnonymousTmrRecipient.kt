package io.seald.seald_sdk

/**
 * AnonymousTmrRecipient Represents an anonymous tmr recipient with the associated rights
 *
 * @property authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @property rawOverEncryptionKey The raw over encryption key
 */
data class AnonymousTmrRecipient(
    val authFactor: AuthFactor,
    val rawOverEncryptionKey: ByteArray,
) {
    internal companion object {
        internal fun toMobileSdkArray(
            anonymousTmrRecipientArray: Array<AnonymousTmrRecipient>?,
        ): io.seald.seald_sdk_internals.mobile_sdk.AnonymousTmrRecipientArray {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .AnonymousTmrRecipientArray()
            for (aTmrR in anonymousTmrRecipientArray.orEmpty()) {
                result.add(aTmrR.toMobileSdk())
            }
            return result
        }
    }

    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.AnonymousTmrRecipient {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .AnonymousTmrRecipient()
        result.authFactor = this.authFactor.toMobileSdk()
        result.rawOverEncryptionKey = this.rawOverEncryptionKey
        return result
    }
}
