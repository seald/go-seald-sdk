package io.seald.seald_sdk

/**
 * Represents a user's authentication factor
 *
 * @property type The type of authentication factor.
 * @property value The value of the authentication factor
 */
data class AuthFactor(
    val type: AuthFactorType,
    val value: String,
) {
    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.AuthFactor {
        val internalAuthFactor = io.seald.seald_sdk_internals.mobile_sdk.AuthFactor()
        internalAuthFactor.type = type.value
        internalAuthFactor.value = value
        return internalAuthFactor
    }
}

enum class AuthFactorType(val value: String) {
    EM("EM"),
    AP("SMS"),
}

/**
 * SaveIdentityResponse is returned by SaveIdentity when an identity has been successfully saved
 *
 * @property ssksId The SSKS ID of the stored identity, which can be used by your backend to manage it
 * @property authenticatedSessionId If a challenge was passed, an authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge
 */
data class SaveIdentityResponse(
    val ssksId: String,
    var authenticatedSessionId: String?,
) {
    internal companion object {
        internal fun fromMobileSdk(resp: io.seald.seald_sdk_internals.mobile_sdk.SaveIdentityResponse): SaveIdentityResponse {
            return SaveIdentityResponse(
                ssksId = resp.ssksId,
                authenticatedSessionId = if (resp.authenticatedSessionId != "") resp.authenticatedSessionId else null,
            )
        }
    }
}

/**
 * RetrieveIdentityResponse holds a retrieved identity
 *
 * @property identity The retrieved identity. It can be used with `sdk.importIdentity()`
 * @property shouldRenewKey If the boolean ShouldRenewKey is set to `true`, the account MUST renew its private key using `sdk.renewKeys()`
 * @property authenticatedSessionId An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge
 */
data class RetrieveIdentityResponse(
    val identity: ByteArray,
    val shouldRenewKey: Boolean,
    var authenticatedSessionId: String,
) {
    internal companion object {
        internal fun fromMobileSdk(resp: io.seald.seald_sdk_internals.mobile_sdk.RetrieveIdentityResponse): RetrieveIdentityResponse {
            return RetrieveIdentityResponse(
                identity = resp.identity,
                shouldRenewKey = resp.shouldRenewKey,
                authenticatedSessionId = resp.authenticatedSessionId,
            )
        }
    }
}

/**
 * GetFactorTokenResponse holds a retrieved authentication factor token
 *
 * @property token The retrieved token. It can be used with `sdk.retrieveEncryptionSessionByTmr()` and `sdk.convertTmrAccesses()`.
 * @property authenticatedSessionId An authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge
 */
data class GetFactorTokenResponse(
    val token: String,
    var authenticatedSessionId: String,
) {
    internal companion object {
        internal fun fromMobileSdk(resp: io.seald.seald_sdk_internals.mobile_sdk.GetFactorTokenResponse): GetFactorTokenResponse {
            return GetFactorTokenResponse(
                token = resp.token,
                authenticatedSessionId = resp.authenticatedSessionId,
            )
        }
    }
}
