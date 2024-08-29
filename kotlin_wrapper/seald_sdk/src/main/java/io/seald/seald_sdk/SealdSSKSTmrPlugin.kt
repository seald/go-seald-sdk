package io.seald.seald_sdk

import kotlinx.coroutines.*

/**
 * The SealdSSKSTmrPlugin class allows to use the SSKS key storage service to store Seald identities
 * easily and securely, encrypted by a key stored on your back-end server.
 *
 * @param ssksURL The SSKS server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `false` if you want to enable colors in the log output. Defaults to `true`.
 */
class SealdSSKSTmrPlugin constructor(
    ssksURL: String = "https://ssks.seald.io/",
    appId: String,
    instanceName: String = "SealdSSKSTmrPlugin",
    logLevel: Byte = 0,
    logNoColor: Boolean = true,
) {
    private var mobileSSKSTMR: io.seald.seald_sdk_internals.mobile_sdk.MobileSSKSTMR

    /**
     * @suppress
     */
    init {
        val initOpts = io.seald.seald_sdk_internals.mobile_sdk.SsksTMRInitializeOptions()
        initOpts.ssksURL = ssksURL
        initOpts.appId = appId
        initOpts.instanceName = instanceName
        initOpts.platform = "android"
        initOpts.logLevel = logLevel
        initOpts.logNoColor = logNoColor

        mobileSSKSTMR = io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk.newSSKSTMRPlugin(initOpts)
    }

    /**
     * Save the Seald account to SSKS.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param identity The identity to save.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return A [SaveIdentityResponse] instance, containing the SSKS ID of the stored identity, which can be used by your backend to manage it, and if a challenge was passed `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun saveIdentity(
        sessionId: String,
        authFactor: AuthFactor,
        rawTMRSymKey: ByteArray,
        identity: ByteArray,
        challenge: String? = null,
    ): SaveIdentityResponse {
        convertExceptions {
            val internalResp = mobileSSKSTMR.saveIdentity(sessionId, authFactor.toMobileSdk(), challenge, rawTMRSymKey, identity)
            return SaveIdentityResponse.fromMobileSdk(internalResp)
        }
    }

    /**
     * Save the Seald account to SSKS.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param identity The identity to save.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return A [SaveIdentityResponse] instance, containing the SSSKS ID of the stored identity, which can be used by your backend to manage it, and if a challenge was passed `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun saveIdentityAsync(
        sessionId: String,
        authFactor: AuthFactor,
        rawTMRSymKey: ByteArray,
        identity: ByteArray,
        challenge: String? = null,
    ): SaveIdentityResponse =
        withContext(Dispatchers.Default) {
            return@withContext saveIdentity(sessionId, authFactor, rawTMRSymKey, identity, challenge)
        }

    /**
     * Retrieve the Seald account previously saved with `SealdSSKSTmrPlugin.saveIdentity`.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return A [RetrieveIdentityResponse] instance, containing `identity`, the retrieved identity, `shouldRenewKey`, a boolean set to true is the user private key should be renewed (using sealdSDKInstance.renewKeys()), and `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun retrieveIdentity(
        sessionId: String,
        authFactor: AuthFactor,
        challenge: String,
        rawTMRSymKey: ByteArray,
    ): RetrieveIdentityResponse {
        convertExceptions {
            val internalResp = mobileSSKSTMR.retrieveIdentity(sessionId, authFactor.toMobileSdk(), challenge, rawTMRSymKey)
            return RetrieveIdentityResponse.fromMobileSdk(internalResp)
        }
    }

    /**
     * Retrieve the Seald account previously saved with `SealdSSKSTmrPlugin.saveIdentity`.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param rawTMRSymKey The raw encryption key used to encrypt / decrypt the stored identity keys. This *MUST* be a cryptographically random buffer of 64 bytes.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return An [RetrieveIdentityResponse] instance, containing `identity`, the retrieved identity, `shouldRenewKey`, a boolean set to true is the user private key should be renewed (using sealdSDKInstance.renewKeys()), and `authenticatedSessionId`, a new authenticated sessionId, that you can use to perform further SSKS TMR operations without challenge.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun retrieveIdentityAsync(
        sessionId: String,
        authFactor: AuthFactor,
        challenge: String,
        rawTMRSymKey: ByteArray,
    ): RetrieveIdentityResponse =
        withContext(Dispatchers.Default) {
            return@withContext retrieveIdentity(sessionId, authFactor, challenge, rawTMRSymKey)
        }

    /**
     * Retrieve the TMR JWT associated with an authentication factor.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return An [GetFactorTokenResponse] instance, containing the retrieved authentication factor token.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    fun getFactorToken(
        sessionId: String,
        authFactor: AuthFactor,
        challenge: String? = null,
    ): GetFactorTokenResponse {
        convertExceptions {
            val internalResp = mobileSSKSTMR.getFactorToken(sessionId, authFactor.toMobileSdk(), challenge)
            return GetFactorTokenResponse.fromMobileSdk(internalResp)
        }
    }

    /**
     * Retrieve the TMR JWT associated with an authentication factor.
     *
     * @param sessionId Session ID given by SSKS to your app's server.
     * @param authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
     * @param challenge Optional. The challenge sent by SSKS to the user's authentication method, if any.
     * @return An [GetFactorTokenResponse] instance, containing the retrieved authentication factor token.
     * @throws SealdException
     */
    @Throws(SealdException::class)
    suspend fun getFactorTokenAsync(
        sessionId: String,
        authFactor: AuthFactor,
        challenge: String? = null,
    ): GetFactorTokenResponse =
        withContext(Dispatchers.Default) {
            return@withContext getFactorToken(sessionId, authFactor, challenge)
        }
}
