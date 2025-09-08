package io.seald.seald_sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * This is the main class for the anonymous Seald SDK. It represents an instance of the Anonymous Seald SDK.
 * @param apiURL The Seald server for this instance to use. This value is given on your Seald dashboard.
 * @param appId The ID given by the Seald server to your app. This value is given on your Seald dashboard.
 * @param instanceName An arbitrary name to give to this Seald instance. Can be useful for debugging when multiple instances are running in parallel, as it is added to logs.
 * @param logLevel The minimum level of logs you want. All logs of this level or above will be displayed. `-1`: Trace; `0`: Debug; `1`: Info; `2`: Warn; `3`: Error; `4`: Fatal; `5`: Panic; `6`: NoLevel; `7`: Disabled.
 * @param logNoColor Should be set to `false` if you want to enable colors in the log output. Defaults to `true`.
 * @throws SealdException
 */
class AnonymousSealdSDK
    @JvmOverloads
    @Throws(SealdException::class)
    constructor(
        apiURL: String = "https://api.seald.io/",
        appId: String,
        instanceName: String = "AnonymousSealdSDK",
        logLevel: Byte = 0,
        logNoColor: Boolean = true,
    ) {
        private var mobileAnonymousSDK: io.seald.seald_sdk_internals.mobile_sdk.MobileAnonymousSDK

        init {
            val initOpts =
                io.seald.seald_sdk_internals.mobile_sdk
                    .AnonymousInitializeOptions()
            initOpts.apiURL = apiURL
            initOpts.appId = appId
            initOpts.instanceName = instanceName
            initOpts.platform = "android"
            initOpts.logLevel = logLevel
            initOpts.logNoColor = logNoColor
            mobileAnonymousSDK =
                convertExceptions {
                    io.seald.seald_sdk_internals.mobile_sdk.Mobile_sdk
                        .createAnonymousSDK(initOpts)
                }
        }

        /**
         * Create an anonymous encryption session, and returns the associated [AnonymousEncryptionSession] instance,
         * with which you can then encrypt / decrypt multiple messages.
         * @param encryptionToken Mandatory. The JWT used for EncryptionSession creation.
         * @param getKeysToken Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
         * @param recipients The Seald IDs of users who should be able to retrieve this session.
         * @param tmrRecipients Array of TMR recipients of the session to create.
         * @return The created [AnonymousEncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        fun createAnonymousEncryptionSession(
            encryptionToken: String,
            getKeysToken: String,
            recipients: Array<String>,
            tmrRecipients: Array<AnonymousTmrRecipient>? = null,
        ): AnonymousEncryptionSession {
            convertExceptions {
                val aes =
                    mobileAnonymousSDK.createAnonymousEncryptionSession(
                        encryptionToken,
                        getKeysToken,
                        arrayToStringArray(recipients),
                        AnonymousTmrRecipient.toMobileSdkArray(tmrRecipients),
                    )
                return AnonymousEncryptionSession(aes)
            }
        }

        /**
         * Create an anonymous encryption session, and returns the associated [AnonymousEncryptionSession] instance,
         * with which you can then encrypt / decrypt multiple messages.
         * @param encryptionToken Mandatory. The JWT used for EncryptionSession creation.
         * @param getKeysToken Optional. The JWT used for the key retrieval. If not supplied, the key retrieval will use `encryptionToken`
         * @param recipients The Seald IDs of users who should be able to retrieve this session.
         * @param tmrRecipients Array of TMR recipients of the session to create.
         * @return The created [AnonymousEncryptionSession].
         * @throws SealdException
         */
        @JvmOverloads
        @Throws(SealdException::class)
        suspend fun createAnonymousEncryptionSessionAsync(
            encryptionToken: String,
            getKeysToken: String,
            recipients: Array<String>,
            tmrRecipients: Array<AnonymousTmrRecipient>? = null,
        ): AnonymousEncryptionSession =
            withContext(Dispatchers.Default) {
                return@withContext createAnonymousEncryptionSession(encryptionToken, getKeysToken, recipients, tmrRecipients)
            }

        /**
         * Deserialize a serialized session.
         * For advanced use.
         *
         * @param serializedSession The serialized anonymous encryption session to deserialize.
         * @return The deserialized [AnonymousEncryptionSession].
         * @throws SealdException
         */
        @Throws(SealdException::class)
        fun deserializeAnonymousEncryptionSession(serializedSession: String): AnonymousEncryptionSession {
            convertExceptions {
                val es = mobileAnonymousSDK.deserializeAnonymousEncryptionSession(serializedSession)
                return AnonymousEncryptionSession(es)
            }
        }
    }
