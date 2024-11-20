package io.seald.seald_sdk

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.lang.IllegalArgumentException
import java.time.Duration
import java.time.Instant

/**
 * SealdException represents an error that happened during a Seald operation.
 *
 * @property status If the error is returned by the Seald server, the HTTP status code.
 * @property code The error code, which is a machine-readable string that represents this error.
 * @property id The error ID, which is a unique string for the precise place this error was thrown from.
 * @property description A human-readable description of the error.
 * @property details Details about the error.
 * @property raw The raw underlying error.
 * @property nativeStack The call stack in Seald native code.
 */
class SealdException(
    originalException: Throwable,
) : RuntimeException() {
    val status: Int?
    val code: String
    val id: String
    val description: String?
    val details: String?
    val raw: String?
    val nativeStack: String?
    override val message: String

    init {
        var jsonObject: JsonObject?

        try {
            val jsonMessage = originalException.message ?: "{}"
            jsonObject = Json.parseToJsonElement(jsonMessage).jsonObject
        } catch (_: Exception) {
            jsonObject = null
        }
        status = jsonObject?.get("status")?.jsonPrimitive?.int
        code = jsonObject?.get("code")?.jsonPrimitive?.content ?: "FAILED_DESERIALIZATION"
        id = jsonObject?.get("id")?.jsonPrimitive?.content ?: "FAILED_DESERIALIZATION"
        description = jsonObject?.get("description")?.jsonPrimitive?.content
        details = jsonObject?.get("details")?.jsonPrimitive?.content
        raw = jsonObject?.get("raw")?.jsonPrimitive?.content ?: originalException.message
        nativeStack = jsonObject?.get("stack")?.jsonPrimitive?.content

        message = toString()
    }

    override fun toString(): String =
        "SealdException(" +
            "status=$status," +
            " code='$code'," +
            " id='$id'," +
            " description='$description'," +
            " details='$details'," +
            " raw='$raw'," +
            " nativeStack='$nativeStack'" +
            ")"
}

internal inline fun <T> convertExceptions(call: () -> T): T {
    try {
        return call()
    } catch (e: Throwable) {
        throw SealdException(e)
    }
}

// We cannot directly pass an array to GO. We need to instantiate a StringArray struct, and pass it.
// Maybe one day... https://github.com/golang/go/issues/13445
internal fun arrayToStringArray(array: Array<String>): io.seald.seald_sdk_internals.mobile_sdk.StringArray {
    var sa =
        io.seald.seald_sdk_internals.mobile_sdk
            .StringArray()
    val arrayIterator = array.iterator()
    while (arrayIterator.hasNext()) {
        sa = sa.add(arrayIterator.next())
    }
    return sa
}

internal fun stringArrayToArray(stringArray: io.seald.seald_sdk_internals.mobile_sdk.StringArray): Array<String> {
    val result = Array(stringArray.size().toInt()) { "" }
    for (i in 0 until stringArray.size().toInt()) {
        result[i] = stringArray.get(i.toLong())
    }
    return result
}

/**
 * ClearFile represents a decrypted file.
 *
 * @property filename The filename of the decrypted file.
 * @property sessionId The ID of the [EncryptionSession] to which this file belongs.
 * @property fileContent The content of the decrypted file.
 */
data class ClearFile(
    val filename: String,
    val sessionId: String,
    val fileContent: ByteArray,
)

/**
 * AccountInfo is returned when calling [SealdSDK.createAccount] or [SealdSDK.getCurrentAccountInfo],
 * containing information about the local account.
 *
 * @property userId The ID of the current user for this SDK instance.
 * @property deviceId The ID of the current device for this SDK instance.
 * @property deviceExpires The [Instant] at which the current device keys expire. For continued operation, renew your device keys before this date. `null` if it is not known locally: use [SealdSDK.updateCurrentDevice] to retrieve it.
 */
data class AccountInfo(
    val userId: String,
    val deviceId: String,
    val deviceExpires: Instant?,
) {
    internal companion object {
        internal fun fromMobileSdk(accountInfo: io.seald.seald_sdk_internals.mobile_sdk.AccountInfo?): AccountInfo? {
            if (accountInfo == null) {
                return null
            }
            return AccountInfo(
                userId = accountInfo.userId,
                deviceId = accountInfo.deviceId,
                deviceExpires = if (accountInfo.deviceExpires == 0L) null else Instant.ofEpochSecond(accountInfo.deviceExpires),
            )
        }
    }
}

/**
 * CreateSubIdentityResponse represents a newly created sub identity.
 *
 * @property deviceId The ID of the newly created device.
 * @property backupKey The identity export of the newly created sub-identity.
 */
data class CreateSubIdentityResponse(
    val deviceId: String,
    val backupKey: ByteArray,
)

/**
 * BeardError represents an error returned by the server.
 * It contains a specific `id` and `code` to determine the underlying reason.
 *
 * @property id The error id.
 * @property code The error code.
 */
data class BeardError(
    val id: String,
    val code: String,
)

/**
 * ConnectorType represents the allowed values for Connector types:
 * - `EM` for email connectors
 * - `AP` for App connectors
 */
enum class ConnectorType(
    val type: String,
) {
    EM("EM"),
    AP("AP"),
    ;

    internal companion object {
        internal fun fromString(t: String): ConnectorType {
            for (ct in ConnectorType.values()) {
                if (ct.type == t) {
                    return ct
                }
            }
            throw IllegalArgumentException("Invalid ConnectorType value: $t")
        }
    }
}

/**
 * ConnectorState represents the allowed values for Connector states.
 */
enum class ConnectorState(
    val state: String,
) {
    PENDING("PE"),
    VALIDATED("VO"),
    REVOKED("RE"),
    REMOVED("RM"),
    ;

    internal companion object {
        internal fun fromString(s: String): ConnectorState {
            for (cs in ConnectorState.values()) {
                if (cs.state == s) {
                    return cs
                }
            }
            throw IllegalArgumentException("Invalid ConnectorState value: $s")
        }
    }
}

/**
 * ConnectorTypeValue is a simplified representation of a connector for which we don't know all details.
 */
data class ConnectorTypeValue(
    val type: ConnectorType,
    val value: String,
) {
    internal companion object {
        internal fun toMobileSdkArray(
            connectorsArray: Array<ConnectorTypeValue>,
        ): io.seald.seald_sdk_internals.mobile_sdk.ConnectorTypeValueArray {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .ConnectorTypeValueArray()
            for (c in connectorsArray) {
                result.add(c.toMobileSdk())
            }
            return result
        }
    }

    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.ConnectorTypeValue {
        val res =
            io.seald.seald_sdk_internals.mobile_sdk
                .ConnectorTypeValue()
        res.type = this.type.type
        res.value = this.value
        return res
    }
}

/**
 * Connector represents all details about a connector.
 */
data class Connector(
    val sealdId: String,
    val type: ConnectorType,
    val value: String,
    val id: String,
    val state: ConnectorState,
) {
    internal companion object {
        internal fun fromMobileSdk(c: io.seald.seald_sdk_internals.mobile_sdk.Connector): Connector =
            Connector(
                sealdId = c.sealdId,
                type = ConnectorType.fromString(c.type),
                value = c.value,
                id = c.id,
                state = ConnectorState.fromString(c.state),
            )

        internal fun fromMobileSdkArray(connectorsArray: io.seald.seald_sdk_internals.mobile_sdk.ConnectorsArray): Array<Connector> =
            Array(
                size = connectorsArray.size().toInt(),
            ) { i -> fromMobileSdk(connectorsArray.get(i.toLong())) }

        internal fun toMobileSdkArray(connectorsArray: Array<Connector>): io.seald.seald_sdk_internals.mobile_sdk.ConnectorsArray {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .ConnectorsArray()
            for (c in connectorsArray) {
                result.add(c.toMobileSdk())
            }
            return result
        }
    }

    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.Connector {
        val res =
            io.seald.seald_sdk_internals.mobile_sdk
                .Connector()
        res.sealdId = this.sealdId
        res.type = this.type.type
        res.value = this.value
        res.id = this.id
        res.state = this.state.state
        return res
    }
}

/**
 * PreValidationToken represents a way for your server to authorize the adding of a connector.
 */
data class PreValidationToken(
    val domainValidationKeyId: String,
    val nonce: String,
    val token: String,
) {
    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.PreValidationToken {
        val res =
            io.seald.seald_sdk_internals.mobile_sdk
                .PreValidationToken()
        res.domainValidationKeyId = this.domainValidationKeyId
        res.nonce = this.nonce
        res.token = this.token
        return res
    }
}

/**
 * Options for [SealdSDK.massReencrypt] function.
 *
 * @property retries Number of times to retry. Defaults to 3.
 * @property retrieveBatchSize Default to 1000.
 * @property waitBetweenRetries Time to wait between retries. Defaults to 3 seconds.
 * @property waitProvisioning Whether to wait for provisioning (new behaviour) or not. Defaults to true.
 * @property waitProvisioningTime Time to wait if device is not provisioned on the server yet. The actual wait time will be increased on subsequent tries, by `waitProvisioningTimeStep`, up to `waitProvisioningTimeMax`. Defaults to 5 seconds.
 * @property waitProvisioningTimeMax Maximum time to wait if device is not provisioned on the server yet. Defaults to 10 seconds.
 * @property waitProvisioningTimeStep Amount to increase the time to wait if device is not provisioned on the server yet. Defaults to 1 second.
 * @property waitProvisioningRetries Maximum number of tries to check if the device is provisioned yet. Defaults to 100.
 * @property forceLocalAccountUpdate Whether to update the local account before trying the reencryption.
 */
data class MassReencryptOptions
    @JvmOverloads
    constructor(
        var retries: Int = 3,
        var retrieveBatchSize: Int = 1000,
        var waitBetweenRetries: Duration = Duration.ofSeconds(3),
        var waitProvisioning: Boolean = true,
        var waitProvisioningTime: Duration = Duration.ofSeconds(5),
        var waitProvisioningTimeMax: Duration = Duration.ofSeconds(10),
        var waitProvisioningTimeStep: Duration = Duration.ofSeconds(1),
        var waitProvisioningRetries: Int = 100,
        var forceLocalAccountUpdate: Boolean = false,
    ) {
        internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.MassReencryptOptions {
            val res =
                io.seald.seald_sdk_internals.mobile_sdk
                    .MassReencryptOptions()
            res.retries = retries.toLong()
            res.retrieveBatchSize = retrieveBatchSize.toLong()
            res.waitBetweenRetries = waitBetweenRetries.toMillis()
            res.waitProvisioning = waitProvisioning
            res.waitProvisioningTime = waitProvisioningTime.toMillis()
            res.waitProvisioningTimeMax = waitProvisioningTimeMax.toMillis()
            res.waitProvisioningTimeStep = waitProvisioningTimeStep.toMillis()
            res.waitProvisioningRetries = waitProvisioningRetries.toLong()
            res.forceLocalAccountUpdate = forceLocalAccountUpdate
            return res
        }
    }

/**
 * Represents the results of a call to [SealdSDK.massReencrypt].
 *
 * @property reencrypted The number of session keys that were reencrypted for the given device.
 * @property failed The number of session keys that could not be reencrypted for the given device.
 */
data class MassReencryptResponse(
    val reencrypted: Int,
    val failed: Int,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.MassReencryptResponse): MassReencryptResponse =
            MassReencryptResponse(
                reencrypted = d.reencrypted.toInt(),
                failed = d.failed.toInt(),
            )
    }
}

/**
 * Represents a device of the current account which is missing some keys, and for which you probably want to call [SealdSDK.massReencrypt].
 *
 * @property deviceId The ID of the device which is missing some keys.
 */
data class DeviceMissingKeys(
    val deviceId: String,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.DeviceMissingKeys): DeviceMissingKeys =
            DeviceMissingKeys(
                deviceId = d.deviceId,
            )

        internal fun fromMobileSdkArray(array: io.seald.seald_sdk_internals.mobile_sdk.DevicesMissingKeysArray): Array<DeviceMissingKeys> =
            Array(
                size = array.size().toInt(),
            ) { i -> fromMobileSdk(array.get(i.toLong())) }
    }
}

/**
 * Represents the status of an operation on single user/device.
 *
 * @property success The status of the action: true if succeeded, false otherwise.
 * @property errorCode An error message, or an empty string.
 * @property result The result of the action.
 */
data class ActionStatus(
    val success: Boolean,
    val errorCode: String,
    val result: String,
) {
    internal companion object {
        internal fun fromMobileSdkArray(goArray: io.seald.seald_sdk_internals.mobile_sdk.ActionStatusArray): Map<String, ActionStatus> {
            val res = mutableMapOf<String, ActionStatus>()
            for (i in 0 until goArray.size().toInt()) {
                val goEl = goArray.get(i.toLong())
                var actionStatus = ActionStatus(success = goEl.success, result = goEl.result, errorCode = goEl.errorCode)
                res[goEl.id] = actionStatus
            }
            return res
        }
    }
}

/**
 * The result of a revocation operation.
 *
 * @property recipients The Seald recipients the revocation operation acted on.
 * @property proxySessions The proxy sessions the revocation operation acted on.
 */
data class RevokeResult(
    val recipients: Map<String, ActionStatus>,
    val proxySessions: Map<String, ActionStatus>,
) {
    internal companion object {
        internal fun fromMobileSdk(r: io.seald.seald_sdk_internals.mobile_sdk.RevokeResult): RevokeResult =
            RevokeResult(
                recipients = ActionStatus.fromMobileSdkArray(r.recipients),
                proxySessions = ActionStatus.fromMobileSdkArray(r.proxySessions),
            )
    }
}

/**
 * RecipientRights represents the rights a user can have over an encrypted message or an encryption session.
 *
 * @property read The right to read the message.
 * @property forward The right to revoke another user from a message, or to remove rights from them.
 * @property revoke The right to forward the message to another user.
 */
data class RecipientRights(
    val read: Boolean = true,
    val forward: Boolean = true,
    val revoke: Boolean = false,
) {
    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.RecipientRights {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .RecipientRights()
        result.read = this.read
        result.revoke = this.revoke
        result.forward = this.forward
        return result
    }
}

/**
 * RecipientWithRight represents a recipient with associated rights.
 * Default rights are: read: true, forward: true, revoke: false
 * Default rights for the current user when creating an encryptionSession are read: true, forward: true, revoke: true
 *
 * @property recipientId Internal Seald IDs. Returned for users with [sdk.getCurrentAccountInfo], for groups when creating them.
 * @property rights The rights for the associated recipient ID.
 */
data class RecipientWithRights(
    val recipientId: String,
    val rights: RecipientRights? = null,
) {
    internal companion object {
        internal fun toMobileSdkArray(
            recipientWithRightArray: Array<RecipientWithRights>,
        ): io.seald.seald_sdk_internals.mobile_sdk.RecipientsWithRightsArray {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .RecipientsWithRightsArray()
            for (rwr in recipientWithRightArray) {
                result.add(rwr.toMobileSdk())
            }
            return result
        }
    }

    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.RecipientWithRights {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .RecipientWithRights()
        result.recipientId = this.recipientId
        result.rights = this.rights?.toMobileSdk()
        return result
    }
}

/**
 * EncryptionSessionRetrievalFlow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session
 */
enum class EncryptionSessionRetrievalFlow(
    val value: Int,
) {
    /** The session was created locally. */
    CREATED(0),

    /** The session was retrieved as a direct recipient. */
    DIRECT(1),

    /** The session was retrieved as a member of a group. */
    VIA_GROUP(2),

    /** The session was retrieved through a proxy session. */
    VIA_PROXY(3),

    /** The session was retrieved through a TMR access. */
    VIA_TMR_ACCESS(4),
    ;

    internal companion object {
        internal fun fromInt(v: Int): EncryptionSessionRetrievalFlow {
            for (f in EncryptionSessionRetrievalFlow.values()) {
                if (f.value == v) {
                    return f
                }
            }
            throw IllegalArgumentException("Invalid EncryptionSessionRetrievalFlow value: $v")
        }
    }
}

/**
 * EncryptionSessionRetrievalDetails represents the details of how an Encryption Session was retrieved.
 *
 * @property flow The way the session was retrieved: as a direct recipient, as a member of a group, or through a proxy session.
 * @property groupId If the session was retrieved as a member of a group, the ID of the group in question. Null if not applicable.
 * @property proxySessionId If the session was retrieved through a proxy session, the ID of this proxy session. Null if not applicable.
 * @property fromCache Indicates if this session was retrieved from the cache.
 */
class EncryptionSessionRetrievalDetails(
    var flow: EncryptionSessionRetrievalFlow,
    var groupId: String?,
    var proxySessionId: String?,
    var fromCache: Boolean,
) {
    internal companion object {
        internal fun fromMobileSdk(
            d: io.seald.seald_sdk_internals.mobile_sdk.EncryptionSessionRetrievalDetails,
        ): EncryptionSessionRetrievalDetails =
            EncryptionSessionRetrievalDetails(
                flow = EncryptionSessionRetrievalFlow.fromInt(d.flow.toInt()),
                groupId = if (d.groupId != "") d.groupId else null,
                proxySessionId = if (d.proxySessionId != "") d.proxySessionId else null,
                fromCache = d.fromCache,
            )
    }
}

/**
 * Represents the results of a call to [SealdSDK.getSigchainHash].
 *
 * @property hash The sigchain hash.
 * @property position The position in the sigchain of the returned hash.
 */
data class GetSigchainResponse(
    val sigchainHash: String,
    val position: Int,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.GetSigchainResponse): GetSigchainResponse =
            GetSigchainResponse(
                sigchainHash = d.hash,
                position = d.position.toInt(),
            )
    }
}

/**
 * Represents the results of a call to [SealdSDK.checkSigchainHash].
 *
 * @property found A boolean set to true if the expected hash was found, false otherwise.
 * @property position The position in the sigchain where the expected hash was found.
 * @property lastPosition The position of the last transaction in the sigchain.
 */
data class CheckSigchainResponse(
    val found: Boolean,
    val position: Int,
    val lastPosition: Int,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.CheckSigchainResponse): CheckSigchainResponse =
            CheckSigchainResponse(
                found = d.found,
                position = d.position.toInt(),
                lastPosition = d.lastPosition.toInt(),
            )
    }
}

/**
 * TMRAccessesRetrievalFilters holds the tmr accesses filters used when retrieving an EncryptionSession.
 *
 * @property createdById SealdId of the user who created the TMR access.
 * @property tmrAccessId Id of the TMR access to use.
 */
data class TMRAccessesRetrievalFilters(
    val createdById: String = "",
    val tmrAccessId: String = "",
) {
    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.TmrAccessesRetrievalFilters {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .TmrAccessesRetrievalFilters()
        result.createdById = this.createdById
        result.tmrAccessId = this.tmrAccessId
        return result
    }
}

/**
 * TMRAccessesConvertFilters holds the tmr accesses filters used when converting TMR accesses.
 *
 * @property sessionId Id of the session with the TMR access.
 * @property createdById SealdId of the user who created the TMR accesses to convert.
 * @property tmrAccessId Id of the TMR access to convert.
 */
data class TMRAccessesConvertFilters(
    val sessionId: String = "",
    val createdById: String = "",
    val tmrAccessId: String = "",
) {
    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.TmrAccessesConvertFilters {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .TmrAccessesConvertFilters()
        result.sessionId = this.sessionId
        result.createdById = this.createdById
        result.tmrAccessId = this.tmrAccessId
        return result
    }
}

/**
 * ConvertTmrAccessesResponse holds the information about the converted tmr accesses.
 *
 * @property status Status of the conversion `ok` or `ko`.
 * @property errored The number of conversions that failed.
 * @property succeeded The number of conversions that succeeded.
 * @property converted IDs of the accesses that were fully converted.
 */
data class ConvertTmrAccessesResponse(
    val status: String,
    val errored: Int,
    val succeeded: Int,
    val converted: Array<String>,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.ConvertTmrAccessesResponse): ConvertTmrAccessesResponse =
            ConvertTmrAccessesResponse(
                status = d.status,
                errored = d.errored.toInt(),
                succeeded = d.succeeded.toInt(),
                converted = stringArrayToArray(d.converted),
            )
    }
}

/**
 * TmrRecipientWithRights Represents a tmr recipient with the associated rights
 *
 * @property authFactor Authentication method of this user, to which SSKS has sent a challenge at the request of your app's server.
 * @property rights The rights for the associated authentication factor
 * @property overEncryptionKey The over encryption key
 */
data class TmrRecipientWithRights(
    val authFactor: AuthFactor,
    val overEncryptionKey: ByteArray,
    val rights: RecipientRights? = null,
) {
    internal companion object {
        internal fun toMobileSdkArray(
            tmrRecipientWithRightsArray: Array<TmrRecipientWithRights>,
        ): io.seald.seald_sdk_internals.mobile_sdk.TmrRecipientWithRightsArray {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .TmrRecipientWithRightsArray()
            for (tmrR in tmrRecipientWithRightsArray) {
                result.add(tmrR.toMobileSdk())
            }
            return result
        }
    }

    internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.TmrRecipientWithRights {
        val result =
            io.seald.seald_sdk_internals.mobile_sdk
                .TmrRecipientWithRights()
        result.authFactor = this.authFactor.toMobileSdk()
        result.rights = this.rights?.toMobileSdk()
        result.overEncryptionKey = this.overEncryptionKey
        return result
    }
}

/**
 * Represents a set of pre-generated private keys.
 * Returned by [generatePrivateKeys].
 * Can be passed to functions that need private keys.
 */
data class PreGeneratedKeys(
    internal val preGeneratedKeys: io.seald.seald_sdk_internals.mobile_sdk.PreGeneratedKeys,
)

/**
 * GroupTmrTemporaryKey holds the information about a group TMR temporary key.
 *
 * @property id Id of the TMR key.
 * @property groupId The id of the group.
 * @property isAdmin Does that key give the admin status.
 * @property createdById Id of the user who created this key.
 * @property authFactorType The type of authentication factor.
 * @property created Date of creation.
 */
data class GroupTmrTemporaryKey(
    val id: String,
    val groupId: String,
    val isAdmin: Boolean,
    val createdById: String,
    val authFactorType: String,
    val created: Instant,
) {
    internal companion object {
        internal fun fromMobileSdk(d: io.seald.seald_sdk_internals.mobile_sdk.GroupTMRTemporaryKey): GroupTmrTemporaryKey =
            GroupTmrTemporaryKey(
                id = d.keyId,
                groupId = d.groupId,
                isAdmin = d.isAdmin,
                createdById = d.createdById,
                authFactorType = d.authFactorType,
                created = Instant.ofEpochSecond(d.created),
            )

        internal fun fromMobileSdkArray(
            goArray: io.seald.seald_sdk_internals.mobile_sdk.GroupTMRTemporaryKeyArray,
        ): Array<GroupTmrTemporaryKey> {
            val result =
                Array(goArray.size().toInt()) {
                    fromMobileSdk(goArray.get(it.toLong()))
                }
            return result
        }
    }
}

/**
 * ListedGroupTMRTemporaryKeys holds a list of GroupTmrTemporaryKey.
 *
 * @property nbPage Number of pages found.
 * @property gTMRTKeys Temporary keys found.
 */
data class ListedGroupTMRTemporaryKeys(
    val nbPage: Int,
    val gTMRTKeys: Array<GroupTmrTemporaryKey>,
) {
    internal companion object {
        internal fun fromMobileSdk(
            nativeList: io.seald.seald_sdk_internals.mobile_sdk.ListedGroupTMRTemporaryKeys,
        ): ListedGroupTMRTemporaryKeys {
            val keys = GroupTmrTemporaryKey.fromMobileSdkArray(nativeList.keys)
            return ListedGroupTMRTemporaryKeys(nativeList.nbPage.toInt(), keys)
        }
    }
}

/**
 * SealdSearchGroupTMRTemporaryKeysOpts holds the tmr filters used when searching group TMR temporary keys.
 *
 * @property groupId Return only the TMR temporary keys that give access to this groupId.
 * @property page Page to return.
 * @property all Should return all pages after `Page`.
 */
data class SearchGroupTMRTemporaryKeysOpts
    @JvmOverloads
    constructor(
        val groupId: String = "",
        val page: Int = 1,
        val all: Boolean = false,
    ) {
        internal fun toMobileSdk(): io.seald.seald_sdk_internals.mobile_sdk.SearchGroupTMRTemporaryKeysOpts {
            val result =
                io.seald.seald_sdk_internals.mobile_sdk
                    .SearchGroupTMRTemporaryKeysOpts()
            result.groupId = this.groupId
            result.page = this.page.toLong()
            result.all = this.all
            return result
        }
    }
