package io.seald.seald_sdk_demo_app_android

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import io.seald.seald_sdk.AuthFactor
import java.util.*
import javax.crypto.SecretKey

class JWTBuilder(
    jwtSharedSecretId: String,
    jwtSharedSecret: String,
) {
    private val jwtSharedSecretId: String
    private val jwtSharedSecret: SecretKey

    init {
        this.jwtSharedSecretId = jwtSharedSecretId
        this.jwtSharedSecret = Keys.hmacShaKeyFor(jwtSharedSecret.toByteArray())
    }

    enum class JWTPermission(
        val perm: Int,
    ) {
        ALL(-1),
        ANONYMOUS_CREATE_MESSAGE(0),
        ANONYMOUS_FIND_KEY(1),
        ANONYMOUS_FIND_SIGCHAIN(2),
        JOIN_TEAM(3),
        ADD_CONNECTOR(4),
    }

    fun signupJWT(): String {
        val date = Date()
        val expiryDate = Date(date.time + 2 * 60 * 60 * 1000)

        return Jwts
            .builder()
            .setHeaderParam("alg", "HS256")
            .setHeaderParam("typ", "JWT")
            .claim("join_team", true)
            .claim("scopes", JWTPermission.JOIN_TEAM)
            .setId(UUID.randomUUID().toString())
            .setIssuer(jwtSharedSecretId)
            .setIssuedAt(date)
            .setExpiration(expiryDate)
            .signWith(jwtSharedSecret, SignatureAlgorithm.HS256)
            .compact()
    }

    fun connectorJWT(
        customUserId: String,
        appId: String,
    ): String {
        val date = Date()
        val expiryDate = Date(date.time + 2 * 60 * 60 * 1000)

        return Jwts
            .builder()
            .setHeaderParam("alg", "HS256")
            .setHeaderParam("typ", "JWT")
            .claim("scopes", JWTPermission.ADD_CONNECTOR)
            .claim("connector_add", mapOf("type" to "AP", "value" to "$customUserId@$appId"))
            .setIssuer(jwtSharedSecretId)
            .setId(UUID.randomUUID().toString())
            .setIssuedAt(date)
            .setExpiration(expiryDate)
            .signWith(jwtSharedSecret, SignatureAlgorithm.HS256)
            .compact()
    }

    fun anonymousFindKeyJWT(recipients: Array<String>): String {
        val date = Date()
        val expiryDate = Date(date.time + 2 * 60 * 60 * 1000)

        // No 'jti' for the 'find keys' JWT: the request may be paginated, so done in multiple API calls
        return Jwts
            .builder()
            .setHeaderParam("alg", "HS256")
            .setHeaderParam("typ", "JWT")
            .claim("recipients", recipients)
            .claim("scopes", JWTPermission.ANONYMOUS_FIND_KEY)
            .setIssuer(jwtSharedSecretId)
            .setIssuedAt(date)
            .setExpiration(expiryDate)
            .signWith(jwtSharedSecret, SignatureAlgorithm.HS256)
            .compact()
    }

    fun anonymousCreateMessageJWT(
        ownerId: String,
        recipients: Array<String>,
        tmrRecipients: Array<AuthFactor>? = null,
    ): String {
        val date = Date()
        val expiryDate = Date(date.time + 2 * 60 * 60 * 1000)

        // the key `recipients` must be present, even for an empty array.
        // the key `tmr_recipients` can be omitted when empty.
        return Jwts
            .builder()
            .setHeaderParam("alg", "HS256")
            .setHeaderParam("typ", "JWT")
            .claim("recipients", recipients)
            .claim("tmr_recipients", tmrRecipients)
            .claim("owner", ownerId)
            .claim("scopes", JWTPermission.ANONYMOUS_CREATE_MESSAGE)
            .setId(UUID.randomUUID().toString())
            .setIssuer(jwtSharedSecretId)
            .setIssuedAt(date)
            .setExpiration(expiryDate)
            .signWith(jwtSharedSecret, SignatureAlgorithm.HS256)
            .compact()
    }
}
