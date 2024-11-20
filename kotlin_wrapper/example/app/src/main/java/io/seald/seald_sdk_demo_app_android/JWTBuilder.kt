package io.seald.seald_sdk_demo_app_android

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
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
}
