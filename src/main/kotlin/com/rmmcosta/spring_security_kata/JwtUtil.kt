package com.rmmcosta.spring_security_kata

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.slf4j.LoggerFactory
import java.util.*

@Component
class JwtUtil(
    @Value("\${jwt.secret}") private val jwtSecret: String,
    @Value("\${jwt.expiration}") private val jwtExpiration: Long
) {
    private val log = LoggerFactory.getLogger(JwtUtil::class.java)
    private val key = Keys.hmacShaKeyFor(jwtSecret.toByteArray())

    fun generateToken(authentication: Authentication): String {
        val username = authentication.name
        val now = Date()
        val expiryDate = Date(now.time + jwtExpiration)

        log.debug("Generating token for user: {}", username)
        log.debug("Token expiration: {}", expiryDate)

        return Jwts.builder()
            .subject(username)
            .issuedAt(now)
            .expiration(expiryDate)
            .signWith(key)
            .compact()
            .also { token ->
                log.debug("Generated token: {}", token.take(10) + "...")
            }
    }

    fun validateToken(token: String): Boolean {
        return try {
            log.debug("Validating token: {}", token.take(10) + "...")

            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .also {
                    log.debug("Token validation successful")
                }
            true
        } catch (ex: Exception) {
            log.error("Token validation failed", ex)
            false
        }
    }

    fun getUsernameFromToken(token: String): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload
            .subject
            .also { username ->
                log.debug("Extracted username from token: {}", username)
            }
    }
}
