// AuthController.kt
package com.rmmcosta.spring_security_kata

import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.slf4j.LoggerFactory

data class AuthResponse(
    val token: String,
    val type: String = "Bearer",
    val username: String,
    val roles: List<String>
)

@RestController
@RequestMapping("/api/auth")
class AuthController(
    private val authenticationManager: AuthenticationManager,
    private val jwtUtil: JwtUtil
) {
    private val log = LoggerFactory.getLogger(AuthController::class.java)

    @GetMapping("/basic")
    fun authenticateBasic(@RequestHeader("Authorization") authHeader: String): ResponseEntity<AuthResponse> {
        try {
            log.debug("Received basic auth request with header: {}", authHeader.take(15) + "...")

            // Extract credentials from Basic Auth header
            val base64Credentials = authHeader.substring("Basic".length).trim()
            val credentials = String(java.util.Base64.getDecoder().decode(base64Credentials))
            val values = credentials.split(":")
            val username = values[0]
            val password = values[1]

            log.debug("Attempting authentication for user: {}", username)

            // Authenticate
            val authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(username, password)
            )

            log.debug("Authentication successful for user: {}", username)
            log.debug("User roles: {}", authentication.authorities.joinToString(", "))

            val token = jwtUtil.generateToken(authentication)
            log.debug("Generated JWT token: {}", token.take(10) + "...")

            val response = AuthResponse(
                token = token,
                username = authentication.name,
                roles = authentication.authorities.map { it.authority }
            )

            log.debug("Sending successful auth response for user: {}", username)
            return ResponseEntity.ok(response)
        } catch (e: Exception) {
            log.error("Authentication failed", e)
            return ResponseEntity.status(401).build()
        }
    }
}
