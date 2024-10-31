// AuthController.kt
package com.rmmcosta.spring_security_kata

import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

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

    @GetMapping("/basic")
    fun authenticateBasic(@RequestHeader("Authorization") authHeader: String): ResponseEntity<AuthResponse> {
        try {
            // Extract credentials from Basic Auth header
            val base64Credentials = authHeader.substring("Basic".length).trim()
            val credentials = String(java.util.Base64.getDecoder().decode(base64Credentials))
            val values = credentials.split(":")
            val username = values[0]
            val password = values[1]

            // Authenticate
            val authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(username, password)
            )

            val token = jwtUtil.generateToken(authentication)

            val response = AuthResponse(
                token = token,
                username = authentication.name,
                roles = authentication.authorities.map { it.authority }
            )

            return ResponseEntity.ok(response)
        } catch (e: Exception) {
            return ResponseEntity.status(401).build()
        }
    }
}
