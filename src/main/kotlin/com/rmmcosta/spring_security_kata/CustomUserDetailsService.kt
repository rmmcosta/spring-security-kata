// CustomUserDetailsService.kt
package com.rmmcosta.spring_security_kata

import org.slf4j.LoggerFactory
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException

class CustomUserDetailsService(
    private val inMemoryUserDetailsManager: UserDetailsService
) : UserDetailsService {

    private val log = LoggerFactory.getLogger(CustomUserDetailsService::class.java)

    override fun loadUserByUsername(username: String): UserDetails {
        log.debug("Loading user details for username: {}", username)

        return try {
            // First try to load from in-memory user details service
            inMemoryUserDetailsManager.loadUserByUsername(username).also {
                log.debug("Successfully loaded user from in-memory store: {}", it.username)
                log.debug("User authorities: {}", it.authorities.joinToString(", "))
            }
        } catch (e: UsernameNotFoundException) {
            log.debug("User not found in in-memory store, handling as OAuth2 user: {}", username)

            // Create UserDetails for OAuth2 user with necessary authorities
            User.builder()
                .username(username)
                .password("") // OAuth2 users don't need a password
                .authorities(
                    listOf(
                        SimpleGrantedAuthority("ROLE_USER"),
                        SimpleGrantedAuthority("ROLE_OAUTH2_USER")
                    )
                )
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build()
                .also {
                    log.debug("Created OAuth2 user details for: {}", it.username)
                    log.debug("Assigned authorities: {}", it.authorities.joinToString(", "))
                }
        }
    }
}
