// JwtAuthenticationFilter.kt
package com.rmmcosta.spring_security_kata

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import org.slf4j.LoggerFactory

@Component
class JwtAuthenticationFilter(
    private val jwtUtil: JwtUtil,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {
    private val log = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            log.debug("Processing request to '{}' with method '{}'", request.requestURI, request.method)

            val jwt = getJwtFromRequest(request)
            if (jwt == null) {
                log.debug("No JWT token found in request")
            } else {
                log.debug("Found JWT token in request")

                if (jwtUtil.validateToken(jwt)) {
                    log.debug("JWT token is valid")
                    val username = jwtUtil.getUsernameFromToken(jwt)
                    log.debug("Username from token: {}", username)

                    val userDetails = userDetailsService.loadUserByUsername(username)
                    log.debug("Loaded user details for {}, roles: {}",
                        username,
                        userDetails.authorities.joinToString(", "))

                    val authentication = UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.authorities
                    ).apply {
                        details = WebAuthenticationDetailsSource().buildDetails(request)
                    }

                    SecurityContextHolder.getContext().authentication = authentication
                    log.debug("Authentication set in SecurityContextHolder")
                } else {
                    log.warn("Invalid JWT token")
                }
            }
        } catch (ex: Exception) {
            log.error("Cannot set user authentication", ex)
        }

        filterChain.doFilter(request, response)
    }

    private fun getJwtFromRequest(request: HttpServletRequest): String? {
        return request.getHeader("Authorization")?.let { bearerToken ->
            if (bearerToken.startsWith("Bearer ")) {
                val token = bearerToken.substring(7)
                log.debug("Extracted Bearer token: {}", token.take(10) + "...")
                token
            } else {
                log.debug("Authorization header is not a Bearer token")
                null
            }
        }
    }
}
