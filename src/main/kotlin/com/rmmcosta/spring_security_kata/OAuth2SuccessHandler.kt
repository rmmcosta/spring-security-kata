// OAuth2SuccessHandler.kt
package com.rmmcosta.spring_security_kata

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.net.URI

@Component
class OAuth2SuccessHandler(
    private val jwtUtil: JwtUtil,
    @Value("\${app.oauth2.redirectUri}") private val redirectUri: String
) : SimpleUrlAuthenticationSuccessHandler() {
    private val log = LoggerFactory.getLogger(OAuth2SuccessHandler::class.java)

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        try {
            if (response.isCommitted) {
                log.warn("Response has already been committed")
                return
            }

            log.debug("OAuth2 authentication successful for user: {}", authentication.name)
            log.debug("User authorities: {}", authentication.authorities.joinToString(", "))

            val token = jwtUtil.generateToken(authentication)
            log.debug("Generated JWT token for OAuth2 user: {}", token.take(10) + "...")

            val targetUrl = URI(redirectUri)
                .resolve("/auth/callback?token=$token&provider=google")
                .toString()

            log.debug("Redirecting to: {}", targetUrl)
            response.sendRedirect(targetUrl)

        } catch (ex: Exception) {
            log.error("Could not redirect after OAuth2 login", ex)
            throw ex
        }
    }
}