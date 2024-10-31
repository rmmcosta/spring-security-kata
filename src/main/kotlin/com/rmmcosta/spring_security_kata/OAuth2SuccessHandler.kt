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

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        try {
            if (response.isCommitted) {
                logger.warn("Response has already been committed")
                return
            }

            val token = jwtUtil.generateToken(authentication)
            logger.debug("Generated JWT token for OAuth2 user")

            val targetUrl = URI(redirectUri)
                .resolve("/auth/callback?token=$token&provider=google")
                .toString()

            logger.debug("Redirecting to: $targetUrl")
            response.sendRedirect(targetUrl)

        } catch (ex: Exception) {
            logger.error("Could not redirect after OAuth2 login", ex)
            throw ex
        }
    }
}