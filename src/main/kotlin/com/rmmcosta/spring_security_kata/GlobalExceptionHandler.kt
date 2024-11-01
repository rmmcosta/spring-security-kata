// GlobalExceptionHandler.kt
package com.rmmcosta.spring_security_kata

import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.AuthenticationException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

data class ErrorResponse(
    val status: Int,
    val error: String,
    val message: String
)

@RestControllerAdvice
class GlobalExceptionHandler {
    private val logger = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)

    @ExceptionHandler(AuthenticationException::class)
    fun handleAuthenticationException(ex: AuthenticationException): ResponseEntity<ErrorResponse> {
        logger.error("Authentication error: ${ex.message}")
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(ErrorResponse(
                status = HttpStatus.UNAUTHORIZED.value(),
                error = "Unauthorized",
                message = "Authentication failed"
            ))
    }

    @ExceptionHandler(Exception::class)
    fun handleGenericException(ex: Exception): ResponseEntity<ErrorResponse> {
        logger.error("Unexpected error: ${ex.message}")
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ErrorResponse(
                status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                error = "Internal Server Error",
                message = "An unexpected error occurred"
            ))
    }
}
