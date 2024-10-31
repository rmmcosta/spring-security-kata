// SecurityConfig.kt
package com.rmmcosta.spring_security_kata

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
class SecurityConfig(
    @Value("\${spring.security.user.name}") private val username: String,
    @Value("\${spring.security.user.password}") private val password: String,
    @Value("\${spring.security.user.roles:USER}") private val roles: String,
    @Value("\${app.cors.allowed-origins}") private val allowedOrigins: List<String>,
    private val oAuth2SuccessHandler: OAuth2SuccessHandler,
) {

    @Bean
    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager {
        return config.authenticationManager
    }

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        jwtFilter: JwtAuthenticationFilter
    ): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/api/public/**").permitAll()
                    .requestMatchers("/api/auth/**").permitAll()
                    .anyRequest().authenticated()
            }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .oauth2Login { oAuth2LoginConfigurer ->
                oAuth2LoginConfigurer.authorizationEndpoint {
                    it.baseUri("/api/auth/oauth2/authorize")
                }
                oAuth2LoginConfigurer.redirectionEndpoint {
                    it.baseUri("/login/oauth2/code/*")  // Use Spring's default callback URI
                }
                oAuth2LoginConfigurer.successHandler(oAuth2SuccessHandler)
            }
            .httpBasic {}
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = allowedOrigins
        configuration.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
        configuration.allowedHeaders = listOf("*")
        configuration.allowCredentials = true
        configuration.exposedHeaders = listOf("Authorization")

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val user = User.builder()
            .username(username)
            .password(passwordEncoder().encode(password))
            .roles(*roles.split(",").map { it.trim() }.toTypedArray())
            .build()
        return InMemoryUserDetailsManager(user)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
}
