package com.rmmcosta.spring_security_kata

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

data class UserInfo(
    val username: String,
    val roles: List<String>
)

data class ResourceInfo(
    val id: String,
    val name: String,
    val description: String
)

@RestController
@RequestMapping("/api")
class ApiController {

    @GetMapping("/public/health")
    fun health() = mapOf("status" to "UP")

    @GetMapping("/resource")
    fun getResource() = ResourceInfo(
        id = "1",
        name = "Sample Resource",
        description = "This is a protected resource"
    )

    @GetMapping("/user/info")
    fun getUserInfo(@AuthenticationPrincipal userDetails: UserDetails): UserInfo {
        return UserInfo(
            username = userDetails.username,
            roles = userDetails.authorities.map { it.authority }
        )
    }
}
