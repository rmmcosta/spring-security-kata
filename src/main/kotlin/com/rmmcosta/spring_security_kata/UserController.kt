package com.rmmcosta.spring_security_kata

import com.sun.security.auth.UserPrincipal
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
@RestController
class UserController {
    @RequestMapping("/user")
    fun getUser(userPrincipal: UserPrincipal): UserPrincipal = userPrincipal
}
