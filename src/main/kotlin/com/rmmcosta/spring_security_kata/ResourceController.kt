package com.rmmcosta.spring_security_kata

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*

@SpringBootApplication
@RestController
class ResourceController {
    @RequestMapping("/resource")
    fun home(): Map<String, Any> {
        val model: MutableMap<String, Any> = HashMap()
        model["id"] = UUID.randomUUID().toString()
        model["message"] = "Hello World"
        return model
    }
}
