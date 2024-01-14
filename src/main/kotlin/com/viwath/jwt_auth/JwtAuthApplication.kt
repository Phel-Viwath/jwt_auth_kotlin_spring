@file:Suppress("DEPRECATION")

package com.viwath.jwt_auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
class JwtAuthApplication

fun main(args: Array<String>) {
    runApplication<JwtAuthApplication>(*args)
}
