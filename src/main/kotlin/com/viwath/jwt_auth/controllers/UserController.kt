package com.viwath.jwt_auth.controllers

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/public")
class UserController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    fun welcome(): ResponseEntity<String>{
        return ResponseEntity.ok("Hello user")
    }
}
