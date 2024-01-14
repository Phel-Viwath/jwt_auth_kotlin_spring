package com.viwath.jwt_auth.controllers

import com.viwath.jwt_auth.models.auth.AuthRequest
import com.viwath.jwt_auth.models.auth.AuthResponse
import com.viwath.jwt_auth.repositories.AuthRepository
import com.viwath.jwt_auth.services.AuthService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth")
class AuthController {

    @Autowired private val service: AuthService? = null
    @Autowired private val passwordEncoder: PasswordEncoder? = null
    @Autowired private val repository: AuthRepository? = null

    @GetMapping
    fun rule(): ResponseEntity<String>{
        return ResponseEntity.ok("Register or authenticate please")
    }

    @GetMapping("admin/hi")
    fun welcome(): ResponseEntity<String>{
        return ResponseEntity.ok("Welcome to our app")
    }

    @PostMapping("/register")
    fun register(@RequestBody request: AuthRequest): ResponseEntity<AuthResponse>{
        // Check all fields and password length
        val areFieldsBlank = request.username.isBlank() || request.password.isBlank()
        val isPasswordTooShort = request.password.length < 8
        if (areFieldsBlank || isPasswordTooShort)
            return ResponseEntity.status(HttpStatus.CONFLICT).body(AuthResponse("Fields can not be blank and Password can not less than 8"))

        // Check username is already have in database return conflict if not register it
        val saveSuccess: Boolean = service!!.register(request)
        if (!saveSuccess)
            return ResponseEntity.status(HttpStatus.CONFLICT).body(AuthResponse("Username already exists"))

        return ResponseEntity.ok(AuthResponse("Success!."))
    }

    @PostMapping("/authenticate")
    fun authenticate(@RequestBody request: AuthRequest): ResponseEntity<AuthResponse>{
        /// Check user null or not
        val user = repository!!.findUsersByUsername(request.username)
            .orElse(null) ?: return ResponseEntity.status(HttpStatus.CONFLICT).body(AuthResponse("Username not found. Register first."))
        // if password is not null check password match or not
        val isPasswordMatch = passwordEncoder!!.matches(request.password, user.password)
        if (!isPasswordMatch)
            return ResponseEntity.status(HttpStatus.CONFLICT).body(AuthResponse("Incorrect password."))
        // if everything perfect authenticate user and return token
        return ResponseEntity.ok(service!!.authenticate(request))
    }
}