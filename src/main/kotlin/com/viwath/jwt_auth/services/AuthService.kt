package com.viwath.jwt_auth.services

import com.viwath.jwt_auth.models.auth.AuthRequest
import com.viwath.jwt_auth.models.auth.AuthResponse
import com.viwath.jwt_auth.models.user.Roles
import com.viwath.jwt_auth.models.user.User
import com.viwath.jwt_auth.models.user.UserDetailsImp
import com.viwath.jwt_auth.repositories.AuthRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthService {

    @Autowired private val repository: AuthRepository? = null
    @Autowired private val jwtService: JwtService? = null
    @Autowired private val authenticationManager: AuthenticationManager? = null
    @Autowired private val passwordEncoder: PasswordEncoder? = null

    // Register
    fun register(request: AuthRequest): Boolean{
        try {
            if (repository!!.findUsersByUsername(request.username).isPresent){
                return false
            }
            val user = User(
                null,
                request.username,
                passwordEncoder!!.encode(request.password),
                Roles.ROLE_USER
            )
            repository.save(user)
            return true
        }catch (e: Exception){
            AuthResponse("Invalid username or password")
            return false
        }
    }

    // Authenticate
    fun authenticate(request: AuthRequest): AuthResponse{
        return try {
            authenticationManager!!.authenticate(
                UsernamePasswordAuthenticationToken(
                    request.username,
                    request.password
                )
            )
            val user = repository!!.findUsersByUsername(request.username).orElseThrow()
            val token = jwtService!!.generateToken(UserDetailsImp(user))
            AuthResponse(token)
        }catch (e: Exception){
            AuthResponse(e.message + HttpStatus.INTERNAL_SERVER_ERROR.toString())
        }
    }

}