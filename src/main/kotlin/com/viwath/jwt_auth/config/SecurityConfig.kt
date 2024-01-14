package com.viwath.jwt_auth.config

import com.viwath.jwt_auth.models.user.UserDetailsImp
import com.viwath.jwt_auth.repositories.AuthRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Suppress("removal", "DEPRECATION")
@EnableWebSecurity
@Configuration
@EnableMethodSecurity
class SecurityConfig(
    private val authRepository: AuthRepository?
){
    @Autowired private lateinit var jwtAuthFilter: JwtAuthFilter

    @Bean
    fun passwordEncoder(): PasswordEncoder{
        return BCryptPasswordEncoder()
    }

    @Bean
    fun userDetailServices(): UserDetailsService{
        return UserDetailsService { username ->
            UserDetailsImp(authRepository!!.findUsersByUsername(username).orElseThrow{
                UsernameNotFoundException("User not found.")
            })
        }
    }

    @Bean
    fun authenticationProvider(): AuthenticationProvider {
        val authenticationProvider = DaoAuthenticationProvider()
        authenticationProvider.setUserDetailsService(userDetailServices())
        authenticationProvider.setPasswordEncoder(passwordEncoder())
        return authenticationProvider
    }

    @Bean
    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager {
        return config.authenticationManager
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain{
        return http.csrf().disable()
            .authorizeHttpRequests()
            .requestMatchers("/api/v1/auth/hello", "/api/v1/auth/register", "/api/v1/auth/authenticate")
                .permitAll()
            .and()
            .authorizeHttpRequests()
            .requestMatchers(
                "/api/v1/auth/admin/**",
                "/api/v1/secret/admin",
                "/api/v1/public/user",)
            .authenticated()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider()).addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)
            .build()
    }
}