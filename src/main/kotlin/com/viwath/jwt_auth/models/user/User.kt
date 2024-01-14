package com.viwath.jwt_auth.models.user

import jakarta.persistence.*

@Suppress("JpaDataSourceORMInspection")
@Entity
@Table(name = "users")
data class User(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long?,
    @Column(unique = true)
    val username: String,
    val password: String,
    @Enumerated(EnumType.STRING)
    val role: Roles
)