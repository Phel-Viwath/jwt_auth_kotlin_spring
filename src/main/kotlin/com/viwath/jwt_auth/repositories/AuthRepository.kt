@file:Suppress("SpringDataRepositoryMethodReturnTypeInspection")

package com.viwath.jwt_auth.repositories

import com.viwath.jwt_auth.models.user.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface AuthRepository: JpaRepository<User, Long>{
    fun findUsersByUsername(username: String): Optional<User>
}