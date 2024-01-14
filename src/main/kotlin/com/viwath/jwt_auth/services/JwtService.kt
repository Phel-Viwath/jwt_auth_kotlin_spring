package com.viwath.jwt_auth.services

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.Date

@Service
class JwtService {
    fun extractEmail(token: String): String? {
        return extractClaim(token, Claims::getSubject)
    }
    fun validateToken(token: String?, userDetails: UserDetails): Boolean {
        val email = extractEmail(token!!)
        return (email == userDetails.username && !isTokenExpired(token))
    }
    fun generateToken(userDetails: UserDetails): String{
        val claims: Map<String, Any> = HashMap()
        return createToken(claims, userDetails)
    }
    private fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T{
        val claims: Claims = extractAllClaims(token)
        return claimsResolver(claims)
    }
    // Private
     fun extractAllClaims(token: String): Claims{
        return Jwts.parserBuilder()
            .setSigningKey(getSignKey())
            .build()
            .parseClaimsJws(token)
            .body
    }
    private fun getSignKey(): Key {
        val keyBytes: ByteArray? = Decoders.BASE64.decode(SECRET)
        return Keys.hmacShaKeyFor(keyBytes)
    }
    private fun isTokenExpired(token: String): Boolean {
        return extractExpiration(token).before(Date())
    }
    private fun extractExpiration(token: String): Date {
        return extractClaim(token, Claims::getExpiration)
    }
    private fun createToken(
        claims: Map<String, Any>,
        userDetails: UserDetails
    ): String{
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() * 60 * 60 * 24))
            .signWith(getSignKey(), SignatureAlgorithm.HS256)
            .compact()
    }

    companion object{
        const val SECRET = "0L3sLtlyKYBAI4e7P1qGWiPbXbAxmgHCpjmdg9AvweWXYZc/WPRhAe4ztjQ75f3FDg/91hKOxcXN7xOuOXYTrczlwf5HgSesjEf05KTGaoV7YRT9WWytTFaMn9gk/cCZAKMtrPv+AzKb2LTqTJEDJJRI7khHHCZ50D0LOTUaKhRp9Z9/WMaQccydK1LNfsodi7svQyi5E2apgZz9w2iEqAStcTnipA7PKGMFw72GTtDqVUhwvUP1f+6TSsBOI+vuFw1zByI731Pix4XScl+U3jcGpy+ZYoVyPgouz+KZjh7qEyo2FtGPoFD8UNaL07GK48GzjmLtFmsuute7S5Jm1u703PF26YrOO3cR4QeP0jw=\n"
    }
}
