package com.authservice.security;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtTokenProvider {

    // Example using a secret key string for HMAC SHA-256
    @Value("${spring.app.jwtSecret}")
    private String secretKey;

    public String generateToken(UserDetails userDetails) {
        long currentTimeMillis = System.currentTimeMillis();
        Key key = getSigninKey(secretKey);

        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse(null);

        return Jwts.builder()
                .claim("sub", userDetails.getUsername())
                .claim("role", role)
                .claim("iat", new Date(currentTimeMillis))
                .claim("exp", new Date(currentTimeMillis + 1000 * 60 * 60 * 12)) // 24 hours expiration
                .signWith(key)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        Key key = getSigninKey(secretKey); // Ensure the key is used here as well
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    private Key getSigninKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    /**
     * Check Toke is Valid or not
     * 
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
