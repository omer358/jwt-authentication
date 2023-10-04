package com.alibo.jwtsecurity.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY = "gDbRSxH5lUCRD/sjH/5ZR336syyWYMwoJnBeAGh+OqnEihVfQNzjN8Zhg6c3Ll0RQa9AMCkmyQyqLELzmqmYXkVWwF/pt6PDKoPA7eS38HtzWiq+1LXFA3idcE+Tu3V09EI6ymxTepG2iMuHtbDmqVLBlF7e51kLhfhvgKgn9AqV0RaH9HDfKtHX3oTqt5KTZiVJoRvGLiE8KdvOaUZh9H2t23EQwmrLp9FhbOooxDa8GEcoBf73b2mOEGjnIV887Canlk/3y0JYpIjbrFHtaj78P9qbC/tZoBkJ4nImg65KHQWZbUO4SwCVr56T6NMFTjKOSgD4LhxqZF56Ymjx/KeDvm8vc3h+o8ZZjLOtU6s=";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date((System.currentTimeMillis() + 1000 * 60 * 24)))
                .signWith(getSigningKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
