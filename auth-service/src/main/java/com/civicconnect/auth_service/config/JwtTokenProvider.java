package com.civicconnect.auth_service.config;

import com.civicconnect.auth_service.model.UserRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;

import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${app.refreshTokenExpirationInMs}")
    private int refreshTokenExpirationInMs;

    public String generateToken(String username, UserRole role) {
        // Generate JWT token
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role.toString())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String generateRefreshToken(String username) {
        // Generate Refresh token
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenExpirationInMs);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            // Log invalid signature
        } catch (MalformedJwtException ex) {
            // Log malformed JWT
        } catch (ExpiredJwtException ex) {
            // Log expired JWT
        } catch (UnsupportedJwtException ex) {
            // Log unsupported JWT
        } catch (IllegalArgumentException ex) {
            // Log empty or null JWT
        }
        return false;
    }

    public boolean validateRefreshToken(String refreshToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(refreshToken);
            return true;
        } catch (SignatureException ex) {
            // Log invalid signature
        } catch (MalformedJwtException ex) {
            // Log malformed JWT
        } catch (ExpiredJwtException ex) {
            // Log expired JWT
        } catch (UnsupportedJwtException ex) {
            // Log unsupported JWT
        } catch (IllegalArgumentException ex) {
            // Log empty or null JWT
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch ( IllegalArgumentException e) {
            return true;
        }
    }

    public String refreshToken(String refreshToken) {
        try {
            if (!validateRefreshToken(refreshToken)) {
                return null;
            }
            String username = getUsernameFromToken(refreshToken);
            return generateToken(username, UserRole.USER); // Assuming role is retrieved from DB
        } catch (Exception ex) {
            return null;
        }
    }
}
