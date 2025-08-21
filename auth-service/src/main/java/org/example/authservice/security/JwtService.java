package org.example.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtService {
    private static final String TOKEN_TYPE = "token_type";
    private static final String USER_ID = "user_id";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Value("${app.security.jwt.access-token-expiration}")
    private Long accessTokenExpiration;

    @Value("${app.security.jwt.refresh-token-expiration}")
    private Long refreshTokenExpiration;

    public JwtService() throws Exception {
        privateKey = KeyUtils.loadPrivateKey("keys/local-only/private_key.pem");
        publicKey = KeyUtils.loadPublicKey("keys/local-only/public_key.pem");
    }

    public String generateAccessToken(String email, String userId) {
        Map<String, Object> claims = Map.of(
                TOKEN_TYPE, "access_token",
                USER_ID, userId
        );
        return buildToken(email, claims, accessTokenExpiration);
    }

    public String generateRefreshToken(String email, String userId) {
        Map<String, Object> claims = Map.of(
                TOKEN_TYPE, "refresh_token",
                USER_ID, userId
        );
        return buildToken(email, claims, refreshTokenExpiration);
    }

    public String refreshAccessToken(String refreshToken) {
        Claims claims = extractClaims(refreshToken);
        if (!"refresh_token".equals(claims.get(TOKEN_TYPE))) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (isTokenExpired(refreshToken)) {
            throw new RuntimeException("Token has expired");
        }

        return buildToken(claims.getSubject(), claims, accessTokenExpiration);
    }

    public boolean isTokenValid(String token, String expectedEmail) {
        String email = extractEmail(token);
        return email.equals(expectedEmail) && !isTokenExpired(token);
    }

    public String extractEmail(String token) {
        return extractClaims(token).getSubject();
    }

    public String extractUserId(String token) {
        return extractClaims(token).get(USER_ID, String.class);
    }


    private String buildToken(String email, Map<String, Object> claims, long expiration) {
        return Jwts.builder()
                .subject(email)
                .claims(claims)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(expiration)))
                .signWith(privateKey)
                .compact();
    }

    private boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    private Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException ex) {
            throw new RuntimeException("Invalid JWT token", ex);
        }
    }
}
