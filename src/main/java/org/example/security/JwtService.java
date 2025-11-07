package org.example.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import io.jsonwebtoken.security.SignatureException;
import org.example.entity.CitizenUser;
import org.example.enums.JWTTokenType;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${security.jwt.access.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.refresh.expiration-time}")
    private long refreshTokenExpiration;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    /**
     * Generate access token for authenticated user
     */
    public String generateAccessToken(CitizenUser user) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", user.getId().toString());
            claims.put("didId", user.getDidId());
            claims.put("email", user.getEmail());
            claims.put("nic", user.getNic());
            claims.put("fullName", user.getFullName());
            claims.put("status", user.getStatus().toString());
            claims.put("verificationStatus", user.getVerificationStatus().toString());
            claims.put("tokenType", JWTTokenType.ACCESS_TOKEN);

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getId().toString())
                    .setIssuer(issuerDid)
                    .setAudience("sludi-api")
                    .setIssuedAt(new Date())
                    .setExpiration(Date.from(Instant.now().plus(jwtExpiration, ChronoUnit.MILLIS)))
                    .setId(UUID.randomUUID().toString())
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_GENERATION_FAILED, "Failed to generate access token", e);
        }
    }

    /**
     * Validate and parse JWT token
     */
    public Claims validateToken(String token) {
        try {
            return parseClaims(token);
        } catch (ExpiredJwtException e) {
            throw new SludiException(ErrorCodes.TOKEN_EXPIRED, "Token has expired");
        } catch (UnsupportedJwtException e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID, "Unsupported JWT token");
        } catch (MalformedJwtException e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID, "Malformed JWT token");
        } catch (SignatureException e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID, "Invalid JWT signature");
        } catch (IllegalArgumentException e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID, "JWT token compact string is invalid");
        }
    }

    /**
     * Extract user ID from JWT token
     */
    public UUID extractUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        return UUID.fromString(claims.get("userId", String.class));
    }

    /**
     * Extract DID from JWT token
     */
    public String extractDidFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("didId", String.class);
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Generate refresh token for token renewal
     */
    public String generateRefreshToken(CitizenUser user) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", user.getId().toString());
            claims.put("didId", user.getDidId());
            claims.put("tokenType", JWTTokenType.REFRESH_TOKEN);

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getId().toString())
                    .setIssuer(issuerDid)
                    .setAudience("sludi-api")
                    .setIssuedAt(new Date())
                    .setExpiration(Date.from(Instant.now().plus(refreshTokenExpiration, ChronoUnit.MILLIS)))
                    .setId(UUID.randomUUID().toString())
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_GENERATION_FAILED, "Failed to generate refresh token", e);
        }
    }

    /**
     * Refresh access token using refresh token
     */
    public String refreshAccessToken(String refreshToken, CitizenUser user) {
        try {
            Claims claims = validateToken(refreshToken);

            // Verify it's a refresh token
            if (!JWTTokenType.REFRESH_TOKEN.name().equals(claims.get("tokenType", String.class))) {
                throw new SludiException(ErrorCodes.INVALID_REFRESH_TOKEN, "Invalid token type");
            }

            // Verify user matches
            if (!user.getId().toString().equals(claims.getSubject())) {
                throw new SludiException(ErrorCodes.INVALID_REFRESH_TOKEN, "Token user mismatch");
            }

            return generateAccessToken(user);

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_REFRESH_FAILED, e);
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}