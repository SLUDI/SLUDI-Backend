package org.example.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.example.entity.OrganizationUser;
import org.example.enums.JWTTokenType;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class OrganizationJwtService {

    @Value("${security.jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${security.jwt.access.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.refresh.expiration-time}")
    private long refreshTokenExpiration;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    /**
     * Generate access token for authenticated organization user
     */
    public String generateAccessToken(OrganizationUser user) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", user.getId().toString());
            claims.put("username", user.getUsername());
            claims.put("email", user.getEmail());
            claims.put("employeeId", user.getEmployeeId());
            claims.put("organizationId", user.getOrganization().getId().toString());
            claims.put("organizationCode", user.getOrganization().getOrgCode());
            claims.put("roleId", user.getAssignedRole().getId().toString());
            claims.put("roleCode", user.getAssignedRole().getRoleCode());
            claims.put("isAdmin", user.getAssignedRole().getIsAdmin());
            claims.put("permissions", user.getAssignedRole().getPermissions());
            claims.put("status", user.getStatus().toString());
            claims.put("verificationStatus", user.getVerificationStatus().toString());
            claims.put("fabricUserId", user.getFabricUserId());
            claims.put("isEnrolledOnBlockchain", user.getIsEnrolledOnBlockchain());
            claims.put("tokenType", JWTTokenType.ACCESS_TOKEN);
            claims.put("userType", "ORGANIZATION_USER");

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getUsername())
                    .setIssuer(issuerDid)
                    .setAudience("sludi-org-api")
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
     * Generate refresh token for token renewal
     */
    public String generateRefreshToken(OrganizationUser user) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", user.getId().toString());
            claims.put("username", user.getUsername());
            claims.put("organizationId", user.getOrganization().getId().toString());
            claims.put("tokenType", JWTTokenType.REFRESH_TOKEN);
            claims.put("userType", "ORGANIZATION_USER");

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getUsername())
                    .setIssuer(issuerDid)
                    .setAudience("sludi-org-api")
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
     * Extract username from JWT token
     */
    public String extractUsernameFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("username", String.class);
    }

    /**
     * Extract user ID from JWT token
     */
    public Long extractUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        return Long.parseLong(claims.get("userId", String.class));
    }

    /**
     * Extract organization ID from JWT token
     */
    public Long extractOrganizationIdFromToken(String token) {
        Claims claims = validateToken(token);
        return Long.parseLong(claims.get("organizationId", String.class));
    }

    /**
     * Extract role code from JWT token
     */
    public String extractRoleCodeFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("roleCode", String.class);
    }

    /**
     * Check if user is admin
     */
    public boolean isAdminUser(String token) {
        Claims claims = validateToken(token);
        return claims.get("isAdmin", Boolean.class);
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
     * Refresh access token using refresh token
     */
    public String refreshAccessToken(String refreshToken, OrganizationUser user) {
        try {
            Claims claims = validateToken(refreshToken);

            // Verify it's a refresh token
            if (!JWTTokenType.REFRESH_TOKEN.name().equals(claims.get("tokenType", String.class))) {
                throw new SludiException(ErrorCodes.INVALID_REFRESH_TOKEN, "Invalid token type");
            }

            // Verify user type
            if (!"ORGANIZATION_USER".equals(claims.get("userType", String.class))) {
                throw new SludiException(ErrorCodes.INVALID_REFRESH_TOKEN, "Invalid user type");
            }

            // Verify user matches
            if (!user.getUsername().equals(claims.getSubject())) {
                throw new SludiException(ErrorCodes.INVALID_REFRESH_TOKEN, "Token user mismatch");
            }

            return generateAccessToken(user);

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_REFRESH_FAILED, e);
        }
    }

    /**
     * Verify user has specific permission from token
     */
    public boolean hasPermission(String token, String permission) {
        try {
            Claims claims = validateToken(token);

            // Admin has all permissions
            if (claims.get("isAdmin", Boolean.class)) {
                return true;
            }

            @SuppressWarnings("unchecked")
            java.util.List<String> permissions = claims.get("permissions", java.util.List.class);

            return permissions != null && (permissions.contains("ALL") || permissions.contains(permission));

        } catch (Exception e) {
            return false;
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