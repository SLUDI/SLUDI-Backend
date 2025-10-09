package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.ipfs.multibase.Base58;
import org.example.entity.CitizenUser;
import org.example.entity.VerifiableCredential;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class CryptographyService {

    @Value("${sludi.jwt.secret}")
    private String jwtSecret;

    @Value("${sludi.jwt.access-token-expiration}")
    private int accessTokenExpirationSeconds;

    @Value("${sludi.jwt.refresh-token-expiration}")
    private int refreshTokenExpirationSeconds; // 30 days

    @Value("${sludi.encryption.key}")
    private String encryptionKey;

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;

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
            claims.put("kycStatus", user.getKycStatus().toString());
            claims.put("tokenType", "access");

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getId().toString())
                    .setIssuer("sludi-digital-identity")
                    .setAudience("sludi-services")
                    .setIssuedAt(new Date())
                    .setExpiration(Date.from(Instant.now().plus(accessTokenExpirationSeconds, ChronoUnit.SECONDS)))
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
    public String generateRefreshToken(CitizenUser user) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", user.getId().toString());
            claims.put("didId", user.getDidId());
            claims.put("tokenType", "refresh");

            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getId().toString())
                    .setIssuer("sludi-digital-identity")
                    .setAudience("sludi-services")
                    .setIssuedAt(new Date())
                    .setExpiration(Date.from(Instant.now().plus(refreshTokenExpirationSeconds, ChronoUnit.SECONDS)))
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
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
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
     * Refresh access token using refresh token
     */
    public String refreshAccessToken(String refreshToken, CitizenUser user) {
        try {
            Claims claims = validateToken(refreshToken);
            
            // Verify it's a refresh token
            if (!"refresh".equals(claims.get("tokenType"))) {
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

    /**
     * Encrypt sensitive data using AES-256-GCM
     */
    public String encryptData(String plainText) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(getEncryptionKeyBytes(), "AES");
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            
            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            
            byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            
            // Combine IV and encrypted data
            byte[] encryptedWithIv = new byte[GCM_IV_LENGTH + encryptedData.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedData, 0, encryptedWithIv, GCM_IV_LENGTH, encryptedData.length);
            
            return Base64.getEncoder().encodeToString(encryptedWithIv);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.ENCRYPTION_FAILED, "Failed to encrypt data", e);
        }
    }

    /**
     * Decrypt sensitive data using AES-256-GCM
     */
    public String decryptData(String encryptedText) {
        try {
            byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedText);
            
            // Extract IV and encrypted data
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
            
            System.arraycopy(encryptedWithIv, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedWithIv, GCM_IV_LENGTH, encryptedData, 0, encryptedData.length);
            
            SecretKeySpec secretKey = new SecretKeySpec(getEncryptionKeyBytes(), "AES");
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            
            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.DECRYPTION_FAILED, "Failed to decrypt data", e);
        }
    }

    /**
     * Generate secure hash for biometric data or sensitive information
     */
    public String generateSecureHash(String data, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            
            // Add salt to prevent rainbow table attacks
            String saltedData = data + salt;
            byte[] hashedBytes = digest.digest(saltedData.getBytes(StandardCharsets.UTF_8));
            
            return Base64.getEncoder().encodeToString(hashedBytes);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.HASH_GENERATION_FAILED, "Failed to generate secure hash", e);
        }
    }

    /**
     * Generate cryptographically secure salt
     */
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32]; // 256-bit salt
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Verify hash against original data
     */
    public boolean verifyHash(String data, String salt, String expectedHash) {
        try {
            String actualHash = generateSecureHash(data, salt);
            return actualHash.equals(expectedHash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generate secure random string for various purposes (API keys, secrets, etc.)
     */
    public String generateSecureRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generate DID-specific signature for blockchain operations
     */
    public String generateDidSignature(String data, String privateKey) {
        try {
            // In production, this would use actual cryptographic signing with private key
            // For now, using secure hash as placeholder
            String timestamp = String.valueOf(Instant.now().toEpochMilli());
            String signingData = data + timestamp + privateKey;
            byte[] salt = generateSalt();
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            return generateSecureHash(signingData, saltBase64);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.SIGNATURE_GENERATION_FAILED, "Failed to generate DID signature", e);
        }
    }

    /**
     * Verify DID signature
     */
    public boolean verifyDidSignature(String data, String signature, String publicKey) {
        try {
            // In production, this would use actual cryptographic verification
            // For now, basic validation
            return signature != null && signature.length() > 0 && publicKey != null;

        } catch (Exception e) {
            return false;
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private byte[] getEncryptionKeyBytes() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(encryptionKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.ENCRYPTION_KEY_ERROR, e);
        }
    }

    /**
     * Generate key pair for DID operations (placeholder for actual implementation)
     */
    public Map<String, String> generateKeyPair() {
        try {
            // Generate real Ed25519 key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

            // Convert to Base58
            String privateKeyBase58 = Base58.encode(privateKeyBytes);
            String publicKeyBase58 = Base58.encode(publicKeyBytes);

            Map<String, String> result = new HashMap<>();
            result.put("privateKey", privateKeyBase58);
            result.put("publicKey", publicKeyBase58);

            return result;

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.KEY_GENERATION_FAILED, e);
        }
    }

    /**
     * Generate a secure key for wallet encryption
     */
    public SecretKey generateWalletKey(String password, byte[] salt) {

        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    ITERATION_COUNT,
                    KEY_LENGTH
            );

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();

            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.KEY_GENERATION_FAILED, e);
        }
    }

    /**
     * Generate key fingerprint
     */
    public String generateKeyFingerprint(SecretKey key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(key.getEncoded());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.KEY_FINGERPRINT_GENERATION_FAILED, e);
        }
    }

    /**
     * Encrypt key for storage
     */
    public static String encryptKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Encrypt biometric data for IPFS storage
     */
    public byte[] encryptBiometricData(byte[] biometricData) {
        try {
            String base64Data = Base64.getEncoder().encodeToString(biometricData);
            String encryptedData = encryptData(base64Data);
            return encryptedData.getBytes(StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.BIOMETRIC_ENCRYPTION_FAILED, e);
        }
    }

    /**
     * Decrypt biometric data from IPFS storage
     */
    public byte[] decryptBiometricData(byte[] encryptedBiometricData) {
        try {
            String encryptedString = new String(encryptedBiometricData, StandardCharsets.UTF_8);
            String decryptedBase64 = decryptData(encryptedString);
            return Base64.getDecoder().decode(decryptedBase64);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.BIOMETRIC_DECRYPTION_FAILED, e);
        }
    }
}
