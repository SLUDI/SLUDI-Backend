package org.example.security;

import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class CryptographyService {

    @Value("${sludi.encryption.key}")
    private String encryptionKey;

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;



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
     * Verify signature using public key
     */
    public boolean verifySignature(String message, String signatureStr, String publicKeyPem) {
        try {
            // TEMPORARY: Accept HMAC signatures for testing
            String hmacKey = "wallet-auth-key-2024";
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                    hmacKey.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] expectedHmac = mac.doFinal(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String expectedSignature = java.util.Base64.getEncoder().encodeToString(expectedHmac);

            System.out.println("Expected HMAC signature: " + expectedSignature);
            System.out.println("Received signature: " + signatureStr);
            System.out.println("Message: " + message);

            if (signatureStr.equals(expectedSignature)) {
                System.out.println("✅ HMAC signature accepted for testing");
                return true;
            } else {
                System.out.println("❌ HMAC signature mismatch");
                System.out.println("Expected: " + expectedSignature);
                System.out.println("Received: " + signatureStr);
            }

            // If HMAC fails, try RSA verification
            try {
                String publicKeyContent = publicKeyPem
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s+", "");

                byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKeyContent);
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                java.security.PublicKey publicKey = keyFactory.generatePublic(
                        new java.security.spec.X509EncodedKeySpec(publicKeyBytes));

                java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                byte[] signatureBytes = java.util.Base64.getDecoder().decode(signatureStr);

                boolean rsaVerified = signature.verify(signatureBytes);
                if (rsaVerified) {
                    System.out.println("✅ RSA signature verified");
                } else {
                    System.out.println("❌ RSA signature verification failed");
                }
                return rsaVerified;
            } catch (Exception rsaError) {
                System.out.println("RSA verification failed: " + rsaError.getMessage());
                return false;
            }

        } catch (Exception e) {
            System.out.println("Signature verification error: " + e.getMessage());
            throw new SludiException(ErrorCodes.SIGNATURE_FAILED, "Failed to verify signature", e);
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
     * Generate secure random string
     */
    public String generateSecureRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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

    private byte[] getEncryptionKeyBytes() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(encryptionKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.ENCRYPTION_KEY_ERROR, e);
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
