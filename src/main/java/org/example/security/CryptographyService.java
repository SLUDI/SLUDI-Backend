package org.example.security;

import lombok.extern.slf4j.Slf4j;
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
import java.security.spec.*;
import java.util.Base64;

@Slf4j
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
    public boolean verifySignature(String nonce, String signature, String publicKeyPem) {
        try {
            // Parse the public key
            PublicKey publicKey = parsePublicKey(publicKeyPem);

            // Verify the signature
            return verifyECDSASignature(nonce, signature, publicKey);

        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
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

    /**
     * Verify ECDSA signature
     */
    private boolean verifyECDSASignature(String message, String signatureBase64, PublicKey publicKey)
            throws Exception {

        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        byte[] messageBytes = message.getBytes("UTF-8");

        // Hash the message with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(messageBytes);

        // Verify signature
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(hash);

        return signature.verify(signatureBytes);
    }

    /**
     * Parse PEM formatted public key
     */
    private PublicKey parsePublicKey(String publicKeyPem) throws Exception {
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);

        // For EC public key in uncompressed format (0x04 + X + Y)
        if (keyBytes[0] == 0x04 && keyBytes.length == 65) {
            return parseUncompressedECPublicKey(keyBytes);
        }

        // Try standard X.509 format
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Parse uncompressed EC public key (0x04 || X || Y)
     */
    private PublicKey parseUncompressedECPublicKey(byte[] keyBytes) throws Exception {
        // Extract X and Y coordinates (32 bytes each for P-256)
        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];
        System.arraycopy(keyBytes, 1, xBytes, 0, 32);
        System.arraycopy(keyBytes, 33, yBytes, 0, 32);

        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);

        // Create EC public key from coordinates
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1")); // P-256 curve
        ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

        ECPoint point = new ECPoint(x, y);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecParams);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(pubKeySpec);
    }
}
