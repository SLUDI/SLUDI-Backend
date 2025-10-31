package org.example.utils;

import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

@Component
public class HashUtil {

    private static final MessageDigest SHA256;

    static {
        try {
            SHA256 = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static String sha256(String input) {
        if (input == null || input.isBlank()) return null;
        byte[] hash = SHA256.digest(input.toLowerCase().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}