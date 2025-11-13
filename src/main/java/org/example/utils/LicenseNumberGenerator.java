package org.example.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
@RequiredArgsConstructor
public class LicenseNumberGenerator {

    private static final String LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final Random RANDOM = new Random();

    /**
     * Generates a random Sri Lankan driving licence number.
     * Format: <Letter><7 digits>
     * Example: B1234567
     */
    public String generateLicenseNumber() {
        // Random prefix letter (A–Z)
        char prefix = LETTERS.charAt(RANDOM.nextInt(LETTERS.length()));

        // Generate 7-digit number
        int number = RANDOM.nextInt(10_000_000); // 0–9999999
        String numberPart = String.format("%07d", number);

        return prefix + numberPart;
    }
}
