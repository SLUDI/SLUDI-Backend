package org.example.utils;

import java.security.SecureRandom;
import java.time.LocalDate;

public class DIDIdGenerator {

    private static final SecureRandom random = new SecureRandom();

    public enum Gender {
        MALE, FEMALE
    }

    public static String generateDID(LocalDate dateOfBirth, Gender gender) {
        // year of birth
        String year = String.valueOf(dateOfBirth.getYear());

        // day of year
        int dayOfYear = dateOfBirth.getDayOfYear();
        if (gender == Gender.FEMALE) {
            dayOfYear += 500; // add 500 for female
        }
        String ddd = String.format("%03d", dayOfYear);

        // serial number (0–9)
        String n = String.valueOf(random.nextInt(10));

        // sequence / checksum (4 digits)
        String sequence = String.format("%04d", random.nextInt(10000));

        return "did:sludi:" + year + ddd + n + sequence;
    }

}
