package org.example.util;

import lombok.extern.slf4j.Slf4j;
import org.example.entity.Organization;

import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Slf4j
public class OrgCodeGenerator {
    private static final Random RANDOM = new SecureRandom();
    private static final int ABBREVIATION_LENGTH = 3;
    private static final int RANDOM_SUFFIX_LENGTH = 3;
    
    //Organization type prefix
    private static final Map<Organization.OrganizationType, String > TYPE_PREFIXES = new HashMap<>();
    
    static {
        TYPE_PREFIXES.put(Organization.OrganizationType.GOVERNMENT, "GOV");
        TYPE_PREFIXES.put(Organization.OrganizationType.FINANCIAL, "FIN");
        TYPE_PREFIXES.put(Organization.OrganizationType.PRIVATE, "PVT");
        TYPE_PREFIXES.put(Organization.OrganizationType.NGO, "NGO");
    }
    
    public static String generate(String name, Organization.OrganizationType type){
        if (name == null || name.trim().isEmpty()){
            throw new IllegalArgumentException("Organization name cannot be null or empty");
        }
        if (type == null){
            throw new IllegalArgumentException("Organization type cannot be null");
        }
        
        String prefix = TYPE_PREFIXES.getOrDefault(type, "ORG");
        String cleanedName = cleanAndNormalize(name);
        String abbreviation = generateAbbreviation(cleanedName);

        String orgCode = String.format("%s-%s", prefix, abbreviation);
        log.debug("Generated org code: {} for name : {}", orgCode, name);
        return orgCode.toUpperCase();
    }

    private static String generateAbbreviation(String text) {
        if (text == null || text.trim().isEmpty()) {
            return generateRandomSuffix(ABBREVIATION_LENGTH);
        }

        String[] words = text.split("\\s+");

        if (words.length == 1) {
            // Single word: take first characters
            return words[0].length() >= ABBREVIATION_LENGTH
                    ? words[0].substring(0, ABBREVIATION_LENGTH)
                    : padRight(words[0], ABBREVIATION_LENGTH);
        } else {
            // Multiple words: take first letter of each word
            StringBuilder abbr = new StringBuilder();
            for (String word : words) {
                if (!word.isEmpty() && abbr.length() < 6) {
                    abbr.append(word.charAt(0));
                }
            }

            // If abbreviation is too short, add characters from first word
            if (abbr.length() < ABBREVIATION_LENGTH && words[0].length() > 1) {
                int needed = ABBREVIATION_LENGTH - abbr.length();
                String firstWord = words[0];
                for (int i = 1; i < firstWord.length() && needed > 0; i++) {
                    abbr.append(firstWord.charAt(i));
                    needed--;
                }
            }

            return abbr.length() >= ABBREVIATION_LENGTH
                    ? abbr.substring(0, Math.min(6, abbr.length()))
                    : padRight(abbr.toString(), ABBREVIATION_LENGTH);
        }
    }

    private static String generateRandomSuffix(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder suffix = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            suffix.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }

        return suffix.toString();
    }

    /**
     * Pad string to right with random characters
     */
    private static String padRight(String text, int length) {
        if (text.length() >= length) {
            return text.substring(0, length);
        }

        return text + generateRandomSuffix(length - text.length());
    }

    private static String cleanAndNormalize(String text) {
        if (text == null || text.trim().isEmpty()){
            return "";
        }
        // Remove accents and special characters
        String normalized = Normalizer.normalize(text, Normalizer.Form.NFD);
        normalized = normalized.replaceAll("\\p{M}", "");

        // Remove special characters except spaces and hyphens
        normalized = normalized.replaceAll("[^a-zA-Z0-9\\s-]", "");

        // Replace multiple spaces with single space
        normalized = normalized.replaceAll("\\s+", " ");

        // Trim and convert to uppercase
        return normalized.trim().toUpperCase();
    }

}
