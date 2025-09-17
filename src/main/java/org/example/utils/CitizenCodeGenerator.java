package org.example.utils;

import java.time.Year;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

public class CitizenCodeGenerator {

    private static final AtomicInteger counter = new AtomicInteger(1);
    private static final String PREFIX = "CIT";
    private static final Random random = new Random();

    // CIT-2025-00001
    public static String generateCitizenCode() {
        int year = Year.now().getValue();
        int number = counter.getAndIncrement();
        return String.format("%s-%d-%05d", PREFIX, year, number);
    }
}
