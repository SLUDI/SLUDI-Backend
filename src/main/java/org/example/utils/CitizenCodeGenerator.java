package org.example.utils;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Year;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@RequiredArgsConstructor
public class CitizenCodeGenerator {

    private final EntityManager entityManager;
    private static final String PREFIX = "CIT";

    public String generateCitizenCode() {
        // Fetch the next value from Postgres sequence
        Long nextVal = ((Number) entityManager
                .createNativeQuery("SELECT nextval('citizen_code_seq')")
                .getSingleResult()).longValue();

        int year = Year.now().getValue();
        return String.format("%s-%d-%05d", PREFIX, year, nextVal);
    }
}
