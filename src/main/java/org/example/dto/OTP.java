package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OTP {
    private String code;
    private Instant expiryTime;

    public boolean isExpired() {
        return Instant.now().isAfter(expiryTime);
    }
}
