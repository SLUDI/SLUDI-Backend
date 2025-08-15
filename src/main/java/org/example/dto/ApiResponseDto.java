package org.example.dto;

import lombok.Builder;
import lombok.Data;
import java.time.Instant;

@Data
@Builder
public class ApiResponseDto<T> {
    private boolean success;
    private String message;
    private String errorCode;
    private T data;
    private Instant timestamp;
}