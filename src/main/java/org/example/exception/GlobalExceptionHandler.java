package org.example.exception;

import com.google.protobuf.Api;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponseDto;
import org.example.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SludiException.class)
    public ResponseEntity<ErrorResponse> handleSludiException(SludiException ex) {
        ErrorResponse error = ErrorResponse.builder()
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .timestamp(System.currentTimeMillis())
                .build();
        
        return ResponseEntity.badRequest().body(error);
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto<Void>> handleGeneralException(Exception ex){
        log.error("Unexpected error",ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDto.<Void>builder()
                        .success(false)
                        .errorCode("INTERNAL ERROR")
                        .message("Unexpected server error")
                        .timestamp(Instant.now())
                        .build()
                );

    }
}