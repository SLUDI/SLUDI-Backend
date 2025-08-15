package org.example.exception;

import org.example.dto.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
}