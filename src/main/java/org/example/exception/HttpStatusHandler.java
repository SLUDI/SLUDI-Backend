package org.example.exception;

import org.springframework.http.HttpStatus;

public class HttpStatusHandler {
    public static HttpStatus getStatus(String errorCode) {
        switch (errorCode) {
            case "USER_NOT_FOUND":
            case "DID_NOT_FOUND":
                return HttpStatus.NOT_FOUND;
            case "UNAUTHORIZED":
                return HttpStatus.UNAUTHORIZED;
            case "USER_EXISTS":
            case "EMAIL_EXISTS":
            case "INVALID_INPUT":
            case "INVALID_NIC":
            case "MISSING_BIOMETRIC":
            case "MISSING_CONTACT":
            case "BIOMETRIC_INVALID":
            case "INVALID_FILE":
            case "FILE_TOO_LARGE":
            case "INVALID_FORMAT":
            case "INVALID_TYPE":
                return HttpStatus.BAD_REQUEST;
            case "USER_INACTIVE":
                return HttpStatus.FORBIDDEN;
            default:
                return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}