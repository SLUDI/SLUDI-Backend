package org.example.exception;

public class SludiException extends RuntimeException {
    private final String errorCode;

    public SludiException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public SludiException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
