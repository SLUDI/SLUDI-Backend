package org.example.exception;

import lombok.Getter;

@Getter
public class SludiException extends RuntimeException {
    private final String errorCode;
    private final String errorDescription;
    
    public SludiException(ErrorCodes errorCode) {
        super(errorCode.getDescription());
        this.errorCode = errorCode.getCode();
        this.errorDescription = errorCode.getDescription();
    }

    public SludiException(ErrorCodes errorCode, String additionalInfo) {
        super(errorCode.getDescription() + ": " + additionalInfo);
        this.errorCode = errorCode.getCode();
        this.errorDescription = errorCode.getDescription();
    }

    public SludiException(ErrorCodes errorCode, Throwable cause) {
        super(errorCode.getDescription() + ": " + cause.getMessage(), cause);
        this.errorCode = errorCode.getCode();
        this.errorDescription = errorCode.getDescription();
    }

    public SludiException(ErrorCodes errorCode, String additionalInfo, Throwable cause) {
        super(errorCode.getDescription() + ": " + additionalInfo, cause);
        this.errorCode = errorCode.getCode();
        this.errorDescription = errorCode.getDescription();
    }
}
