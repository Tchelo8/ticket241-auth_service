package com.tchelo.auth_service.exception;

public class OtpVerificationUnavailableException extends RuntimeException {
    public OtpVerificationUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}