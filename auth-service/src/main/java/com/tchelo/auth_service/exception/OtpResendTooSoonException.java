package com.tchelo.auth_service.exception;

public class OtpResendTooSoonException extends RuntimeException {
    public OtpResendTooSoonException(String message) {
        super(message);
    }
}
