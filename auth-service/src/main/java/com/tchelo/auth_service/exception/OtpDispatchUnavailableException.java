package com.tchelo.auth_service.exception;

public class OtpDispatchUnavailableException extends RuntimeException {
    public OtpDispatchUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}