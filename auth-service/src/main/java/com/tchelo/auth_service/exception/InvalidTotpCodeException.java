package com.tchelo.auth_service.exception;

public class InvalidTotpCodeException extends RuntimeException {
    public InvalidTotpCodeException(String message) {
        super(message);
    }
}
