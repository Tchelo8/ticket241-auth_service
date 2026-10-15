package com.tchelo.auth_service.exception;

public class InvalidInvitationCodeException extends RuntimeException {
    public InvalidInvitationCodeException(String message) {
        super(message);
    }
}
