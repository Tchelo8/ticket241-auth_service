package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import lombok.Getter;

// Porte la réponse 401 (code invalide/expiré) décodée par OtpAwareErrorDecoder,
// pour la distinguer d'une vraie panne de notification-service.
@Getter
public class OtpInvalidCodeException extends RuntimeException {

    private final OtpVerifyResponseDto response;

    public OtpInvalidCodeException(OtpVerifyResponseDto response) {
        super(response != null ? response.getMessage() : "Code OTP invalide");
        this.response = response;
    }
}
