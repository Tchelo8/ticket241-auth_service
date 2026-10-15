package com.tchelo.auth_service.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {

    String generateToken(String phoneNumber, UserDetails userDetails);

    // JWT court (5 min) avec claim scope=pre_mfa, utilisé pendant le challenge MFA
    String generateTempToken(String phone);

    String extractPhoneNumber(String token);

    // Retourne la valeur du claim "scope" (ex: "pre_mfa"), ou null si absent
    String extractScope(String token);

    boolean isTokenValid(String token, UserDetails userDetails);

    boolean isTokenExpired(String token);
}
