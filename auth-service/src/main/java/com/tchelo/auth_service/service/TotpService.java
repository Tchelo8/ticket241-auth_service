package com.tchelo.auth_service.service;

public interface TotpService {

    String generateSecret();

    // Retourne l'URI otpauth:// que le front-end utilise pour générer le QR code
    String buildOtpAuthUri(String secret, String phone);

    boolean verifyCode(String secret, String code);
}
