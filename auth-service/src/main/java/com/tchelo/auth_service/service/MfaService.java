package com.tchelo.auth_service.service;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.MfaSetupResponseDto;

public interface MfaService {

    // Génère le secret TOTP et retourne l'URI QR — tempToken identifie l'admin
    MfaSetupResponseDto setupMfa(String tempToken);

    // Vérifie le premier code TOTP, active le MFA et retourne le JWT complet
    AuthResponseDto confirmMfa(String tempToken, String code);

    // Connexions suivantes : échange (tempToken + code) contre le JWT complet
    AuthResponseDto validateMfaCode(String tempToken, String code);
}
