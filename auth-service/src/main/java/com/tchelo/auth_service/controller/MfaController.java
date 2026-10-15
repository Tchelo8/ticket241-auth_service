package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.MfaConfirmRequestDto;
import com.tchelo.auth_service.dto.MfaSetupRequestDto;
import com.tchelo.auth_service.dto.MfaSetupResponseDto;
import com.tchelo.auth_service.dto.MfaValidateRequestDto;
import com.tchelo.auth_service.service.MfaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;

    // Étape 1 (première connexion) : génère le secret + URI QR
    @PostMapping("/setup")
    public ResponseEntity<MfaSetupResponseDto> setup(
            @Valid @RequestBody MfaSetupRequestDto request) {
        return ResponseEntity.ok(mfaService.setupMfa(request.getTempToken()));
    }

    // Étape 2 (première connexion) : valide le premier code, active le MFA, retourne le JWT
    @PostMapping("/confirm")
    public ResponseEntity<AuthResponseDto> confirm(
            @Valid @RequestBody MfaConfirmRequestDto request) {
        return ResponseEntity.ok(mfaService.confirmMfa(request.getTempToken(), request.getCode()));
    }

    // Connexions suivantes : échange tempToken + code contre le JWT complet
    @PostMapping("/validate")
    public ResponseEntity<AuthResponseDto> validate(
            @Valid @RequestBody MfaValidateRequestDto request) {
        return ResponseEntity.ok(mfaService.validateMfaCode(request.getTempToken(), request.getCode()));
    }
}
