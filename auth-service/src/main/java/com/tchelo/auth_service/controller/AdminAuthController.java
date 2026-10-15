package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.*;
import com.tchelo.auth_service.service.AdminAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/admin")
@RequiredArgsConstructor
public class AdminAuthController {

    private final AdminAuthService adminAuthService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> registerAdmin(
            @Valid @RequestBody RegisterAdminDto request
    ) {
        AuthResponseDto response = adminAuthService.registerAdmin(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> loginAdmin(
            @Valid @RequestBody LoginAdminDto request
    ) {
        AuthResponseDto response = adminAuthService.loginAdmin(request);
        return ResponseEntity.ok(response);
    }

    // vérifie le code OTP reçu par email et active le compte admin si valide
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponseDto> verifyOtpAdmin(
            @Valid @RequestBody VerifyOtpRequestDto request
    ) {
        AuthResponseDto response = adminAuthService.verifyOtpAdmin(request);
        return ResponseEntity.ok(response);
    }
}