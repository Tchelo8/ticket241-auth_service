package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.LoginRequestDto;
import com.tchelo.auth_service.dto.RegisterRequestDto;
import com.tchelo.auth_service.dto.ResendOtpRequestDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;
import com.tchelo.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

  //route pour l'inscription d'un utilisateur
    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        AuthResponseDto response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // vérifie le code OTP reçu par email et active le compte si valide
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponseDto> verifyOtp(@Valid @RequestBody VerifyOtpRequestDto request) {
        AuthResponseDto response = authService.verifyOtp(request);
        return ResponseEntity.ok(response);
    }

    // renvoie un nouveau code OTP pour un compte pas encore vérifié
    @PostMapping("/resend-otp")
    public ResponseEntity<AuthResponseDto> resendOtp(@Valid @RequestBody ResendOtpRequestDto request) {
        AuthResponseDto response = authService.resendOtp(request);
        return ResponseEntity.ok(response);
    }

    //celle pour la connexion de l'utilisateur
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        AuthResponseDto response = authService.login(request);
        return ResponseEntity.ok(response);
    }


    //validation du token jwt généré et cette route est utilisée par mon api gateway
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String authHeader) {
        // Extraire le token en enlevant le bearer avant
        String token = authHeader.substring(7);
        boolean isValid = authService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }


    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Le service d'authentification est en marche");
    }
}
