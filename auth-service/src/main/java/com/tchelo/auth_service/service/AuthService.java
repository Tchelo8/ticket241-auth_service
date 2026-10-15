package com.tchelo.auth_service.service;



import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.LoginRequestDto;
import com.tchelo.auth_service.dto.RegisterRequestDto;
import com.tchelo.auth_service.dto.ResendOtpRequestDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;


public interface AuthService {

    // Inscrit un nouvel utilisateur
    AuthResponseDto register(RegisterRequestDto request);

    // Authentifie un utilisateur
    AuthResponseDto login(LoginRequestDto request);

    // Valide un token JWT
    boolean validateToken(String token);

    // Vérifie l'OTP reçu par email et active le compte si le code est valide
    AuthResponseDto verifyOtp(VerifyOtpRequestDto request);

    // Redéclenche l'envoi d'un OTP pour un compte non encore vérifié
    AuthResponseDto resendOtp(ResendOtpRequestDto request);
}