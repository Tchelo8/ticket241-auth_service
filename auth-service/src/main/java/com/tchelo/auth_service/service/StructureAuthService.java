package com.tchelo.auth_service.service;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.CreateAgentDto;
import com.tchelo.auth_service.dto.RegisterStructureAdminDto;
import com.tchelo.auth_service.dto.LoginStructureAdminDto;
import com.tchelo.auth_service.dto.StructureUserDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;

import java.util.List;

public interface StructureAuthService {


    AuthResponseDto registerStructureAdmin(RegisterStructureAdminDto request);

    AuthResponseDto loginStructureAdmin(LoginStructureAdminDto request);

    AuthResponseDto verifyOtpStructureAdmin(VerifyOtpRequestDto request);

    List<StructureUserDto> getUsersByStructure(Long structureId);

    // Crée un contrôleur d'entrée (ROLE_AGENT) pour la structure : admin Ticket241 ou admin de cette
    // structure. Le compte s'active avec l'OTP reçu par email (/api/auth/verify-otp).
    AuthResponseDto createAgent(Long structureId, CreateAgentDto request);
}
