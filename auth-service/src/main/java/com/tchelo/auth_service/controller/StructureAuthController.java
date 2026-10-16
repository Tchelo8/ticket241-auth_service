package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.*;
import com.tchelo.auth_service.service.StructureAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth/structure")
@RequiredArgsConstructor
public class StructureAuthController {

    private final StructureAuthService structureAuthService;

    // Inscription d'un administrateur de structure
    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> registerStructureAdmin(
            @Valid @RequestBody RegisterStructureAdminDto request
    ) {
        AuthResponseDto response = structureAuthService.registerStructureAdmin(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // Connexion d'un administrateur de structure
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> loginStructureAdmin(
            @Valid @RequestBody LoginStructureAdminDto request
    ) {
        AuthResponseDto response = structureAuthService.loginStructureAdmin(request);
        return ResponseEntity.ok(response);
    }

    // vérifie le code OTP reçu par email et active le compte admin structure si valide
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponseDto> verifyOtpStructureAdmin(
            @Valid @RequestBody VerifyOtpRequestDto request
    ) {
        AuthResponseDto response = structureAuthService.verifyOtpStructureAdmin(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{structureId}/users")
    public ResponseEntity<StructureUsersResponseDto> getUsersByStructure(
            @PathVariable Long structureId
    ) {
        List<StructureUserDto> users = structureAuthService.getUsersByStructure(structureId);
        return ResponseEntity.ok(new StructureUsersResponseDto(users.size(), users));
    }

    // Création d'un contrôleur d'entrée (scanne les billets des événements de la structure)
    @PostMapping("/{structureId}/agents")
    public ResponseEntity<AuthResponseDto> createAgent(
            @PathVariable Long structureId,
            @Valid @RequestBody CreateAgentDto request
    ) {
        AuthResponseDto response = structureAuthService.createAgent(structureId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
