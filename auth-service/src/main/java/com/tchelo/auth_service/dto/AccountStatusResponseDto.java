package com.tchelo.auth_service.dto;

import com.tchelo.auth_service.entity.AccountStatus;

import java.time.LocalDateTime;

// Réponse de GET /internal/accounts/status : les autres services refusent toute écriture si active=false
public record AccountStatusResponseDto(String phone, AccountStatus status, LocalDateTime suspendedUntil,
                                       boolean active) {
}
