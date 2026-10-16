package com.tchelo.auth_service.dto;

import com.tchelo.auth_service.entity.AccountStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

// Fiche d'un compte pour la gestion (admins) : identité, rôles, statut et historique du dernier changement
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountSummaryDto {

    private Long id;
    private String phone;
    private String email;
    private String firstName;
    private String lastName;
    private List<String> roles;
    private Long structureId;
    private boolean emailVerified;
    private AccountStatus accountStatus;
    private LocalDateTime suspendedUntil;
    private LocalDateTime statusChangedAt;
    private String statusChangedBy;
    private String statusReason;
    private String message;
}
