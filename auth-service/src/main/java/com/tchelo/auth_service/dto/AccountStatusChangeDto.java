package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

// Suspension, suppression ou réactivation d'un compte par un admin
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountStatusChangeDto {

    @Size(max = 500, message = "La raison ne peut pas dépasser 500 caractères")
    private String reason;

    // Suspension uniquement : fin de la suspension (vide = jusqu'à réactivation manuelle)
    @Future(message = "La fin de suspension doit être dans le futur")
    private LocalDateTime until;
}
