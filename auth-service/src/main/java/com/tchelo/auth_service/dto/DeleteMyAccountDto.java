package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// Suppression de son propre compte : le mot de passe est redemandé (un téléphone laissé
// déverrouillé ne doit pas suffire à supprimer le compte)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeleteMyAccountDto {

    @NotBlank(message = "Le mot de passe est requis pour confirmer la suppression")
    private String password;

    @Size(max = 500, message = "La raison ne peut pas dépasser 500 caractères")
    private String reason;
}
