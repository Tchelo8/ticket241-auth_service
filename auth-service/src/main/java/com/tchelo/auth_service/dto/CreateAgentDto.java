package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// Contrôleur d'entrée créé par l'admin d'une structure : il pourra scanner les billets des
// événements de cette structure, et rien d'autre
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateAgentDto {

    @NotBlank(message = "Le numéro de téléphone est requis")
    @Size(min = 3, max = 50, message = "Le numéro de téléphone doit avoir au moins 8 caractères")
    private String phone;

    @NotBlank(message = "L'Email est requis")
    @Email(message = "L'Email doit être valide")
    private String email;

    @NotBlank(message = "Mot de passe requis")
    @Size(min = 6, message = "Le mot de passe doit avoir au moins 6 caractères")
    private String password;

    @NotBlank(message = "Le prénom est requis")
    private String firstName;

    @NotBlank(message = "Le nom est requis")
    private String lastName;
}
