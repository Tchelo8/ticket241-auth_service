package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequestDto {

    @NotBlank(message = "Le numéro de téléphone est requis")
    private String phone;

    @NotBlank(message = "Le mot de passe est requis")
    private String password;
}