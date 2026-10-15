package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class MfaValidateRequestDto {

    @NotBlank(message = "Le token temporaire est obligatoire")
    private String tempToken;

    @NotBlank(message = "Le code TOTP est obligatoire")
    @Pattern(regexp = "^[0-9]{6}$", message = "Le code TOTP doit contenir exactement 6 chiffres")
    private String code;
}
