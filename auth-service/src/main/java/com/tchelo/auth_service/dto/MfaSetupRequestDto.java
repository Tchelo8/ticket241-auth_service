package com.tchelo.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class MfaSetupRequestDto {

    @NotBlank(message = "Le token temporaire est obligatoire")
    private String tempToken;
}
