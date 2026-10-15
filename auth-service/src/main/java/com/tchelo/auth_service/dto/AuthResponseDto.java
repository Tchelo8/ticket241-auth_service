package com.tchelo.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponseDto {

    private String token;
    private String type = "Bearer";
    private String phone;
    private String email;
    private String firstName;
    private Long structureId;
    private String lastName;
    private List<String> roles;

    private String message;

    private boolean mfaRequired;
    private boolean mfaSetupRequired;
    private String tempToken;
}
