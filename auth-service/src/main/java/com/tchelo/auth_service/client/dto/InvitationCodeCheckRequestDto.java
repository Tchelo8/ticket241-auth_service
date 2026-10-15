package com.tchelo.auth_service.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Miroir d'InvitationCodeCheckRequestDto côté event-service : mêmes noms de champs pour le JSON
@Data
@NoArgsConstructor
@AllArgsConstructor
public class InvitationCodeCheckRequestDto {
    private String code;
}
