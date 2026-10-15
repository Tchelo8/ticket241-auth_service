package com.tchelo.auth_service.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Miroir d'InvitationCodeCheckResponseDto côté event-service
@Data
@NoArgsConstructor
@AllArgsConstructor
public class InvitationCodeCheckResponseDto {
    private boolean valid;
    private String message;
}
