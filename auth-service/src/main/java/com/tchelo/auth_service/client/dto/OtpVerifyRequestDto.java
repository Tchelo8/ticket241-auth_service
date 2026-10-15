package com.tchelo.auth_service.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Miroir de OtpVerificationRequestDto côté notification-service : mêmes noms de champs pour le JSON
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpVerifyRequestDto {
    private Long userId;
    private String code;
}