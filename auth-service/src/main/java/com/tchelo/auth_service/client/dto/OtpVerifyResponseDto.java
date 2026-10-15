package com.tchelo.auth_service.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Miroir de OtpVerificationResponseDto côté notification-service
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpVerifyResponseDto {
    private Boolean valid;
    private String message;
    private Integer remainingAttempts;
}