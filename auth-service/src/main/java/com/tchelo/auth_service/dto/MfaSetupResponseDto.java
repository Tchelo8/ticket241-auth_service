package com.tchelo.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaSetupResponseDto {

    // URI otpauth:// à passer à une lib QR côté front (qrcode.react, ngx-qrcode…)
    private String otpAuthUri;
    private String secretKey;
    private String message;
}
