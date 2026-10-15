package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.OtpVerifyRequestDto;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class NotificationServiceClient {

    private final NotificationServiceFeignClient feignClient;

    // notification-service répond en 401 quand le code est invalide/expiré, avec le détail dans le corps :
    // OtpAwareErrorDecoder le désérialise en amont, on le récupère ici pour le traiter comme une réponse normale.
    public OtpVerifyResponseDto verifyOtp(Long userId, String code) {
        try {
            return feignClient.verifyOtp(new OtpVerifyRequestDto(userId, code));
        } catch (OtpInvalidCodeException e) {
            return e.getResponse();
        }
    }
}