package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.AdminAlertRequestDto;
import com.tchelo.auth_service.client.dto.OtpVerifyRequestDto;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

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

    // Alerte best-effort aux admins Ticket241 : un échec (service arrêté, SMTP en panne) est journalisé
    // mais ne doit jamais annuler l'action qui l'a déclenchée (suspension, suppression...)
    public void sendAdminAlert(List<String> recipients, String subject, String message) {
        if (recipients == null || recipients.isEmpty()) {
            log.error("[ALERTE non envoyée] Aucun administrateur Ticket241 actif avec un email : {}", subject);
            return;
        }
        try {
            feignClient.sendAdminAlert(new AdminAlertRequestDto(recipients, subject, message));
        } catch (Exception e) {
            log.error("[ALERTE non envoyée] {} : {}", subject, e.getMessage());
        }
    }
}