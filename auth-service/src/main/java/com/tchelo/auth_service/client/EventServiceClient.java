package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.InvitationCodeCheckRequestDto;
import com.tchelo.auth_service.client.dto.InvitationCodeCheckResponseDto;
import com.tchelo.auth_service.exception.InvalidInvitationCodeException;
import com.tchelo.auth_service.exception.StructureServiceUnavailableException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

// Codes d'invitation des admins de structure, détenus par event-service.
// Un code refusé lève InvalidInvitationCodeException (403) ; event-service injoignable lève
// StructureServiceUnavailableException (503) pour ne jamais confondre les deux.
@Slf4j
@Component
@RequiredArgsConstructor
public class EventServiceClient {

    private final EventServiceFeignClient feignClient;

    // Vérifie le code sans le consommer
    public void checkInvitationCode(Long structureId, String code) {
        InvitationCodeCheckResponseDto result = call(() ->
                feignClient.checkInvitationCode(structureId, new InvitationCodeCheckRequestDto(code)), structureId);
        requireValid(result);
    }

    // Vérifie et consomme le code (usage unique)
    public void consumeInvitationCode(Long structureId, String code) {
        InvitationCodeCheckResponseDto result = call(() ->
                feignClient.consumeInvitationCode(structureId, new InvitationCodeCheckRequestDto(code)), structureId);
        requireValid(result);
    }

    private InvitationCodeCheckResponseDto call(java.util.function.Supplier<InvitationCodeCheckResponseDto> request,
                                                Long structureId) {
        try {
            return request.get();
        } catch (RuntimeException e) {
            log.error("[Invitation] Appel à event-service impossible pour la structure {} : {}", structureId, e.getMessage());
            throw new StructureServiceUnavailableException(
                    "Vérification du code d'invitation momentanément indisponible, réessayez plus tard", e);
        }
    }

    private void requireValid(InvitationCodeCheckResponseDto result) {
        if (result == null || !result.isValid()) {
            throw new InvalidInvitationCodeException(
                    result != null && result.getMessage() != null ? result.getMessage() : "Code d'invitation invalide ou expiré");
        }
    }
}
