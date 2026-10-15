package com.tchelo.auth_service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tchelo.auth_service.client.OtpInvalidCodeException;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import feign.Response;
import feign.Util;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

// notification-service répond en 401 avec le détail dans le corps quand le code OTP est invalide/expiré :
// on le désérialise ici pour que l'appelant puisse le traiter comme une réponse normale plutôt qu'une panne.
// Tout autre cas (403 clé interne refusée, 5xx, corps inattendu) reste une erreur technique.
@Slf4j
public class OtpAwareErrorDecoder implements ErrorDecoder {

    private final ObjectMapper objectMapper;
    private final ErrorDecoder delegate = new Default();

    public OtpAwareErrorDecoder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Exception decode(String methodKey, Response response) {
        if (response.status() == 403) {
            log.error("[OTP] notification-service a refusé la clé interne (403) : vérifier que INTERNAL_API_KEY "
                    + "est identique dans auth-service et notification-service");
            return delegate.decode(methodKey, response);
        }

        if (response.status() == 401 && response.body() != null) {
            byte[] bodyBytes;
            try {
                bodyBytes = Util.toByteArray(response.body().asInputStream());
            } catch (IOException e) {
                return delegate.decode(methodKey, response);
            }

            try {
                OtpVerifyResponseDto dto = objectMapper.readValue(bodyBytes, OtpVerifyResponseDto.class);
                // Seule une vraie réponse OTP porte le champ "valid" : un autre 401 n'est pas un code invalide
                if (dto != null && dto.getValid() != null) {
                    return new OtpInvalidCodeException(dto);
                }
            } catch (IOException e) {
                // corps illisible : on retombe sur le décodage d'erreur par défaut
            }

            // Le flux du corps a été consommé : on le remet pour que le décodeur par défaut garde le détail
            return delegate.decode(methodKey, response.toBuilder().body(bodyBytes).build());
        }

        return delegate.decode(methodKey, response);
    }
}
