package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.InvitationCodeCheckRequestDto;
import com.tchelo.auth_service.client.dto.InvitationCodeCheckResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

// Résolu via Eureka (spring.application.name=event-service-ticket241). Endpoints internes :
// la clé X-Internal-Api-Key est ajoutée par FeignConfig.
@FeignClient(name = "event-service-ticket241", path = "/internal/structures")
public interface EventServiceFeignClient {

    @PostMapping("/{structureId}/invitation-code/check")
    InvitationCodeCheckResponseDto checkInvitationCode(@PathVariable("structureId") Long structureId,
                                                       @RequestBody InvitationCodeCheckRequestDto request);

    @PostMapping("/{structureId}/invitation-code/consume")
    InvitationCodeCheckResponseDto consumeInvitationCode(@PathVariable("structureId") Long structureId,
                                                         @RequestBody InvitationCodeCheckRequestDto request);
}
