package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.AccountStatusResponseDto;
import com.tchelo.auth_service.entity.AccountStatus;
import com.tchelo.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Appelé par event-service et ticket-service (clé interne, voir InternalSecurityConfig) pour qu'une
// suspension ou une suppression prenne effet tout de suite, sans attendre l'expiration du JWT
@RestController
@RequestMapping("/internal/accounts")
@RequiredArgsConstructor
public class InternalAccountController {

    private final UserRepository userRepository;

    @GetMapping("/status")
    public ResponseEntity<AccountStatusResponseDto> getStatus(@RequestParam String phone) {
        // Numéro inconnu : traité comme supprimé (un JWT ne peut pas légitimement viser un compte inexistant)
        AccountStatusResponseDto response = userRepository.findByPhone(phone)
                .map(user -> new AccountStatusResponseDto(phone, user.getEffectiveStatus(),
                        user.getEffectiveStatus() == AccountStatus.SUSPENDED ? user.getSuspendedUntil() : null,
                        user.isActiveAccount()))
                .orElseGet(() -> new AccountStatusResponseDto(phone, AccountStatus.DELETED, null, false));
        return ResponseEntity.ok(response);
    }
}
