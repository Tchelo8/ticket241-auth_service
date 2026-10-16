package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.AccountStatusChangeDto;
import com.tchelo.auth_service.dto.AccountSummaryDto;
import com.tchelo.auth_service.dto.DeleteMyAccountDto;
import com.tchelo.auth_service.service.AccountManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Cycle de vie des comptes (JWT obligatoire, voir SecurityConfig). Rien n'est jamais effacé :
// suspendre et supprimer changent seulement le statut du compte.
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AccountController {

    private final AccountManagementService accountManagementService;

    // Le titulaire supprime son propre compte (mot de passe redemandé)
    @DeleteMapping("/me")
    public ResponseEntity<AccountSummaryDto> deleteMyAccount(@Valid @RequestBody DeleteMyAccountDto request) {
        return ResponseEntity.ok(accountManagementService.deleteMyAccount(request));
    }

    // Admins Ticket241 : retrouver un compte (et son id) à partir du téléphone
    @GetMapping("/accounts/by-phone/{phone}")
    public ResponseEntity<AccountSummaryDto> getAccountByPhone(@PathVariable String phone) {
        return ResponseEntity.ok(accountManagementService.getAccountByPhone(phone));
    }

    @PostMapping("/accounts/{userId}/suspend")
    public ResponseEntity<AccountSummaryDto> suspend(
            @PathVariable Long userId,
            @Valid @RequestBody(required = false) AccountStatusChangeDto request
    ) {
        return ResponseEntity.ok(accountManagementService.suspend(userId, orEmpty(request)));
    }

    @PostMapping("/accounts/{userId}/delete")
    public ResponseEntity<AccountSummaryDto> delete(
            @PathVariable Long userId,
            @Valid @RequestBody(required = false) AccountStatusChangeDto request
    ) {
        return ResponseEntity.ok(accountManagementService.delete(userId, orEmpty(request)));
    }

    @PostMapping("/accounts/{userId}/reactivate")
    public ResponseEntity<AccountSummaryDto> reactivate(
            @PathVariable Long userId,
            @Valid @RequestBody(required = false) AccountStatusChangeDto request
    ) {
        return ResponseEntity.ok(accountManagementService.reactivate(userId, orEmpty(request)));
    }

    private AccountStatusChangeDto orEmpty(AccountStatusChangeDto request) {
        return request != null ? request : new AccountStatusChangeDto();
    }
}
