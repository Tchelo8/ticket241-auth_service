package com.tchelo.auth_service.controller;

import com.tchelo.auth_service.dto.AccountStatusChangeDto;
import com.tchelo.auth_service.dto.AccountSummaryDto;
import com.tchelo.auth_service.dto.DeleteMyAccountDto;
import com.tchelo.auth_service.dto.UpdateProfileDto;
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

    // Profil de la personne connectée (statut du compte compris)
    @GetMapping("/me")
    public ResponseEntity<AccountSummaryDto> getMyAccount() {
        return ResponseEntity.ok(accountManagementService.getMyAccount());
    }

    // Prénom et nom ; l'email et le téléphone ne se modifient pas encore (revérification à prévoir)
    @PutMapping("/me")
    public ResponseEntity<AccountSummaryDto> updateMyProfile(@Valid @RequestBody UpdateProfileDto request) {
        return ResponseEntity.ok(accountManagementService.updateMyProfile(request));
    }

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
