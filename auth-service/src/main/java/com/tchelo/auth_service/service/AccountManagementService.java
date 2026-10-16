package com.tchelo.auth_service.service;

import com.tchelo.auth_service.dto.AccountStatusChangeDto;
import com.tchelo.auth_service.dto.AccountSummaryDto;
import com.tchelo.auth_service.dto.DeleteMyAccountDto;
import com.tchelo.auth_service.dto.UpdateProfileDto;

// Cycle de vie des comptes (soft delete : rien n'est jamais effacé).
// - Admin Ticket241 : suspend, supprime ou réactive n'importe quel compte (jamais le dernier admin actif)
// - Admin de structure : suspend, supprime ou réactive (si suspendu) les agents de SA structure
// - Chacun : supprime son propre compte via deleteMyAccount
public interface AccountManagementService {

    AccountSummaryDto getAccountByPhone(String phone);

    AccountSummaryDto suspend(Long userId, AccountStatusChangeDto request);

    AccountSummaryDto delete(Long userId, AccountStatusChangeDto request);

    AccountSummaryDto reactivate(Long userId, AccountStatusChangeDto request);

    // Profil de la personne connectée
    AccountSummaryDto getMyAccount();

    AccountSummaryDto updateMyProfile(UpdateProfileDto request);

    AccountSummaryDto deleteMyAccount(DeleteMyAccountDto request);
}
