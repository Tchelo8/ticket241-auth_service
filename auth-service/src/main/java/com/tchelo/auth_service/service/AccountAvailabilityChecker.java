package com.tchelo.auth_service.service;

import com.tchelo.auth_service.entity.AccountStatus;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.UserAlreadyExistsException;
import com.tchelo.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

// Contrôle commun à toutes les créations de compte (client, admin, admin de structure, agent).
// Rien n'est jamais effacé : le téléphone et l'email d'un compte supprimé restent pris, et la
// personne doit passer par le support pour le faire réactiver plutôt que de recréer un compte.
@Component
@RequiredArgsConstructor
public class AccountAvailabilityChecker {

    private final UserRepository userRepository;

    public void requirePhoneAndEmailAvailable(String phone, String email) {
        userRepository.findByPhone(phone).ifPresent(existing -> {
            throw alreadyUsed(existing, "Ce numéro de téléphone existe déjà sur Ticket241 : " + phone);
        });
        userRepository.findByEmail(email).ifPresent(existing -> {
            throw alreadyUsed(existing, "Cet email existe déjà sur Ticket241 : " + email);
        });
    }

    private UserAlreadyExistsException alreadyUsed(User existing, String defaultMessage) {
        if (existing.getEffectiveStatus() == AccountStatus.DELETED) {
            return new UserAlreadyExistsException(
                    "Ce numéro ou cet email appartient à un compte supprimé : contactez le support Ticket241 "
                            + "pour le réactiver.");
        }
        return new UserAlreadyExistsException(defaultMessage);
    }
}
