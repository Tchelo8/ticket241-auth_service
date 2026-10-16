package com.tchelo.auth_service.exception;

import com.tchelo.auth_service.entity.AccountStatus;
import com.tchelo.auth_service.entity.User;

import java.time.format.DateTimeFormatter;

// Action refusée car le compte est suspendu ou supprimé (connexion, OTP, renvoi d'OTP…)
public class AccountNotActiveException extends RuntimeException {

    public AccountNotActiveException(String message) {
        super(message);
    }

    public static AccountNotActiveException of(User user) {
        if (user.getEffectiveStatus() == AccountStatus.DELETED) {
            return new AccountNotActiveException(
                    "Ce compte a été supprimé. Contactez le support Ticket241 pour le réactiver.");
        }
        if (user.getSuspendedUntil() != null) {
            return new AccountNotActiveException("Ce compte est suspendu jusqu'au "
                    + user.getSuspendedUntil().format(DateTimeFormatter.ofPattern("dd/MM/yyyy 'à' HH:mm")) + ".");
        }
        return new AccountNotActiveException("Ce compte est suspendu. Contactez le support Ticket241.");
    }

    // À appeler sur tout parcours qui pourrait rendre l'accès à un compte bloqué (OTP, MFA…)
    public static void requireActive(User user) {
        if (!user.isActiveAccount()) {
            throw of(user);
        }
    }
}
