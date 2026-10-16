package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.dto.AccountStatusChangeDto;
import com.tchelo.auth_service.dto.AccountSummaryDto;
import com.tchelo.auth_service.dto.DeleteMyAccountDto;
import com.tchelo.auth_service.entity.AccountStatus;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.InvalidCredentialsException;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.AccountManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountManagementServiceImpl implements AccountManagementService {

    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_STRUCTURE_ADMIN = "ROLE_STRUCTURE_ADMIN";
    private static final String ROLE_AGENT = "ROLE_AGENT";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NotificationServiceClient notificationServiceClient;

    @Override
    @Transactional(readOnly = true)
    public AccountSummaryDto getAccountByPhone(String phone) {
        if (!hasRole(currentUser(), ROLE_ADMIN)) {
            throw new AccessDeniedException("Recherche de comptes réservée aux administrateurs Ticket241");
        }
        User user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new UsernameNotFoundException("Aucun compte avec le numéro : " + phone));
        return toSummary(user, null);
    }

    @Override
    @Transactional
    public AccountSummaryDto suspend(Long userId, AccountStatusChangeDto request) {
        User caller = currentUser();
        User target = findTarget(userId);
        requireCanManage(caller, target);
        requireNotLastPlatformAdmin(target);

        target.changeStatus(AccountStatus.SUSPENDED, request.getUntil(), caller.getPhone(), request.getReason());
        userRepository.save(target);
        log.info("Compte {} suspendu par {} jusqu'au {}", target.getId(), caller.getPhone(), request.getUntil());

        alertIfStructureLostItsLastAdmin(target);
        return toSummary(target, request.getUntil() != null
                ? "Compte suspendu jusqu'au " + request.getUntil()
                : "Compte suspendu jusqu'à réactivation");
    }

    @Override
    @Transactional
    public AccountSummaryDto delete(Long userId, AccountStatusChangeDto request) {
        User caller = currentUser();
        User target = findTarget(userId);
        requireCanManage(caller, target);
        requireNotLastPlatformAdmin(target);

        target.changeStatus(AccountStatus.DELETED, null, caller.getPhone(), request.getReason());
        userRepository.save(target);
        log.info("Compte {} supprimé (soft delete) par {}", target.getId(), caller.getPhone());

        alertIfStructureLostItsLastAdmin(target);
        return toSummary(target, "Compte supprimé. Seul un administrateur Ticket241 peut le réactiver.");
    }

    @Override
    @Transactional
    public AccountSummaryDto reactivate(Long userId, AccountStatusChangeDto request) {
        User caller = currentUser();
        User target = findTarget(userId);
        requireCanManage(caller, target);

        // Un compte supprimé ne se réactive que par Ticket241 (pas par l'admin d'une structure)
        if (target.getEffectiveStatus() == AccountStatus.DELETED && !hasRole(caller, ROLE_ADMIN)) {
            throw new AccessDeniedException("Seul un administrateur Ticket241 peut réactiver un compte supprimé");
        }
        if (target.getEffectiveStatus() == AccountStatus.ACTIVE) {
            return toSummary(target, "Ce compte est déjà actif");
        }

        target.changeStatus(AccountStatus.ACTIVE, null, caller.getPhone(), request.getReason());
        userRepository.save(target);
        log.info("Compte {} réactivé par {}", target.getId(), caller.getPhone());

        return toSummary(target, "Compte réactivé");
    }

    @Override
    @Transactional
    public AccountSummaryDto deleteMyAccount(DeleteMyAccountDto request) {
        User caller = currentUser();

        if (!passwordEncoder.matches(request.getPassword(), caller.getPassword())) {
            throw new InvalidCredentialsException("Mot de passe incorrect");
        }
        requireNotLastPlatformAdmin(caller);

        String reason = request.getReason() != null ? request.getReason() : "Supprimé par l'utilisateur";
        caller.changeStatus(AccountStatus.DELETED, null, caller.getPhone(), reason);
        userRepository.save(caller);
        log.info("Compte {} supprimé par son titulaire", caller.getId());

        alertIfStructureLostItsLastAdmin(caller);
        return toSummary(caller, "Votre compte a été supprimé. Vos billets déjà payés restent valables ; "
                + "contactez le support Ticket241 pour toute réactivation.");
    }

    // ===== Règles d'accès =====

    // Admin Ticket241 : tout le monde. Admin de structure : uniquement les agents de sa structure.
    // Personne n'agit sur son propre compte par cette voie (suppression de soi : deleteMyAccount).
    private void requireCanManage(User caller, User target) {
        if (caller.getId().equals(target.getId())) {
            throw new AccessDeniedException("Pour votre propre compte, utilisez /api/auth/me");
        }
        if (hasRole(caller, ROLE_ADMIN)) {
            return;
        }
        boolean isAgentOfCallerStructure = hasRole(caller, ROLE_STRUCTURE_ADMIN)
                && caller.getStructureId() != null
                && caller.getStructureId().equals(target.getStructureId())
                && hasRole(target, ROLE_AGENT)
                && !hasRole(target, ROLE_STRUCTURE_ADMIN)
                && !hasRole(target, ROLE_ADMIN);
        if (!isAgentOfCallerStructure) {
            throw new AccessDeniedException("Vous ne pouvez gérer que les contrôleurs d'entrée de votre structure");
        }
    }

    // La plateforme doit toujours garder au moins un admin actif, sinon plus personne ne peut rien réactiver
    private void requireNotLastPlatformAdmin(User target) {
        if (!hasRole(target, ROLE_ADMIN)) {
            return;
        }
        long otherActiveAdmins = userRepository.findActivePlatformAdmins().stream()
                .filter(admin -> !admin.getId().equals(target.getId()))
                .count();
        if (otherActiveAdmins == 0) {
            throw new AccessDeniedException(
                    "Impossible : c'est le dernier administrateur Ticket241 actif. Créez d'abord un autre administrateur.");
        }
    }

    // Une structure sans admin actif ne peut plus gérer ses événements : on prévient les admins Ticket241,
    // qui peuvent reprendre la main ou générer un code d'invitation pour un remplaçant
    private void alertIfStructureLostItsLastAdmin(User removed) {
        if (!hasRole(removed, ROLE_STRUCTURE_ADMIN) || removed.getStructureId() == null) {
            return;
        }
        if (userRepository.countActiveStructureAdmins(removed.getStructureId()) > 0) {
            return;
        }

        List<String> recipients = userRepository.findActivePlatformAdmins().stream()
                .map(User::getEmail)
                .filter(email -> email != null && !email.isBlank())
                .toList();
        log.warn("[ALERTE] La structure {} n'a plus aucun administrateur actif (dernier retiré : userId={})",
                removed.getStructureId(), removed.getId());

        notificationServiceClient.sendAdminAlert(
                recipients,
                "Structure " + removed.getStructureId() + " sans administrateur",
                "La structure n°" + removed.getStructureId() + " n'a plus aucun administrateur actif : le compte de "
                        + displayName(removed) + " (" + removed.getPhone() + ") vient d'être suspendu ou supprimé.\n\n"
                        + "Ses événements ne peuvent plus être gérés par la structure. Vous pouvez les gérer vous-même, "
                        + "ou générer un code d'invitation pour un nouvel administrateur "
                        + "(POST /api/events/structures/" + removed.getStructureId() + "/invitation-code).");
    }

    // ===== Utilitaires =====

    private User currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof User caller)) {
            throw new AccessDeniedException("Authentification requise");
        }
        return caller;
    }

    private User findTarget(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("Aucun compte avec l'identifiant : " + userId));
    }

    private boolean hasRole(User user, String roleName) {
        return user.getRoles().stream().map(Role::getName).anyMatch(roleName::equals);
    }

    private String displayName(User user) {
        String name = ((user.getFirstName() != null ? user.getFirstName() : "") + " "
                + (user.getLastName() != null ? user.getLastName() : "")).trim();
        return name.isEmpty() ? "l'administrateur" : name;
    }

    private AccountSummaryDto toSummary(User user, String message) {
        return AccountSummaryDto.builder()
                .id(user.getId())
                .phone(user.getPhone())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles().stream().map(Role::getName).toList())
                .structureId(user.getStructureId())
                .emailVerified(user.isEnabled())
                .accountStatus(user.getEffectiveStatus())
                .suspendedUntil(user.getSuspendedUntil())
                .statusChangedAt(user.getStatusChangedAt())
                .statusChangedBy(user.getStatusChangedBy())
                .statusReason(user.getStatusReason())
                .message(message)
                .build();
    }
}
