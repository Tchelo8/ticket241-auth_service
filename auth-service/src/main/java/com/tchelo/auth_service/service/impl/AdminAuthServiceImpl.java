package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import com.tchelo.auth_service.dto.*;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.AccountNotActiveException;
import com.tchelo.auth_service.exception.InvalidOtpException;
import com.tchelo.auth_service.exception.OtpVerificationUnavailableException;
import com.tchelo.auth_service.exception.RoleNotFoundException;
import com.tchelo.auth_service.exception.UserAlreadyExistsException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.RoleRepository;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.AccountAvailabilityChecker;
import com.tchelo.auth_service.service.AdminAuthService;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.OtpDispatchService;
import com.tchelo.auth_service.service.StructureAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthServiceImpl implements AdminAuthService {

    private final UserRepository userRepository;
    private final AccountAvailabilityChecker accountAvailabilityChecker;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final NotificationServiceClient notificationServiceClient;
    private final OtpDispatchService otpDispatchService;

    // Appelant authentifié par son JWT (JwtAuthenticationFilter) et détenteur de ROLE_ADMIN.
    // Un tempToken MFA (scope pre_mfa) n'authentifie personne : il ne passe pas ce contrôle.
    private boolean isCallerAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated()
                && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority()));
    }

    @Override
    @Transactional
    public AuthResponseDto registerAdmin(RegisterAdminDto request) {

        // Un admin général a tous les droits sur la plateforme : seul un admin connecté peut en créer
        // un autre. Seule exception, l'installation initiale (aucun admin en base) pour créer le premier.
        if (userRepository.existsByRolesName("ROLE_ADMIN") && !isCallerAdmin()) {
            throw new AccessDeniedException(
                    "Seul un administrateur Ticket241 connecté peut créer un compte administrateur");
        }

        accountAvailabilityChecker.requirePhoneAndEmailAvailable(request.getPhone(), request.getEmail());



        User user = User.builder()
                .phone(request.getPhone())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(false)
                .build();


        Role AdminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new RoleNotFoundException(
                        "Le rôle ROLE_ADMIN n'existe pas dans Ticket241. "
                ));

        Set<Role> roles = new HashSet<>();
        roles.add(AdminRole);
        user.setRoles(roles);


        User savedUser = userRepository.save(user);

        // Publication bloquante (max 5s) : si Kafka ne confirme pas la réception, on annule
        // toute l'inscription plutôt que de laisser un compte désactivé sans OTP envoyé.
        otpDispatchService.dispatch(savedUser);

        // Pas de JWT ici : le compte reste désactivé (isEnabled=false) tant que le code OTP envoyé
        // par email n'a pas été validé via /api/auth/admin/verify-otp
        return userMapper.toAuthResponse(savedUser, null,
                "Inscription admin réussie. Un code de vérification a été envoyé par email : "
                        + "validez-le via /api/auth/admin/verify-otp pour activer votre compte.");
    }

    @Override
    @Transactional
    public AuthResponseDto verifyOtpAdmin(VerifyOtpRequestDto request) {

        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + request.getPhone()
                ));

        AccountNotActiveException.requireActive(user);

        if (user.isEnabled()) {
            return userMapper.toAuthResponse(user, null,
                    "Compte déjà vérifié, connectez-vous via /api/auth/admin/login");
        }

        OtpVerifyResponseDto otpResponse;
        try {
            otpResponse = notificationServiceClient.verifyOtp(user.getId(), request.getCode());
        } catch (RuntimeException e) {
            log.error("[OTP] Appel à notification-service impossible pour l'admin userId={} : {}", user.getId(), e.getMessage());
            throw new OtpVerificationUnavailableException(
                    "Service de vérification OTP momentanément indisponible, réessayez plus tard", e);
        }

        if (!Boolean.TRUE.equals(otpResponse.getValid())) {
            throw new InvalidOtpException(
                    otpResponse.getMessage() != null ? otpResponse.getMessage() : "Code OTP invalide");
        }

        user.setEnabled(true);
        User savedUser = userRepository.save(user);

        log.info("[OTP] Compte admin vérifié et activé pour userId={}", savedUser.getId());

        // Pas de JWT ici : la première connexion admin déclenche la configuration MFA via /api/auth/admin/login
        return userMapper.toAuthResponse(savedUser, null,
                "Compte vérifié avec succès. Connectez-vous via /api/auth/admin/login pour configurer la double authentification.");
    }

    @Override
    public AuthResponseDto loginAdmin(LoginAdminDto request) {


        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getPhone(),
                        request.getPassword()
                )
        );


        UserDetails userDetails = (UserDetails) authentication.getPrincipal();


        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec ce numéro de téléphone : " + request.getPhone()
                ));

        boolean isAdmin = user.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        if (!isAdmin) {
            throw new UsernameNotFoundException(
                    "Ce compte n'est pas un compte administrateur général et donc n'a pas accès !"
            );
        }


        // Première connexion admin — MFA jamais configuré
        if (user.getMfaSecret() == null) {
            String tempToken = jwtService.generateTempToken(user.getPhone());
            log.info("Premier login admin, setup MFA requis pour : {}", user.getPhone());
            return AuthResponseDto.builder()
                    .mfaRequired(true)
                    .mfaSetupRequired(true)
                    .tempToken(tempToken)
                    .phone(user.getPhone())
                    .message("Configurez Google Authenticator via /api/auth/mfa/setup")
                    .build();
        }

        // MFA configuré — validation du code TOTP requise
        if (user.isMfaEnabled()) {
            String tempToken = jwtService.generateTempToken(user.getPhone());
            log.info("Login admin, code MFA requis pour : {}", user.getPhone());
            return AuthResponseDto.builder()
                    .mfaRequired(true)
                    .mfaSetupRequired(false)
                    .tempToken(tempToken)
                    .phone(user.getPhone())
                    .message("Saisissez le code Google Authenticator via /api/auth/mfa/validate")
                    .build();
        }

        String token = jwtService.generateToken(user.getPhone(), userDetails);
        return userMapper.toAuthResponse(user, token, "Connexion admin réussie sur Ticket241");
    }

}

