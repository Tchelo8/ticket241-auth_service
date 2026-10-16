package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.EventServiceClient;
import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.CreateAgentDto;
import com.tchelo.auth_service.dto.RegisterStructureAdminDto;
import com.tchelo.auth_service.dto.LoginStructureAdminDto;
import com.tchelo.auth_service.dto.StructureUserDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;
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
public class StructureAuthServiceImpl implements StructureAuthService {

    private final UserRepository userRepository;
    private final AccountAvailabilityChecker accountAvailabilityChecker;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final NotificationServiceClient notificationServiceClient;
    private final EventServiceClient eventServiceClient;
    private final OtpDispatchService otpDispatchService;

    @Override
    @Transactional
    public AuthResponseDto registerStructureAdmin(RegisterStructureAdminDto request) {


        accountAvailabilityChecker.requirePhoneAndEmailAvailable(request.getPhone(), request.getEmail());

        // Le code d'invitation (généré par un admin Ticket241 pour CETTE structure) prouve que la
        // personne est bien mandatée par la structure. Refus immédiat s'il est faux ou expiré ;
        // une structure inexistante donne le même refus.
        eventServiceClient.checkInvitationCode(request.getStructureId(), request.getStructureInvitationCode());

        User user = User.builder()
                .phone(request.getPhone())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .structureId(request.getStructureId())
                .enabled(false)
                .build();


        Role structureAdminRole = roleRepository.findByName("ROLE_STRUCTURE_ADMIN")
                .orElseThrow(() -> new RoleNotFoundException(
                        "Le rôle ROLE_STRUCTURE_ADMIN n'existe pas dans Ticket241. "
                ));

        Set<Role> roles = new HashSet<>();
        roles.add(structureAdminRole);
        user.setRoles(roles);


        User savedUser = userRepository.save(user);

        // Consommation atomique du code (usage unique) : si quelqu'un l'a utilisé entre-temps, l'exception
        // annule toute l'inscription. Fait avant l'envoi de l'OTP pour ne jamais écrire à un compte annulé.
        eventServiceClient.consumeInvitationCode(request.getStructureId(), request.getStructureInvitationCode());

        // Publication bloquante (max 5s) : si Kafka ne confirme pas la réception, on annule
        // toute l'inscription plutôt que de laisser un compte désactivé sans OTP envoyé.
        // Le code d'invitation, lui, est déjà consommé : il faudra en redemander un.
        otpDispatchService.dispatch(savedUser);

        // Pas de JWT ici : le compte reste désactivé (isEnabled=false) tant que le code OTP envoyé
        // par email n'a pas été validé via /api/auth/structure/verify-otp
        return userMapper.toAuthResponse(savedUser, null,
                "Inscription admin structure réussie. Un code de vérification a été envoyé par email : "
                        + "validez-le via /api/auth/structure/verify-otp pour activer votre compte.");
    }

    @Override
    @Transactional
    public AuthResponseDto verifyOtpStructureAdmin(VerifyOtpRequestDto request) {

        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + request.getPhone()
                ));

        AccountNotActiveException.requireActive(user);

        if (user.isEnabled()) {
            // Déjà vérifié : PAS de token ici (avant, un JWT était renvoyé sans contrôler le code)
            return userMapper.toAuthResponse(user, null,
                    "Compte déjà vérifié, connectez-vous via /api/auth/structure/login");
        }

        OtpVerifyResponseDto otpResponse;
        try {
            otpResponse = notificationServiceClient.verifyOtp(user.getId(), request.getCode());
        } catch (RuntimeException e) {
            log.error("[OTP] Appel à notification-service impossible pour l'admin structure userId={} : {}", user.getId(), e.getMessage());
            throw new OtpVerificationUnavailableException(
                    "Service de vérification OTP momentanément indisponible, réessayez plus tard", e);
        }

        if (!Boolean.TRUE.equals(otpResponse.getValid())) {
            throw new InvalidOtpException(
                    otpResponse.getMessage() != null ? otpResponse.getMessage() : "Code OTP invalide");
        }

        user.setEnabled(true);
        User savedUser = userRepository.save(user);

        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(savedUser.getPhone())
                .password(savedUser.getPassword())
                .authorities(savedUser.getAuthorities())
                .build();
        String token = jwtService.generateToken(savedUser.getPhone(), userDetails);

        log.info("[OTP] Compte admin structure vérifié et activé pour userId={}", savedUser.getId());
        return userMapper.toAuthResponse(savedUser, token, "Compte vérifié avec succès");
    }

    @Override
    public AuthResponseDto loginStructureAdmin(LoginStructureAdminDto request) {


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

        boolean isStructureAdmin = user.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_STRUCTURE_ADMIN"));

        if (!isStructureAdmin) {
            throw new UsernameNotFoundException(
                    "Ce compte n'est pas un compte administrateur de structure et donc n'a pas accès !"
            );
        }

        if (user.getStructureId() == null) {
            throw new IllegalStateException(
                    "Ce compte admin n'est lié à aucune structure sur Ticket241, Contactez un administrateur."
            );
        }

        String token = jwtService.generateToken(user.getPhone(), userDetails);

        return userMapper.toAuthResponse(user, token, "Connexion admin structure réussie sur Ticket241");
    }

    // Données personnelles (téléphones, emails) : réservé à un admin Ticket241 ou à un admin de CETTE structure.
    // SecurityConfig exige déjà un JWT valide sur cette route ; ici on vérifie le périmètre.
    @Override
    public List<StructureUserDto> getUsersByStructure(Long structureId) {
        requireStructureAccess(structureId, "Vous n'avez pas accès aux utilisateurs de cette structure");

        List<User> users = userRepository.findByStructureId(structureId);
        return users.stream()
                .map(userMapper::toStructureUserDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public AuthResponseDto createAgent(Long structureId, CreateAgentDto request) {
        requireStructureAccess(structureId, "Seuls les administrateurs de cette structure peuvent créer ses contrôleurs");

        accountAvailabilityChecker.requirePhoneAndEmailAvailable(request.getPhone(), request.getEmail());

        Role agentRole = roleRepository.findByName("ROLE_AGENT")
                .orElseThrow(() -> new RoleNotFoundException("Le rôle ROLE_AGENT n'existe pas dans Ticket241. "));

        // Même parcours qu'une inscription : compte désactivé jusqu'à la validation de l'OTP reçu par
        // email (/api/auth/verify-otp), ce qui prouve que l'adresse est bien celle de l'agent
        User agent = User.builder()
                .phone(request.getPhone())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .structureId(structureId)
                .enabled(false)
                .build();
        Set<Role> roles = new HashSet<>();
        roles.add(agentRole);
        agent.setRoles(roles);

        User savedAgent = userRepository.save(agent);
        otpDispatchService.dispatch(savedAgent);

        log.info("Contrôleur d'entrée créé pour la structure {} : userId={}", structureId, savedAgent.getId());

        return userMapper.toAuthResponse(savedAgent, null,
                "Contrôleur créé. Il doit valider le code reçu par email via /api/auth/verify-otp, "
                        + "puis se connecter via /api/auth/login pour scanner les billets.");
    }

    // Admin Ticket241, ou admin de CETTE structure (JWT déjà exigé par SecurityConfig sur ces routes)
    private void requireStructureAccess(Long structureId, String deniedMessage) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof User caller)) {
            throw new AccessDeniedException("Authentification requise");
        }
        boolean isAdmin = hasRole(caller, "ROLE_ADMIN");
        boolean isAdminOfThisStructure = hasRole(caller, "ROLE_STRUCTURE_ADMIN")
                && structureId.equals(caller.getStructureId());
        if (!isAdmin && !isAdminOfThisStructure) {
            throw new AccessDeniedException(deniedMessage);
        }
    }

    private boolean hasRole(User user, String roleName) {
        return user.getRoles().stream().anyMatch(role -> roleName.equals(role.getName()));
    }
}
