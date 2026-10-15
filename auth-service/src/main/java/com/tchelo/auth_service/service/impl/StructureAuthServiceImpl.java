package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.RegisterStructureAdminDto;
import com.tchelo.auth_service.dto.LoginStructureAdminDto;
import com.tchelo.auth_service.dto.StructureUserDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.InvalidOtpException;
import com.tchelo.auth_service.exception.OtpVerificationUnavailableException;
import com.tchelo.auth_service.exception.RoleNotFoundException;
import com.tchelo.auth_service.exception.UserAlreadyExistsException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.RoleRepository;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.OtpDispatchService;
import com.tchelo.auth_service.service.StructureAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final NotificationServiceClient notificationServiceClient;
    private final OtpDispatchService otpDispatchService;

    @Override
    @Transactional
    public AuthResponseDto registerStructureAdmin(RegisterStructureAdminDto request) {


        if (userRepository.existsByPhone(request.getPhone())) {
            throw new UserAlreadyExistsException(
                    "Ce numéro de téléphone existe déjà sur Ticket241 : " + request.getPhone()
            );
        }


        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException(
                    "Cet email existe déjà sur Ticket241 : " + request.getEmail()
            );
        }

        //  TODO: Vérifier que la structure existe (appel vers Event Service via OpenFeign)
        // Structure structure = structureClient.getStructure(request.getStructureId());

        //  TODO: Valider le code d'invitation
        // Pour l'instant, on accepte n'importe quel code
        // En production, vérifier dans une table structure_invitation_codes


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

        // Publication bloquante (max 5s) : si Kafka ne confirme pas la réception, on annule
        // toute l'inscription plutôt que de laisser un compte désactivé sans OTP envoyé.
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

        if (user.isEnabled()) {
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(user.getPhone())
                    .password(user.getPassword())
                    .authorities(user.getAuthorities())
                    .build();
            String token = jwtService.generateToken(user.getPhone(), userDetails);
            return userMapper.toAuthResponse(user, token, "Compte déjà vérifié");
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

    @Override
    public List<StructureUserDto> getUsersByStructure(Long structureId) {
        List<User> users = userRepository.findByStructureId(structureId);
        return users.stream()
                .map(userMapper::toStructureUserDto)
                .collect(Collectors.toList());
    }
}
