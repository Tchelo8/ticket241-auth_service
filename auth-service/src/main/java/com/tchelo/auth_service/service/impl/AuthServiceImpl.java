package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.LoginRequestDto;
import com.tchelo.auth_service.dto.RegisterRequestDto;
import com.tchelo.auth_service.dto.ResendOtpRequestDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.AccountNotActiveException;
import com.tchelo.auth_service.exception.InvalidOtpException;
import com.tchelo.auth_service.exception.OtpResendTooSoonException;
import com.tchelo.auth_service.exception.OtpVerificationUnavailableException;
import com.tchelo.auth_service.exception.RoleNotFoundException;
import com.tchelo.auth_service.exception.UserAlreadyExistsException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.RoleRepository;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.AccountAvailabilityChecker;
import com.tchelo.auth_service.service.AuthService;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.OtpDispatchService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final AccountAvailabilityChecker accountAvailabilityChecker;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final UserDetailsService userDetailsService;
    private final NotificationServiceClient notificationServiceClient;
    private final OtpDispatchService otpDispatchService;

    // Délai minimum entre deux renvois manuels d'OTP, pour éviter le spam de /resend-otp
    private static final long RESEND_COOLDOWN_SECONDS = 60;

    @Override
    @Transactional
    public AuthResponseDto register(RegisterRequestDto request) {

        accountAvailabilityChecker.requirePhoneAndEmailAvailable(request.getPhone(), request.getEmail());

        User user = userMapper.toEntity(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RoleNotFoundException(
                        "Le rôle ROLE_USER n'existe pas dans la base de données"
                ));

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        User savedUser = userRepository.save(user);

        // Publication bloquante (max 5s) : si Kafka ne confirme pas la réception, on annule
        // toute l'inscription plutôt que de laisser un compte désactivé sans OTP envoyé.
        otpDispatchService.dispatch(savedUser);

        // Pas de JWT ici : le compte reste désactivé (isEnabled=false) tant que le code OTP envoyé
        // par email n'a pas été validé via /api/auth/verify-otp
        return userMapper.toAuthResponse(savedUser, null,
                "Inscription réussie. Un code de vérification a été envoyé par email : "
                        + "validez-le via /api/auth/verify-otp pour activer votre compte.");
    }

    @Override
    public AuthResponseDto resendOtp(ResendOtpRequestDto request) {

        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + request.getPhone()
                ));

        // Un compte suspendu ou supprimé ne doit pas pouvoir se réactiver par le parcours OTP
        AccountNotActiveException.requireActive(user);

        if (user.isEnabled()) {
            return userMapper.toAuthResponse(user, null,
                    "Compte déjà vérifié, connectez-vous via /api/auth/login");
        }

        if (user.getLastOtpDispatchAt() != null) {
            long secondsSinceLastDispatch = ChronoUnit.SECONDS.between(user.getLastOtpDispatchAt(), LocalDateTime.now());
            if (secondsSinceLastDispatch < RESEND_COOLDOWN_SECONDS) {
                throw new OtpResendTooSoonException(
                        "Un code a déjà été envoyé récemment, réessayez dans "
                                + (RESEND_COOLDOWN_SECONDS - secondsSinceLastDispatch) + " secondes");
            }
        }

        otpDispatchService.dispatch(user);

        log.info("[OTP] Renvoi manuel déclenché pour userId={}", user.getId());
        return userMapper.toAuthResponse(user, null,
                "Un nouveau code de vérification a été envoyé par email : validez-le via /api/auth/verify-otp");
    }

    @Override
    public AuthResponseDto login(LoginRequestDto request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getPhone(), request.getPassword())
        );
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + request.getPhone()
                ));

        String token = jwtService.generateToken(user.getPhone(), userDetails);
        return userMapper.toAuthResponse(user, token, "Connexion réussie sur Ticket241");
    }

    @Override
    @Transactional
    public AuthResponseDto verifyOtp(VerifyOtpRequestDto request) {

        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + request.getPhone()
                ));

        AccountNotActiveException.requireActive(user);

        if (user.isEnabled()) {
            // Déjà vérifié : PAS de token ici. Avant, ce cas renvoyait un JWT sans contrôler le code,
            // ce qui permettait d'ouvrir le compte de n'importe qui en connaissant son téléphone.
            return userMapper.toAuthResponse(user, null, "Compte déjà vérifié, connectez-vous via /api/auth/login");
        }

        OtpVerifyResponseDto otpResponse;
        try {
            otpResponse = notificationServiceClient.verifyOtp(user.getId(), request.getCode());
        } catch (RuntimeException e) {
            log.error("[OTP] Appel à notification-service impossible pour userId={} : {}", user.getId(), e.getMessage());
            throw new OtpVerificationUnavailableException(
                    "Service de vérification OTP momentanément indisponible, réessayez plus tard", e);
        }

        if (!Boolean.TRUE.equals(otpResponse.getValid())) {
            throw new InvalidOtpException(
                    otpResponse.getMessage() != null ? otpResponse.getMessage() : "Code OTP invalide");
        }

        user.setEnabled(true);
        User savedUser = userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(savedUser.getPhone());
        String token = jwtService.generateToken(savedUser.getPhone(), userDetails);

        log.info("[OTP] Compte vérifié et activé pour userId={}", savedUser.getId());
        return userMapper.toAuthResponse(savedUser, token, "Compte vérifié avec succès");
    }

    @Override
    public boolean validateToken(String token) {
        try {
            String phone = jwtService.extractPhoneNumber(token);
            User user = userRepository.findByPhone(phone)
                    .orElseThrow(() -> new UsernameNotFoundException(
                            "Utilisateur non retrouvé avec le numéro : " + phone
                    ));
            return jwtService.isTokenValid(token, user);
        } catch (Exception e) {
            return false;
        }
    }
}