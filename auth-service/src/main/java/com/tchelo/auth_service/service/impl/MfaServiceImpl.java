package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.MfaSetupResponseDto;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.InvalidCredentialsException;
import com.tchelo.auth_service.exception.InvalidTotpCodeException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.MfaService;
import com.tchelo.auth_service.service.TotpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaServiceImpl implements MfaService {

    private final UserRepository userRepository;
    private final TotpService totpService;
    private final JwtService jwtService;
    private final UserMapper userMapper;

    @Override
    @Transactional
    public MfaSetupResponseDto setupMfa(String tempToken) {
        String phone = extractPhoneFromTempToken(tempToken);
        User user = findUserByPhone(phone);

        String secret = totpService.generateSecret();
        user.setMfaSecret(secret);
        user.setMfaEnabled(false);
        userRepository.save(user);

        String otpAuthUri = totpService.buildOtpAuthUri(secret, phone);
        log.info("Setup MFA initié pour l'admin : {}", phone);

        return MfaSetupResponseDto.builder()
                .otpAuthUri(otpAuthUri)
                .secretKey(secret)
                .message("Scannez le QR code avec Google Authenticator puis confirmez via /mfa/confirm")
                .build();
    }

    @Override
    @Transactional
    public AuthResponseDto confirmMfa(String tempToken, String code) {
        String phone = extractPhoneFromTempToken(tempToken);
        User user = findUserByPhone(phone);

        if (user.getMfaSecret() == null) {
            throw new IllegalStateException("Initiez d'abord le setup MFA via /mfa/setup");
        }

        if (!totpService.verifyCode(user.getMfaSecret(), code)) {
            throw new InvalidTotpCodeException("Code TOTP invalide ou expiré");
        }

        user.setMfaEnabled(true);
        userRepository.save(user);

        String jwt = jwtService.generateToken(user.getPhone(), user);
        log.info("MFA activé et connexion réussie pour l'admin : {}", phone);
        return userMapper.toAuthResponse(user, jwt, "MFA activé — connexion admin réussie sur Ticket241");
    }

    @Override
    public AuthResponseDto validateMfaCode(String tempToken, String code) {
        String phone = extractPhoneFromTempToken(tempToken);
        User user = findUserByPhone(phone);

        if (!totpService.verifyCode(user.getMfaSecret(), code)) {
            throw new InvalidTotpCodeException("Code TOTP invalide ou expiré");
        }

        String jwt = jwtService.generateToken(user.getPhone(), user);
        log.info("Connexion MFA réussie pour l'admin : {}", phone);
        return userMapper.toAuthResponse(user, jwt, "Connexion admin réussie sur Ticket241");
    }

    private String extractPhoneFromTempToken(String tempToken) {
        if (!"pre_mfa".equals(jwtService.extractScope(tempToken))) {
            throw new InvalidCredentialsException("Token invalide pour l'opération MFA");
        }
        if (jwtService.isTokenExpired(tempToken)) {
            throw new InvalidCredentialsException("Session expirée — veuillez vous reconnecter");
        }
        return jwtService.extractPhoneNumber(tempToken);
    }

    private User findUserByPhone(String phone) {
        return userRepository.findByPhone(phone)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Utilisateur non retrouvé avec le numéro : " + phone));
    }
}
