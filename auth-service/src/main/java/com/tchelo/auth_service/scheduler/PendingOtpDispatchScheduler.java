package com.tchelo.auth_service.scheduler;

import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.OtpDispatchService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

// Filet de sécurité pour les comptes non vérifiés dont l'OTP n'a jamais atteint l'utilisateur
// à cause d'une panne côté notification-service (au-delà du retry+DLQ du consumer Kafka),
// ce que le rollback transactionnel côté auth-service ne peut pas détecter.
@Slf4j
@Component
@RequiredArgsConstructor
public class PendingOtpDispatchScheduler {

    private static final int LOOKBACK_MINUTES = 5;
    // 1 tentative initiale (inscription) + 3 relances automatiques avant d'exiger une intervention manuelle
    private static final int MAX_AUTO_DISPATCH_ATTEMPTS = 4;

    private final UserRepository userRepository;
    private final OtpDispatchService otpDispatchService;

    @Scheduled(fixedRate = LOOKBACK_MINUTES * 60 * 1000L)
    public void retryPendingOtpDispatch() {
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(LOOKBACK_MINUTES);
        List<User> pending = userRepository.findPendingOtpDispatch(threshold);

        if (pending.isEmpty()) {
            return;
        }

        log.info("[OTP] {} compte(s) non vérifié(s) sans OTP reçu depuis {} min, tentative de relance",
                pending.size(), LOOKBACK_MINUTES);

        for (User user : pending) {
            int attempts = user.getOtpDispatchAttempts() == null ? 0 : user.getOtpDispatchAttempts();

            if (attempts >= MAX_AUTO_DISPATCH_ATTEMPTS) {
                log.error("[OTP][ALERTE OPÉRATEUR] userId={} phone={} toujours non vérifié après {} tentatives "
                                + "d'envoi — intervention manuelle requise",
                        user.getId(), user.getPhone(), attempts);
                continue;
            }

            try {
                otpDispatchService.dispatch(user);
                log.info("[OTP] Relance automatique réussie pour userId={}", user.getId());
            } catch (Exception e) {
                log.warn("[OTP] Relance automatique échouée pour userId={} : {}", user.getId(), e.getMessage());
            }
        }
    }
}
