package com.tchelo.auth_service.service;

import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.event.UserRegisteredEvent;
import com.tchelo.auth_service.exception.OtpDispatchUnavailableException;
import com.tchelo.auth_service.exception.OtpResendTooSoonException;
import com.tchelo.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

// Point d'entrée unique pour déclencher l'envoi d'un OTP (inscription, renvoi manuel, job de
// relance) : évite d'avoir la même logique de publication Kafka dupliquée à plusieurs endroits.
@Slf4j
@Service
@RequiredArgsConstructor
public class OtpDispatchService {

    private static final long DISPATCH_TIMEOUT_SECONDS = 5;

    private final UserRepository userRepository;

    @Autowired(required = false)
    private KafkaTemplate<String, UserRegisteredEvent> kafkaTemplate;

    @Value("${kafka.topics.user-registered:user.registered}")
    private String userRegisteredTopic;

    @Value("${kafka.enabled:false}")
    private boolean kafkaEnabled;

    // Au plus 3 codes par fenêtre de 15 min, tous déclencheurs confondus (inscription, renvoi, job).
    // notification-service garde une limite plus large en filet de sécurité.
    private static final int MAX_DISPATCH_PER_WINDOW = 3;
    private static final long DISPATCH_WINDOW_MINUTES = 15;

    // Publie (ou republie) l'événement déclenchant l'envoi d'OTP pour un utilisateur.
    // Bloque jusqu'à 5s pour avoir la confirmation du broker ; en cas d'échec ou de timeout,
    // lève OtpDispatchUnavailableException plutôt que de laisser croire que l'OTP est parti.
    // Lève OtpResendTooSoonException si le quota de la fenêtre courante est atteint.
    public void dispatch(User user) {
        if (!kafkaEnabled || kafkaTemplate == null) {
            log.info("[Kafka désactivé] OTP non déclenché pour userId={}", user.getId());
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowStart = user.getOtpWindowStartedAt();
        boolean windowExpired = windowStart == null
                || !windowStart.plusMinutes(DISPATCH_WINDOW_MINUTES).isAfter(now);
        int dispatchesInWindow = windowExpired || user.getOtpWindowDispatchCount() == null
                ? 0 : user.getOtpWindowDispatchCount();

        if (dispatchesInWindow >= MAX_DISPATCH_PER_WINDOW) {
            long minutesLeft = Math.max(1,
                    ChronoUnit.MINUTES.between(now, windowStart.plusMinutes(DISPATCH_WINDOW_MINUTES)) + 1);
            throw new OtpResendTooSoonException(
                    "Nombre maximum de codes atteint (" + MAX_DISPATCH_PER_WINDOW + " en "
                            + DISPATCH_WINDOW_MINUTES + " minutes). Réessayez dans " + minutesLeft + " minute(s).");
        }

        UserRegisteredEvent event = UserRegisteredEvent.builder()
                .userId(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .phone(user.getPhone())
                .build();

        try {
            kafkaTemplate.send(userRegisteredTopic, String.valueOf(user.getId()), event)
                    .get(DISPATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            log.info("[Kafka] Événement user.registered publié pour userId={}", user.getId());
        } catch (Exception e) {
            log.error("[Kafka] Échec de publication de l'événement pour userId={} : {}", user.getId(), e.getMessage());
            throw new OtpDispatchUnavailableException(
                    "Service d'envoi de code OTP indisponible, réessayez votre inscription", e);
        }

        if (windowExpired) {
            user.setOtpWindowStartedAt(now);
        }
        user.setOtpWindowDispatchCount(dispatchesInWindow + 1);
        user.setLastOtpDispatchAt(now);
        user.setOtpDispatchAttempts(
                (user.getOtpDispatchAttempts() == null ? 0 : user.getOtpDispatchAttempts()) + 1);
        userRepository.save(user);
    }
}
