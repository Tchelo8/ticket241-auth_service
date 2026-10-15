package com.tchelo.auth_service.service;

import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.event.UserRegisteredEvent;
import com.tchelo.auth_service.exception.OtpResendTooSoonException;
import com.tchelo.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class OtpDispatchServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private KafkaTemplate<String, UserRegisteredEvent> kafkaTemplate;

    private OtpDispatchService otpDispatchService;

    @BeforeEach
    void setUp() {
        otpDispatchService = new OtpDispatchService(userRepository);
        ReflectionTestUtils.setField(otpDispatchService, "kafkaTemplate", kafkaTemplate);
        ReflectionTestUtils.setField(otpDispatchService, "userRegisteredTopic", "user.registered");
        ReflectionTestUtils.setField(otpDispatchService, "kafkaEnabled", true);
        lenient().when(kafkaTemplate.send(anyString(), anyString(), any(UserRegisteredEvent.class)))
                .thenReturn(CompletableFuture.completedFuture(null));
    }

    private User newUser() {
        User user = new User();
        user.setId(7L);
        user.setEmail("user@test.com");
        user.setPhone("+24100000000");
        return user;
    }

    @Test
    void allowsThreeDispatchesThenRefusesTheFourthInTheSameWindow() {
        User user = newUser();

        otpDispatchService.dispatch(user);
        otpDispatchService.dispatch(user);
        otpDispatchService.dispatch(user);

        assertThatThrownBy(() -> otpDispatchService.dispatch(user))
                .isInstanceOf(OtpResendTooSoonException.class)
                .hasMessageContaining("Réessayez dans");
        verify(kafkaTemplate, times(3)).send(anyString(), anyString(), any(UserRegisteredEvent.class));
        assertThat(user.getOtpWindowDispatchCount()).isEqualTo(3);
    }

    @Test
    void windowResetsAfterFifteenMinutes() {
        User user = newUser();
        user.setOtpWindowStartedAt(LocalDateTime.now().minusMinutes(16));
        user.setOtpWindowDispatchCount(3);

        otpDispatchService.dispatch(user);

        assertThat(user.getOtpWindowDispatchCount()).isEqualTo(1);
        assertThat(user.getOtpWindowStartedAt()).isAfter(LocalDateTime.now().minusMinutes(1));
    }

    @Test
    void refusedDispatchDoesNotPublishNorChangeCounters() {
        User user = newUser();
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);
        user.setOtpWindowStartedAt(windowStart);
        user.setOtpWindowDispatchCount(3);
        user.setOtpDispatchAttempts(3);

        assertThatThrownBy(() -> otpDispatchService.dispatch(user))
                .isInstanceOf(OtpResendTooSoonException.class);

        verify(kafkaTemplate, never()).send(anyString(), anyString(), any(UserRegisteredEvent.class));
        assertThat(user.getOtpWindowStartedAt()).isEqualTo(windowStart);
        assertThat(user.getOtpDispatchAttempts()).isEqualTo(3);
    }
}
