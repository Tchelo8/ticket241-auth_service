package com.tchelo.auth_service.client;

import com.tchelo.auth_service.client.dto.OtpVerifyRequestDto;
import com.tchelo.auth_service.client.dto.OtpVerifyResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

// Résolu via Eureka (nom d'application notification-service : spring.application.name=notification-service-ticket241)
@FeignClient(name = "notification-service-ticket241")
public interface NotificationServiceFeignClient {

    @PostMapping("/api/notifications/otp/verify")
    OtpVerifyResponseDto verifyOtp(@RequestBody OtpVerifyRequestDto request);
}
