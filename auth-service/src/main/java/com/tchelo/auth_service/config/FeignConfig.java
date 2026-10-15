package com.tchelo.auth_service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignConfig {

    // Doit être identique à notification.internal.api-key côté notification-service
    @Value("${notification.internal.api-key}")
    private String internalApiKey;

    @Bean
    public RequestInterceptor requestInterceptor() {
        return template -> template.header("X-Internal-Api-Key", internalApiKey);
    }

    @Bean
    public ErrorDecoder errorDecoder(ObjectMapper objectMapper) {
        return new OtpAwareErrorDecoder(objectMapper);
    }
}
