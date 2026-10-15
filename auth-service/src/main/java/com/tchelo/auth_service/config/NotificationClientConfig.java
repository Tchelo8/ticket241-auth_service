package com.tchelo.auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class NotificationClientConfig {

    @Value("${notification.service.base-url:http://localhost:9004}")
    private String notificationServiceBaseUrl;

    // Doit être identique à notification.internal.api-key côté notification-service
    @Value("${notification.internal.api-key}")
    private String internalApiKey;

    @Bean
    public RestClient notificationServiceRestClient() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(5000);
        requestFactory.setReadTimeout(5000);

        return RestClient.builder()
                .baseUrl(notificationServiceBaseUrl)
                .requestFactory(requestFactory)
                .defaultHeader("X-Internal-Api-Key", internalApiKey)
                .build();
    }
}