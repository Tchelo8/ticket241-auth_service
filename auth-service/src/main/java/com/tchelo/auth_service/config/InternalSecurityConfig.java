package com.tchelo.auth_service.config;

import com.tchelo.auth_service.security.InternalApiKeyFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InternalSecurityConfig {

    // Même clé que celle envoyée par les autres services (INTERNAL_API_KEY)
    @Value("${notification.internal.api-key}")
    private String internalApiKey;

    // Filtre appliqué uniquement aux endpoints internes, pas à l'ensemble de l'API
    @Bean
    public FilterRegistrationBean<InternalApiKeyFilter> internalApiKeyFilterRegistration() {
        FilterRegistrationBean<InternalApiKeyFilter> registration =
                new FilterRegistrationBean<>(new InternalApiKeyFilter(internalApiKey));

        registration.addUrlPatterns("/internal/*");
        registration.setOrder(1);
        registration.setName("internalApiKeyFilter");

        return registration;
    }
}
