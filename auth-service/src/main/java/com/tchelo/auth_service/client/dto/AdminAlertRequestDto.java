package com.tchelo.auth_service.client.dto;

import java.util.List;

// Corps de POST /api/notifications/internal/admin-alert (notification-service)
public record AdminAlertRequestDto(List<String> recipients, String subject, String message) {
}
