package com.tchelo.auth_service.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class StructureUserDto {
    private String phone;
    private String email;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private Long structureId;
    private List<String> roles;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}