package com.tchelo.auth_service.mapper;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.RegisterRequestDto;
import com.tchelo.auth_service.dto.StructureUserDto;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class UserMapper {

    // Je convertis le RegisterRequestDto en entité User
    public User toEntity(RegisterRequestDto dto) {
        User user = new User();
        BeanUtils.copyProperties(dto, user);

        // Propriétés non présentes dans le DTO : le compte reste désactivé jusqu'à vérification de l'OTP
        user.setEnabled(false);
        log.debug("Utilisateur crée : {}", dto.getPhone());
        return user;
    }

    // Convertit un User en AuthResponseDto
    public AuthResponseDto toAuthResponse(User user, String token) {
        AuthResponseDto response = new AuthResponseDto();
        BeanUtils.copyProperties(user, response);

        // Propriétés spécifiques qui ne sont pas dans mon entité
        response.setToken(token);
        response.setType("Bearer");

        // Extraire les noms des rôles
        List<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
        response.setRoles(roleNames);

        response.setStructureId(user.getStructureId());

        response.setMessage("Connexion réussie");
        log.debug("AuthResponseDto crée: {}", user.getPhone());
        return response;
    }

    // Variante pour un message personnalisé
    public AuthResponseDto toAuthResponse(User user, String token, String customMessage) {
        AuthResponseDto response = toAuthResponse(user, token);
        response.setMessage(customMessage);
        return response;
    }

    public StructureUserDto toStructureUserDto(User user) {
        StructureUserDto dto = new StructureUserDto();
        dto.setPhone(user.getPhone());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setEnabled(user.isEnabled());
        dto.setStructureId(user.getStructureId());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());

        List<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
        dto.setRoles(roleNames);

        return dto;
    }
}