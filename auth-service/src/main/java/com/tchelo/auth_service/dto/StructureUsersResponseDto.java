package com.tchelo.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.List;

@Data
@AllArgsConstructor
public class StructureUsersResponseDto {
    private int count;
    private List<StructureUserDto> users;
}