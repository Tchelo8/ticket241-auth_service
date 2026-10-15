package com.tchelo.auth_service.service;

import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.RegisterStructureAdminDto;
import com.tchelo.auth_service.dto.LoginStructureAdminDto;
import com.tchelo.auth_service.dto.StructureUserDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;

import java.util.List;

public interface StructureAuthService {


    AuthResponseDto registerStructureAdmin(RegisterStructureAdminDto request);

    AuthResponseDto loginStructureAdmin(LoginStructureAdminDto request);

    AuthResponseDto verifyOtpStructureAdmin(VerifyOtpRequestDto request);

    List<StructureUserDto> getUsersByStructure(Long structureId);
}
