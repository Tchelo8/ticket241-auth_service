package com.tchelo.auth_service.service;

import com.tchelo.auth_service.dto.*;

import java.util.List;

public interface AdminAuthService {
    AuthResponseDto registerAdmin(RegisterAdminDto request);

    AuthResponseDto loginAdmin(LoginAdminDto request);

    AuthResponseDto verifyOtpAdmin(VerifyOtpRequestDto request);

}
