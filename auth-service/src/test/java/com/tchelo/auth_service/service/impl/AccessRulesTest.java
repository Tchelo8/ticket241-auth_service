package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.EventServiceClient;
import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.dto.RegisterAdminDto;
import com.tchelo.auth_service.dto.RegisterStructureAdminDto;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.InvalidInvitationCodeException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.RoleRepository;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.OtpDispatchService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// Règles d'accès d'auth-service : code d'invitation des admins de structure, création d'admins
// généraux, liste des utilisateurs d'une structure
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AccessRulesTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private NotificationServiceClient notificationServiceClient;
    @Mock private EventServiceClient eventServiceClient;
    @Mock private OtpDispatchService otpDispatchService;

    private StructureAuthServiceImpl structureAuthService;
    private AdminAuthServiceImpl adminAuthService;

    @BeforeEach
    void setUp() {
        UserMapper userMapper = new UserMapper();
        structureAuthService = new StructureAuthServiceImpl(userRepository, roleRepository, passwordEncoder, jwtService,
                authenticationManager, userMapper, notificationServiceClient, eventServiceClient, otpDispatchService);
        adminAuthService = new AdminAuthServiceImpl(userRepository, roleRepository, passwordEncoder, jwtService,
                authenticationManager, userMapper, notificationServiceClient, otpDispatchService);

        when(roleRepository.findByName(anyString()))
                .thenAnswer(inv -> Optional.of(Role.builder().name(inv.getArgument(0, String.class)).build()));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User user = inv.getArgument(0);
            user.setId(10L);
            return user;
        });
        when(passwordEncoder.encode(anyString())).thenReturn("hash");
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private void loggedInAs(String role, Long structureId) {
        User caller = User.builder().id(1L).phone("+24100000000").email("a@b.c").password("x")
                .structureId(structureId)
                .roles(Set.of(Role.builder().name(role).build()))
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(caller, null, caller.getAuthorities()));
    }

    private RegisterStructureAdminDto structureAdminRequest(String code) {
        return RegisterStructureAdminDto.builder()
                .structureId(1L).structureInvitationCode(code)
                .phone("+24177000000").email("org@test.com").password("secret123")
                .firstName("Awa").lastName("Mba")
                .build();
    }

    @Test
    void structureAdminRegistrationIsRefusedWithAWrongInvitationCode() {
        doThrow(new InvalidInvitationCodeException("Code d'invitation invalide ou expiré"))
                .when(eventServiceClient).checkInvitationCode(1L, "nimportequoi");

        assertThatThrownBy(() -> structureAuthService.registerStructureAdmin(structureAdminRequest("nimportequoi")))
                .isInstanceOf(InvalidInvitationCodeException.class);
        verify(userRepository, never()).save(any(User.class));
        verify(otpDispatchService, never()).dispatch(any(User.class));
    }

    @Test
    void validInvitationCodeIsConsumedBeforeTheOtpIsSent() {
        structureAuthService.registerStructureAdmin(structureAdminRequest("ABCD-EFGH-JKLM"));

        InOrder order = inOrder(eventServiceClient, userRepository, otpDispatchService);
        order.verify(eventServiceClient).checkInvitationCode(1L, "ABCD-EFGH-JKLM");
        order.verify(userRepository).save(any(User.class));
        order.verify(eventServiceClient).consumeInvitationCode(1L, "ABCD-EFGH-JKLM");
        order.verify(otpDispatchService).dispatch(any(User.class));
    }

    @Test
    void anonymousCannotCreateAnAdminOnceOneExists() {
        when(userRepository.existsByRolesName("ROLE_ADMIN")).thenReturn(true);

        assertThatThrownBy(() -> adminAuthService.registerAdmin(adminRequest()))
                .isInstanceOf(AccessDeniedException.class);

        loggedInAs("ROLE_USER", null);
        assertThatThrownBy(() -> adminAuthService.registerAdmin(adminRequest()))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void aLoggedInAdminCanCreateAnotherAdmin() {
        when(userRepository.existsByRolesName("ROLE_ADMIN")).thenReturn(true);
        loggedInAs("ROLE_ADMIN", null);

        assertThat(adminAuthService.registerAdmin(adminRequest())).isNotNull();
    }

    @Test
    void theFirstAdminCanBeCreatedOnAFreshInstallation() {
        when(userRepository.existsByRolesName("ROLE_ADMIN")).thenReturn(false);

        assertThat(adminAuthService.registerAdmin(adminRequest())).isNotNull();
    }

    @Test
    void structureUsersAreVisibleOnlyToAdminsOrThatStructure() {
        when(userRepository.findByStructureId(anyLong())).thenReturn(List.of());

        loggedInAs("ROLE_STRUCTURE_ADMIN", 1L);
        assertThat(structureAuthService.getUsersByStructure(1L)).isEmpty();
        assertThatThrownBy(() -> structureAuthService.getUsersByStructure(2L))
                .isInstanceOf(AccessDeniedException.class);

        loggedInAs("ROLE_USER", null);
        assertThatThrownBy(() -> structureAuthService.getUsersByStructure(1L))
                .isInstanceOf(AccessDeniedException.class);

        loggedInAs("ROLE_ADMIN", null);
        assertThat(structureAuthService.getUsersByStructure(2L)).isEmpty();
    }

    private RegisterAdminDto adminRequest() {
        return RegisterAdminDto.builder()
                .phone("+24166000000").email("admin2@test.com").password("secret123")
                .firstName("Admin").lastName("Deux")
                .build();
    }
}
