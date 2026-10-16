package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.client.NotificationServiceClient;
import com.tchelo.auth_service.dto.AccountStatusChangeDto;
import com.tchelo.auth_service.dto.AuthResponseDto;
import com.tchelo.auth_service.dto.DeleteMyAccountDto;
import com.tchelo.auth_service.dto.VerifyOtpRequestDto;
import com.tchelo.auth_service.entity.AccountStatus;
import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.exception.AccountNotActiveException;
import com.tchelo.auth_service.exception.InvalidCredentialsException;
import com.tchelo.auth_service.exception.UserAlreadyExistsException;
import com.tchelo.auth_service.mapper.UserMapper;
import com.tchelo.auth_service.repository.RoleRepository;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.AccountAvailabilityChecker;
import com.tchelo.auth_service.service.JwtService;
import com.tchelo.auth_service.service.OtpDispatchService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// Cycle de vie des comptes (soft delete) : qui peut suspendre / supprimer / réactiver qui,
// et ce qu'un compte non actif ne peut plus faire
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AccountLifecycleTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserDetailsService userDetailsService;
    @Mock private NotificationServiceClient notificationServiceClient;
    @Mock private OtpDispatchService otpDispatchService;

    private AccountManagementServiceImpl accountService;
    private AuthServiceImpl authService;
    private AccountAvailabilityChecker availabilityChecker;

    private final User platformAdmin = user(1L, "+24160000001", null, "ROLE_ADMIN");
    private final User otherPlatformAdmin = user(2L, "+24160000002", null, "ROLE_ADMIN");
    private final User structureAdmin = user(3L, "+24160000003", 7L, "ROLE_STRUCTURE_ADMIN");
    private final User agentOfStructure7 = user(4L, "+24160000004", 7L, "ROLE_AGENT");
    private final User agentOfStructure8 = user(5L, "+24160000005", 8L, "ROLE_AGENT");
    private final User client = user(6L, "+24160000006", null, "ROLE_USER");

    @BeforeEach
    void setUp() {
        availabilityChecker = new AccountAvailabilityChecker(userRepository);
        accountService = new AccountManagementServiceImpl(userRepository, passwordEncoder, notificationServiceClient);
        authService = new AuthServiceImpl(userRepository, availabilityChecker, roleRepository, passwordEncoder,
                jwtService, authenticationManager, new UserMapper(), userDetailsService, notificationServiceClient,
                otpDispatchService);

        for (User u : List.of(platformAdmin, otherPlatformAdmin, structureAdmin, agentOfStructure7,
                agentOfStructure8, client)) {
            when(userRepository.findById(u.getId())).thenReturn(Optional.of(u));
            when(userRepository.findByPhone(u.getPhone())).thenReturn(Optional.of(u));
        }
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.findActivePlatformAdmins()).thenReturn(List.of(platformAdmin, otherPlatformAdmin));
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aStructureAdminManagesOnlyTheAgentsOfItsOwnStructure() {
        loggedInAs(structureAdmin);

        assertThat(accountService.suspend(4L, change()).getAccountStatus()).isEqualTo(AccountStatus.SUSPENDED);
        assertThat(agentOfStructure7.getStatusChangedBy()).isEqualTo(structureAdmin.getPhone());

        assertThatThrownBy(() -> accountService.suspend(5L, change())).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> accountService.delete(6L, change())).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> accountService.delete(1L, change())).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void onlyATicket241AdminCanReactivateADeletedAccount() {
        loggedInAs(structureAdmin);
        accountService.delete(4L, change());
        assertThatThrownBy(() -> accountService.reactivate(4L, change())).isInstanceOf(AccessDeniedException.class);

        loggedInAs(platformAdmin);
        assertThat(accountService.reactivate(4L, change()).getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    @Test
    void aStructureAdminCanReactivateASuspendedAgent() {
        loggedInAs(structureAdmin);
        accountService.suspend(4L, change());

        assertThat(accountService.reactivate(4L, change()).getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    @Test
    void nobodyActsOnTheirOwnAccountThroughTheAdminRoutes() {
        loggedInAs(platformAdmin);

        assertThatThrownBy(() -> accountService.suspend(1L, change())).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void theLastActiveTicket241AdminCannotBeRemoved() {
        when(userRepository.findActivePlatformAdmins()).thenReturn(List.of(platformAdmin));
        loggedInAs(otherPlatformAdmin);

        assertThatThrownBy(() -> accountService.delete(1L, change())).isInstanceOf(AccessDeniedException.class);
        assertThat(platformAdmin.getEffectiveStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    @Test
    void removingTheLastStructureAdminAlertsTicket241Admins() {
        when(userRepository.countActiveStructureAdmins(7L)).thenReturn(0L);
        loggedInAs(platformAdmin);

        accountService.delete(3L, change());

        verify(notificationServiceClient).sendAdminAlert(eq(List.of("1@test.com", "2@test.com")), anyString(), anyString());
    }

    @Test
    void noAlertWhileTheStructureStillHasAnAdmin() {
        when(userRepository.countActiveStructureAdmins(7L)).thenReturn(1L);
        loggedInAs(platformAdmin);

        accountService.suspend(3L, change());

        verify(notificationServiceClient, never()).sendAdminAlert(anyList(), anyString(), anyString());
    }

    @Test
    void aClientDeletesTheirOwnAccountOnlyWithTheirPassword() {
        loggedInAs(client);
        when(passwordEncoder.matches("mauvais", "hash")).thenReturn(false);
        when(passwordEncoder.matches("bon", "hash")).thenReturn(true);

        assertThatThrownBy(() -> accountService.deleteMyAccount(new DeleteMyAccountDto("mauvais", null)))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThat(client.getEffectiveStatus()).isEqualTo(AccountStatus.ACTIVE);

        assertThat(accountService.deleteMyAccount(new DeleteMyAccountDto("bon", null)).getAccountStatus())
                .isEqualTo(AccountStatus.DELETED);
    }

    @Test
    void aUserUpdatesOnlyTheirOwnNames() {
        loggedInAs(client);

        var updated = accountService.updateMyProfile(new com.tchelo.auth_service.dto.UpdateProfileDto("  Awa ", "Mba"));

        assertThat(updated.getFirstName()).isEqualTo("Awa");
        assertThat(client.getLastName()).isEqualTo("Mba");
        assertThat(client.getPhone()).isEqualTo("+24160000006");
        assertThat(accountService.getMyAccount().getId()).isEqualTo(6L);
    }

    @Test
    void aTemporarySuspensionEndsByItself() {
        client.changeStatus(AccountStatus.SUSPENDED, LocalDateTime.now().minusMinutes(1), "admin", null);
        assertThat(client.isActiveAccount()).isTrue();

        client.changeStatus(AccountStatus.SUSPENDED, LocalDateTime.now().plusDays(3), "admin", null);
        assertThat(client.isActiveAccount()).isFalse();
        assertThat(client.isAccountNonLocked()).isFalse();
    }

    @Test
    void thePhoneOfADeletedAccountCannotBeRegisteredAgain() {
        client.changeStatus(AccountStatus.DELETED, null, client.getPhone(), null);

        assertThatThrownBy(() -> availabilityChecker.requirePhoneAndEmailAvailable(client.getPhone(), "new@test.com"))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("support");
    }

    @Test
    void aSuspendedAccountCannotUseTheOtpFlow() {
        client.changeStatus(AccountStatus.SUSPENDED, null, "admin", null);

        assertThatThrownBy(() -> authService.verifyOtp(otpRequest(client.getPhone())))
                .isInstanceOf(AccountNotActiveException.class);
    }

    @Test
    void verifyingAnAlreadyVerifiedAccountNeverReturnsAToken() {
        AuthResponseDto response = authService.verifyOtp(otpRequest(client.getPhone()));

        assertThat(response.getToken()).isNull();
        verify(jwtService, never()).generateToken(anyString(), any());
        verify(notificationServiceClient, never()).verifyOtp(any(), anyString());
    }

    private void loggedInAs(User caller) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(caller, null, caller.getAuthorities()));
    }

    private static AccountStatusChangeDto change() {
        return new AccountStatusChangeDto();
    }

    private static VerifyOtpRequestDto otpRequest(String phone) {
        VerifyOtpRequestDto request = new VerifyOtpRequestDto();
        request.setPhone(phone);
        request.setCode("123456");
        return request;
    }

    private static User user(Long id, String phone, Long structureId, String role) {
        User user = User.builder().id(id).phone(phone).email(id + "@test.com").password("hash")
                .firstName("Prénom" + id).lastName("Nom")
                .structureId(structureId)
                .roles(Set.of(Role.builder().name(role).build()))
                .build();
        user.setEnabled(true);
        return user;
    }
}
