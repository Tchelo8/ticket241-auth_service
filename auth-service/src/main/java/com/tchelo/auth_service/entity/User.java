package com.tchelo.auth_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String phone;

    @Column(nullable = false, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;  // Sera hashé avec BCrypt

    @Column(name = "first_name", length = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Column(name = "is_enabled")
    private boolean enabled = true;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "structure_id")
    private Long structureId;

    @Column(name = "mfa_secret")
    private String mfaSecret;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;

    // Dernier envoi (ou renvoi) de code OTP déclenché pour ce compte, utilisé pour le
    // cooldown de /resend-otp et pour éviter au job planifié de spammer un compte
    @Column(name = "last_otp_dispatch_at")
    private LocalDateTime lastOtpDispatchAt;

    // Nombre de fois où l'envoi d'OTP a été déclenché (inscription + renvois), utilisé
    // pour plafonner les relances automatiques du job planifié
    @Column(name = "otp_dispatch_attempts")
    @Builder.Default
    private Integer otpDispatchAttempts = 0;

    // Fenêtre glissante de limitation des envois d'OTP (3 max par 15 min) : début de la fenêtre
    // courante et nombre d'envois déjà faits dedans. Alignée sur la limite de notification-service
    // pour ne jamais annoncer un envoi que notification-service refuserait.
    @Column(name = "otp_window_started_at")
    private LocalDateTime otpWindowStartedAt;

    @Column(name = "otp_window_dispatch_count")
    @Builder.Default
    private Integer otpWindowDispatchCount = 0;

    // Statut administratif (voir AccountStatus). null sur les comptes créés avant son ajout = ACTIVE.
    @Enumerated(EnumType.STRING)
    @Column(name = "account_status", length = 20)
    @Builder.Default
    private AccountStatus accountStatus = AccountStatus.ACTIVE;

    // Fin d'une suspension temporaire (null = jusqu'à réactivation manuelle)
    @Column(name = "suspended_until")
    private LocalDateTime suspendedUntil;

    // Traçabilité du dernier changement de statut : quand, par qui (téléphone), pourquoi
    @Column(name = "status_changed_at")
    private LocalDateTime statusChangedAt;

    @Column(name = "status_changed_by", length = 100)
    private String statusChangedBy;

    @Column(name = "status_reason", length = 500)
    private String statusReason;

    // Relation Many-to-Many avec Role
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // ==========================================
    // Implémentation de UserDetails (Spring Security)
    // ==========================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return phone;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // Statut réellement en vigueur : une suspension dont la date de fin est passée ne bloque plus
    public AccountStatus getEffectiveStatus() {
        if (accountStatus == null) {
            return AccountStatus.ACTIVE;
        }
        if (accountStatus == AccountStatus.SUSPENDED && suspendedUntil != null
                && !suspendedUntil.isAfter(LocalDateTime.now())) {
            return AccountStatus.ACTIVE;
        }
        return accountStatus;
    }

    public boolean isActiveAccount() {
        return getEffectiveStatus() == AccountStatus.ACTIVE;
    }

    public void changeStatus(AccountStatus newStatus, LocalDateTime until, String changedBy, String reason) {
        this.accountStatus = newStatus;
        this.suspendedUntil = newStatus == AccountStatus.SUSPENDED ? until : null;
        this.statusChangedAt = LocalDateTime.now();
        this.statusChangedBy = changedBy;
        this.statusReason = reason;
    }

    // Spring Security refuse la connexion d'un compte "verrouillé" (LockedException) : c'est ainsi qu'un
    // compte suspendu ou supprimé ne peut plus se connecter, indépendamment de la vérification de l'email
    @Override
    public boolean isAccountNonLocked() {
        return isActiveAccount();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
