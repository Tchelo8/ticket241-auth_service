package com.tchelo.auth_service.repository;

import com.tchelo.auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {



    Optional<User> findByPhone(String phone);


    Optional<User> findByEmail(String email);


    boolean existsByPhone(String phone);


    boolean existsByEmail(String email);

    List<User> findByStructureId(Long structureId);

    // Existe-t-il au moins un compte avec ce rôle (ex: ROLE_ADMIN, pour fermer l'inscription des admins)
    boolean existsByRolesName(String roleName);

    // Comptes non vérifiés créés avant le seuil, pas encore relancés depuis (ou jamais relancés) :
    // utilisé par le job planifié pour retrouver les OTP jamais reçus par le consommateur Kafka.
    // Les comptes suspendus ou supprimés sont exclus : on ne relance jamais l'OTP d'un compte bloqué.
    @Query("SELECT u FROM User u WHERE u.enabled = false AND u.createdAt < :threshold " +
            "AND (u.lastOtpDispatchAt IS NULL OR u.lastOtpDispatchAt < :threshold) " +
            "AND (u.accountStatus IS NULL OR u.accountStatus = com.tchelo.auth_service.entity.AccountStatus.ACTIVE)")
    List<User> findPendingOtpDispatch(@Param("threshold") LocalDateTime threshold);

    // Admins de structure encore actifs d'une structure (alerte quand le dernier est retiré)
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE u.structureId = :structureId " +
            "AND r.name = 'ROLE_STRUCTURE_ADMIN' " +
            "AND (u.accountStatus IS NULL OR u.accountStatus = com.tchelo.auth_service.entity.AccountStatus.ACTIVE)")
    long countActiveStructureAdmins(@Param("structureId") Long structureId);

    // Admins Ticket241 encore actifs (on ne retire jamais le dernier ; destinataires des alertes)
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' " +
            "AND (u.accountStatus IS NULL OR u.accountStatus = com.tchelo.auth_service.entity.AccountStatus.ACTIVE)")
    List<User> findActivePlatformAdmins();
}
