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
    @Query("SELECT u FROM User u WHERE u.enabled = false AND u.createdAt < :threshold " +
            "AND (u.lastOtpDispatchAt IS NULL OR u.lastOtpDispatchAt < :threshold)")
    List<User> findPendingOtpDispatch(@Param("threshold") LocalDateTime threshold);
}
