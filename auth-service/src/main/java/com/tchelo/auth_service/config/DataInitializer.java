package com.tchelo.auth_service.config;

import com.tchelo.auth_service.entity.Role;
import com.tchelo.auth_service.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j  // Pour les logs
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;

    //programme qui s'exécute automatiquement au démarrage de l'application (je dois l'enlever en prod)
    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            Role userRole = Role.builder()
                    .name("ROLE_USER")
                    .description("Rôle utilisateur par défaut")
                    .build();
            roleRepository.save(userRole);
            log.info("Rôle ROLE_USER crée avec succès");
        }

        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            Role adminRole = Role.builder()
                    .name("ROLE_ADMIN")
                    .description("Rôle administrateur par défaut")
                    .build();
            roleRepository.save(adminRole);
            log.info("Rôle ROLE_ADMIN crée avec succès");
        }

        log.info("Les données d'initialization de l'authentification de ticket241 sont crée avec succès");
    }
}