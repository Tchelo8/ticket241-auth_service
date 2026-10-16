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

        // Sans lui, sur une base neuve, l'inscription des admins de structure échoue (« rôle introuvable »)
        if (roleRepository.findByName("ROLE_STRUCTURE_ADMIN").isEmpty()) {
            Role structureAdminRole = Role.builder()
                    .name("ROLE_STRUCTURE_ADMIN")
                    .description("Administrateur d'une structure organisatrice")
                    .build();
            roleRepository.save(structureAdminRole);
            log.info("Rôle ROLE_STRUCTURE_ADMIN crée avec succès");
        }

        // Contrôleur d'entrée : scanne les billets des événements de sa structure (/api/tickets/validate)
        if (roleRepository.findByName("ROLE_AGENT").isEmpty()) {
            Role agentRole = Role.builder()
                    .name("ROLE_AGENT")
                    .description("Contrôleur d'entrée rattaché à une structure")
                    .build();
            roleRepository.save(agentRole);
            log.info("Rôle ROLE_AGENT crée avec succès");
        }

        log.info("Les données d'initialization de l'authentification de ticket241 sont crée avec succès");
    }
}