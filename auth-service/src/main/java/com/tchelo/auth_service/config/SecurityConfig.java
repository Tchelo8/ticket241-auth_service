package com.tchelo.auth_service.config;


import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;

    /**
     * UserDetailsService : indique à Spring Security comment charger un utilisateur
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return phone -> userRepository.findByPhone(phone)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non retrouvé: " + phone));
    }


      // algorithme pour hasher les passwords (BCrypt)

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * AuthenticationProvider : définit comment authentifier
     */
    @Bean
    public AuthenticationProvider authenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider authProvider =
                new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        // L'état du compte (suspendu, supprimé, non vérifié) n'est contrôlé qu'APRÈS le mot de passe :
        // sans le bon mot de passe, tout le monde reçoit le même "identifiants incorrects", ce qui
        // évite de révéler à un inconnu le statut d'un numéro de téléphone
        authProvider.setPreAuthenticationChecks(user -> { });
        authProvider.setPostAuthenticationChecks(user -> {
            if (!user.isAccountNonLocked()) {
                throw new LockedException("Compte suspendu ou supprimé");
            }
            if (!user.isEnabled()) {
                throw new DisabledException("Compte non vérifié");
            }
        });
        return authProvider;
    }



    //  AuthenticationManager : utilisé par AuthService pour authentifier

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


     // Configuration de la sécurité HTTP
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService) throws Exception {
        // Instanciation manuelle pour éviter la dépendance circulaire avec UserDetailsService
        JwtAuthenticationFilter jwtFilter =
                new JwtAuthenticationFilter(jwtService, userDetailsService());

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Données personnelles des utilisateurs d'une structure : JWT obligatoire
                        // (le périmètre admin / admin de la structure est vérifié dans StructureAuthService).
                        // Doit rester AVANT la règle /api/auth/** qui ouvre tout le reste.
                        .requestMatchers("/api/auth/structure/*/users").authenticated()
                        // Création des contrôleurs d'entrée d'une structure : même règle
                        .requestMatchers("/api/auth/structure/*/agents").authenticated()
                        // Cycle de vie des comptes : suppression de son compte, gestion par les admins
                        // (le périmètre de chacun est vérifié dans AccountManagementService)
                        .requestMatchers("/api/auth/me", "/api/auth/accounts/**").authenticated()
                        // Inscription, connexion, OTP, MFA : publics par nature. /admin/register vérifie
                        // lui-même qu'un admin est connecté (sauf première installation).
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        // Service-à-service : pas de JWT, protégé par la clé interne (InternalApiKeyFilter)
                        .requestMatchers("/internal/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 401 sans token valide (au lieu du 403 par défaut), pour que le front sache qu'il doit se reconnecter
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }



}