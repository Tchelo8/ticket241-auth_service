package com.tchelo.auth_service.exception;

import com.tchelo.auth_service.dto.ErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.tchelo.auth_service.exception.InvalidTotpCodeException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;


//Gestionnaire global des exceptions pour l'app , il intercepte toutes les exceptions et renvoie des réponses JSON structurées
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    //gestion d'erreur d'auth
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponseDto> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request
    ) {
        log.error("Échec d'authentification veuillez vérifier vos identifiants : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message("Numéro de téléphone ou mot de passe incorrect")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    //gestion des utilisateurs non trouvés
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleUsernameNotFound(
            UsernameNotFoundException ex,
            HttpServletRequest request
    ) {
        log.error("Utilisateur non trouvé  sur Ticket241: {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.NOT_FOUND.value())
                .message("Utilisateur non trouvé sur Ticket241")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    // gère les utilisateurs de Ticket241 qui existent déjà
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponseDto> handleUserAlreadyExists(
            UserAlreadyExistsException ex,
            HttpServletRequest request
    ) {
        log.error("Utilisateur existe déjà sur Ticket241: {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.CONFLICT.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

   //gestion des rôles non trouvés
    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleRoleNotFound(
            RoleNotFoundException ex,
            HttpServletRequest request
    ) {
        log.error("Rôle non trouvé sur la plateforme: {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("Erreur de configuration : " + ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    //gère les erreurs de validation dto
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        log.error("Erreurs de validation : {}", errors);

        Map<String, Object> response = new HashMap<>();
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("message", "Erreur de validation");
        response.put("errors", errors);
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }


    @ExceptionHandler(InvalidTotpCodeException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidTotpCode(
            InvalidTotpCodeException ex,
            HttpServletRequest request
    ) {
        log.warn("Code TOTP invalide : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    // compte pas encore vérifié (OTP non validé) : Spring Security lève ça au login via DaoAuthenticationProvider
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponseDto> handleDisabledAccount(
            DisabledException ex,
            HttpServletRequest request
    ) {
        log.warn("Tentative de connexion sur un compte non vérifié : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .message("Compte non vérifié. Validez le code OTP reçu par email via /api/auth/verify-otp avant de vous connecter.")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidOtp(
            InvalidOtpException ex,
            HttpServletRequest request
    ) {
        log.warn("Code OTP invalide : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(OtpVerificationUnavailableException.class)
    public ResponseEntity<ErrorResponseDto> handleOtpVerificationUnavailable(
            OtpVerificationUnavailableException ex,
            HttpServletRequest request
    ) {
        log.error("Vérification OTP indisponible : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(error);
    }

    @ExceptionHandler(OtpDispatchUnavailableException.class)
    public ResponseEntity<ErrorResponseDto> handleOtpDispatchUnavailable(
            OtpDispatchUnavailableException ex,
            HttpServletRequest request
    ) {
        log.error("Envoi du code OTP indisponible : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                .message("Service d'envoi de code OTP indisponible, réessayez votre inscription")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(error);
    }

    @ExceptionHandler(OtpResendTooSoonException.class)
    public ResponseEntity<ErrorResponseDto> handleOtpResendTooSoon(
            OtpResendTooSoonException ex,
            HttpServletRequest request
    ) {
        log.warn("Renvoi OTP trop rapproché : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.TOO_MANY_REQUESTS.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(error);
    }

    // Accès refusé (ex: créer un admin sans être admin, lire les utilisateurs d'une autre structure)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDto> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request
    ) {
        log.warn("Accès refusé sur {} : {}", request.getRequestURI(), ex.getMessage());
        return error(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    // Connexion avec le bon mot de passe sur un compte suspendu ou supprimé
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponseDto> handleLockedAccount(
            LockedException ex,
            HttpServletRequest request
    ) {
        log.warn("Connexion refusée sur un compte suspendu ou supprimé");
        return error(HttpStatus.FORBIDDEN,
                "Ce compte est suspendu ou supprimé. Contactez le support Ticket241.", request);
    }

    // OTP, MFA ou autre action sur un compte suspendu ou supprimé
    @ExceptionHandler(AccountNotActiveException.class)
    public ResponseEntity<ErrorResponseDto> handleAccountNotActive(
            AccountNotActiveException ex,
            HttpServletRequest request
    ) {
        log.warn("Action refusée sur un compte non actif : {}", ex.getMessage());
        return error(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    // Code d'invitation faux, expiré ou déjà utilisé
    @ExceptionHandler(InvalidInvitationCodeException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidInvitationCode(
            InvalidInvitationCodeException ex,
            HttpServletRequest request
    ) {
        log.warn("Code d'invitation refusé : {}", ex.getMessage());
        return error(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    // event-service injoignable : ce n'est pas la faute du code saisi
    @ExceptionHandler(StructureServiceUnavailableException.class)
    public ResponseEntity<ErrorResponseDto> handleStructureServiceUnavailable(
            StructureServiceUnavailableException ex,
            HttpServletRequest request
    ) {
        log.error("Vérification du code d'invitation indisponible : {}", ex.getMessage());
        return error(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage(), request);
    }

    private ResponseEntity<ErrorResponseDto> error(HttpStatus status, String message, HttpServletRequest request) {
        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(status.value())
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponseDto> handleIllegalState(
            IllegalStateException ex,
            HttpServletRequest request
    ) {
        log.warn("État MFA invalide : {}", ex.getMessage());

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    //Gère toutes les autres exceptions non prévues
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleGenericException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.error("Erreur inattendue : ", ex);

        ErrorResponseDto error = ErrorResponseDto.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("Une erreur interne s'est produite. Veuillez réessayer plus tard.")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
