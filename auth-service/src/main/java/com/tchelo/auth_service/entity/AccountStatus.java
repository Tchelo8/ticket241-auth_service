package com.tchelo.auth_service.entity;

// État administratif d'un compte, indépendant de "email vérifié" (User.enabled).
// Rien n'est jamais effacé : SUSPENDED et DELETED bloquent l'accès en gardant toutes les données.
public enum AccountStatus {
    ACTIVE,     // Compte utilisable
    SUSPENDED,  // Bloqué temporairement (jusqu'à suspendedUntil, ou jusqu'à réactivation manuelle)
    DELETED     // Supprimé (par l'utilisateur ou un admin) : seul un admin Ticket241 peut le réactiver ;
                // son téléphone et son email ne peuvent pas servir à une nouvelle inscription
}
