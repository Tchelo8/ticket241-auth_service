# Ticket241 — Connexion utilisateur (auth-service) : guide d'intégration front

> Document destiné à l'agent / développeur front. Il décrit **exactement** ce que renvoie le backend
> (codes HTTP, corps JSON, messages) pour la **connexion d'un utilisateur client** (`ROLE_USER`).
> Les connexions admin et admin de structure ne sont **pas** couvertes ici.

---

## 1. Généralités

| Élément | Valeur |
|---|---|
| Base URL (direct) | `http://localhost:8083` (en prod : passer par l'API Gateway) |
| Préfixe | `/api/auth` |
| Format | JSON — toujours envoyer `Content-Type: application/json` |
| Identifiant de connexion | **le numéro de téléphone** (`phone`), pas l'email |
| Auth | JWT HS256 dans le header `Authorization: Bearer <token>` |
| Durée de vie du JWT | **24 h** (pas de refresh token → à expiration, renvoyer vers la page de login) |
| CORS | ⚠️ aucune config CORS dans ce service : depuis un navigateur, passer par la Gateway (ou un proxy de dev Vite/Angular) |

### Routes utilisées

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/auth/login` | connexion |
| POST | `/api/auth/verify-otp` | activer le compte avec le code reçu par email (si login → 403) |
| POST | `/api/auth/resend-otp` | renvoyer le code OTP |

### Contenu du JWT (payload décodable côté front)

```json
{
  "roles": ["ROLE_USER"],
  "sub": "+24106000000",   // numéro de téléphone
  "iat": 1760000000,
  "exp": 1760086400
}
```

Le front peut le décoder (`jwt-decode`) pour lire `exp`, mais la sécurité reste côté backend.

---

## 2. Formats de réponse

Le backend renvoie **3 formes** de JSON.

### 2.1 Succès — `AuthResponse`

Tous les champs sont **toujours présents** (valeur `null` si non applicable).

```ts
interface AuthResponse {
  token: string | null;        // JWT — null si pas de connexion (ex. resend-otp)
  type: "Bearer";
  phone: string;
  email: string;
  firstName: string;
  lastName: string;
  structureId: null;           // toujours null pour un utilisateur
  roles: string[];             // ["ROLE_USER"]
  message: string;             // message lisible, affichable
  mfaRequired: false;          // toujours false pour un utilisateur — ignorer
  mfaSetupRequired: false;     // toujours false pour un utilisateur — ignorer
  tempToken: null;             // toujours null pour un utilisateur — ignorer
}
```

### 2.2 Erreur métier — `ErrorResponse`

```ts
interface ErrorResponse {
  status: number;      // = code HTTP
  message: string;     // message en français, affichable tel quel
  timestamp: string;   // "2026-10-09 14:32:10"
  path: string;        // ex. "/api/auth/login"
}
```

Exemple :
```json
{
  "status": 401,
  "message": "Numéro de téléphone ou mot de passe incorrect",
  "timestamp": "2026-10-09 14:32:10",
  "path": "/api/auth/login"
}
```

### 2.3 Erreur de validation (400) — `ValidationErrorResponse`

Renvoyée quand un champ est manquant ou mal formé. **Contient un objet `errors` champ → message**, à afficher sous chaque input.

```ts
interface ValidationErrorResponse {
  status: 400;
  message: "Erreur de validation";
  errors: Record<string, string>;   // { "phone": "Le numéro de téléphone est requis", ... }
  timestamp: string;                // ⚠️ format ISO ici : "2026-10-09T14:32:10.123456"
  path: string;
}
```

Exemple :
```json
{
  "status": 400,
  "message": "Erreur de validation",
  "errors": {
    "phone": "Le numéro de téléphone est requis",
    "password": "Le mot de passe est requis"
  },
  "timestamp": "2026-10-09T14:32:10.123456",
  "path": "/api/auth/login"
}
```

> **Règle de détection** : si `status === 400` et `body.errors` existe → erreurs de formulaire ; sinon c'est un `ErrorResponse`.

### 2.4 Erreur inattendue (500)

```json
{
  "status": 500,
  "message": "Une erreur interne s'est produite. Veuillez réessayer plus tard.",
  "timestamp": "2026-10-09 14:32:10",
  "path": "/api/auth/login"
}
```

---

## 3. `POST /api/auth/login`

**Requête**
```json
{ "phone": "+24106000000", "password": "secret123" }
```

| Champ | Règle | Message si invalide |
|---|---|---|
| `phone` | obligatoire | `Le numéro de téléphone est requis` |
| `password` | obligatoire | `Le mot de passe est requis` |

**✅ 200 — Connexion réussie**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "phone": "+24106000000",
  "email": "jean@mail.com",
  "firstName": "Jean",
  "structureId": null,
  "lastName": "Mba",
  "roles": ["ROLE_USER"],
  "message": "Connexion réussie sur Ticket241",
  "mfaRequired": false,
  "mfaSetupRequired": false,
  "tempToken": null
}
```

**Détail des champs renvoyés**

| Champ | Type | Valeur en cas de succès | Usage front |
|---|---|---|---|
| `token` | string | JWT signé (valable 24 h) | à stocker ; à envoyer dans `Authorization: Bearer <token>` |
| `type` | string | `"Bearer"` | préfixe du header Authorization |
| `phone` | string | numéro de l'utilisateur | identifiant, profil |
| `email` | string | email de l'utilisateur | profil |
| `firstName` | string | prénom | affichage (« Bonjour Jean ») |
| `lastName` | string | nom | affichage |
| `roles` | string[] | `["ROLE_USER"]` | redirection / droits |
| `message` | string | `"Connexion réussie sur Ticket241"` | toast de succès (optionnel) |
| `structureId` | null | `null` | ignorer (pas utilisé pour un utilisateur) |
| `mfaRequired` | boolean | `false` | ignorer |
| `mfaSetupRequired` | boolean | `false` | ignorer |
| `tempToken` | null | `null` | ignorer |

**❌ Erreurs**

| HTTP | Cas | `message` | Action front |
|---|---|---|---|
| 400 | champ vide | `Erreur de validation` + `errors` | afficher sous les champs |
| 401 | mauvais mot de passe **ou** numéro inconnu | `Numéro de téléphone ou mot de passe incorrect` | message générique sur le formulaire |
| 403 | compte pas encore vérifié par OTP | `Compte non vérifié. Validez le code OTP reçu par email via /api/auth/verify-otp avant de vous connecter.` | **rediriger vers l'écran de saisie OTP** (garder le `phone`), proposer « renvoyer le code » |
| 500 | erreur serveur | `Une erreur interne s'est produite. Veuillez réessayer plus tard.` | toast générique |

---

## 4. `POST /api/auth/verify-otp` — activer le compte

Après l'inscription, le compte est **désactivé** et un code à 6 chiffres est envoyé **par email**. Tant qu'il n'est pas validé, le login renvoie **403**.

**Requête**
```json
{ "phone": "+24106000000", "code": "482913" }
```

| Champ | Règle | Message si invalide |
|---|---|---|
| `phone` | obligatoire | `Le numéro de téléphone est requis` |
| `code` | obligatoire, exactement 6 caractères | `Le code OTP est requis` / `Le code OTP doit contenir 6 chiffres` |

**✅ 200 — compte activé et utilisateur connecté** (un `token` est renvoyé, pas besoin de repasser par le login)
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "phone": "+24106000000",
  "email": "jean@mail.com",
  "firstName": "Jean",
  "structureId": null,
  "lastName": "Mba",
  "roles": ["ROLE_USER"],
  "message": "Compte vérifié avec succès",
  "mfaRequired": false,
  "mfaSetupRequired": false,
  "tempToken": null
}
```
Si le compte était déjà vérifié : même réponse avec `message: "Compte déjà vérifié"` (et un token valide).

**❌ Erreurs**

| HTTP | Cas | `message` | Action front |
|---|---|---|---|
| 400 | champ manquant / code ≠ 6 caractères | `Erreur de validation` + `errors` | afficher sous le champ |
| 401 | code faux ou expiré | message du service de notification (ex. `Code OTP invalide`) | afficher l'erreur, vider le champ, proposer « renvoyer le code » |
| 404 | numéro inconnu | `Utilisateur non trouvé sur Ticket241` | retour à l'inscription |
| 503 | service de vérification indisponible | `Service de vérification OTP momentanément indisponible, réessayez plus tard` | toast + bouton réessayer |

---

## 5. `POST /api/auth/resend-otp` — renvoyer le code

**Requête**
```json
{ "phone": "+24106000000" }
```

**✅ 200** (`token` toujours `null`)

| Cas | `message` | Action front |
|---|---|---|
| code renvoyé | `Un nouveau code de vérification a été envoyé par email : validez-le via /api/auth/verify-otp` | afficher l'info, démarrer un cooldown de 60 s |
| compte déjà actif | `Compte déjà vérifié, connectez-vous via /api/auth/login` | rediriger vers le login |

**❌ Erreurs**

| HTTP | Cas | `message` | Action front |
|---|---|---|---|
| 400 | `phone` vide | `Erreur de validation` + `errors` | — |
| 404 | numéro inconnu | `Utilisateur non trouvé sur Ticket241` | — |
| 429 | renvoi demandé moins de 60 s après le précédent | `Un code a déjà été envoyé récemment, réessayez dans 42 secondes` | désactiver le bouton ; extraire le nombre de secondes du message pour un compte à rebours |
| 503 | envoi impossible | `Service d'envoi de code OTP indisponible, réessayez votre inscription` | toast |

---

## 6. Après la connexion

- Stocker `token` (+ `firstName`, `lastName`, `email`, `phone`) dès qu'une réponse 200 contient `token !== null`.
- Envoyer sur chaque appel protégé : `Authorization: Bearer <token>`.
- **Déconnexion** : purement côté front (supprimer le token). Il n'y a pas de route `/logout`.
- **Expiration** : vérifier `exp` du JWT ; sur un 401 d'un service protégé → purger le token et rediriger vers le login.

---

## 7. Logique à implémenter côté front

```ts
const API = "/api/auth";

async function post(path: string, payload: unknown) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => null);
  return { res, body };
}

function handleError(status: number, body: any, ctx: { phone?: string }) {
  switch (status) {
    case 400: return body?.errors ? showFieldErrors(body.errors) : showError(body?.message);
    case 401: return showError(body.message);                    // identifiants / code OTP incorrects
    case 403: return goTo("verify-otp", { phone: ctx.phone });   // compte non vérifié
    case 404: return showError(body.message);
    case 429: return startCooldown(body.message);
    case 503: return showError(body.message, { retry: true });
    default:  return showError("Une erreur est survenue, réessayez plus tard.");
  }
}

export async function login(phone: string, password: string) {
  const { res, body } = await post("/login", { phone, password });
  if (res.ok) return saveSessionAndRedirect(body);
  return handleError(res.status, body, { phone });
}

export async function verifyOtp(phone: string, code: string) {
  const { res, body } = await post("/verify-otp", { phone, code });
  if (res.ok) return saveSessionAndRedirect(body);              // token renvoyé → connecté
  return handleError(res.status, body, { phone });
}

export async function resendOtp(phone: string) {
  const { res, body } = await post("/resend-otp", { phone });
  if (res.ok) {
    if (body.message.startsWith("Compte déjà vérifié")) return goTo("login");
    showInfo(body.message);
    return startCooldown(60);
  }
  return handleError(res.status, body, { phone });
}
```

### Parcours

```
 login ──200 (token)───────────────────────────────────► connecté
   │
   ├─401 ─► "Numéro de téléphone ou mot de passe incorrect"
   │
   └─403 (compte non vérifié)
          │
          ▼
     écran OTP ── verify-otp ──200 (token)─────────────► connecté
          │  ▲
          └──┘ resend-otp (cooldown 60 s, 429 si trop tôt)
```
