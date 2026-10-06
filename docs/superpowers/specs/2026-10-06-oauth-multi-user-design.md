# OAuth multi-utilisateur — design

Date : 2026-10-06 · Branche : `feat/oauth-multi-user` · Statut : validé en conversation, en relecture

## Objectif

Aujourd'hui le fork parle à Odoo avec **un seul compte** (`ODOO_USER` / `ODOO_API_KEY`) : tout client
connecté agit sous ce compte. On veut :

```
Agent Hermes      ──▶ MCP ──▶ Odoo avec le compte « Hermes »
Utilisatrice Alice ──▶ MCP ──▶ Odoo avec le compte d'Alice
Utilisateur Bob   ──▶ MCP ──▶ Odoo avec le compte de Bob
```

Clients visés : claude.ai / Claude Desktop / mobile (OAuth obligatoire), Claude Code / Cursor / VS Code
(OAuth), Hermes (jeton fixe).

**Critère de succès** : une action faite par Alice depuis claude.ai est exécutée dans Odoo avec l'uid
d'Alice et bornée par ses droits Odoo ; Hermes continue d'agir avec le compte de service.

## Non-objectifs

- Pas de stockage serveur (ni base, ni volume) : approche « tokens chiffrés » retenue.
- Pas de révocation token par token côté serveur (on coupe l'accès dans Odoo).
- Pas de scopes MCP (lecture/écriture) : les droits Odoo de l'utilisateur + `ODOO_YOLO` suffisent.
- Pas de CIMD (Client ID Metadata Documents) : enregistrement dynamique (DCR) uniquement.
- Pas de langue par utilisateur (le `ODOO_LOCALE` global reste tel quel).
- Le mode stdio et le mode HTTP sans OAuth ne changent pas de comportement.

## Parcours

**Utilisateur (claude.ai)** : Connecteurs → ajouter `https://<domaine>/mcp` → la page « Connexion Odoo »
du fork s'ouvre → il saisit **son identifiant Odoo et sa clé API Odoo** (créée dans *Mon profil >
Sécurité du compte > Nouvelle clé API*) → le fork vérifie auprès d'Odoo → retour dans claude.ai,
connecté. Token d'accès 1 h renouvelé automatiquement, refresh token 30 jours.

**Hermes** : en-tête `Authorization: Bearer <jeton>` avec un jeton de `ODOO_MCP_AUTH_TOKENS` ; il agit
avec le compte de service (`ODOO_USER` / `ODOO_API_KEY`).

**Couper un accès** : révoquer la clé API dans Odoo ou désactiver le compte Odoo.

## Configuration

Variables existantes inchangées (`ODOO_URL`, `ODOO_DB`, `ODOO_USER`, `ODOO_API_KEY`, `ODOO_YOLO`,
`ODOO_MCP_TRANSPORT`, `ODOO_MCP_HOST`, `ODOO_MCP_PORT`…). Nouvelles :

| Variable | Rôle |
| --- | --- |
| `ODOO_MCP_PUBLIC_URL` | URL publique de base du serveur (ex. `https://mcp-odoo.up.railway.app`). Sert d'`issuer` OAuth ; la ressource protégée est `<PUBLIC_URL>/mcp`. |
| `ODOO_MCP_SECRET_KEY` | Clé Fernet (`Fernet.generate_key()`) qui chiffre tous les blobs. La changer déconnecte tout le monde (sauf Hermes). |
| `ODOO_MCP_AUTH_TOKENS` | (existante sur la branche, sens redéfini) jetons fixes séparés par des virgules ; chaque jeton agit avec le compte de service. |

Validation au démarrage (`config.py`) :
- `ODOO_MCP_PUBLIC_URL` et `ODOO_MCP_SECRET_KEY` : les deux ou aucune → sinon erreur.
- OAuth activé ⇒ `ODOO_MCP_TRANSPORT=streamable-http`, sinon erreur.
- `ODOO_MCP_AUTH_TOKENS` non vide ⇒ OAuth activé, sinon erreur.
- `ODOO_MCP_SECRET_KEY` doit être une clé Fernet valide.
- `ODOO_MCP_PUBLIC_URL` en `https://` (le SDK accepte `http://localhost` pour les tests).

Propriété dérivée : `config.oauth_enabled = bool(public_url and secret_key)`.

## Architecture

### Nouveau module `mcp_server_odoo/oauth.py`

**`seal(typ, payload) -> str` / `unseal(token, typ, ttl) -> dict`** — Fernet(`ODOO_MCP_SECRET_KEY`) sur
du JSON `{"typ": typ, ...payload}`. `unseal` rejette (exception dédiée) : mauvais type, TTL dépassé
(horodatage Fernet), contenu altéré, mauvaise clé.

| `typ` | Contenu | Durée |
| --- | --- | --- |
| `client` | `OAuthClientInformationFull` sans `client_id` (inclut `client_secret`, `redirect_uris`…) | illimitée |
| `req` | `client_id`, `redirect_uri`, `redirect_uri_provided_explicitly`, `code_challenge`, `state`, `scopes`, `resource` | 600 s |
| `code` | idem `req` sans `state` + `jti` aléatoire + `uid`, `login`, `key` | 300 s |
| `access` | `client_id`, `scopes`, `uid`, `login`, `key` | 3600 s |
| `refresh` | `client_id`, `scopes`, `uid`, `login`, `key` | 30 jours |

**`OdooOAuthProvider`** (protocole `OAuthAuthorizationServerProvider` du SDK `mcp`) :
- `register_client(info)` : remplace `info.client_id` par `seal("client", info sans client_id)`. Le
  handler DCR du SDK renvoie ce même objet → le client reçoit l'identifiant scellé. (Couvert par un
  test passant par la vraie route `/register` pour détecter un changement du SDK.)
- `get_client(client_id)` : `unseal("client")` → `OAuthClientInformationFull`, `None` si invalide.
- `authorize(client, params)` : renvoie `<PUBLIC_URL>/oauth/login?req=<seal("req", …)>`.
- `load_authorization_code(client, code)` : `unseal("code")` ; `None` si invalide, expiré, `client_id`
  différent, ou `jti` déjà consommé (ensemble en mémoire, purgé des entrées expirées).
- `exchange_authorization_code(client, code)` : marque le `jti` consommé, émet `access` + `refresh`.
- `load_refresh_token` / `exchange_refresh_token` : `unseal("refresh")`, vérifie le `client_id`, **ré-
  authentifie `(db, login, key)` auprès d'Odoo** ; uid différent ou échec → `TokenError("invalid_grant")`
  ; sinon émet un nouveau couple `access` + `refresh`.
- `load_access_token(token)` : si `token` ∈ `ODOO_MCP_AUTH_TOKENS` (`hmac.compare_digest`) →
  `OdooAccessToken(client_id="static", odoo_uid=None, odoo_key=None)` (= compte de service) ; sinon
  `unseal("access")` → `OdooAccessToken(..., odoo_uid, odoo_key, expires_at)` ; sinon `None` (→ 401).
- `revoke_token` : non exposé (`revocation_options` désactivées).

`OdooAccessToken(AccessToken)` ajoute `odoo_uid: int | None` et `odoo_key: str | None` ; le champ
standard `subject` reçoit `str(uid)` (ou `"service"` pour un jeton fixe). Même principe pour
`OdooAuthorizationCode(AuthorizationCode)` et `OdooRefreshToken(RefreshToken)`.

**Page de connexion** (routes personnalisées FastMCP, publiques, en français) :
- `GET /oauth/login?req=…` : formulaire (identifiant, clé API, `req` caché) ; affiche le nom du client
  échappé (`html.escape`) ; `req` invalide/expiré → page « Lien expiré, relancez la connexion depuis
  votre application ».
- `POST /oauth/login` : `unseal("req")` ; `common.authenticate(db, login, key, {})` exécuté dans un
  thread ; uid faux → formulaire réaffiché avec « Identifiant ou clé API incorrect » (HTTP 200) ;
  Odoo injoignable → message d'erreur clair ; succès → `302` vers
  `construct_redirect_uri(redirect_uri, code=seal("code", …), state=state)`.

**`caller_identity()`** : lit `mcp.server.lowlevel.server.request_ctx` (contexte posé **par message**
par le SDK, propagé dans `asyncio.to_thread`) puis `request.scope["user"]` :
- hors requête MCP → `None` ;
- requête sans utilisateur authentifié → `MISSING` ;
- jeton fixe → `SERVICE` ;
- token OAuth → `OdooIdentity(uid, key)`.

On n'utilise **pas** `auth_context_var` du SDK : il est posé dans la tâche HTTP, alors que les outils
s'exécutent dans la tâche de session (créée à la première requête) — l'identité pourrait être celle
d'une autre requête.

### `odoo_connection.py`

- `execute_kw` : `ident = caller_identity()`
  - `OdooIdentity` → `uid, secret = ident.uid, ident.key` ;
  - `MISSING` et `config.oauth_enabled` → `OdooConnectionError` (**fail-closed**, jamais de repli sur
    le compte de service) ;
  - sinon (`None`, `SERVICE`, ou `MISSING` sans OAuth) → compte de service (comportement actuel).
- `uid` (propriété) renvoie l'uid de l'appelant s'il y en a un → `get_current_context` et
  `user_context.py` montrent le contexte de l'appelant.
- Cache `fields_get` : clé `(model, uid effectif)` (`PerformanceManager.get_cached_fields` /
  `cache_fields` reçoivent l'uid).

### `server.py`

- Si `config.oauth_enabled` : `FastMCP(..., auth_server_provider=OdooOAuthProvider(...),
  auth=AuthSettings(issuer_url=PUBLIC_URL, resource_server_url=PUBLIC_URL + "/mcp",
  client_registration_options=ClientRegistrationOptions(enabled=True)))` + routes `/oauth/login`.
- Si `config.oauth_enabled` : `_apply_dynamic_instructions` ne personnalise pas les instructions avec
  le compte de service (instructions statiques ; `get_current_context` reste disponible).
- Suppression de `BearerAuthMiddleware` et `_serve_http_with_bearer_auth` (ajoutés plus tôt sur la
  branche, non publiés) : retour à `self.app.run_streamable_http_async()`.
- `_warn_if_exposed` : pas d'avertissement « pas d'authentification » si `config.oauth_enabled`.

### Autres

- `pyproject.toml` : déclarer `cryptography` (déjà installée via `mcp` → `pyjwt[crypto]`).
- Docs : README (section multi-utilisateur + tableau des variables), `.env.example`, aide `--help`.
- `tools.py`, `resources.py` : inchangés (tout passe par `execute_kw`).

## Sécurité

- Clés API présentes uniquement dans des blobs Fernet (AES-128-CBC + HMAC-SHA256) ; jamais en clair sur
  disque ni dans les logs ; clé de chiffrement uniquement en variable Railway.
- PKCE S256 et vérification `redirect_uri` assurés par le SDK.
- Code à usage unique (mémoire) + expiration 5 min + PKCE.
- Clé révoquée dans Odoo : appels refusés immédiatement par Odoo ; renouvellement refusé.
- Refresh tokens non révocables un par un (sans état) ; la rotation laisse les anciens valides jusqu'à
  expiration — accepté, l'accès se coupe dans Odoo.
- XSS : seul le nom du client (fourni par DCR) est affiché, échappé.
- Formulaire utilisable uniquement avec un `req` scellé du flux en cours.
- Pas de limitation de débit ajoutée : clés API Odoo aléatoires longues + limitation de connexion Odoo.

## Erreurs visibles

| Cas | Résultat |
| --- | --- |
| Identifiant ou clé faux | formulaire + « Identifiant ou clé API incorrect » |
| `req` expiré/invalide | page « Lien expiré, relancez la connexion depuis votre application » |
| Odoo injoignable au login | page d'erreur explicite |
| Token absent/invalide/expiré sur `/mcp` | 401 + `WWW-Authenticate` (SDK) → le client propose de se reconnecter |
| Refresh avec clé révoquée | `invalid_grant` → reconnexion |
| Requête sans identité avec OAuth actif | erreur outil, aucun appel Odoo |

## Tests (écrits avant le code)

1. `seal`/`unseal` : aller-retour ; rejet sur mauvais type, TTL, altération, mauvaise clé.
2. Flux OAuth complet via les vraies routes du SDK (client ASGI, Odoo `authenticate` simulé) :
   `/register` → `/authorize` → `GET`/`POST /oauth/login` → `/token` (PKCE) → `/mcp` avec le token →
   refresh. Plus : code rejoué refusé, login faux, `req` expiré, jeton fixe accepté, token invalide 401,
   nom de client échappé.
3. Identité : `execute_kw` utilise l'uid/clé de l'appelant ; compte de service hors requête et pour le
   jeton fixe ; fail-closed si `MISSING` avec OAuth ; cache des champs séparé par uid.
4. Configuration : couples obligatoires, clé Fernet invalide, OAuth sans HTTP, jetons fixes sans OAuth.
5. Bout en bout (Docker local, Odoo 20 réel, deux comptes admin / utilisateur limité) : flux OAuth pour
   chacun, `get_current_context` renvoie le bon nom, l'utilisateur limité est refusé là où l'admin
   passe, jeton fixe = compte de service.
6. Suite existante verte (hors `test_setup_logging`, déjà en échec sous Windows).

## Limites connues

- Validation réelle avec claude.ai seulement après déploiement (URL publique requise).
- Clients ne supportant que CIMD (pas DCR) non pris en charge.
- Tous les jetons fixes agissent avec le même compte de service.
