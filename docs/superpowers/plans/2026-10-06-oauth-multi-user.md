# OAuth multi-utilisateur — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chaque client du serveur MCP agit dans Odoo avec son propre compte : OAuth (identifiant + clé API Odoo) pour les humains, jeton fixe → compte de service pour Hermes.

**Architecture:** On branche le serveur OAuth du SDK `mcp` (`auth_server_provider` de FastMCP) sur un fournisseur sans état : tous les blobs (client, requête de login, code, tokens) sont chiffrés Fernet. Une page `/oauth/login` vérifie la clé API auprès d'Odoo. `caller_identity()` lit l'identité du message MCP en cours et `OdooConnection.execute_kw` l'utilise pour chaque appel Odoo (fail-closed si OAuth actif).

**Tech Stack:** Python ≥3.10, `mcp` 1.27 (FastMCP, `mcp.server.auth`), Starlette, `cryptography` (Fernet), XML-RPC Odoo, pytest + pytest-asyncio (`asyncio_mode = "auto"`), Docker pour le bout en bout.

**Spec:** `docs/superpowers/specs/2026-10-06-oauth-multi-user-design.md` (à lire avant chaque tâche).

## Global Constraints

- Dépendances : `mcp>=1.27.0,<2` inchangé ; seule ajout autorisé : déclarer `cryptography>=42` (déjà résolue en 48.0.1 via `pyjwt[crypto]`).
- Durées : `REQ_TTL = 600`, `CODE_TTL = 300`, `ACCESS_TTL = 3600`, `REFRESH_TTL = 2_592_000` (30 jours), blob `client` sans expiration.
- URLs : `issuer_url = ODOO_MCP_PUBLIC_URL` (sans `/` final), `resource_server_url = ODOO_MCP_PUBLIC_URL + "/mcp"`, page de login `ODOO_MCP_PUBLIC_URL + "/oauth/login"`.
- Textes de la page (français, exacts) : titre `Connexion Odoo` ; erreurs `Identifiant ou clé API incorrect`, `Lien expiré, relancez la connexion depuis votre application`, `Odoo est injoignable, réessayez dans quelques instants.`
- Jamais de token, clé API ou blob scellé dans les logs.
- OAuth désactivé (variables absentes) ⇒ comportement strictement identique à `main`.
- Qualité CI : `uv run ruff format --check .`, `uv run ruff check .`, `uv run ty check .` propres ; ligne max 100.
- Tests unitaires : `uv run pytest -m "not yolo and not mcp" -q -p no:cacheprovider` → seul échec toléré : `tests/test_error_handling.py::TestLoggingConfiguration::test_setup_logging` (verrou de fichier Windows, préexistant).
- Commits : chaque implémenteur ne commite **que les fichiers de sa tâche** (`git add <fichiers>` puis `git commit`), message terminé par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Si `index.lock` existe, attendre et réessayer. Ne jamais pousser.

## Review Focus

1. Deux utilisateurs dont les appels outils s'exécutent en même temps (threads) : chacun doit utiliser sa propre clé → test `test_concurrent_callers_use_own_identity` (Tâche 3).
2. `ODOO_MCP_PUBLIC_URL` saisie avec un `/` final : aucune URL en `//mcp` → test `test_public_url_trailing_slash_normalized` (Tâche 1).
3. Identifiant ou clé collés avec des espaces / retour à la ligne : acceptés après nettoyage → test `test_post_strips_whitespace` (Tâche 4).
4. Token émis avant un changement de `ODOO_MCP_SECRET_KEY` : 401 propre, pas d'erreur 500 → test `test_load_access_token_from_other_key_returns_none` (Tâche 2).
5. Odoo injoignable pendant un renouvellement : `invalid_grant` (reconnexion), pas d'erreur 500 → test `test_refresh_odoo_unreachable_is_invalid_grant` (Tâche 2).

## Exécution en parallèle

Fichiers disjoints par vague → les implémenteurs d'une même vague tournent en parallèle ; chaque tâche terminée part en relecture (sous-agent relecteur : conformité spec + qualité + sécurité) **pendant** que la vague suivante se développe.

| Vague | Implémentation (parallèle) | Relecture (parallèle) |
| --- | --- | --- |
| 1 | Tâche 1, Tâche 2 | — |
| 2 | Tâche 3 (après 1), Tâche 4 (après 2) | Tâches 1, 2 |
| 3 | Tâche 5 (après 1–4) | Tâches 3, 4 |
| 4 | Tâche 6 (après 5) | Tâche 5 |
| fin | — | Relecture globale de la branche + Tâche 6 |

Un relecteur qui trouve un problème le renvoie à un sous-agent de correction (même tâche, mêmes fichiers) ; la tâche n'est validée qu'après re-relecture.

---

### Tâche 1 : configuration OAuth + retrait du contrôle Bearer provisoire

**Files:**
- Modify: `mcp_server_odoo/config.py` (dataclass `OdooConfig`, `__post_init__`, `load_config`)
- Modify: `mcp_server_odoo/server.py` (retirer `BearerAuthMiddleware`, `_serve_http_with_bearer_auth`, imports `hmac`/`JSONResponse` devenus inutiles ; `run_http` rappelle `self.app.run_streamable_http_async()` ; `_warn_if_exposed`)
- Modify: `mcp_server_odoo/__main__.py` (aide `--help`), `.env.example`, `pyproject.toml` (+ `uv lock`)
- Test: `tests/test_config.py` (nouvelle classe `TestOAuthConfig`), `tests/test_server_foundation.py` (retirer `TestBearerAuth`, adapter le test d'avertissement)

**Interfaces:**
- Produces : `OdooConfig.public_url: Optional[str] = None`, `OdooConfig.secret_key: Optional[str] = None`, `OdooConfig.auth_tokens: list[str]` (existant), propriété `OdooConfig.oauth_enabled -> bool` ; variables `ODOO_MCP_PUBLIC_URL`, `ODOO_MCP_SECRET_KEY`, `ODOO_MCP_AUTH_TOKENS`.

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_config.py`)

```python
from cryptography.fernet import Fernet

KEY = Fernet.generate_key().decode()
BASE = {"url": "http://localhost:8069", "api_key": "k"}
OAUTH = {**BASE, "transport": "streamable-http", "public_url": "https://mcp.example.com", "secret_key": KEY}

class TestOAuthConfig:
    def test_oauth_disabled_by_default(self):
        assert OdooConfig(**BASE).oauth_enabled is False

    def test_oauth_enabled_with_url_and_key(self):
        assert OdooConfig(**OAUTH).oauth_enabled is True

    @pytest.mark.parametrize("drop", ["public_url", "secret_key"])
    def test_url_and_key_go_together(self, drop):
        with pytest.raises(ValueError, match="ODOO_MCP_PUBLIC_URL and ODOO_MCP_SECRET_KEY"):
            OdooConfig(**{k: v for k, v in OAUTH.items() if k != drop})

    def test_invalid_secret_key_rejected(self):
        with pytest.raises(ValueError, match="ODOO_MCP_SECRET_KEY"):
            OdooConfig(**{**OAUTH, "secret_key": "nope"})

    def test_oauth_requires_http_transport(self):
        with pytest.raises(ValueError, match="streamable-http"):
            OdooConfig(**{**OAUTH, "transport": "stdio"})

    def test_auth_tokens_require_oauth(self):
        with pytest.raises(ValueError, match="ODOO_MCP_AUTH_TOKENS"):
            OdooConfig(**BASE, auth_tokens=["t"])

    def test_public_url_trailing_slash_normalized(self):
        assert OdooConfig(**{**OAUTH, "public_url": "https://mcp.example.com/"}).public_url == "https://mcp.example.com"

    def test_public_url_must_be_https_except_localhost(self):
        with pytest.raises(ValueError, match="https"):
            OdooConfig(**{**OAUTH, "public_url": "http://mcp.example.com"})
        assert OdooConfig(**{**OAUTH, "public_url": "http://localhost:8000"}).oauth_enabled

    def test_load_config_reads_oauth_env(self):
        env = {"ODOO_URL": "http://localhost:8069", "ODOO_API_KEY": "k",
               "ODOO_MCP_TRANSPORT": "streamable-http", "ODOO_MCP_PUBLIC_URL": "https://mcp.example.com/",
               "ODOO_MCP_SECRET_KEY": KEY, "ODOO_MCP_AUTH_TOKENS": " a , b ,"}
        with patch.dict(os.environ, env, clear=True):
            cfg = load_config()
        assert (cfg.public_url, cfg.secret_key, cfg.auth_tokens) == ("https://mcp.example.com", KEY, ["a", "b"])
```

Dans `tests/test_server_foundation.py` : supprimer la classe `TestBearerAuth` et l'import `BearerAuthMiddleware`/`load_config` ajoutés ; renommer `test_no_warning_when_auth_tokens_set` en `test_no_warning_when_oauth_enabled` avec `self._make_server(transport="streamable-http", public_url="https://mcp.example.com", secret_key=KEY)` → `mock_warning.assert_not_called()`.

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest tests/test_config.py::TestOAuthConfig -q -p no:cacheprovider`
Expected: FAIL (`unexpected keyword argument 'public_url'`).

- [ ] **Step 3: Implémenter dans `config.py`**

Champs `public_url`, `secret_key` ; `oauth_enabled` = `bool(self.public_url and self.secret_key)`. Dans `__post_init__` : `public_url.rstrip("/")` ; erreurs exactes contenant `"ODOO_MCP_PUBLIC_URL and ODOO_MCP_SECRET_KEY must be set together"`, `"ODOO_MCP_SECRET_KEY must be a valid Fernet key"` (tester avec `Fernet(key)`), `"OAuth requires ODOO_MCP_TRANSPORT=streamable-http"`, `"ODOO_MCP_AUTH_TOKENS requires OAuth (ODOO_MCP_PUBLIC_URL and ODOO_MCP_SECRET_KEY)"`, `"ODOO_MCP_PUBLIC_URL must use https (http allowed only for localhost/127.0.0.1)"`. `load_config` lit les deux variables (`strip()`, vide → `None`). `pyproject.toml` : ajouter `"cryptography>=42"` aux dépendances puis `uv lock`.

- [ ] **Step 4: Retirer le contrôle Bearer provisoire de `server.py`**

`run_http` appelle de nouveau `await self.app.run_streamable_http_async()` sans condition ; supprimer `BearerAuthMiddleware`, `_serve_http_with_bearer_auth` et les imports devenus inutiles ; `_warn_if_exposed` : `if host in (...) or self.config.oauth_enabled: return`.

- [ ] **Step 5: Docs**

`.env.example` et aide `__main__.py` : `ODOO_MCP_PUBLIC_URL` (URL publique, active OAuth avec la clé), `ODOO_MCP_SECRET_KEY` (clé Fernet, `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`), `ODOO_MCP_AUTH_TOKENS` (jetons fixes → compte de service, nécessite OAuth). `README.md` : annuler les modifications provisoires sur `ODOO_MCP_AUTH_TOKENS` (`git checkout main -- README.md`) — la doc multi-utilisateur arrive en Tâche 5.

- [ ] **Step 6: Vérifier**

Run: `uv run pytest -m "not yolo and not mcp" -q -p no:cacheprovider` → seul échec `test_setup_logging`. Puis `uv run ruff format --check . && uv run ruff check . && uv run ty check .` → propres.

- [ ] **Step 7: Commit**

```bash
git add mcp_server_odoo/config.py mcp_server_odoo/server.py mcp_server_odoo/__main__.py .env.example pyproject.toml uv.lock README.md tests/test_config.py tests/test_server_foundation.py
git commit -m "feat(config): OAuth settings (public URL, secret key, static tokens)"
```

---

### Tâche 2 : chiffrement des blobs + fournisseur OAuth sans état

**Files:**
- Create: `mcp_server_odoo/oauth.py`
- Test: `tests/test_oauth.py`

**Interfaces:**
- Consumes : rien des autres tâches (paramètres explicites, pas d'`OdooConfig`).
- Produces :
  - `class SealError(Exception)`
  - `class Sealer: __init__(self, secret_key: str)`, `seal(self, typ: str, payload: dict) -> str`, `unseal(self, token: str, typ: str, ttl: int | None, now: int | None = None) -> dict` (`now` → `Fernet.decrypt_at_time`, pour les tests).
  - Constantes `REQ_TTL`, `CODE_TTL`, `ACCESS_TTL`, `REFRESH_TTL` (valeurs : Global Constraints).
  - `OdooAuthorizationCode(AuthorizationCode)`, `OdooRefreshToken(RefreshToken)` : + `odoo_uid: int`, `odoo_login: str`, `odoo_key: str`. `OdooAccessToken(AccessToken)` : + `odoo_uid: int | None`, `odoo_login: str | None`, `odoo_key: str | None` ; `subject = str(uid)` ou `"service"`.
  - `VerifyKey = Callable[[str, str], Awaitable[Optional[int]]]` (login, clé → uid ou `None` ; peut lever).
  - `class OdooOAuthProvider: __init__(self, sealer: Sealer, public_url: str, static_tokens: list[str], verify_key: VerifyKey)` + méthodes du protocole SDK (`get_client`, `register_client`, `authorize`, `load_authorization_code`, `exchange_authorization_code`, `load_refresh_token`, `exchange_refresh_token`, `load_access_token`, `revoke_token` no-op) + `open_login_request(self, req: str) -> dict` (lève `SealError`) + `issue_code(self, req: dict, uid: int, login: str, key: str) -> str` + attribut public `verify_key`.

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_oauth.py`)

```python
KEY = Fernet.generate_key().decode()
CB = "https://claude.ai/api/mcp/auth_callback"

def provider(verify=None, key=KEY):
    return OdooOAuthProvider(Sealer(key), "https://mcp.example.com", ["static-tok"], verify or AsyncMock(return_value=7))

async def registered(p, name="Claude"):
    info = OAuthClientInformationFull(client_id="tmp", redirect_uris=[CB], client_name=name)
    await p.register_client(info)
    return info

async def login_req(p, client):
    params = AuthorizationParams(state="s", scopes=None, code_challenge="c" * 43,
                                 redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True)
    url = await p.authorize(client, params)
    return p.open_login_request(url.split("req=", 1)[1])

def test_seal_roundtrip_and_type_check():
    s = Sealer(KEY); t = s.seal("access", {"a": 1})
    assert s.unseal(t, "access", ttl=60)["a"] == 1
    with pytest.raises(SealError): s.unseal(t, "refresh", ttl=60)

def test_unseal_rejects_expired_tampered_and_wrong_key():
    s = Sealer(KEY); t = s.seal("code", {})
    for bad in (lambda: s.unseal(t, "code", ttl=300, now=int(time.time()) + 301),
                lambda: s.unseal(t[:-4] + "AAAA", "code", ttl=300),
                lambda: Sealer(Fernet.generate_key().decode()).unseal(t, "code", ttl=300)):
        with pytest.raises(SealError): bad()

async def test_register_client_seals_client_id():
    p = provider(); info = await registered(p)
    assert info.client_id != "tmp"
    client = await p.get_client(info.client_id)
    assert client.client_name == "Claude" and str(client.redirect_uris[0]) == CB

async def test_get_client_garbage_returns_none():
    assert await provider().get_client("garbage") is None

async def test_authorize_points_to_login_page():
    p = provider(); client = await registered(p)
    params = AuthorizationParams(state="s", scopes=None, code_challenge="c" * 43,
                                 redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True)
    url = await p.authorize(client, params)
    assert url.startswith("https://mcp.example.com/oauth/login?req=")
    req = p.open_login_request(url.split("req=", 1)[1])
    assert (req["state"], req["client_id"]) == ("s", client.client_id)

async def test_code_exchange_and_single_use():
    p = provider(); client = await registered(p); req = await login_req(p, client)
    code = p.issue_code(req, uid=7, login="alice", key="k-alice")
    ac = await p.load_authorization_code(client, code)
    assert (ac.odoo_uid, ac.odoo_login) == (7, "alice")
    tok = await p.exchange_authorization_code(client, ac)
    at = await p.load_access_token(tok.access_token)
    assert (at.odoo_uid, at.odoo_key, at.subject) == (7, "k-alice", "7")
    assert await p.load_authorization_code(client, code) is None

async def test_code_for_other_client_rejected():
    p = provider(); a = await registered(p, "A"); b = await registered(p, "B")
    code = p.issue_code(await login_req(p, a), uid=7, login="alice", key="k")
    assert await p.load_authorization_code(b, code) is None

async def test_token_types_not_interchangeable():
    p = provider(); client = await registered(p)
    ac = await p.load_authorization_code(client, p.issue_code(await login_req(p, client), uid=7, login="alice", key="k"))
    tok = await p.exchange_authorization_code(client, ac)
    assert await p.load_refresh_token(client, tok.access_token) is None
    assert await p.load_access_token(tok.refresh_token) is None

async def test_static_token_maps_to_service():
    at = await provider().load_access_token("static-tok")
    assert (at.odoo_uid, at.odoo_key, at.subject) == (None, None, "service")

async def test_unknown_token_returns_none():
    assert await provider().load_access_token("nope") is None

async def test_load_access_token_from_other_key_returns_none():
    old = provider(key=Fernet.generate_key().decode()); client = await registered(old)
    ac = await old.load_authorization_code(client, old.issue_code(await login_req(old, client), uid=7, login="a", key="k"))
    tok = await old.exchange_authorization_code(client, ac)
    assert await provider().load_access_token(tok.access_token) is None

@pytest.mark.parametrize("verify_result, ok", [(7, True), (None, False), (8, False)])
async def test_refresh_rechecks_key_with_odoo(verify_result, ok):
    verify = AsyncMock(return_value=verify_result); p = provider(verify); client = await registered(p)
    ac = await p.load_authorization_code(client, p.issue_code(await login_req(p, client), uid=7, login="alice", key="k"))
    rt = await p.load_refresh_token(client, (await p.exchange_authorization_code(client, ac)).refresh_token)
    if ok:
        new = await p.exchange_refresh_token(client, rt, [])
        assert (await p.load_access_token(new.access_token)).odoo_uid == 7
    else:
        with pytest.raises(TokenError) as e: await p.exchange_refresh_token(client, rt, [])
        assert e.value.error == "invalid_grant"
    verify.assert_awaited_with("alice", "k")

async def test_refresh_odoo_unreachable_is_invalid_grant():
    p = provider(AsyncMock(side_effect=OSError("down"))); client = await registered(p)
    ac = await p.load_authorization_code(client, p.issue_code(await login_req(p, client), uid=7, login="a", key="k"))
    rt = await p.load_refresh_token(client, (await p.exchange_authorization_code(client, ac)).refresh_token)
    with pytest.raises(TokenError) as e: await p.exchange_refresh_token(client, rt, [])
    assert e.value.error == "invalid_grant"
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest tests/test_oauth.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: mcp_server_odoo.oauth`).

- [ ] **Step 3: Implémenter `mcp_server_odoo/oauth.py`**

Contenu de chaque blob et règles : tableau « `typ` » de la spec. Points non déterminés par les tests :
- `register_client` **mute** `client_info.client_id` (le handler DCR du SDK renvoie ce même objet — la Tâche 5 le vérifie via la vraie route) ; payload = `client_info.model_dump(mode="json", exclude={"client_id"})`.
- Codes à usage unique : `self._used_codes: dict[str, float]` (`jti` → expiration), purgé des entrées expirées à chaque consommation.
- `exchange_*` renvoient `OAuthToken(access_token=…, token_type="Bearer", expires_in=ACCESS_TTL, refresh_token=…, scope=" ".join(scopes) or None)` ; `expires_at` des modèles = `int(time.time()) + TTL`.
- `exchange_refresh_token` : `uid = await self.verify_key(login, key)` dans un `try` ; exception, `None` ou uid différent → `TokenError(error="invalid_grant", error_description=…)`.
- `load_access_token` : jetons fixes comparés avec `hmac.compare_digest` sur chaque jeton.
- Aucun `logger` ne reçoit de token, clé ou blob.

- [ ] **Step 4: Vérifier**

Run: `uv run pytest tests/test_oauth.py -q -p no:cacheprovider` → PASS ; puis ruff + ty propres.

- [ ] **Step 5: Commit**

```bash
git add mcp_server_odoo/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): stateless Fernet-sealed OAuth provider"
```

---

### Tâche 3 : identité de l'appelant dans la connexion Odoo

**Files:**
- Create: `mcp_server_odoo/identity.py`
- Modify: `mcp_server_odoo/odoo_connection.py` (`execute_kw` l. ~968-1000, propriété `uid` l. ~931, `fields_get` l. ~1148-1185, nouvelle méthode `check_user_key`)
- Modify: `mcp_server_odoo/performance.py` (`get_cached_fields`, `cache_fields` l. ~495-516)
- Test: `tests/test_identity.py`

**Interfaces:**
- Consumes : `OdooConfig.oauth_enabled` (Tâche 1) ; attributs `access_token.odoo_uid` / `access_token.odoo_key` posés par la Tâche 2 (lus par duck typing, pas d'import de `oauth.py`).
- Produces :
  - `identity.py` : `@dataclass(frozen=True) class OdooIdentity: uid: int; key: str` ; sentinelles `SERVICE`, `MISSING` ; `caller_identity() -> OdooIdentity | object | None` (`None` hors requête MCP).
  - `OdooConnection.check_user_key(self, login: str, key: str) -> Optional[int]` : `authenticate(database, login, key, {})` via un **nouveau** `xmlrpc.client.ServerProxy` vers l'endpoint `common` (`config.get_endpoint_paths()["common"]`, timeout de la connexion) ; uid faux → `None` ; erreur réseau → `OdooConnectionError`.
  - `PerformanceManager.get_cached_fields(model: str, uid: Optional[int])`, `cache_fields(model: str, fields: dict, uid: Optional[int])` (uid dans la clé).

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_identity.py`)

```python
from mcp.server.lowlevel.server import request_ctx

def ctx(user=None, request=True):
    scope = {"user": user} if user is not None else {}
    return SimpleNamespace(request=SimpleNamespace(scope=scope) if request else None)

def user(uid, key):
    return SimpleNamespace(access_token=SimpleNamespace(odoo_uid=uid, odoo_key=key))

@contextmanager
def as_caller(c):
    t = request_ctx.set(c)
    try: yield
    finally: request_ctx.reset(t)

def connected(config):  # même recette que tests/test_locale.py::_make_connected
    conn = OdooConnection(config); conn._connected = conn._authenticated = True
    conn._uid, conn._database, conn._auth_method = 2, "db", "api_key"
    conn._object_proxy = MagicMock(); conn._object_proxy.execute_kw.return_value = []
    return conn

SVC = OdooConfig(url="http://localhost:8069", api_key="svc")
OAUTH = OdooConfig(url="http://localhost:8069", api_key="svc", transport="streamable-http",
                   public_url="https://mcp.example.com", secret_key=Fernet.generate_key().decode())

def test_caller_identity_cases():
    assert caller_identity() is None
    with as_caller(ctx(request=False)): assert caller_identity() is MISSING
    with as_caller(ctx()): assert caller_identity() is MISSING
    with as_caller(ctx(user(None, None))): assert caller_identity() is SERVICE
    with as_caller(ctx(user(7, "k"))): assert caller_identity() == OdooIdentity(7, "k")

def creds(conn): return conn._object_proxy.execute_kw.call_args[0][:3]

def test_execute_kw_uses_caller_identity():
    conn = connected(OAUTH)
    with as_caller(ctx(user(7, "k-alice"))): conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 7, "k-alice")

def test_execute_kw_service_outside_request_and_for_static_token():
    conn = connected(OAUTH); conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")
    with as_caller(ctx(user(None, None))): conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")

def test_execute_kw_fails_closed_when_identity_missing():
    conn = connected(OAUTH)
    with as_caller(ctx()), pytest.raises(OdooConnectionError):
        conn.execute_kw("res.partner", "search", [[]], {})
    conn._object_proxy.execute_kw.assert_not_called()

def test_execute_kw_missing_identity_without_oauth_uses_service():
    conn = connected(SVC)
    with as_caller(ctx()): conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")

def test_uid_property_returns_caller_uid():
    conn = connected(OAUTH)
    assert conn.uid == 2
    with as_caller(ctx(user(7, "k"))): assert conn.uid == 7

def test_fields_cache_is_per_user():
    conn = connected(OAUTH); conn._object_proxy.execute_kw.return_value = {"name": {}}
    with as_caller(ctx(user(7, "k7"))): conn.fields_get("res.partner")
    with as_caller(ctx(user(8, "k8"))): conn.fields_get("res.partner")
    assert conn._object_proxy.execute_kw.call_count == 2

async def test_concurrent_callers_use_own_identity():
    conn = connected(OAUTH)
    conn._object_proxy.execute_kw.side_effect = lambda db, uid, key, *a: [uid, key]
    async def call(uid, key):
        with as_caller(ctx(user(uid, key))):
            await asyncio.sleep(0)
            return await asyncio.to_thread(conn.execute_kw, "res.partner", "search", [[]], {})
    results = await asyncio.gather(*(call(u, f"k{u}") for u in (7, 8, 7, 8)))
    assert results == [[7, "k7"], [8, "k8"], [7, "k7"], [8, "k8"]]

@pytest.mark.parametrize("auth_result, expected", [(7, 7), (False, None)])
def test_check_user_key(auth_result, expected):
    conn = connected(OAUTH)
    with patch("xmlrpc.client.ServerProxy") as sp:
        sp.return_value.authenticate.return_value = auth_result
        assert conn.check_user_key("alice", "k") == expected
    sp.return_value.authenticate.assert_called_once_with("db", "alice", "k", {})

def test_check_user_key_network_error():
    conn = connected(OAUTH)
    with patch("xmlrpc.client.ServerProxy") as sp, pytest.raises(OdooConnectionError):
        sp.return_value.authenticate.side_effect = OSError("down")
        conn.check_user_key("alice", "k")
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest tests/test_identity.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: mcp_server_odoo.identity`).

- [ ] **Step 3: Implémenter `identity.py`**

`caller_identity` lit `mcp.server.lowlevel.server.request_ctx` (pas `auth_context_var`, voir spec) :

```python
try:
    rc = request_ctx.get()
except LookupError:
    return None
scope = getattr(rc.request, "scope", None) or {}
token = getattr(scope.get("user"), "access_token", None)
if token is None or not hasattr(token, "odoo_uid"):
    return MISSING
return SERVICE if token.odoo_uid is None else OdooIdentity(token.odoo_uid, token.odoo_key)
```

- [ ] **Step 4: Implémenter dans `odoo_connection.py` / `performance.py`**

- Méthode privée `_credentials(self) -> tuple[int, str]` : `OdooIdentity` → `(ident.uid, ident.key)` ; `MISSING` et `self.config.oauth_enabled` → `OdooConnectionError("Unauthenticated MCP request: no Odoo identity")` ; sinon `(self._uid, <secret de service actuel>)`. `execute_kw` l'appelle **avant** tout appel proxy (après les contrôles `_authenticated` / `_connected`).
- Propriété `uid` : uid de `caller_identity()` si `OdooIdentity`, sinon `self._uid`.
- `fields_get` passe `uid=self.uid` au cache ; `performance.py` ajoute `uid=uid` à `cache_key("fields", …)`.
- `check_user_key` : interface ci-dessus.

- [ ] **Step 5: Vérifier**

Run: `uv run pytest tests/test_identity.py tests/test_locale.py tests/test_odoo_connection_basic.py tests/test_performance.py -q -p no:cacheprovider` → PASS ; puis suite unitaire complète, ruff, ty.

- [ ] **Step 6: Commit**

```bash
git add mcp_server_odoo/identity.py mcp_server_odoo/odoo_connection.py mcp_server_odoo/performance.py tests/test_identity.py
git commit -m "feat(identity): run each Odoo call as the calling user"
```

---

### Tâche 4 : page de connexion `/oauth/login`

**Files:**
- Create: `mcp_server_odoo/oauth_login.py`
- Test: `tests/test_oauth_login.py`

**Interfaces:**
- Consumes (Tâche 2) : `OdooOAuthProvider.open_login_request(req) -> dict` (lève `SealError`), `.get_client(client_id)`, `.verify_key(login, key)`, `.issue_code(req, uid, login, key) -> str` ; `construct_redirect_uri` de `mcp.server.auth.provider` ; `OdooConnectionError` (`odoo_connection.py`).
- Produces : `login_endpoint(provider: OdooOAuthProvider) -> Callable[[Request], Awaitable[Response]]` gérant `GET` et `POST` (la Tâche 5 l'enregistre sur `/oauth/login`).

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_oauth_login.py`)

```python
KEY = Fernet.generate_key().decode()
CB = "https://claude.ai/api/mcp/auth_callback"

async def setup(verify=None, client_name="Claude"):
    p = OdooOAuthProvider(Sealer(KEY), "https://mcp.example.com", [], verify or AsyncMock(return_value=7))
    info = OAuthClientInformationFull(client_id="tmp", redirect_uris=[CB], client_name=client_name)
    await p.register_client(info)
    url = await p.authorize(info, AuthorizationParams(state="s", scopes=None, code_challenge="c" * 43,
                            redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True))
    app = Starlette(routes=[Route("/oauth/login", login_endpoint(p), methods=["GET", "POST"])])
    return p, info, TestClient(app), url.split("req=", 1)[1]

async def test_get_shows_form_with_escaped_client_name():
    _, _, client, req = await setup(client_name="<script>x</script>")
    r = client.get("/oauth/login", params={"req": req})
    assert r.status_code == 200 and "Connexion Odoo" in r.text and 'name="api_key"' in r.text
    assert "&lt;script&gt;" in r.text and "<script>x" not in r.text

async def test_get_expired_or_invalid_req():
    _, _, client, _ = await setup()
    r = client.get("/oauth/login", params={"req": "garbage"})
    assert r.status_code == 400 and "Lien expiré, relancez la connexion depuis votre application" in r.text

async def test_post_valid_redirects_with_code_and_state():
    p, info, client, req = await setup()
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "k"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith(CB)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["state"] == ["s"]
    assert (await p.load_authorization_code(info, q["code"][0])).odoo_uid == 7

async def test_post_strips_whitespace():
    verify = AsyncMock(return_value=7); _, _, client, req = await setup(verify)
    client.post("/oauth/login", data={"req": req, "login": " alice ", "api_key": " k \n"}, follow_redirects=False)
    verify.assert_awaited_once_with("alice", "k")

async def test_post_wrong_credentials_rerenders_form():
    _, _, client, req = await setup(AsyncMock(return_value=None))
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "bad"})
    assert r.status_code == 200 and "Identifiant ou clé API incorrect" in r.text and 'name="api_key"' in r.text

async def test_post_odoo_unreachable():
    _, _, client, req = await setup(AsyncMock(side_effect=OdooConnectionError("down")))
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "k"})
    assert r.status_code == 502 and "Odoo est injoignable, réessayez dans quelques instants." in r.text

async def test_post_expired_req():
    _, _, client, _ = await setup()
    r = client.post("/oauth/login", data={"req": "garbage", "login": "a", "api_key": "k"})
    assert r.status_code == 400 and "Lien expiré" in r.text
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest tests/test_oauth_login.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: mcp_server_odoo.oauth_login`).

- [ ] **Step 3: Implémenter `oauth_login.py`**

Page HTML minimale autonome (pas de ressource externe) : titre `Connexion Odoo`, nom du client via `html.escape`, champs `login` (texte) et `api_key` (`type="password"`), `req` caché, aide « Créez une clé API dans Odoo : Mon profil > Sécurité du compte > Nouvelle clé API ». Toute valeur réinjectée dans la page passe par `html.escape`. Succès → `RedirectResponse(construct_redirect_uri(req["redirect_uri"], code=…, state=req["state"]), status_code=302)`.

- [ ] **Step 4: Vérifier**

Run: `uv run pytest tests/test_oauth_login.py -q -p no:cacheprovider` → PASS ; ruff + ty propres.

- [ ] **Step 5: Commit**

```bash
git add mcp_server_odoo/oauth_login.py tests/test_oauth_login.py
git commit -m "feat(oauth): Odoo API-key login page"
```

---

### Tâche 5 : branchement dans le serveur + documentation

**Files:**
- Modify: `mcp_server_odoo/server.py` (`__init__` l. ~97-150, `_apply_dynamic_instructions` l. ~339, nouvelle méthode `_verify_odoo_key`)
- Modify: `README.md` (section « Multi-utilisateur (OAuth) » + lignes du tableau des variables)
- Test: `tests/test_oauth_server.py`

**Interfaces:**
- Consumes : Tâche 1 (`config.oauth_enabled`, `public_url`, `secret_key`, `auth_tokens`), Tâche 2 (`Sealer`, `OdooOAuthProvider`), Tâche 3 (`connection.check_user_key`), Tâche 4 (`login_endpoint`).
- Produces : `OdooMCPServer._verify_odoo_key(self, login: str, key: str) -> Optional[int]` (async : `_ensure_connection` sous `_connect_lock`, puis `asyncio.to_thread(self.connection.check_user_key, login, key)`).

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_oauth_server.py`)

Fixture : `OdooConfig(url="http://localhost:8069", api_key="svc", transport="streamable-http", host="0.0.0.0", public_url="https://mcp.example.com", secret_key=KEY, auth_tokens=["static-tok"])` ; `server._verify_odoo_key = AsyncMock(return_value=7)` ; `server._ensure_connection`, `server._register_resources`, `server._register_tools` remplacés par des `Mock()` ; `with TestClient(server.app.streamable_http_app(), base_url="https://mcp.example.com") as c:` (le `with` lance le lifespan). Helper PKCE : `verifier = secrets.token_urlsafe(48)`, `challenge = base64url(sha256(verifier))` sans `=`. Helper `oauth_tokens(c)` : `/register` → `GET /authorize` (`response_type=code`, `client_id`, `redirect_uri=CB`, `code_challenge`, `code_challenge_method=S256`, `state=s`, `follow_redirects=False`) → suivre `Location` (`/oauth/login?req=…`) → `POST /oauth/login` → extraire `code` → `POST /token` (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`) ; renvoie le JSON de `/token` complété de `"_client_id"`. Fixture `server_unpatched_verify` : même config, sans remplacer `_verify_odoo_key`. `INIT` = requête JSON-RPC `initialize` ; en-têtes `Accept: application/json, text/event-stream`.

```python
def test_metadata_advertises_endpoints(c):
    md = c.get("/.well-known/oauth-authorization-server").json()
    assert md["authorization_endpoint"] == "https://mcp.example.com/authorize"
    assert md["registration_endpoint"] == "https://mcp.example.com/register"
    assert c.get("/.well-known/oauth-protected-resource/mcp").json()["resource"] == "https://mcp.example.com/mcp"

def test_registration_returns_sealed_client_id(c):
    r = c.post("/register", json={"redirect_uris": [CB], "client_name": "Claude", "token_endpoint_auth_method": "none"})
    assert r.status_code == 201 and len(r.json()["client_id"]) > 100

def test_full_oauth_flow_reaches_mcp(c):
    tok = oauth_tokens(c)
    r = c.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": f"Bearer {tok['access_token']}"})
    assert r.status_code == 200

def test_refresh_flow(c):
    tok = oauth_tokens(c)
    r = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": tok["_client_id"]})
    assert r.status_code == 200 and r.json()["access_token"] != tok["access_token"]

def test_mcp_without_token_is_401_with_resource_metadata(c):
    r = c.post("/mcp", json=INIT, headers=ACCEPT)
    assert r.status_code == 401
    assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]

def test_static_token_accepted_on_mcp(c):
    assert c.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer static-tok"}).status_code == 200

def test_health_stays_public(c):
    assert c.get("/health").status_code == 200

async def test_instructions_not_personalized_in_oauth_mode(server):
    server.connection = Mock(is_authenticated=True)
    with patch("mcp_server_odoo.server.build_user_context") as b:
        await server._apply_dynamic_instructions()
    b.assert_not_called()

async def test_verify_odoo_key_uses_connection(server_unpatched_verify):
    server_unpatched_verify.connection = Mock(check_user_key=Mock(return_value=7), is_authenticated=True)
    assert await server_unpatched_verify._verify_odoo_key("alice", "k") == 7
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest tests/test_oauth_server.py -q -p no:cacheprovider`
Expected: FAIL (pas de route `/.well-known/oauth-authorization-server`, 404).

- [ ] **Step 3: Implémenter dans `server.py`**

Si `config.oauth_enabled` : créer `OdooOAuthProvider(Sealer(config.secret_key), config.public_url, config.auth_tokens, self._verify_odoo_key)` puis passer à `FastMCP(...)` : `auth_server_provider=provider`, `auth=AuthSettings(issuer_url=config.public_url, resource_server_url=f"{config.public_url}/mcp", client_registration_options=ClientRegistrationOptions(enabled=True))` ; enregistrer `self.app.custom_route("/oauth/login", methods=["GET", "POST"])(login_endpoint(provider))`. `_verify_odoo_key` : interface ci-dessus. `_apply_dynamic_instructions` : en mode OAuth, établir la connexion (pour la page de login) puis `return` sans personnaliser. Sans OAuth : aucun changement.

- [ ] **Step 4: README**

Section « Multi-utilisateur (OAuth) » : parcours claude.ai (ajouter `<PUBLIC_URL>/mcp`, page Connexion Odoo, clé API créée dans *Mon profil > Sécurité du compte*), jetons fixes pour agents, variables (`ODOO_MCP_PUBLIC_URL`, `ODOO_MCP_SECRET_KEY` + commande de génération, `ODOO_MCP_AUTH_TOKENS`), révocation via Odoo, limites (DCR seulement, refresh tokens non révocables un par un). Lignes correspondantes dans le tableau des variables d'environnement.

- [ ] **Step 5: Vérifier**

Run: `uv run pytest -m "not yolo and not mcp" -q -p no:cacheprovider` → seul échec `test_setup_logging` ; ruff + ty propres.

- [ ] **Step 6: Commit**

```bash
git add mcp_server_odoo/server.py README.md tests/test_oauth_server.py
git commit -m "feat(server): enable multi-user OAuth when configured"
```

---

### Tâche 6 : bout en bout Docker contre un vrai Odoo 20

**Files:**
- Create: `tests/docker/oauth_e2e/run.sh`, `tests/docker/oauth_e2e/setup_odoo.py`, `tests/docker/oauth_e2e/client.py`

**Interfaces:**
- Consumes : tout le serveur (Tâches 1-5) ; image construite depuis le `Dockerfile` du dépôt.

- [ ] **Step 1: `setup_odoo.py`** (exécuté via `odoo shell` sur stdin)

Crée l'utilisatrice `alice` (« Alice », groupe `base.group_user` uniquement) ; génère des clés API `rpc` pour `admin` et `alice` via `env(user=u)["res.users.apikeys"]._generate("rpc", "e2e", now + 1 jour)` ; écrit `/var/lib/odoo/key_admin` et `/var/lib/odoo/key_alice` ; affiche `SETUP OK`.

- [ ] **Step 2: `client.py`** (exécuté dans le conteneur du serveur, `python /tmp/client.py`, cible `http://localhost:8000`)

Avec `httpx` et `mcp.client.streamable_http.streamablehttp_client` + `ClientSession`, il vérifie dans l'ordre et affiche une ligne `OK <cas>` par assertion (sortie code 1 à la première erreur) :
1. `POST /mcp` sans token → 401.
2. Flux OAuth complet (register → authorize → `/oauth/login` avec `alice` + sa clé → token PKCE) puis `get_current_context` → texte contient `Alice`.
3. Même flux avec `admin` → `get_current_context` contient `Administrator`.
4. `search_records` sur `ir.config_parameter` : admin → succès ; alice → résultat `isError` (droit Odoo refusé).
5. Refresh du token d'alice → nouveau token accepté par `get_current_context` (`Alice`).
6. Jeton fixe `static-e2e` → `get_current_context` contient `Administrator` (compte de service).
7. Login avec une mauvaise clé → page contenant `Identifiant ou clé API incorrect`.

- [ ] **Step 3: `run.sh`**

Orchestration (`set -euo pipefail`, nettoyage par `trap` en sortie) : réseau + volume Docker ; `postgres:16` ; init `odoo:20.0` (`-d e2e -i base --without-demo=all --stop-after-init`) ; `setup_odoo.py` via `odoo shell` ; Odoo lancé avec `--http-interface=0.0.0.0` ; image du dépôt construite (`docker build -t mcp-oauth-e2e .`) et lancée en `--user 0` avec `ODOO_URL=http://<odoo>:8069`, `ODOO_DB=e2e`, `ODOO_USER=admin`, `ODOO_API_KEY=$(cat key_admin)` (lu dans le conteneur), `ODOO_YOLO=read`, `ODOO_MCP_TRANSPORT=streamable-http`, `ODOO_MCP_HOST=0.0.0.0`, `ODOO_MCP_PORT=8000`, `ODOO_MCP_PUBLIC_URL=http://localhost:8000`, `ODOO_MCP_SECRET_KEY=<générée>`, `ODOO_MCP_AUTH_TOKENS=static-e2e` ; `docker cp` de `client.py` et des clés ; exécution ; affiche `E2E OK` si tout passe.

- [ ] **Step 4: Exécuter**

Run: `bash tests/docker/oauth_e2e/run.sh`
Expected: sept lignes `OK …` puis `E2E OK`, code de sortie 0, aucun conteneur restant (`docker ps -a --filter name=mcp-oauth-e2e` vide).

- [ ] **Step 5: Commit**

```bash
git add tests/docker/oauth_e2e
git commit -m "test(e2e): multi-user OAuth against a real Odoo 20"
```

---

### Fin : relecture globale

Un relecteur reçoit la spec, ce plan et `git diff main...feat/oauth-multi-user` : conformité à chaque section de la spec, Review Focus couvert, sécurité (aucun secret journalisé, fail-closed, échappement HTML), comportement inchangé sans OAuth. Puis : suite unitaire, ruff, ty, `run.sh` une dernière fois. Aucun push : l'utilisateur pousse lui-même.
