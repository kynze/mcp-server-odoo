"""Stateless OAuth provider: every artifact is a Fernet-sealed blob, the server stores nothing.

Users authorize with their Odoo login + API key; the key travels inside the sealed code,
access and refresh tokens. Static tokens map to the service account.
"""

import hmac
import json
import logging
import secrets
import time
from typing import Awaitable, Callable, Optional

from cryptography.fernet import Fernet, InvalidToken
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, Field

logger = logging.getLogger(__name__)

REQ_TTL = 600
CODE_TTL = 300
ACCESS_TTL = 3600
REFRESH_TTL = 2_592_000  # 30 days

VerifyKey = Callable[[str, str], Awaitable[Optional[int]]]


class SealError(Exception):
    """Sealed blob is invalid, expired, tampered, of the wrong type or from another key."""


class Sealer:
    def __init__(self, secret_key: str):
        self._fernet = Fernet(secret_key)

    def seal(self, typ: str, payload: dict) -> str:
        return self._fernet.encrypt(json.dumps({**payload, "typ": typ}).encode()).decode()

    def unseal(self, token: str, typ: str, ttl: int | None) -> dict:
        try:
            data = json.loads(self._fernet.decrypt(token, ttl))
        except (InvalidToken, ValueError):  # ValueError: non-ASCII input
            raise SealError("invalid or expired token") from None
        if data.pop("typ", None) != typ:
            raise SealError("wrong token type")
        return data


class OdooAuthorizationCode(AuthorizationCode):
    odoo_uid: int
    odoo_login: str
    odoo_key: str = Field(repr=False)
    jti: str


class OdooRefreshToken(RefreshToken):
    odoo_uid: int
    odoo_login: str
    odoo_key: str = Field(repr=False)


class OdooAccessToken(AccessToken):
    odoo_uid: int | None
    odoo_key: str | None = Field(repr=False)


class OdooOAuthProvider(
    OAuthAuthorizationServerProvider[OdooAuthorizationCode, OdooRefreshToken, OdooAccessToken]
):
    def __init__(
        self, sealer: Sealer, public_url: str, static_tokens: list[str], verify_key: VerifyKey
    ):
        self._sealer = sealer
        self._public_url = public_url
        self._static_tokens = [t.encode() for t in static_tokens]
        self.verify_key = verify_key
        self._used_codes: dict[str, float] = {}  # jti -> time after which it can be forgotten

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        try:
            data = self._sealer.unseal(client_id, "client", None)
        except SealError:
            return None
        return OAuthClientInformationFull.model_validate({**data, "client_id": client_id})

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # The SDK's /register handler returns this same object, so the client gets the sealed id.
        client_info.client_id = self._sealer.seal(
            "client", client_info.model_dump(mode="json", exclude={"client_id"})
        )

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        req = self._sealer.seal(
            "req",
            {
                "client_id": client.client_id,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "code_challenge": params.code_challenge,
                "state": params.state,
                "scopes": params.scopes or [],
                "resource": params.resource,
            },
        )
        return f"{self._public_url}/oauth/login?req={req}"

    def open_login_request(self, req: str) -> dict:
        return self._sealer.unseal(req, "req", REQ_TTL)

    def issue_code(self, req: dict, uid: int, login: str, key: str) -> str:
        code = {k: v for k, v in req.items() if k != "state"}
        jti = secrets.token_urlsafe(16)
        return self._sealer.seal(
            "code", {**code, "jti": jti, "uid": uid, "login": login, "key": key}
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> OdooAuthorizationCode | None:
        try:
            d = self._sealer.unseal(authorization_code, "code", CODE_TTL)
        except SealError:
            return None
        if d["client_id"] != client.client_id or d["jti"] in self._used_codes:
            return None
        return OdooAuthorizationCode(
            code=authorization_code,
            scopes=d["scopes"],
            expires_at=int(time.time()) + CODE_TTL,
            client_id=d["client_id"],
            code_challenge=d["code_challenge"],
            redirect_uri=AnyUrl(d["redirect_uri"]),
            redirect_uri_provided_explicitly=d["redirect_uri_provided_explicitly"],
            resource=d["resource"],
            subject=str(d["uid"]),
            odoo_uid=d["uid"],
            odoo_login=d["login"],
            odoo_key=d["key"],
            jti=d["jti"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: OdooAuthorizationCode
    ) -> OAuthToken:
        now = time.time()
        self._used_codes = {j: t for j, t in self._used_codes.items() if t > now}
        if authorization_code.jti in self._used_codes:
            raise TokenError(error="invalid_grant", error_description="code already used")
        # +1: Fernet timestamps are whole seconds, keep the jti past any copy's validity
        self._used_codes[authorization_code.jti] = now + CODE_TTL + 1
        return self._issue_tokens(
            authorization_code.client_id,
            authorization_code.scopes,
            authorization_code.odoo_uid,
            authorization_code.odoo_login,
            authorization_code.odoo_key,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> OdooRefreshToken | None:
        try:
            d = self._sealer.unseal(refresh_token, "refresh", REFRESH_TTL)
        except SealError:
            return None
        if d["client_id"] != client.client_id:
            return None
        return OdooRefreshToken(
            token=refresh_token,
            client_id=d["client_id"],
            scopes=d["scopes"],
            subject=str(d["uid"]),
            odoo_uid=d["uid"],
            odoo_login=d["login"],
            odoo_key=d["key"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: OdooRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        try:
            uid = await self.verify_key(refresh_token.odoo_login, refresh_token.odoo_key)
        except Exception as e:  # Odoo unreachable or any failure: the client must log in again
            logger.warning("Refresh refused: Odoo key check failed (%s)", type(e).__name__)
            uid = None
        if uid != refresh_token.odoo_uid:
            raise TokenError(
                error="invalid_grant", error_description="Odoo API key no longer valid"
            )
        return self._issue_tokens(
            refresh_token.client_id,
            scopes,
            refresh_token.odoo_uid,
            refresh_token.odoo_login,
            refresh_token.odoo_key,
        )

    async def load_access_token(self, token: str) -> OdooAccessToken | None:
        raw = token.encode()
        if any(hmac.compare_digest(raw, t) for t in self._static_tokens):
            return OdooAccessToken(
                token=token,
                client_id="static",
                scopes=[],
                subject="service",
                odoo_uid=None,
                odoo_key=None,
            )
        try:
            d = self._sealer.unseal(token, "access", ACCESS_TTL)
        except SealError:
            return None
        return OdooAccessToken(
            token=token,
            client_id=d["client_id"],
            scopes=d["scopes"],
            subject=str(d["uid"]),
            odoo_uid=d["uid"],
            odoo_key=d["key"],
        )

    async def revoke_token(self, token: OdooAccessToken | OdooRefreshToken) -> None:
        pass  # stateless: access is cut by revoking the API key in Odoo

    def _issue_tokens(
        self, client_id: str, scopes: list[str], uid: int, login: str, key: str
    ) -> OAuthToken:
        claims = {"client_id": client_id, "scopes": scopes, "uid": uid, "login": login, "key": key}
        return OAuthToken(
            access_token=self._sealer.seal("access", claims),
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            refresh_token=self._sealer.seal("refresh", claims),
            scope=" ".join(scopes) or None,
        )
