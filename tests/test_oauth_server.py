"""Multi-user OAuth wired into the FastMCP server: real SDK routes, Odoo key check mocked."""

import asyncio
import base64
import hashlib
import logging
import secrets
import xmlrpc.client
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from mcp_server_odoo.config import OdooConfig
from mcp_server_odoo.oauth import Sealer
from mcp_server_odoo.odoo_connection import OdooConnection, OdooConnectionError
from mcp_server_odoo.server import OdooMCPServer

KEY = Fernet.generate_key().decode()
API_KEY = "0123456789abcdef0123456789abcdef01234567"  # Odoo API keys: 40 lowercase hex
CB = "https://claude.ai/api/mcp/auth_callback"
ACCEPT = {"Accept": "application/json, text/event-stream"}
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


def make_server() -> OdooMCPServer:
    server = OdooMCPServer(
        OdooConfig(
            url="http://localhost:8069",
            username="svc-user",
            api_key="svc",
            transport="streamable-http",
            host="0.0.0.0",
            public_url="https://mcp.example.com",
            secret_key=KEY,
            auth_tokens=["static-tok"],
        )
    )
    server._ensure_connection = Mock()
    server._register_resources = Mock()
    server._register_tools = Mock()
    return server


@pytest.fixture
def server(monkeypatch):
    # Patched on the class before construction: the OAuth provider captures the bound method.
    monkeypatch.setattr(OdooMCPServer, "_verify_odoo_key", AsyncMock(return_value=7))
    return make_server()


@pytest.fixture
def server_unpatched_verify():
    return make_server()


@pytest.fixture
def c(server):
    with TestClient(server.app.streamable_http_app(), base_url="https://mcp.example.com") as c:
        yield c


def oauth_tokens(c: TestClient) -> dict:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    client_id = c.post(
        "/register",
        json={"redirect_uris": [CB], "client_name": "Claude", "token_endpoint_auth_method": "none"},
    ).json()["client_id"]
    r = c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CB,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
        follow_redirects=False,
    )
    login_url = r.headers["location"]
    assert login_url.startswith("https://mcp.example.com/oauth/login?req=")
    req = parse_qs(urlparse(login_url).query)["req"][0]
    assert c.get(login_url).status_code == 200
    r = c.post(
        "/oauth/login",
        data={"req": req, "login": "alice", "api_key": "k"},
        follow_redirects=False,
    )
    assert r.status_code == 302 and r.headers["location"].startswith(CB)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CB,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200, r.text
    return {**r.json(), "_client_id": client_id}


def test_metadata_advertises_endpoints(c):
    md = c.get("/.well-known/oauth-authorization-server").json()
    assert md["authorization_endpoint"] == "https://mcp.example.com/authorize"
    assert md["registration_endpoint"] == "https://mcp.example.com/register"
    resource = c.get("/.well-known/oauth-protected-resource/mcp").json()["resource"]
    assert resource == "https://mcp.example.com/mcp"


def test_registration_returns_sealed_client_id(c):
    r = c.post(
        "/register",
        json={"redirect_uris": [CB], "client_name": "Claude", "token_endpoint_auth_method": "none"},
    )
    assert r.status_code == 201 and len(r.json()["client_id"]) > 100


def test_full_oauth_flow_reaches_mcp(c):
    tok = oauth_tokens(c)
    r = c.post(
        "/mcp", json=INIT, headers={**ACCEPT, "Authorization": f"Bearer {tok['access_token']}"}
    )
    assert r.status_code == 200


def test_refresh_flow(c):
    tok = oauth_tokens(c)
    r = c.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": tok["_client_id"],
        },
    )
    assert r.status_code == 200 and r.json()["access_token"] != tok["access_token"]


def test_mcp_without_token_is_401_with_resource_metadata(c):
    r = c.post("/mcp", json=INIT, headers=ACCEPT)
    assert r.status_code == 401
    assert (
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        in r.headers["www-authenticate"]
    )


def test_mcp_token_sealed_under_other_key_is_401(c):
    claims = {"client_id": "x", "scopes": [], "uid": 7, "login": "alice", "key": API_KEY}
    token = Sealer(Fernet.generate_key().decode()).seal("access", claims)
    r = c.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_static_token_accepted_on_mcp(c):
    r = c.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer static-tok"})
    assert r.status_code == 200


def test_health_stays_public(c):
    assert c.get("/health").status_code == 200


def call_tool(c: TestClient, token: str, name: str) -> None:
    h = {**ACCEPT, "Authorization": f"Bearer {token}"}
    h["mcp-session-id"] = c.post("/mcp", json=INIT, headers=h).headers["mcp-session-id"]
    c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=h)
    r = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name}},
        headers=h,
    )
    assert r.status_code == 200 and '"isError":false' in r.text, r.text


def test_tool_calls_run_as_the_token_identity(server, c):
    # Guards the SDK internals caller_identity() relies on (request_ctx, scope["user"]):
    # an OAuth token runs as its Odoo user, a static token as the service account.
    conn = OdooConnection(server.config)
    conn._connected = conn._authenticated = True
    conn._uid, conn._database, conn._auth_method = 2, "db", "api_key"
    conn._object_proxy = MagicMock()
    conn._object_proxy.execute_kw.return_value = []
    server.connection = conn

    @server.app.tool()
    async def probe() -> list:
        return await asyncio.to_thread(conn.execute_kw, "res.users", "search", [[]], {})

    for token, expected in (
        (oauth_tokens(c)["access_token"], ("db", 7, "k")),
        ("static-tok", ("db", 2, "svc")),
    ):
        call_tool(c, token, "probe")
        assert conn._object_proxy.execute_kw.call_args[0][:3] == expected


async def test_instructions_not_personalized_in_oauth_mode(server):
    server.connection = Mock(is_authenticated=True)
    with patch("mcp_server_odoo.server.build_user_context") as b:
        await server._apply_dynamic_instructions()
    b.assert_not_called()


def odoo(server, *results):
    server.connection = Mock(check_user_key=Mock(side_effect=results), is_authenticated=True)
    return server.connection.check_user_key


async def test_verify_odoo_key_uses_connection(server_unpatched_verify):
    check = odoo(server_unpatched_verify, 7)
    assert await server_unpatched_verify._verify_odoo_key("alice", API_KEY) == 7
    check.assert_called_once_with("alice", API_KEY)


async def test_verify_odoo_key_wraps_unexpected_errors(server_unpatched_verify, caplog):
    # Anything but OdooConnectionError would make the login page answer 500 instead of 502.
    odoo(server_unpatched_verify, xmlrpc.client.Fault(1, "boom"))
    with caplog.at_level(logging.DEBUG), pytest.raises(OdooConnectionError):
        await server_unpatched_verify._verify_odoo_key("alice", API_KEY)
    assert API_KEY not in caplog.text


@pytest.mark.parametrize(
    "key", ["my-password", "k", API_KEY.upper(), API_KEY[:-1], API_KEY + "0", "g" * 40]
)
async def test_verify_odoo_key_rejects_non_api_key_without_calling_odoo(
    server_unpatched_verify, key
):
    # Never feeds Odoo's per-IP login cooldown, and a password never gets sealed into tokens.
    check = odoo(server_unpatched_verify, 7)
    assert await server_unpatched_verify._verify_odoo_key("alice", key) is None
    check.assert_not_called()
