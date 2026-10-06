"""Multi-user OAuth wired into the FastMCP server: real SDK routes, Odoo key check mocked."""

import asyncio
import base64
import hashlib
import logging
import secrets
import time
import xmlrpc.client
from unittest.mock import AsyncMock, Mock, call, patch
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from mcp_server_odoo.config import OdooConfig
from mcp_server_odoo.odoo_connection import OdooConnectionError
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


def test_static_token_accepted_on_mcp(c):
    r = c.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer static-tok"})
    assert r.status_code == 200


def test_health_stays_public(c):
    assert c.get("/health").status_code == 200


async def test_instructions_not_personalized_in_oauth_mode(server):
    server.connection = Mock(is_authenticated=True)
    with patch("mcp_server_odoo.server.build_user_context") as b:
        await server._apply_dynamic_instructions()
    b.assert_not_called()


def odoo(server, *results, auth_method="api_key"):
    server.connection = Mock(
        check_user_key=Mock(side_effect=results), is_authenticated=True, auth_method=auth_method
    )
    return server.connection.check_user_key


async def test_verify_odoo_key_uses_connection(server_unpatched_verify):
    check = odoo(server_unpatched_verify, 7)
    assert await server_unpatched_verify._verify_odoo_key("alice", API_KEY) == 7
    check.assert_called_once_with("alice", API_KEY)  # a success needs no failure reset


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


@pytest.mark.parametrize("auth_method, secret", [("api_key", "svc"), ("password", "svc-pw")])
async def test_failed_check_resets_odoo_login_failures(
    server_unpatched_verify, auth_method, secret
):
    # One successful service login pops Odoo's failure counter for this server's IP.
    server_unpatched_verify.config.password = "svc-pw"
    check = odoo(server_unpatched_verify, None, 2, auth_method=auth_method)
    assert await server_unpatched_verify._verify_odoo_key("alice", f" {API_KEY}\n") is None
    assert check.call_args_list == [call("alice", API_KEY), call("svc-user", secret)]


async def test_failure_reset_skipped_without_service_username(server_unpatched_verify):
    server_unpatched_verify.config.username = None
    check = odoo(server_unpatched_verify, None)
    assert await server_unpatched_verify._verify_odoo_key("alice", API_KEY) is None
    check.assert_called_once()


async def test_failure_reset_never_raises(server_unpatched_verify, caplog):
    odoo(server_unpatched_verify, None, OdooConnectionError(f"down {API_KEY}"))
    with caplog.at_level(logging.DEBUG):
        assert await server_unpatched_verify._verify_odoo_key("alice", API_KEY) is None
    assert "OdooConnectionError" in caplog.text and API_KEY not in caplog.text


async def test_key_checks_are_serialized(server_unpatched_verify):
    # Concurrent bad keys must not stack up Odoo failures before each reset.
    active, peak = 0, 0

    def check(login, key):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        time.sleep(0.05)
        active -= 1
        return 7

    server_unpatched_verify.connection = Mock(check_user_key=check, is_authenticated=True)
    await asyncio.gather(
        *(server_unpatched_verify._verify_odoo_key("alice", API_KEY) for _ in range(3))
    )
    assert peak == 1
