"""Tests for the /oauth/login page."""

from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_server_odoo.oauth import OdooOAuthProvider, Sealer
from mcp_server_odoo.oauth_login import login_endpoint
from mcp_server_odoo.odoo_connection import OdooConnectionError

KEY = Fernet.generate_key().decode()
CB = "https://claude.ai/api/mcp/auth_callback"


async def setup(verify=None, client_name="Claude", redirect_uri=CB):
    p = OdooOAuthProvider(
        Sealer(KEY), "https://mcp.example.com", [], verify or AsyncMock(return_value=7)
    )
    info = OAuthClientInformationFull(client_id="tmp", redirect_uris=[CB], client_name=client_name)
    await p.register_client(info)
    url = await p.authorize(
        info,
        AuthorizationParams(
            state="s",
            scopes=None,
            code_challenge="c" * 43,
            redirect_uri=AnyUrl(redirect_uri),
            redirect_uri_provided_explicitly=True,
        ),
    )
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
    assert (
        r.status_code == 400
        and "Lien expiré, relancez la connexion depuis votre application" in r.text
    )


async def test_post_valid_redirects_with_code_and_state():
    p, info, client, req = await setup()
    r = client.post(
        "/oauth/login",
        data={"req": req, "login": "alice", "api_key": "k"},
        follow_redirects=False,
    )
    assert r.status_code == 302 and r.headers["location"].startswith(CB)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["state"] == ["s"]
    assert (await p.load_authorization_code(info, q["code"][0])).odoo_uid == 7


async def test_post_strips_whitespace():
    verify = AsyncMock(return_value=7)
    _, _, client, req = await setup(verify)
    client.post(
        "/oauth/login",
        data={"req": req, "login": " alice ", "api_key": " k \n"},
        follow_redirects=False,
    )
    verify.assert_awaited_once_with("alice", "k")


async def test_post_wrong_credentials_rerenders_form():
    _, _, client, req = await setup(AsyncMock(return_value=None))
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "bad"})
    assert (
        r.status_code == 200
        and "Identifiant ou clé API incorrect" in r.text
        and 'name="api_key"' in r.text
    )


async def test_post_odoo_unreachable():
    _, _, client, req = await setup(AsyncMock(side_effect=OdooConnectionError("down")))
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "k"})
    assert (
        r.status_code == 502 and "Odoo est injoignable, réessayez dans quelques instants." in r.text
    )


async def test_post_expired_req():
    _, _, client, _ = await setup()
    r = client.post("/oauth/login", data={"req": "garbage", "login": "a", "api_key": "k"})
    assert r.status_code == 400 and "Lien expiré" in r.text


SECURITY_HEADERS = {
    "content-security-policy": "frame-ancestors 'none'",
    "cache-control": "no-store",
}


@pytest.mark.parametrize(
    "redirect_uri, shown",
    [
        ("https://claude.ai@evil.example/cb", "evil.example"),
        ("https://a&b@evil.example/cb", "evil.example"),
        ("http://localhost:9999/cb", "localhost:9999"),
    ],
)
async def test_form_shows_real_destination_host(redirect_uri, shown):
    # Open registration: client name and URL userinfo are attacker-chosen, only the host counts.
    _, _, client, req = await setup(redirect_uri=redirect_uri)
    r = client.get("/oauth/login", params={"req": req})
    assert f"Vous serez ensuite renvoyé vers <strong>{shown}</strong>." in r.text


async def test_rerendered_form_shows_destination_host():
    _, _, client, req = await setup(AsyncMock(return_value=None))
    r = client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "bad"})
    assert "Vous serez ensuite renvoyé vers <strong>claude.ai</strong>." in r.text


async def test_every_login_page_forbids_framing_and_caching():
    _, _, client, req = await setup(AsyncMock(return_value=None))
    _, _, down, down_req = await setup(AsyncMock(side_effect=OdooConnectionError("down")))
    for r in (
        client.get("/oauth/login", params={"req": req}),
        client.post("/oauth/login", data={"req": req, "login": "alice", "api_key": "bad"}),
        client.get("/oauth/login", params={"req": "garbage"}),
        down.post("/oauth/login", data={"req": down_req, "login": "alice", "api_key": "k"}),
    ):
        assert {h: r.headers.get(h) for h in SECURITY_HEADERS} == SECURITY_HEADERS
