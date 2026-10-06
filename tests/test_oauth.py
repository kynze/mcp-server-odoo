"""Tests for the stateless Fernet-sealed OAuth provider."""

import time
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from mcp_server_odoo.oauth import OdooOAuthProvider, Sealer, SealError

KEY = Fernet.generate_key().decode()
CB = "https://claude.ai/api/mcp/auth_callback"


def provider(verify=None, key=KEY):
    return OdooOAuthProvider(
        Sealer(key), "https://mcp.example.com", ["static-tok"], verify or AsyncMock(return_value=7)
    )


async def registered(p, name="Claude"):
    info = OAuthClientInformationFull(client_id="tmp", redirect_uris=[CB], client_name=name)
    await p.register_client(info)
    return info


async def login_req(p, client):
    params = AuthorizationParams(
        state="s",
        scopes=None,
        code_challenge="c" * 43,
        redirect_uri=AnyUrl(CB),
        redirect_uri_provided_explicitly=True,
    )
    url = await p.authorize(client, params)
    return p.open_login_request(url.split("req=", 1)[1])


def test_seal_roundtrip_and_type_check():
    s = Sealer(KEY)
    t = s.seal("access", {"a": 1})
    assert s.unseal(t, "access", ttl=60)["a"] == 1
    with pytest.raises(SealError):
        s.unseal(t, "refresh", ttl=60)


def test_unseal_rejects_expired_tampered_and_wrong_key():
    s = Sealer(KEY)
    t = s.seal("code", {})
    for bad in (
        lambda: s.unseal(t, "code", ttl=300, now=int(time.time()) + 301),
        lambda: s.unseal(t[:-4] + "AAAA", "code", ttl=300),
        lambda: Sealer(Fernet.generate_key().decode()).unseal(t, "code", ttl=300),
    ):
        with pytest.raises(SealError):
            bad()


async def test_register_client_seals_client_id():
    p = provider()
    info = await registered(p)
    assert info.client_id != "tmp"
    client = await p.get_client(info.client_id)
    assert client.client_name == "Claude" and str(client.redirect_uris[0]) == CB


async def test_get_client_garbage_returns_none():
    assert await provider().get_client("garbage") is None


async def test_authorize_points_to_login_page():
    p = provider()
    client = await registered(p)
    params = AuthorizationParams(
        state="s",
        scopes=None,
        code_challenge="c" * 43,
        redirect_uri=AnyUrl(CB),
        redirect_uri_provided_explicitly=True,
    )
    url = await p.authorize(client, params)
    assert url.startswith("https://mcp.example.com/oauth/login?req=")
    req = p.open_login_request(url.split("req=", 1)[1])
    assert (req["state"], req["client_id"]) == ("s", client.client_id)


async def test_code_exchange_and_single_use():
    p = provider()
    client = await registered(p)
    req = await login_req(p, client)
    code = p.issue_code(req, uid=7, login="alice", key="k-alice")
    ac = await p.load_authorization_code(client, code)
    assert (ac.odoo_uid, ac.odoo_login) == (7, "alice")
    tok = await p.exchange_authorization_code(client, ac)
    at = await p.load_access_token(tok.access_token)
    assert (at.odoo_uid, at.odoo_key, at.subject) == (7, "k-alice", "7")
    assert await p.load_authorization_code(client, code) is None


async def test_code_for_other_client_rejected():
    p = provider()
    a = await registered(p, "A")
    b = await registered(p, "B")
    code = p.issue_code(await login_req(p, a), uid=7, login="alice", key="k")
    assert await p.load_authorization_code(b, code) is None


async def test_token_types_not_interchangeable():
    p = provider()
    client = await registered(p)
    ac = await p.load_authorization_code(
        client, p.issue_code(await login_req(p, client), uid=7, login="alice", key="k")
    )
    tok = await p.exchange_authorization_code(client, ac)
    assert await p.load_refresh_token(client, tok.access_token) is None
    assert await p.load_access_token(tok.refresh_token) is None


async def test_static_token_maps_to_service():
    at = await provider().load_access_token("static-tok")
    assert (at.odoo_uid, at.odoo_key, at.subject) == (None, None, "service")


async def test_unknown_token_returns_none():
    assert await provider().load_access_token("nope") is None


async def test_load_access_token_from_other_key_returns_none():
    old = provider(key=Fernet.generate_key().decode())
    client = await registered(old)
    ac = await old.load_authorization_code(
        client, old.issue_code(await login_req(old, client), uid=7, login="a", key="k")
    )
    tok = await old.exchange_authorization_code(client, ac)
    assert await provider().load_access_token(tok.access_token) is None


@pytest.mark.parametrize("verify_result, ok", [(7, True), (None, False), (8, False)])
async def test_refresh_rechecks_key_with_odoo(verify_result, ok):
    verify = AsyncMock(return_value=verify_result)
    p = provider(verify)
    client = await registered(p)
    ac = await p.load_authorization_code(
        client, p.issue_code(await login_req(p, client), uid=7, login="alice", key="k")
    )
    rt = await p.load_refresh_token(
        client, (await p.exchange_authorization_code(client, ac)).refresh_token
    )
    if ok:
        new = await p.exchange_refresh_token(client, rt, [])
        assert (await p.load_access_token(new.access_token)).odoo_uid == 7
    else:
        with pytest.raises(TokenError) as e:
            await p.exchange_refresh_token(client, rt, [])
        assert e.value.error == "invalid_grant"
    verify.assert_awaited_with("alice", "k")


async def test_refresh_odoo_unreachable_is_invalid_grant():
    p = provider(AsyncMock(side_effect=OSError("down")))
    client = await registered(p)
    ac = await p.load_authorization_code(
        client, p.issue_code(await login_req(p, client), uid=7, login="a", key="k")
    )
    rt = await p.load_refresh_token(
        client, (await p.exchange_authorization_code(client, ac)).refresh_token
    )
    with pytest.raises(TokenError) as e:
        await p.exchange_refresh_token(client, rt, [])
    assert e.value.error == "invalid_grant"


async def test_used_code_variant_spelling_rejected():
    # base64 decoding ignores stray characters: single use must hold on the jti, not the string
    p = provider()
    client = await registered(p)
    code = p.issue_code(await login_req(p, client), uid=7, login="alice", key="k")
    await p.exchange_authorization_code(client, await p.load_authorization_code(client, code))
    assert await p.load_authorization_code(client, code + "!") is None


async def test_non_ascii_token_returns_none():
    p = provider()
    assert await p.load_access_token("clé") is None
    assert await p.get_client("clé") is None


async def test_token_reprs_hide_odoo_key():
    p = provider()
    client = await registered(p)
    ac = await p.load_authorization_code(
        client, p.issue_code(await login_req(p, client), uid=7, login="a", key="secret")
    )
    tok = await p.exchange_authorization_code(client, ac)
    rt = await p.load_refresh_token(client, tok.refresh_token)
    at = await p.load_access_token(tok.access_token)
    for obj in (ac, rt, at):
        assert "odoo_key" not in repr(obj) and "secret" not in repr(obj)
