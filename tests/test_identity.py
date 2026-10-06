"""Tests for per-request caller identity on Odoo calls (multi-user OAuth)."""

import asyncio
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from mcp.server.lowlevel.server import request_ctx

from mcp_server_odoo.config import OdooConfig
from mcp_server_odoo.identity import MISSING, SERVICE, OdooIdentity, caller_identity
from mcp_server_odoo.odoo_connection import OdooConnection, OdooConnectionError


def ctx(user=None, request=True):
    scope = {"user": user} if user is not None else {}
    return SimpleNamespace(request=SimpleNamespace(scope=scope) if request else None)


def user(uid, key):
    return SimpleNamespace(access_token=SimpleNamespace(odoo_uid=uid, odoo_key=key))


@contextmanager
def as_caller(c):
    t = request_ctx.set(c)
    try:
        yield
    finally:
        request_ctx.reset(t)


def connected(config):  # same recipe as tests/test_locale.py::_make_connected
    conn = OdooConnection(config)
    conn._connected = conn._authenticated = True
    conn._uid, conn._database, conn._auth_method = 2, "db", "api_key"
    conn._object_proxy = MagicMock()
    conn._object_proxy.execute_kw.return_value = []
    return conn


SVC = OdooConfig(url="http://localhost:8069", api_key="svc")
OAUTH = OdooConfig(
    url="http://localhost:8069",
    api_key="svc",
    transport="streamable-http",
    public_url="https://mcp.example.com",
    secret_key=Fernet.generate_key().decode(),
)


def test_caller_identity_cases():
    assert caller_identity() is None
    with as_caller(ctx(request=False)):
        assert caller_identity() is MISSING
    with as_caller(ctx()):
        assert caller_identity() is MISSING
    with as_caller(ctx(user(None, None))):
        assert caller_identity() is SERVICE
    with as_caller(ctx(user(7, "k"))):
        assert caller_identity() == OdooIdentity(7, "k")


def creds(conn):
    return conn._object_proxy.execute_kw.call_args[0][:3]


def test_execute_kw_uses_caller_identity():
    conn = connected(OAUTH)
    with as_caller(ctx(user(7, "k-alice"))):
        conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 7, "k-alice")


def test_execute_kw_static_token_uses_service():
    conn = connected(OAUTH)
    with as_caller(ctx(user(None, None))):
        conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")


@pytest.mark.parametrize("caller", [None, ctx()], ids=["outside-request", "missing"])
def test_execute_kw_fails_closed_without_identity_under_oauth(caller):
    # Outside any MCP request too: nothing legitimate calls Odoo there under OAuth, and an
    # SDK change that stops exposing request_ctx must not turn every caller into the service.
    conn = connected(OAUTH)
    with as_caller(caller) if caller else nullcontext(), pytest.raises(OdooConnectionError):
        conn.execute_kw("res.partner", "search", [[]], {})
    conn._object_proxy.execute_kw.assert_not_called()


def test_execute_kw_without_oauth_uses_service():
    conn = connected(SVC)
    conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")
    with as_caller(ctx()):
        conn.execute_kw("res.partner", "search", [[]], {})
    assert creds(conn) == ("db", 2, "svc")


def test_uid_property_returns_caller_uid():
    conn = connected(OAUTH)
    assert conn.uid == 2
    with as_caller(ctx(user(7, "k"))):
        assert conn.uid == 7


def test_fields_cache_is_per_user():
    conn = connected(OAUTH)
    conn._object_proxy.execute_kw.return_value = {"name": {}}
    with as_caller(ctx(user(7, "k7"))):
        conn.fields_get("res.partner")
    with as_caller(ctx(user(8, "k8"))):
        conn.fields_get("res.partner")
    assert conn._object_proxy.execute_kw.call_count == 2


def test_fields_get_fails_closed_before_cache():
    conn = connected(OAUTH)
    conn._object_proxy.execute_kw.return_value = {"name": {}}
    with as_caller(ctx(user(None, None))):
        conn.fields_get("res.partner")  # static-token (service) call fills the cache
    with as_caller(ctx()), pytest.raises(OdooConnectionError):
        conn.fields_get("res.partner")


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
