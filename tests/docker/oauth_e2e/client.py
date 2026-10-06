import asyncio
import base64
import hashlib
import os
import sys
from urllib.parse import parse_qs, urlparse

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BASE = "http://localhost:8000"
CB = "http://localhost:9999/cb"
KEYS = {u: open(f"/tmp/key_{u}").read().strip() for u in ("admin", "alice")}


def check(cond, name, detail=""):
    if not cond:
        print(f"FAIL {name} {detail}")
        sys.exit(1)
    print(f"OK {name}")


async def call(token, tool, args=None):
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(f"{BASE}/mcp", headers=headers) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args or {})
            return res.isError, "".join(c.text for c in res.content if hasattr(c, "text"))


async def login(h, client_id, challenge, user, key):
    r = await h.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CB,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st",
        },
    )
    assert r.status_code == 302, r.text
    req = parse_qs(urlparse(r.headers["location"]).query)["req"][0]
    return await h.post("/oauth/login", data={"req": req, "login": user, "api_key": key})


async def register(h, grants):
    r = await h.post(
        "/register",
        json={
            "redirect_uris": [CB],
            "token_endpoint_auth_method": "none",
            "grant_types": grants,
            "response_types": ["code"],
            "client_name": "e2e",
        },
    )
    return r.json()["client_id"]


async def oauth(h, user):
    cid = await register(h, ["authorization_code", "refresh_token"])
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    r = await login(h, cid, challenge, user, KEYS[user])
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    t = await h.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CB,
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    assert t.status_code == 200, t.text
    return cid, t.json()


async def main():
    async with httpx.AsyncClient(base_url=BASE, follow_redirects=False) as h:
        r = await h.post("/mcp", json={}, headers={"Accept": "application/json, text/event-stream"})
        check(r.status_code == 401, "no token -> 401", r.status_code)

        cid_a, tok_a = await oauth(h, "alice")
        err, txt = await call(tok_a["access_token"], "get_current_context")
        check(not err and "Alice" in txt, "oauth alice -> Alice", txt[:200])

        _, tok_adm = await oauth(h, "admin")
        err, txt = await call(tok_adm["access_token"], "get_current_context")
        check(not err and "Administrator" in txt, "oauth admin -> Administrator", txt[:200])

        q = {"model": "ir.config_parameter", "limit": 1}
        err, txt = await call(tok_adm["access_token"], "search_records", q)
        check(not err, "admin reads ir.config_parameter", txt[:200])
        err, txt = await call(tok_a["access_token"], "search_records", q)
        check(
            err and "not allowed to access" in txt.lower(),
            "alice refused ir.config_parameter",
            txt[:300],
        )

        t = await h.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tok_a["refresh_token"],
                "client_id": cid_a,
            },
        )
        check(t.status_code == 200, "refresh ok", t.text)
        check(t.json()["access_token"] != tok_a["access_token"], "refresh issues new access token")
        err, txt = await call(t.json()["access_token"], "get_current_context")
        check(not err and "Alice" in txt, "refreshed token -> Alice", txt[:200])

        err, txt = await call("static-e2e", "get_current_context")
        check(not err and "Administrator" in txt, "static token -> Administrator", txt[:200])

        cid = await register(h, ["authorization_code", "refresh_token"])
        r = await login(h, cid, "x" * 43, "alice", "wrong-key")
        check(
            r.status_code == 200
            and "location" not in r.headers
            and "Identifiant ou clé API incorrect" in r.text,
            "bad key rejected, no code issued",
            r.status_code,
        )


asyncio.run(main())
