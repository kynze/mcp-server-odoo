"""`/oauth/login` page: the user types an Odoo login + API key, we check it and hand back a code."""

import html
from typing import Awaitable, Callable
from urllib.parse import urlparse

from mcp.server.auth.provider import construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .oauth import OdooOAuthProvider, SealError
from .odoo_connection import OdooConnectionError

PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connexion Odoo</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem}}
input{{display:block;width:100%;box-sizing:border-box;padding:.5rem;margin:.25rem 0 1rem}}
button{{padding:.6rem 1.2rem}} .err{{color:#b00020}} small{{color:#555}}
</style></head><body>{body}</body></html>"""

FORM = """<h1>Connexion Odoo</h1>
<p>{client} demande l'accès à votre compte Odoo.</p>
<p>Vous serez ensuite renvoyé vers <strong>{host}</strong>.</p>
{error}
<form method="post">
<input type="hidden" name="req" value="{req}">
<label>Identifiant Odoo<input type="text" name="login" value="{login}" required autofocus></label>
<label>Clé API<input type="password" name="api_key" required></label>
<button type="submit">Se connecter</button>
</form>
<p><small>Créez une clé API dans Odoo : Mon profil &gt; Sécurité du compte &gt; Nouvelle clé API</small></p>"""

EXPIRED = "Lien expiré, relancez la connexion depuis votre application"

# No framing (clickjacking) and no caching of a page that takes an API key.
HEADERS = {
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(body=body), status_code=status, headers=HEADERS)


def login_endpoint(provider: OdooOAuthProvider) -> Callable[[Request], Awaitable[Response]]:
    async def render(req: str, data: dict, login: str = "", error: str = "", status: int = 200):
        client = await provider.get_client(data["client_id"])
        name = (client and client.client_name) or "Une application"
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = FORM.format(
            client=html.escape(name),
            host=html.escape(urlparse(data["redirect_uri"]).netloc),
            error=err,
            req=html.escape(req),
            login=html.escape(login),
        )
        return _page(body, status)

    async def endpoint(request: Request) -> Response:
        post = request.method == "POST"
        form = await request.form() if post else request.query_params
        req = str(form.get("req", ""))
        try:
            data = provider.open_login_request(req)
        except SealError:
            return _page(f'<p class="err">{html.escape(EXPIRED)}</p>', 400)
        if not post:
            return await render(req, data)

        login = str(form.get("login", "")).strip()
        key = str(form.get("api_key", "")).strip()
        try:
            uid = await provider.verify_key(login, key)
        except OdooConnectionError:
            return await render(
                req, data, login, "Odoo est injoignable, réessayez dans quelques instants.", 502
            )
        if uid is None:
            return await render(req, data, login, "Identifiant ou clé API incorrect")
        code = provider.issue_code(data, uid, login, key)
        return RedirectResponse(
            construct_redirect_uri(data["redirect_uri"], code=code, state=data["state"]),
            status_code=302,
        )

    return endpoint
