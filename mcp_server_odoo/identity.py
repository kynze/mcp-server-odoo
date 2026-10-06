"""Identity of the MCP caller, used to run each Odoo call as that user."""

from dataclasses import dataclass, field

from mcp.server.lowlevel.server import request_ctx


@dataclass(frozen=True)
class OdooIdentity:
    uid: int
    key: str = field(repr=False)


SERVICE = object()  # static service token: use the configured service account


def caller_identity() -> OdooIdentity | object | None:
    """Identity of the MCP message being handled, or None when it has none.

    Reads the SDK's per-message ``request_ctx`` (copied into ``asyncio.to_thread``),
    not ``auth_context_var``, which is set in the HTTP task rather than the session
    task that runs tools.
    """
    try:
        rc = request_ctx.get()
    except LookupError:
        return None
    scope = getattr(rc.request, "scope", None) or {}
    token = getattr(scope.get("user"), "access_token", None)
    if token is None or not hasattr(token, "odoo_uid"):
        return None
    return SERVICE if token.odoo_uid is None else OdooIdentity(token.odoo_uid, token.odoo_key)
