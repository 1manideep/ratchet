"""ratchet_mcp.resource_server — MCP adapter for the Ratchet broker.

Positions Ratchet as the MCP server's OAuth 2.1 resource-server validation
step:
https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

Two pieces, matching the two places enforcement is possible:

  - `RatchetASGIMiddleware` validates the `Authorization: Bearer <token>`
    header on every HTTP request — signature, expiry, revocation, and
    sender-binding — via Broker.verify_token(), and returns 401 before the
    wrapped MCP server app runs if it fails. This is transport-level: it
    does not yet know which tool is being called, so `resource` (RFC 8707
    audience restriction) is what it checks the token against, not
    `tool_name`.
  - `authorize_tool_call` is a decorator for an individual tool handler,
    evaluating the actual tool_name/args against the token's caveats once
    they are known — this is where tool_name/arg_constraint caveats apply.

No MCP SDK dependency is required — both pieces are pure ASGI / stdlib
Python, usable from any Python MCP server implementation.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from ratchet_core import (
    Broker,
    ProposedToolCall,
    RatchetMalformedToken,
    Token,
    WorkloadIdentity,
    deserialize_token,
)

logger = logging.getLogger(__name__)

ASGIReceive = Callable[[], Awaitable[Mapping[str, Any]]]
ASGISend = Callable[[Mapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Mapping[str, Any], ASGIReceive, ASGISend], Awaitable[None]]
IdentityResolver = Callable[[Mapping[str, Any]], WorkloadIdentity]


class RatchetASGIMiddleware:
    """ASGI middleware validating the Authorization Bearer token before the
    wrapped MCP server app runs.

    Attaches the verified Token and WorkloadIdentity to
    `scope["state"]["ratchet_token"]` / `["ratchet_identity"]` for the
    downstream app to reuse with `authorize_tool_call`, so the token isn't
    re-parsed per tool call.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        broker: Broker,
        identity_resolver: IdentityResolver,
    ) -> None:
        self._app = app
        self._broker = broker
        self._identity_resolver = identity_resolver

    async def __call__(
        self, scope: Mapping[str, Any], receive: ASGIReceive, send: ASGISend
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        if not auth_header.startswith("Bearer "):
            await self._deny(send, status=401, detail="missing Bearer token")
            return

        blob = auth_header[len("Bearer ") :]
        try:
            token = deserialize_token(blob)
        except RatchetMalformedToken as exc:
            await self._deny(send, status=401, detail=f"malformed token: {exc}")
            return

        try:
            identity = self._identity_resolver(scope)
            decision = self._broker.verify_token(token, presenting_identity=identity)
        except Exception as exc:  # never let adapter-level errors bypass the gate
            logger.exception("Ratchet ASGI middleware failed to verify a token; denying")
            await self._deny(send, status=401, detail=f"internal error: {type(exc).__name__}")
            return

        if not decision.allowed:
            status = 403 if decision.reason_code == "CAVEAT_NOT_SATISFIED" else 401
            await self._deny(
                send, status=status, detail=f"{decision.reason_code}: {decision.detail}"
            )
            return

        mutable_scope = dict(scope)
        mutable_scope["state"] = {
            **scope.get("state", {}),
            "ratchet_token": token,
            "ratchet_identity": identity,
        }
        await self._app(mutable_scope, receive, send)

    @staticmethod
    async def _deny(send: ASGISend, *, status: int, detail: str) -> None:
        body = json.dumps({"error": "unauthorized", "detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})


def authorize_tool_call(
    broker: Broker,
    *,
    token_resolver: Callable[..., Token],
    identity_resolver: Callable[..., WorkloadIdentity],
    resource: str | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator for an MCP tool handler `handler(tool_name, args, *ctx)`.

    `resource` is this MCP server's own canonical URI (RFC 8707) -- a
    per-deployment constant, not a per-call value -- checked against any
    `resource` caveat on the token. Wraps the handler so it only runs if
    Broker.authorize() allows the call; raises PermissionError with the
    Decision's reason code otherwise.
    """

    def decorator(handler: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(handler)
        async def wrapper(
            tool_name: str, args: Mapping[str, Any], *ctx_args: Any, **ctx_kwargs: Any
        ) -> Any:
            token = token_resolver(*ctx_args, **ctx_kwargs)
            identity = identity_resolver(*ctx_args, **ctx_kwargs)
            proposed_call = ProposedToolCall(
                tool_name=tool_name, args=dict(args), resource=resource
            )
            decision = broker.authorize(
                token, presenting_identity=identity, proposed_tool_call=proposed_call
            )
            if not decision.allowed:
                reason = (
                    f"{decision.reason_code}: {decision.detail}"
                    if decision.detail
                    else decision.reason_code
                )
                raise PermissionError(f"Ratchet denied {tool_name}: {reason}")
            return await handler(tool_name, args, *ctx_args, **ctx_kwargs)

        return wrapper

    return decorator
