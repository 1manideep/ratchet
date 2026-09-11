"""MCP + Ratchet quickstart.

Runnable without any API key or MCP SDK: RatchetASGIMiddleware is pure ASGI,
driven here with a minimal mock scope/receive/send (the same three-argument
ASGI contract any real server — Starlette, Uvicorn, etc. — uses). In a real
deployment, wrap your MCP server's ASGI app once:

    app = RatchetASGIMiddleware(mcp_app, broker=broker, identity_resolver=...)
"""

from __future__ import annotations

import asyncio

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    resource_caveat,
    serialize_token,
    tool_name_caveat,
)
from ratchet_mcp import RatchetASGIMiddleware, authorize_tool_call


async def main() -> None:
    broker = Broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    mcp_client = Ed25519WorkloadIdentity("mcp-client")

    root_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("list_files|read_file")],
    )
    # RFC 8707 audience restriction: this token is only valid for this MCP server.
    client_token = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary,
        delegatee_identity=mcp_client,
        new_caveats=[
            tool_name_caveat("read_file"),
            resource_caveat(r"https://files\.example\.com/mcp"),
        ],
    )
    client_token_blob = serialize_token(client_token)

    @authorize_tool_call(
        broker,
        token_resolver=lambda scope: scope["state"]["ratchet_token"],
        identity_resolver=lambda scope: scope["state"]["ratchet_identity"],
        resource="https://files.example.com/mcp",
    )
    async def read_file_handler(tool_name: str, args: dict, scope: dict) -> str:
        return f"contents of {args['path']}"

    async def mcp_app(scope, receive, send):
        result = await read_file_handler("read_file", {"path": "/docs/readme.md"}, scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": result.encode()})

    app = RatchetASGIMiddleware(mcp_app, broker=broker, identity_resolver=lambda scope: mcp_client)

    async def run_request(auth_header: bytes | None) -> list[dict]:
        responses: list[dict] = []

        async def send(message):
            responses.append(message)

        async def receive():
            return {"type": "http.request"}

        headers = [(b"authorization", auth_header)] if auth_header else []
        await app({"type": "http", "headers": headers}, receive, send)
        return responses

    valid = await run_request(f"Bearer {client_token_blob}".encode())
    print("valid bearer token -> status", valid[0]["status"], "body", valid[1]["body"])

    missing = await run_request(None)
    print("missing bearer token -> status", missing[0]["status"])


if __name__ == "__main__":
    asyncio.run(main())
