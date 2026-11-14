# ratchet-authz-mcp

MCP adapter for **[Ratchet](https://github.com/1manideep/ratchet)** — ASGI
middleware that validates an `Authorization: Bearer <token>` header against
the [Ratchet broker](https://github.com/1manideep/ratchet) before an MCP
tool handler runs, aligned with RFC 8693 (Token Exchange) and RFC 8707
(Resource Indicators). Pure stdlib, no MCP SDK dependency required.

## Install

```bash
pip install ratchet-authz-mcp
```

## Minimal usage

```python
from ratchet_core import Broker, Ed25519WorkloadIdentity, tool_name_caveat
from ratchet_mcp import RatchetASGIMiddleware

broker = Broker()
primary = Ed25519WorkloadIdentity("primary-agent")
token = broker.issue(
    human_identity="alice@example.com",
    primary_identity=primary,
    caveats=[tool_name_caveat("read_file")],
)

app = RatchetASGIMiddleware(mcp_app, broker=broker, identity_resolver=lambda scope: primary)
```

Full runnable example and architecture diagram:
https://github.com/1manideep/ratchet/blob/main/examples/mcp_example.py
