# ratchet-authz-core

Framework-agnostic authorization broker core for **Ratchet** — an
open-source implementation of the delegation-authorization broker
described in [arXiv:2609.00267](https://arxiv.org/abs/2609.00267)
("Delegation Without Trust"). A fully prompt-hijacked LLM agent still
cannot exceed the authority explicitly delegated to it.

Implements workload identity, macaroon-style capability tokens, the
broker/PEP, hash-chained audit logging, and revocation. **Zero
third-party runtime dependencies** beyond the standard library and
`cryptography` (used only for Ed25519 workload identity keys).

## Install

```bash
pip install ratchet-authz-core
```

For a specific agent framework, install the matching adapter instead (it
pulls in `ratchet-authz-core` automatically): `ratchet-authz-langgraph`,
`ratchet-authz-crewai`, `ratchet-authz-autogen`, or `ratchet-authz-mcp`.

## Minimal usage

```python
from ratchet_core import Broker, Ed25519WorkloadIdentity, tool_name_caveat

broker = Broker()
primary = Ed25519WorkloadIdentity("primary-agent")
token = broker.issue(
    human_identity="alice@example.com",
    primary_identity=primary,
    caveats=[tool_name_caveat("read_calendar")],
)

decision = broker.authorize(
    token,
    presenting_identity=primary,
    proposed_tool_call=...,  # ratchet_core.ProposedToolCall
)
```

Full documentation, architecture diagram, and per-framework quickstarts:
https://github.com/1manideep/ratchet
