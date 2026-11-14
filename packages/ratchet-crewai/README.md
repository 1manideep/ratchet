# ratchet-authz-crewai

CrewAI adapter for **[Ratchet](https://github.com/1manideep/ratchet)** —
plugs the [Ratchet authorization broker](https://github.com/1manideep/ratchet)
into CrewAI's `@on(InterceptionPoint.PRE_TOOL_CALL)` hook. No
monkey-patching of CrewAI itself; a hijacked model still can't exceed what
was explicitly delegated to it.

## Install

```bash
pip install ratchet-authz-crewai
```

## Minimal usage

```python
from ratchet_core import Broker, Ed25519WorkloadIdentity, tool_name_caveat
from ratchet_crewai import register_ratchet_hook

broker = Broker()
primary = Ed25519WorkloadIdentity("primary-agent")
token = broker.issue(
    human_identity="alice@example.com",
    primary_identity=primary,
    caveats=[tool_name_caveat("web_search")],
)

register_ratchet_hook(
    broker,
    token_resolver=lambda ctx: token,
    identity_resolver=lambda ctx: primary,
)
```

Full runnable example and architecture diagram:
https://github.com/1manideep/ratchet/blob/main/examples/crewai_example.py
