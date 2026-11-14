# ratchet-authz-langgraph

LangGraph adapter for **[Ratchet](https://github.com/1manideep/ratchet)** —
plugs the [Ratchet authorization broker](https://github.com/1manideep/ratchet)
into LangChain's `wrap_tool_call` middleware hook. No monkey-patching of
LangGraph itself; a hijacked model still can't exceed what was explicitly
delegated to it.

## Install

```bash
pip install ratchet-authz-langgraph
```

## Minimal usage

```python
from ratchet_core import Broker, Ed25519WorkloadIdentity, tool_name_caveat
from ratchet_langgraph import RatchetMiddleware

broker = Broker()
primary = Ed25519WorkloadIdentity("primary-agent")
token = broker.issue(
    human_identity="alice@example.com",
    primary_identity=primary,
    caveats=[tool_name_caveat("read_calendar")],
)

middleware = RatchetMiddleware(
    broker,
    token_resolver=lambda request: token,
    identity_resolver=lambda request: primary,
)
agent = create_agent(model=..., tools=[...], middleware=[middleware])
```

Full runnable example and architecture diagram:
https://github.com/1manideep/ratchet/blob/main/examples/langgraph_example.py
