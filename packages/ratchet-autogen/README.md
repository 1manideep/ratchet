# ratchet-autogen

AutoGen adapter for **[Ratchet](https://github.com/1manideep/ratchet)** —
plugs the [Ratchet authorization broker](https://github.com/1manideep/ratchet)
into a `DefaultInterventionHandler` registered on the
`SingleThreadedAgentRuntime`. No monkey-patching of AutoGen itself; a
hijacked model still can't exceed what was explicitly delegated to it.

## Install

```bash
pip install ratchet-autogen
```

## Minimal usage

```python
from ratchet_core import Broker, Ed25519WorkloadIdentity, tool_name_caveat
from ratchet_autogen import RatchetInterventionHandler

broker = Broker()
primary = Ed25519WorkloadIdentity("primary-agent")
token = broker.issue(
    human_identity="alice@example.com",
    primary_identity=primary,
    caveats=[tool_name_caveat("run_python")],
)

handler = RatchetInterventionHandler(
    broker,
    token_resolver=lambda msg, ctx: token,
    identity_resolver=lambda msg, ctx: primary,
)
runtime = SingleThreadedAgentRuntime(intervention_handlers=[handler])
```

Full runnable example and architecture diagram:
https://github.com/1manideep/ratchet/blob/main/examples/autogen_example.py
