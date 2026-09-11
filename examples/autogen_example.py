"""AutoGen + Ratchet quickstart.

Runnable without any API key: it drives RatchetInterventionHandler.on_send()
directly with a real autogen_core.FunctionCall, the same message shape
AutoGen's ToolAgent sends internally. In a real deployment, register the
handler once on the runtime and it gates every FunctionCall automatically.
"""

from __future__ import annotations

import asyncio

from autogen_core import FunctionCall
from autogen_core.tool_agent import ToolException

from ratchet_autogen import RatchetInterventionHandler
from ratchet_core import Broker, Ed25519WorkloadIdentity, max_depth_caveat, tool_name_caveat


async def main() -> None:
    broker = Broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("code-exec-sub-agent")

    root_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("run_python|delete_file"), max_depth_caveat(3)],
    )
    sub_token = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary,
        delegatee_identity=sub,
        new_caveats=[tool_name_caveat("run_python")],
    )

    # Real integration:
    #   runtime = SingleThreadedAgentRuntime(intervention_handlers=[handler])
    handler = RatchetInterventionHandler(
        broker,
        token_resolver=lambda msg, ctx: sub_token,
        identity_resolver=lambda msg, ctx: sub,
    )

    in_scope_call = FunctionCall(id="1", name="run_python", arguments='{"code": "print(1 + 1)"}')
    result = await handler.on_send(in_scope_call, message_context=None, recipient=None)
    print("in-scope call: allowed ->", result)

    # Simulates a confused-deputy scenario: the sub-agent's legitimate
    # code-execution authority is redirected toward deleting files (T1).
    out_of_scope_call = FunctionCall(
        id="2", name="delete_file", arguments='{"path": "/etc/passwd"}'
    )
    try:
        await handler.on_send(out_of_scope_call, message_context=None, recipient=None)
        print("out-of-scope call: BUG, should have been blocked")
    except ToolException as exc:
        print("out-of-scope call: blocked ->", exc)


if __name__ == "__main__":
    asyncio.run(main())
