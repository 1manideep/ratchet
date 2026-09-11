"""LangGraph + Ratchet quickstart.

Runnable without any API key: it drives RatchetMiddleware.wrap_tool_call()
directly with real langchain ToolCallRequest/ToolMessage objects, the same
call shape LangGraph itself uses internally. In a real deployment, wire the
same middleware instance into `create_agent(middleware=[...])` and it runs
automatically on every tool call the model makes.
"""

from __future__ import annotations

from langchain.messages import ToolMessage
from langchain.tools.tool_node import ToolCallRequest

from ratchet_core import Broker, Ed25519WorkloadIdentity, arg_constraint_caveat, tool_name_caveat
from ratchet_langgraph import RatchetMiddleware


def read_calendar(calendar_id: str) -> str:
    """The real tool implementation a LangGraph agent would call."""
    return f"3 events on {calendar_id}'s calendar today."


def main() -> None:
    broker = Broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("calendar-sub-agent")

    root_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("read_calendar|send_email")],
    )
    # Delegate to a sub-agent narrowed to exactly one tool and one calendar.
    sub_token = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary,
        delegatee_identity=sub,
        new_caveats=[
            tool_name_caveat("read_calendar"),
            arg_constraint_caveat("calendar_id", equals="team"),
        ],
    )

    # This is the real integration point:
    #   agent = create_agent(model=..., tools=[...], middleware=[middleware])
    middleware = RatchetMiddleware(
        broker,
        token_resolver=lambda request: sub_token,
        identity_resolver=lambda request: sub,
    )

    def handler(request: ToolCallRequest) -> ToolMessage:
        result = read_calendar(**request.tool_call["args"])
        return ToolMessage(content=result, tool_call_id=request.tool_call["id"])

    in_scope_call = ToolCallRequest(
        tool_call={
            "name": "read_calendar",
            "args": {"calendar_id": "team"},
            "id": "call-1",
            "type": "tool_call",
        },
        tool=None,
        state=None,
        runtime=None,
    )
    print("in-scope call  ->", middleware.wrap_tool_call(in_scope_call, handler))

    # Simulates a hijacked model trying to escalate to send_email, which the
    # sub-agent's narrowed token never granted (T3: prompt-injection escalation).
    out_of_scope_call = ToolCallRequest(
        tool_call={
            "name": "send_email",
            "args": {"to": "eve@attacker.example"},
            "id": "call-2",
            "type": "tool_call",
        },
        tool=None,
        state=None,
        runtime=None,
    )
    print("out-of-scope call ->", middleware.wrap_tool_call(out_of_scope_call, handler))


if __name__ == "__main__":
    main()
