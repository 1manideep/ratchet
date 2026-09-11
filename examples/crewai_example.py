"""CrewAI + Ratchet quickstart.

Runnable without any API key: it registers RatchetMiddleware's PRE_TOOL_CALL
hook via the real crewai.hooks engine and drives it with a minimal duck-typed
ToolCallHookContext (only the attributes the hook actually reads). In a real
crew, register the hook once at startup and every agent's tool calls flow
through it automatically.
"""

from __future__ import annotations

from types import SimpleNamespace

from crewai.hooks import HookAborted, clear_all_hooks

from ratchet_core import Broker, Ed25519WorkloadIdentity, arg_constraint_caveat, tool_name_caveat
from ratchet_crewai import register_ratchet_hook


def main() -> None:
    clear_all_hooks()  # keep this example isolated from any prior hook registrations

    broker = Broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("research-sub-agent")

    root_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("web_search|refund_payment")],
    )
    sub_token = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary,
        delegatee_identity=sub,
        new_caveats=[
            tool_name_caveat("web_search"),
            arg_constraint_caveat("query", pattern=r".{3,200}"),
        ],
    )

    # Real integration: call this once at crew startup.
    register_ratchet_hook(
        broker,
        token_resolver=lambda ctx: sub_token,
        identity_resolver=lambda ctx: sub,
    )

    in_scope_ctx = SimpleNamespace(
        tool_name="web_search", tool_input={"query": "latest agent security research"}
    )
    try:
        from crewai.hooks import InterceptionPoint, get_hooks

        for hook in get_hooks(InterceptionPoint.PRE_TOOL_CALL):
            hook(in_scope_ctx)
        print("in-scope call: allowed, tool would execute")
    except HookAborted as exc:
        print("in-scope call: unexpectedly blocked ->", exc)

    # Simulates a compromised sub-agent reaching for a tool far outside its
    # delegated research task (T4: compromised sub-agent / over-broad scope).
    out_of_scope_ctx = SimpleNamespace(tool_name="refund_payment", tool_input={"amount": 50_000})
    try:
        from crewai.hooks import InterceptionPoint, get_hooks

        for hook in get_hooks(InterceptionPoint.PRE_TOOL_CALL):
            hook(out_of_scope_ctx)
        print("out-of-scope call: BUG, should have been blocked")
    except HookAborted as exc:
        print("out-of-scope call: blocked ->", exc.reason)

    clear_all_hooks()


if __name__ == "__main__":
    main()
