"""ratchet_crewai.hooks — CrewAI adapter for the Ratchet broker.

Plugs Broker.authorize() into CrewAI's PRE_TOOL_CALL hook:
https://docs.crewai.com/edge/en/learn/tool-hooks

No core authorization logic lives here — this only translates a CrewAI
ToolCallHookContext into a ratchet_core.ProposedToolCall and translates the
Decision into CrewAI's own abort mechanism.

CrewAI's hook contract only blocks a call if the hook raises HookAborted —
any *other* exception is swallowed and the tool call proceeds (fail-open,
per CrewAI's documented "Abort loudly" guidance). That is the opposite of
Ratchet's fail-closed design, so every path below is wrapped to guarantee
it either does nothing (ALLOW) or raises HookAborted (DENY); nothing else
is allowed to escape this hook.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from crewai.hooks import HookAborted, InterceptionPoint, ToolCallHookContext, on

from ratchet_core import Broker, ProposedToolCall, Token, WorkloadIdentity

logger = logging.getLogger(__name__)

TokenResolver = Callable[[ToolCallHookContext], Token]
IdentityResolver = Callable[[ToolCallHookContext], WorkloadIdentity]


def register_ratchet_hook(
    broker: Broker,
    *,
    token_resolver: TokenResolver,
    identity_resolver: IdentityResolver,
    tools: list[str] | None = None,
    agents: list[str] | None = None,
) -> Callable[[ToolCallHookContext], None]:
    """Register a PRE_TOOL_CALL hook that gates matching tool calls through `broker`.

    `tools` / `agents` are the same optional CrewAI filters `@on` accepts.
    Returns the registered hook function (pass to `unregister_hook` to remove
    it, e.g. between tests).
    """

    @on(InterceptionPoint.PRE_TOOL_CALL, tools=tools, agents=agents)
    def ratchet_pre_tool_call(ctx: ToolCallHookContext) -> None:
        try:
            token = token_resolver(ctx)
            identity = identity_resolver(ctx)
            proposed_call = ProposedToolCall(tool_name=ctx.tool_name, args=dict(ctx.tool_input))
            decision = broker.authorize(
                token, presenting_identity=identity, proposed_tool_call=proposed_call
            )
        except HookAborted:
            raise
        except Exception as exc:
            # CrewAI fails OPEN on any exception other than HookAborted, so an
            # adapter-level bug must never become a silent ALLOW.
            logger.exception("Ratchet hook failed to evaluate a tool call; denying")
            raise HookAborted(
                reason=f"Ratchet internal error: {type(exc).__name__}: {exc}", source="ratchet"
            ) from exc

        if not decision.allowed:
            reason = (
                f"{decision.reason_code}: {decision.detail}"
                if decision.detail
                else decision.reason_code
            )
            raise HookAborted(reason=reason, source="ratchet")

    return ratchet_pre_tool_call
