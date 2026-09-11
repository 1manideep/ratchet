"""ratchet_langgraph.middleware — LangGraph adapter for the Ratchet broker.

Plugs Broker.authorize() into LangChain's class-based middleware system via
the `wrap_tool_call` hook:
https://docs.langchain.com/oss/python/langchain/middleware/custom
https://reference.langchain.com/python/langchain/agents/middleware/types/wrap_tool_call

No core authorization logic lives here — this only translates LangGraph's
ToolCallRequest into a ratchet_core.ProposedToolCall and translates the
resulting Decision back into a clean ToolMessage rejection, so a DENY never
raises an uncaught exception into the graph and a hijacked model can't just
route around a raised exception.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from langchain.tools.tool_node import ToolCallRequest
from langgraph.types import Command

from ratchet_core import Broker, ProposedToolCall, Token, WorkloadIdentity

logger = logging.getLogger(__name__)

TokenResolver = Callable[[ToolCallRequest], Token]
IdentityResolver = Callable[[ToolCallRequest], WorkloadIdentity]


class RatchetMiddleware(AgentMiddleware):
    """Gates every LangGraph tool call through Broker.authorize().

    `token_resolver` and `identity_resolver` locate the current capability
    token and presenting workload identity for a given request — how those
    are wired into the request (runtime context, closures, a session store,
    ...) is application-specific, so this middleware does not assume a shape.

    Example:
        middleware = RatchetMiddleware(
            broker,
            token_resolver=lambda request: current_token,
            identity_resolver=lambda request: primary_identity,
        )
        agent = create_agent(model=..., tools=[...], middleware=[middleware])
    """

    def __init__(
        self,
        broker: Broker,
        *,
        token_resolver: TokenResolver,
        identity_resolver: IdentityResolver,
    ) -> None:
        super().__init__()
        self._broker = broker
        self._token_resolver = token_resolver
        self._identity_resolver = identity_resolver

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command],
    ) -> ToolMessage | Command:
        tool_call = request.tool_call
        tool_call_id = tool_call.get("id")

        try:
            token = self._token_resolver(request)
            identity = self._identity_resolver(request)
            proposed_call = ProposedToolCall(
                tool_name=tool_call["name"], args=dict(tool_call.get("args", {}))
            )
            decision = self._broker.authorize(
                token, presenting_identity=identity, proposed_tool_call=proposed_call
            )
        except Exception as exc:  # never let adapter-level errors bypass the gate
            logger.exception("Ratchet middleware failed to evaluate a tool call; denying")
            return ToolMessage(
                content=f"Tool call blocked by Ratchet: internal error ({type(exc).__name__})",
                tool_call_id=tool_call_id,
                status="error",
            )

        if not decision.allowed:
            reason = (
                f"{decision.reason_code}: {decision.detail}"
                if decision.detail
                else decision.reason_code
            )
            return ToolMessage(
                content=f"Tool call blocked by Ratchet: {reason}",
                tool_call_id=tool_call_id,
                status="error",
            )

        return handler(request)
