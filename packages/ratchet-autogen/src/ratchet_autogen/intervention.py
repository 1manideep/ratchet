"""ratchet_autogen.intervention — AutoGen adapter for the Ratchet broker.

Plugs Broker.authorize() into AutoGen core's intervention-handler hook:
https://microsoft.github.io/autogen/0.7.3/user-guide/core-user-guide/cookbook/tool-use-with-intervention.html

No core authorization logic lives here — this only translates an AutoGen
FunctionCall into a ratchet_core.ProposedToolCall and translates the
resulting Decision into AutoGen's own ToolException mechanism.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from autogen_core import (
    AgentId,
    DefaultInterventionHandler,
    DropMessage,
    FunctionCall,
    MessageContext,
)
from autogen_core.tool_agent import ToolException

from ratchet_core import Broker, ProposedToolCall, Token, WorkloadIdentity

logger = logging.getLogger(__name__)

TokenResolver = Callable[[FunctionCall, MessageContext], Token]
IdentityResolver = Callable[[FunctionCall, MessageContext], WorkloadIdentity]


class RatchetInterventionHandler(DefaultInterventionHandler):
    """Gates every FunctionCall sent through the runtime via Broker.authorize().

    Register with `SingleThreadedAgentRuntime(intervention_handlers=[handler])`.
    `token_resolver` / `identity_resolver` locate the current capability
    token and presenting workload identity for a given call — how those are
    tracked per-agent (a dict keyed by `recipient`, a closure, ...) is
    application-specific.
    """

    def __init__(
        self,
        broker: Broker,
        *,
        token_resolver: TokenResolver,
        identity_resolver: IdentityResolver,
    ) -> None:
        self._broker = broker
        self._token_resolver = token_resolver
        self._identity_resolver = identity_resolver

    async def on_send(
        self, message: Any, *, message_context: MessageContext, recipient: AgentId
    ) -> Any | type[DropMessage]:
        if not isinstance(message, FunctionCall):
            return message

        try:
            args = (
                json.loads(message.arguments)
                if isinstance(message.arguments, str)
                else dict(message.arguments)
            )
            token = self._token_resolver(message, message_context)
            identity = self._identity_resolver(message, message_context)
            proposed_call = ProposedToolCall(tool_name=message.name, args=args)
            decision = self._broker.authorize(
                token, presenting_identity=identity, proposed_tool_call=proposed_call
            )
        except ToolException:
            raise
        except Exception as exc:  # never let adapter-level errors bypass the gate
            logger.exception("Ratchet intervention handler failed to evaluate a tool call; denying")
            raise ToolException(
                content=f"Tool call blocked by Ratchet: internal error ({type(exc).__name__})",
                call_id=message.id,
                name=message.name,
            ) from exc

        if not decision.allowed:
            reason = (
                f"{decision.reason_code}: {decision.detail}"
                if decision.detail
                else decision.reason_code
            )
            raise ToolException(
                content=f"Tool call blocked by Ratchet: {reason}",
                call_id=message.id,
                name=message.name,
            )

        return message
