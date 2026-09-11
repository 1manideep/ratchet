"""ratchet_core.broker — the Ratchet authorization broker (issuer + PEP).

Implements the flow from the architecture diagram: a human's identity roots
a capability token (issue), each delegation hop mints a strictly narrower,
re-bound token (exchange), and every tool call is verified against the
presented token before it executes (authorize) — entirely outside the
calling agent's own model.

authorize() is a pure, synchronous, in-process function call: no network
hop, no model call. That is what makes microsecond-level enforcement
possible (see benchmarks/reproduce_paper_numbers.py). A future
`ratchet-remote` package could add a network-mediated PEP for multi-process
deployments without changing this module's public API.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass

from ratchet_core.audit import AuditSink, build_entry
from ratchet_core.caveats import (
    ACTION_CAVEAT_KINDS,
    Caveat,
    ProposedToolCall,
    evaluate_caveat,
    extract_bound_to,
    extract_expires_at,
    extract_max_depth,
)
from ratchet_core.exceptions import (
    RatchetDenied,
    RatchetDepthExceeded,
    RatchetExpired,
    RatchetInvalidSignature,
    RatchetNotBound,
    RatchetRevoked,
)
from ratchet_core.identity import IdentityRegistry, WorkloadIdentity
from ratchet_core.revocation import InMemoryRevocationStore, RevocationStore
from ratchet_core.tokens import (
    Token,
    mint_root,
    rebind_for_exchange,
    token_identity_chain,
    verify_signature,
)

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 900.0  # 15 minutes


@dataclass(frozen=True, slots=True)
class Decision:
    """The result of Broker.authorize() — never a bare boolean.

    `reason_code` is stable and machine-checkable (used in tests and by
    adapters to build framework-native rejection messages).
    """

    allowed: bool
    reason_code: str
    detail: str = ""

    @classmethod
    def allow(cls) -> Decision:
        return cls(allowed=True, reason_code="OK", detail="")

    @classmethod
    def deny(cls, reason_code: str, detail: str = "") -> Decision:
        return cls(allowed=False, reason_code=reason_code, detail=detail)


_DENY_REASON_TO_EXCEPTION: dict[str, type[RatchetDenied]] = {
    "INVALID_SIGNATURE": RatchetInvalidSignature,
    "REVOKED": RatchetRevoked,
    "NOT_BOUND": RatchetNotBound,
    "EXPIRED": RatchetExpired,
}


def _raise_for_denial(decision: Decision) -> None:
    exc_type = _DENY_REASON_TO_EXCEPTION.get(decision.reason_code, RatchetDenied)
    if exc_type is RatchetDenied:
        raise RatchetDenied(decision.reason_code, decision.detail)
    raise exc_type(decision.detail)


class Broker:
    """The Ratchet authorization broker: token issuer, exchange, and PEP."""

    def __init__(
        self,
        *,
        secret: bytes | None = None,
        identity_registry: IdentityRegistry | None = None,
        revocation_store: RevocationStore | None = None,
        audit_sink: AuditSink | None = None,
        default_ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self._identity_registry = identity_registry or IdentityRegistry()
        self._revocation_store = revocation_store or InMemoryRevocationStore()
        self._audit_sink = audit_sink
        self._default_ttl_seconds = default_ttl_seconds

    @property
    def revocation_store(self) -> RevocationStore:
        return self._revocation_store

    @property
    def identity_registry(self) -> IdentityRegistry:
        return self._identity_registry

    def issue(
        self,
        *,
        human_identity: str,
        primary_identity: WorkloadIdentity,
        caveats: Sequence[Caveat] = (),
        ttl_seconds: float | None = None,
    ) -> Token:
        """Mint the root capability token (cap1), rooted at a human grant.

        `human_identity` is folded into `root_id`, so it is cryptographically
        bound by the signature chain (R1). v0.1 treats it as an opaque
        string; wiring it to a real OIDC subject claim is a future extension
        (see README "Out of Scope").
        """
        self._identity_registry.register(primary_identity)
        root_id = f"human:{human_identity}:{secrets.token_hex(8)}"
        return mint_root(
            secret=self._secret,
            root_id=root_id,
            bound_to_fingerprint=primary_identity.fingerprint,
            caveats=caveats,
            ttl_seconds=ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds,
        )

    def exchange(
        self,
        *,
        parent_token: Token,
        delegator_identity: WorkloadIdentity,
        delegatee_identity: WorkloadIdentity,
        new_caveats: Sequence[Caveat] = (),
        ttl_seconds: float | None = None,
    ) -> Token:
        """Per-hop token exchange: verify, attenuate, and rebind to the delegatee.

        Raises a RatchetDenied subclass if `parent_token` fails verification
        (bad signature, revoked, expired, or `delegator_identity` does not
        hold it). Raises RatchetDepthExceeded if the parent's max_depth
        caveat would be violated. Raises RatchetNotNarrowing (from
        tokens.rebind_for_exchange) if `new_caveats` would widen authority.
        """
        failure = self._check_token(parent_token, presenting_identity=delegator_identity)
        if failure is not None:
            _raise_for_denial(failure)

        max_depth = extract_max_depth(parent_token.caveats)
        next_depth = parent_token.depth + 1
        if max_depth is not None and next_depth > max_depth:
            raise RatchetDepthExceeded(
                f"exchange would reach depth {next_depth}, exceeding max_depth {max_depth}"
            )

        self._identity_registry.register(delegatee_identity)
        return rebind_for_exchange(
            parent_token,
            secret=self._secret,
            new_bound_to_fingerprint=delegatee_identity.fingerprint,
            extra_caveats=tuple(new_caveats),
            ttl_seconds=ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds,
        )

    def verify_token(self, token: Token, *, presenting_identity: WorkloadIdentity) -> Decision:
        """Verify signature, revocation, sender-binding, and expiry only — no
        action caveats evaluated, and no audit entry appended.

        Useful as a transport-level gate (e.g. ratchet-mcp's ASGI middleware)
        that validates a credential before a specific tool call is known,
        deferring caveat evaluation to authorize().
        """
        failure = self._check_token(token, presenting_identity=presenting_identity)
        return failure if failure is not None else Decision.allow()

    def authorize(
        self,
        token: Token,
        *,
        presenting_identity: WorkloadIdentity,
        proposed_tool_call: ProposedToolCall,
    ) -> Decision:
        """The Policy Enforcement Point. Pure, synchronous, in-process.

        Fails closed: any internal error results in DENY, never an implicit
        ALLOW. Always appends an audit entry, for both ALLOW and DENY.
        """
        try:
            failure = self._check_token(token, presenting_identity=presenting_identity)
            decision = (
                failure
                if failure is not None
                else self._evaluate_action_caveats(token, proposed_tool_call)
            )
        except Exception as exc:  # fail closed on any internal error, by design
            logger.exception("authorize() internal error; failing closed to DENY")
            decision = Decision.deny("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}")

        self._append_audit(token, proposed_tool_call, decision)
        return decision

    def _check_token(
        self, token: Token, *, presenting_identity: WorkloadIdentity
    ) -> Decision | None:
        """Signature, revocation, sender-binding, and expiry checks. Returns
        a DENY Decision on the first failure, else None."""
        if not verify_signature(token, self._secret):
            return Decision.deny("INVALID_SIGNATURE", "token signature does not verify")
        if self._revocation_store.is_root_revoked(token.root_id):
            return Decision.deny("REVOKED", "root token has been revoked")
        if self._revocation_store.is_any_token_revoked(token.chain):
            return Decision.deny("REVOKED", "a token in this delegation chain has been revoked")

        bound_to = extract_bound_to(token.caveats)
        if bound_to is None or bound_to != presenting_identity.fingerprint:
            return Decision.deny("NOT_BOUND", "presenting identity does not match token's bound_to")

        expires_at = extract_expires_at(token.caveats)
        if expires_at is None or time.time() >= expires_at:
            return Decision.deny("EXPIRED", "token has expired or carries no expires_at caveat")

        return None

    def _evaluate_action_caveats(self, token: Token, call: ProposedToolCall) -> Decision:
        for caveat in token.caveats:
            if caveat.kind not in ACTION_CAVEAT_KINDS:
                continue
            if not evaluate_caveat(caveat, call):
                return Decision.deny(
                    "CAVEAT_NOT_SATISFIED", f"{caveat.kind.value} caveat rejected the call"
                )
        return Decision.allow()

    def _append_audit(self, token: Token, call: ProposedToolCall, decision: Decision) -> None:
        if self._audit_sink is None:
            return
        try:
            delegation_chain = tuple(
                self._identity_uri(fingerprint) for fingerprint in token_identity_chain(token)
            )
            entry = build_entry(
                prev_hash=self._audit_sink.last_hash(),
                delegation_chain=delegation_chain,
                tool_name=call.tool_name,
                args=call.args,
                resource=call.resource,
                decision="ALLOW" if decision.allowed else "DENY",
                reason_code=decision.reason_code,
                token_id=token.token_id,
            )
            self._audit_sink.append(entry)
        except Exception:
            # Audit-sink failures must never block or flip an authorization
            # decision (that would let an attacker DoS the audit log to gate
            # access) — log loudly and continue.
            logger.exception("failed to append audit entry; decision was %s", decision)

    def _identity_uri(self, fingerprint: str) -> str:
        identity = self._identity_registry.get(fingerprint)
        return identity.uri if identity is not None else f"ratchet://unknown/{fingerprint}"
