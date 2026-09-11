"""ratchet_core — framework-agnostic authorization broker for multi-agent LLM delegation.

Re-exports only; no logic lives here. See broker.py for the Broker/Decision
entrypoint most integrations need.
"""

from __future__ import annotations

from ratchet_core.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditSink,
    JsonlAuditSink,
    build_entry,
    verify_audit_chain,
)
from ratchet_core.broker import Broker, Decision
from ratchet_core.caveats import (
    ACTION_CAVEAT_KINDS,
    Caveat,
    CaveatKind,
    ProposedToolCall,
    arg_constraint_caveat,
    bound_to_caveat,
    check_narrowing,
    evaluate_caveat,
    expires_at_caveat,
    extract_bound_to,
    extract_expires_at,
    extract_max_depth,
    max_depth_caveat,
    resource_caveat,
    tool_name_caveat,
)
from ratchet_core.exceptions import (
    RatchetDenied,
    RatchetDepthExceeded,
    RatchetError,
    RatchetExpired,
    RatchetInvalidSignature,
    RatchetMalformedToken,
    RatchetNotBound,
    RatchetNotNarrowing,
    RatchetRevoked,
)
from ratchet_core.identity import (
    Ed25519WorkloadIdentity,
    IdentityRegistry,
    PublicWorkloadIdentity,
    WorkloadIdentity,
)
from ratchet_core.revocation import InMemoryRevocationStore, RevocationStore
from ratchet_core.tokens import (
    Token,
    attenuate,
    deserialize_token,
    mint_root,
    rebind_for_exchange,
    serialize_token,
    token_identity_chain,
    verify_signature,
)

__all__ = [
    "ACTION_CAVEAT_KINDS",
    "AuditEntry",
    "AuditSink",
    "Broker",
    "Caveat",
    "CaveatKind",
    "Decision",
    "Ed25519WorkloadIdentity",
    "GENESIS_HASH",
    "IdentityRegistry",
    "InMemoryRevocationStore",
    "JsonlAuditSink",
    "ProposedToolCall",
    "PublicWorkloadIdentity",
    "RatchetDenied",
    "RatchetDepthExceeded",
    "RatchetError",
    "RatchetExpired",
    "RatchetInvalidSignature",
    "RatchetMalformedToken",
    "RatchetNotBound",
    "RatchetNotNarrowing",
    "RatchetRevoked",
    "RevocationStore",
    "Token",
    "WorkloadIdentity",
    "arg_constraint_caveat",
    "attenuate",
    "bound_to_caveat",
    "build_entry",
    "check_narrowing",
    "deserialize_token",
    "evaluate_caveat",
    "expires_at_caveat",
    "extract_bound_to",
    "extract_expires_at",
    "extract_max_depth",
    "max_depth_caveat",
    "mint_root",
    "rebind_for_exchange",
    "resource_caveat",
    "serialize_token",
    "token_identity_chain",
    "tool_name_caveat",
    "verify_audit_chain",
    "verify_signature",
]
