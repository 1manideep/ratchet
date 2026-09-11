"""ratchet_core.caveats — capability-token caveat types and evaluation.

A Token carries a flat, append-only list of Caveat objects. Only three
kinds are evaluated against a *specific tool call*, via `evaluate_caveat`,
inside Broker.authorize(): TOOL_NAME, ARG_CONSTRAINT, RESOURCE. The other
three kinds are "meta" caveats that constrain the token itself rather than
one call, and are extracted and checked directly by tokens.py / broker.py
instead of going through the per-call evaluator:

  - BOUND_TO   -> checked against the presenting identity's fingerprint in
                  Broker.authorize(); can only be added by
                  tokens.rebind_for_exchange(), never by the public
                  tokens.attenuate().
  - EXPIRES_AT -> checked against wall-clock time in Broker.authorize().
  - MAX_DEPTH  -> checked against the delegation-chain depth in
                  Broker.exchange(), before minting a child token.

Narrowing (`check_narrowing`) is a deterministic approximation, not an
SMT-solver-verified proof (contrast with Progent, arXiv:2504.11703):
TOOL_NAME / ARG_CONSTRAINT / RESOURCE caveats are evaluated with AND
semantics, so any well-formed addition can only shrink or preserve the
accepted set, never grow it — no subset check is needed for those three.
EXPIRES_AT and MAX_DEPTH require the new value to tighten (or match, for
expiry) the existing bound. BOUND_TO is never accepted here at all.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ratchet_core.exceptions import RatchetMalformedToken, RatchetNotNarrowing


class CaveatKind(enum.StrEnum):
    """Caveat kinds a Ratchet token can carry."""

    TOOL_NAME = "tool_name"
    ARG_CONSTRAINT = "arg_constraint"
    RESOURCE = "resource"
    EXPIRES_AT = "expires_at"
    BOUND_TO = "bound_to"
    MAX_DEPTH = "max_depth"


ACTION_CAVEAT_KINDS = frozenset(
    {CaveatKind.TOOL_NAME, CaveatKind.ARG_CONSTRAINT, CaveatKind.RESOURCE}
)


@dataclass(frozen=True, slots=True)
class Caveat:
    """One restriction appended to a capability token at some delegation hop."""

    kind: CaveatKind
    params: Mapping[str, Any]

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical, signature-safe representation of this caveat."""
        return {"kind": self.kind.value, "params": dict(self.params)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Caveat:
        """Parse a caveat from its canonical dict form. Fails closed on malformed input."""
        try:
            kind = CaveatKind(data["kind"])
            params = data["params"]
        except (KeyError, ValueError) as exc:
            raise RatchetMalformedToken(f"invalid caveat data: {data!r}") from exc
        if not isinstance(params, dict):
            raise RatchetMalformedToken(f"caveat params must be a dict, got {type(params)!r}")
        return cls(kind=kind, params=params)


@dataclass(frozen=True, slots=True)
class ProposedToolCall:
    """The action being authorized — passed to Broker.authorize()."""

    tool_name: str
    args: Mapping[str, Any]
    resource: str | None = None


def tool_name_caveat(pattern: str) -> Caveat:
    """Restrict to tool names fully matching a regex `pattern`."""
    return Caveat(kind=CaveatKind.TOOL_NAME, params={"pattern": pattern})


def arg_constraint_caveat(key: str, *, equals: Any = None, pattern: str | None = None) -> Caveat:
    """Restrict argument `key` to an exact value (`equals`) or a regex `pattern`."""
    if pattern is not None:
        return Caveat(kind=CaveatKind.ARG_CONSTRAINT, params={"key": key, "pattern": pattern})
    return Caveat(kind=CaveatKind.ARG_CONSTRAINT, params={"key": key, "equals": equals})


def resource_caveat(pattern: str) -> Caveat:
    """Restrict to resource URIs fully matching a regex `pattern`."""
    return Caveat(kind=CaveatKind.RESOURCE, params={"pattern": pattern})


def expires_at_caveat(timestamp: float) -> Caveat:
    """Restrict the token to be usable only before `timestamp` (Unix epoch seconds)."""
    return Caveat(kind=CaveatKind.EXPIRES_AT, params={"timestamp": timestamp})


def bound_to_caveat(fingerprint: str) -> Caveat:
    """Sender-constrain the token to a workload identity fingerprint."""
    return Caveat(kind=CaveatKind.BOUND_TO, params={"fingerprint": fingerprint})


def max_depth_caveat(depth: int) -> Caveat:
    """Limit how many more delegation hops (Broker.exchange calls) may occur."""
    return Caveat(kind=CaveatKind.MAX_DEPTH, params={"depth": depth})


def extract_bound_to(caveats: Sequence[Caveat]) -> str | None:
    """Return the fingerprint of the current holder (most recent BOUND_TO caveat), if any."""
    fingerprint: str | None = None
    for caveat in caveats:
        if caveat.kind is CaveatKind.BOUND_TO:
            value = caveat.params.get("fingerprint")
            if isinstance(value, str):
                fingerprint = value
    return fingerprint


def extract_expires_at(caveats: Sequence[Caveat]) -> float | None:
    """Return the most restrictive (earliest) EXPIRES_AT timestamp, if any."""
    timestamps = [c.params.get("timestamp") for c in caveats if c.kind is CaveatKind.EXPIRES_AT]
    numeric = [t for t in timestamps if isinstance(t, (int, float))]
    return min(numeric) if numeric else None


def extract_max_depth(caveats: Sequence[Caveat]) -> int | None:
    """Return the most restrictive (smallest) MAX_DEPTH limit, if any."""
    depths = [c.params.get("depth") for c in caveats if c.kind is CaveatKind.MAX_DEPTH]
    numeric = [d for d in depths if isinstance(d, int)]
    return min(numeric) if numeric else None


def evaluate_caveat(caveat: Caveat, call: ProposedToolCall) -> bool:
    """Evaluate a single action caveat (TOOL_NAME / ARG_CONSTRAINT / RESOURCE) against a call.

    Raises RatchetMalformedToken (fail closed) if `caveat` is malformed, or
    is not an action caveat — bound_to/expires_at/max_depth never reach here.
    """
    if caveat.kind not in ACTION_CAVEAT_KINDS:
        raise RatchetMalformedToken(f"{caveat.kind!r} is not an action caveat")

    if caveat.kind is CaveatKind.TOOL_NAME:
        pattern = caveat.params.get("pattern")
        if not isinstance(pattern, str):
            raise RatchetMalformedToken("tool_name caveat missing string 'pattern'")
        return re.fullmatch(pattern, call.tool_name) is not None

    if caveat.kind is CaveatKind.ARG_CONSTRAINT:
        key = caveat.params.get("key")
        if not isinstance(key, str):
            raise RatchetMalformedToken("arg_constraint caveat missing string 'key'")
        if key not in call.args:
            return False
        value = call.args[key]
        if "equals" in caveat.params:
            return value == caveat.params["equals"]
        pattern = caveat.params.get("pattern")
        if not isinstance(pattern, str):
            raise RatchetMalformedToken(
                "arg_constraint caveat missing 'equals' or string 'pattern'"
            )
        return re.fullmatch(pattern, str(value)) is not None

    # RESOURCE
    pattern = caveat.params.get("pattern")
    if not isinstance(pattern, str):
        raise RatchetMalformedToken("resource caveat missing string 'pattern'")
    if call.resource is None:
        return False
    return re.fullmatch(pattern, call.resource) is not None


def check_narrowing(parent_caveats: Sequence[Caveat], new_caveats: Sequence[Caveat]) -> None:
    """Raise RatchetNotNarrowing if appending `new_caveats` could widen authority.

    See module docstring for the exact (deterministic, non-SMT) rules.
    """
    parent_max_depth = extract_max_depth(parent_caveats)
    parent_expires_at = extract_expires_at(parent_caveats)

    for caveat in new_caveats:
        if caveat.kind is CaveatKind.BOUND_TO:
            raise RatchetNotNarrowing(
                "bound_to may only be set via Broker.exchange(), not attenuate()"
            )
        if caveat.kind is CaveatKind.MAX_DEPTH:
            depth = caveat.params.get("depth")
            if not isinstance(depth, int):
                raise RatchetMalformedToken("max_depth caveat missing int 'depth'")
            if parent_max_depth is not None and depth >= parent_max_depth:
                raise RatchetNotNarrowing(
                    f"max_depth {depth} does not narrow existing limit {parent_max_depth}"
                )
        elif caveat.kind is CaveatKind.EXPIRES_AT:
            timestamp = caveat.params.get("timestamp")
            if not isinstance(timestamp, (int, float)):
                raise RatchetMalformedToken("expires_at caveat missing numeric 'timestamp'")
            if parent_expires_at is not None and timestamp > parent_expires_at:
                raise RatchetNotNarrowing(
                    f"expires_at {timestamp} widens existing bound {parent_expires_at}"
                )
        elif caveat.kind not in ACTION_CAVEAT_KINDS:
            raise RatchetNotNarrowing(
                f"unknown caveat kind cannot be verified as narrowing: {caveat.kind!r}"
            )
        # else: action caveat — AND semantics guarantee narrowing (see module docstring).
        # Malformed action caveats still fail closed later, in evaluate_caveat().
